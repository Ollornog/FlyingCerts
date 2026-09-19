package acme

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	legoapi "github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	legolog "github.com/go-acme/lego/v5/log"
)

// Issuer obtains certificates from an ACME CA on behalf of hosts that cannot
// reach one themselves.
type Issuer struct {
	accounts *AccountStore
	opts     ClientOptions
	zones    *ZoneLock

	// dnsProvider names the lego DNS provider, e.g. "cloudflare". Its
	// credentials come from the environment, as lego expects.
	dnsProvider string
	// provider, when set, is used instead of looking dnsProvider up. It lets
	// tests drive the whole path without a real DNS account, and lets someone
	// embedding this package bring a provider we do not compile in.
	provider challenge.Provider
	// dnsOptions tune propagation behaviour (see DNSOptions).
	dnsOptions []dns01.ChallengeOption

	log *slog.Logger
}

// DNSOptions describe how patient to be while a DNS change spreads.
//
// A fixed, configurable wait rather than clever detection. Cert Warden built an
// active propagation check, found it "somewhat hit or miss depending on
// provider", and removed it again in favour of exactly this. An unreliable
// check is worse than an honest timeout, because it fails in ways nobody can
// reproduce.
type DNSOptions struct {
	// PropagationWait is how long to wait before asking the CA to validate.
	// Zero leaves lego's own behaviour in place.
	PropagationWait time.Duration

	// SkipPropagationCheck stops lego from polling nameservers itself. Useful
	// with split-horizon DNS, where the nameserver lego can reach is not the
	// one the CA will ask.
	SkipPropagationCheck bool
}

// IssuerConfig assembles an Issuer.
type IssuerConfig struct {
	Accounts    *AccountStore
	Client      ClientOptions
	DNSProvider string
	DNS         DNSOptions

	// Secrets are values that must never appear in a log line. DNS provider
	// credentials belong here. See NewRedactor for why this matters.
	Secrets []string

	// Log receives our own messages. Nil means slog's default.
	Log *slog.Logger

	// Provider overrides DNSProvider with a ready-made solver. DNSProvider is
	// then only a label for messages.
	Provider challenge.Provider
}

// NewIssuer builds an Issuer and installs the logging redactor.
//
// Installing the redactor is a side effect on a package-global in lego, which
// is unusual enough to say out loud: lego logs through its own package-level
// logger, so there is no other place to intercept it. Without this, provider
// credentials can reach the journal through a library we do not control —
// which is how certwarden#144 happened.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	if cfg.Accounts == nil {
		return nil, fmt.Errorf("no account store given")
	}
	if cfg.DNSProvider == "" {
		return nil, fmt.Errorf("no DNS provider named: DNS-01 is the only challenge this tool uses")
	}
	// Fail at construction, not at the first renewal at four in the morning.
	if _, ok := providers[cfg.DNSProvider]; !ok && cfg.Provider == nil {
		return nil, fmt.Errorf("DNS provider %q is not compiled into this build; available: %v",
			cfg.DNSProvider, SupportedProviders())
	}

	own := cfg.Log
	if own == nil {
		own = slog.Default()
	}
	// Both our own logger and lego's get the same redactor, so a secret cannot
	// escape through whichever of the two happens to print it.
	redacted := slog.New(NewRedactor(own.Handler(), cfg.Secrets...))
	legolog.SetDefault(redacted)

	var opts []dns01.ChallengeOption
	if cfg.DNS.PropagationWait > 0 {
		opts = append(opts, dns01.PropagationWait(cfg.DNS.PropagationWait, cfg.DNS.SkipPropagationCheck))
	}

	return &Issuer{
		accounts:    cfg.Accounts,
		opts:        cfg.Client,
		zones:       NewZoneLock(),
		dnsProvider: cfg.DNSProvider,
		provider:    cfg.Provider,
		dnsOptions:  opts,
		log:         redacted,
	}, nil
}

// Request describes one certificate to obtain.
type Request struct {
	// Domains are the names the certificate must cover, most specific first.
	Domains []string

	// KeyType selects the key algorithm. Empty means EC256.
	KeyType certcrypto.KeyType

	// Profile optionally selects a CA issuance profile, such as Let's
	// Encrypt's "shortlived". Empty leaves the CA's default.
	Profile string

	// Replaces is the certificate this one supersedes, if any.
	//
	// Passing it matters more than it looks: under RFC 9773 §5 a renewal that
	// names its predecessor is exempt from rate limits. Certbot reportedly
	// still omits this, which is a good reason not to.
	Replaces *x509.Certificate
}

// Result is a freshly obtained certificate.
type Result struct {
	// CertificatePEM is the chain, leaf first.
	CertificatePEM []byte
	// PrivateKeyPEM is the key lego generated for this certificate.
	PrivateKeyPEM []byte
	// IssuerPEM is the issuing chain without the leaf.
	IssuerPEM []byte
}

// Obtain fetches a certificate for the requested names.
//
// Work competing for the same DNS challenge record is serialised (see
// ZoneLock). The lock is taken on the challenge target derived from the
// names, so a domain and its wildcard form cannot trip over each other.
func (i *Issuer) Obtain(ctx context.Context, req Request) (*Result, error) {
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("no domains requested")
	}

	acct, err := i.accounts.Load()
	if err != nil {
		// Deliberately not "register a new one": see the package comment.
		return nil, fmt.Errorf("load ACME account: %w", err)
	}

	client, err := newClient(acct, i.opts)
	if err != nil {
		return nil, err
	}

	provider := i.provider
	if provider == nil {
		var err error
		if provider, err = newDNSProvider(i.dnsProvider); err != nil {
			return nil, err
		}
	}
	if err := client.Challenge.SetDNS01Provider(provider, i.dnsOptions...); err != nil {
		return nil, fmt.Errorf("install DNS-01 solver: %w", err)
	}

	keyType := req.KeyType
	if keyType == "" {
		keyType = certcrypto.EC256
	}

	obtain := certificate.ObtainRequest{
		Domains: req.Domains,
		Bundle:  true,
		KeyType: keyType,
		Profile: req.Profile,
	}
	if req.Replaces != nil {
		id, err := legoapi.MakeARICertID(req.Replaces)
		if err != nil {
			// Not fatal: a renewal without the hint still works, it just does
			// not get the rate-limit exemption.
			i.log.Warn("could not derive the ARI certificate id; renewing without the replaces hint",
				slog.String("error", err.Error()))
		} else {
			obtain.ReplacesCertID = id
		}
	}

	release := i.zones.Acquire(challengeTarget(req.Domains))
	defer release()

	res, err := client.Certificate.Obtain(ctx, obtain)
	if err != nil {
		return nil, fmt.Errorf("obtain certificate for %s: %w", strings.Join(req.Domains, ", "), err)
	}

	return &Result{
		CertificatePEM: res.Certificate,
		PrivateKeyPEM:  res.PrivateKey,
		IssuerPEM:      res.IssuerCertificate,
	}, nil
}

// challengeTarget derives the key under which orders are serialised.
//
// A wildcard and its base name share one _acme-challenge record, so
// "*.example.com" and "example.com" must map to the same key — otherwise two
// orders write over each other's TXT value and the CA sees a mismatch. That is
// the failure Cert Warden chased through issues #23 and #74.
//
// This covers the common case. Names delegated by CNAME to a shared target
// also collide, and no amount of string handling can see that — resolving the
// delegation is the honest fix and belongs with the DNS work, not here.
func challengeTarget(domains []string) string {
	base := strings.TrimPrefix(domains[0], "*.")
	return "_acme-challenge." + strings.ToLower(base)
}

// Provider reports the configured DNS provider name.
func (i *Issuer) Provider() string { return i.dnsProvider }

// RenewalInfo asks the CA when it would prefer this certificate to be renewed.
//
// It returns legoapi.ErrNoARI when the CA does not offer renewal information,
// which callers treat as "fall back to our own arithmetic" rather than as a
// failure — plenty of CAs do not implement RFC 9773 yet.
func (i *Issuer) RenewalInfo(ctx context.Context, cert *x509.Certificate) (RenewalInfoFetcher, error) {
	acct, err := i.accounts.Load()
	if err != nil {
		return nil, fmt.Errorf("load ACME account: %w", err)
	}
	client, err := newClient(acct, i.opts)
	if err != nil {
		return nil, err
	}
	info, err := client.Certificate.GetRenewalInfo(ctx, cert)
	if err != nil {
		return nil, err
	}
	return info, nil
}
