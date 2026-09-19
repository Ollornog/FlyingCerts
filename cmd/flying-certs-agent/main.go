// Command flying-certs-agent runs on an internal host: it proves who it is to
// the broker, collects its certificates and puts them where the local service
// will find them.
//
// It identifies itself with a key pair it generates on first run and never
// sends anywhere. You authorise the host once by putting the matching
// fingerprint in the broker's configuration — the same arrangement as
// authorized_keys — and from then on it needs nothing from you, including
// after being switched off for longer than its identity lasts.
//
// It is meant to run from a timer. Nothing happens when nothing changed —
// no write, no reload — so running it often is cheap.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/agent"
	"github.com/Ollornog/FlyingCerts/internal/deploy"
	"github.com/Ollornog/FlyingCerts/internal/devicekey"
	"github.com/Ollornog/FlyingCerts/internal/version"
)

const usage = `flying-certs-agent %s — collect certificates from a FlyingCerts broker

Usage:
  flying-certs-agent [-config PATH] <command>

Commands:
  keygen        create this host's device key and print its fingerprint
  fingerprint   print it again, for pasting into the broker's public_key
  enrol         obtain an identity — with the device key, or -token for a
                one-time bootstrap token
  run           collect every configured certificate and deploy what changed
  status        show the identity and what is deployed
  version       print the version

Flags:
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "flying-certs-agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "/etc/flying-certs/agent.yaml", "path to the configuration file")
		verbose    = flag.Bool("verbose", false, "log debug detail")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage, version.Version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		return errors.New("exactly one command expected")
	}
	command := flag.Arg(0)

	// Flags that belong to the command are read here, after its name. Go's
	// flag package stops at the first non-flag argument, so `enrol -token X`
	// would otherwise arrive as "the command enrol plus two stray arguments"
	// — which is exactly how a person types it.
	sub := flag.NewFlagSet(command, flag.ContinueOnError)
	sub.SetOutput(os.Stderr)
	token := sub.String("token", "", "bootstrap token — the alternative to a device key (enrol)")
	caFile := sub.String("broker-ca", "", "the broker's CA certificate, needed for first contact (enrol)")
	if err := sub.Parse(flag.Args()[1:]); err != nil {
		return err
	}
	if sub.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q after %q", sub.Arg(0), command)
	}
	if command == "version" {
		fmt.Println(version.Version)
		return nil
	}

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch command {
	case "keygen":
		return cmdKeygen(cfg)
	case "fingerprint":
		return cmdFingerprint(cfg)
	case "enrol", "enroll":
		return cmdEnrol(ctx, cfg, *token, *caFile, log)
	case "run":
		return cmdRun(ctx, cfg, log)
	case "status":
		return cmdStatus(cfg)
	default:
		flag.Usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

// cmdKeygen creates the device key and prints what to do with it.
func cmdKeygen(cfg *agent.Config) error {
	key, created, err := devicekey.LoadOrCreate(cfg.IdentityDir)
	if err != nil {
		return err
	}
	fp, err := key.Fingerprint()
	if err != nil {
		return err
	}
	if !created {
		fmt.Printf("this host already has a device key\n\n  %s\n", fp)
		return nil
	}
	fmt.Printf("created %s\n\n  %s\n\n", devicekey.Path(cfg.IdentityDir), fp)
	fmt.Println("Put that fingerprint in the broker's configuration:")
	fmt.Println()
	fmt.Println("  agents:")
	fmt.Println("    - name: <this host>")
	fmt.Printf("      public_key: %q\n", fp)
	fmt.Println()
	fmt.Println("Then run `enrol`. The private key stays here and is never sent anywhere.")
	return nil
}

// cmdFingerprint prints the fingerprint on its own, for scripts and for
// pasting. Nothing else, so its output can be used directly.
func cmdFingerprint(cfg *agent.Config) error {
	key, err := devicekey.Load(cfg.IdentityDir)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("this host has no device key yet — run `keygen`")
	}
	if err != nil {
		return err
	}
	fp, err := key.Fingerprint()
	if err != nil {
		return err
	}
	fmt.Println(fp)
	return nil
}

// cmdEnrol obtains an identity.
//
// Two ways in, and the device key is the ordinary one: it also works when the
// identity has already expired, which is the situation a token cannot help
// with. The token remains for the case where nobody wants to fetch a
// fingerprint off the host first.
func cmdEnrol(ctx context.Context, cfg *agent.Config, token, caFile string, log *slog.Logger) error {
	if caFile == "" {
		caFile = agent.CAPath(cfg.IdentityDir)
		if _, err := os.Stat(caFile); err != nil {
			return errors.New("-broker-ca is required for first contact: without the broker's " +
				"certificate there is nothing to verify the handshake against")
		}
	}
	if token == "" {
		return enrolWithDeviceKey(ctx, cfg, caFile, log)
	}
	if existing, err := agent.LoadIdentity(cfg.IdentityDir); err == nil {
		// Not an error: running enrol twice is a reasonable thing to try.
		// Overwriting would spend a token for nothing and throw away a
		// working identity.
		log.Info("this host is already enrolled; nothing to do",
			slog.String("agent", existing.Name()),
			slog.Time("identity_expires", existing.Certificate.NotAfter))
		return nil
	} else if !errors.Is(err, agent.ErrNotEnrolled) {
		return err
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read the broker CA certificate: %w", err)
	}
	client, err := agent.NewEnrolmentClient(cfg.Broker, caPEM, cfg.Timeout)
	if err != nil {
		return err
	}

	keyPEM, csrPEM, err := agent.NewKeyAndCSR("agent")
	if err != nil {
		return err
	}
	res, err := client.Enrol(ctx, token, string(csrPEM))
	if err != nil {
		return err
	}
	id, err := agent.SaveIdentity(cfg.IdentityDir, []byte(res.CertificatePEM), keyPEM, []byte(res.CAPem))
	if err != nil {
		return fmt.Errorf("the broker issued an identity but it could not be stored (%w) — "+
			"the token is spent, so a new one is needed to try again", err)
	}
	log.Info("enrolled",
		slog.String("agent", id.Name()),
		slog.Time("identity_expires", id.Certificate.NotAfter))
	return nil
}

// enrolWithDeviceKey asks for an identity with the key this host holds.
//
// Unlike the token path this may run at any time, including when an identity
// already exists or has long since expired. That is the point of it: there is
// no state in which the host cannot ask again.
func enrolWithDeviceKey(ctx context.Context, cfg *agent.Config, caFile string, log *slog.Logger) error {
	key, err := devicekey.Load(cfg.IdentityDir)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("this host has no device key — run `keygen` first, or pass -token " +
			"to use a bootstrap token instead")
	}
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read the broker CA certificate: %w", err)
	}
	clientCert, err := key.ClientCertificate("device")
	if err != nil {
		return err
	}
	client, err := agent.NewDeviceClient(cfg.Broker, caPEM, clientCert, cfg.Timeout)
	if err != nil {
		return err
	}

	// A fresh key for the identity, never the device key: the long-lived
	// secret stays out of daily traffic, and the broker refuses the request
	// if the two are the same.
	keyPEM, csrPEM, err := agent.NewKeyAndCSR("agent")
	if err != nil {
		return err
	}
	res, err := client.RequestIdentity(ctx, string(csrPEM))
	if err != nil {
		return err
	}
	id, err := agent.SaveIdentity(cfg.IdentityDir,
		[]byte(res.CertificatePEM), keyPEM, []byte(res.CAPem))
	if err != nil {
		return err
	}
	log.Info("obtained an identity with this host's device key",
		slog.String("agent", id.Name()),
		slog.Time("identity_expires", id.Certificate.NotAfter))
	return nil
}

func cmdRun(ctx context.Context, cfg *agent.Config, log *slog.Logger) error {
	id, fresh, err := ensureIdentity(ctx, cfg, log)
	if err != nil {
		return err
	}
	client, err := agent.NewClient(cfg.Broker, id, cfg.Timeout)
	if err != nil {
		return err
	}

	// Renew the identity while it still works. Cheaper than the device-key
	// path above and it keeps the host out of the recovery case entirely.
	//
	// Skipped when one was just issued: with a very short lifetime a brand
	// new identity is already past its renewal point, and asking again in
	// the same run would mint a second certificate for nothing.
	if !fresh && id.NeedsRenewalAt(time.Now()) {
		if err := renewIdentity(ctx, cfg, client, log); err != nil {
			// Not fatal: the current identity still works, so the certificates
			// can still be collected, and with a device key the host can
			// recover even if this keeps failing. Still worth saying loudly.
			log.Error("could not renew this host's identity",
				slog.Time("expires", id.Certificate.NotAfter),
				slog.String("error", err.Error()))
		}
	}

	var failures int
	for _, target := range cfg.Certificates {
		entry := log.With(slog.String("certificate", target.Name))
		cert, err := collect(ctx, client, target)
		if err != nil {
			entry.Error("could not collect", slog.String("error", err.Error()))
			failures++
			continue
		}

		// In issue mode this is the key generated on this host, which collect()
		// paired up after the request came back; in share mode it is the one
		// the broker sent. Either way it is what belongs next to the chain.
		keyPEM := []byte(cert.PrivateKeyPEM)

		outcome, err := deploy.Deploy(deploy.Target{
			CertPath:         target.CertPath,
			KeyPath:          target.KeyPath,
			Owner:            target.Owner,
			Group:            target.Group,
			KeyMode:          os.FileMode(target.KeyMode),
			ReloadCommand:    target.Reload,
			ReloadTimeout:    target.ReloadTimeout,
			VerifyAddress:    target.VerifyAddress,
			VerifyServerName: target.VerifyServerName,
		}, []byte(cert.CertificatePEM), keyPEM)

		switch {
		case err != nil:
			entry.Error("deployment failed", slog.String("error", err.Error()))
			failures++
		case !outcome.Changed:
			entry.Debug("already current")
		case outcome.Verified:
			entry.Info("deployed and confirmed", slog.String("detail", outcome.Message))
		case outcome.VerifySkipped:
			// Said out loud every time, not once: an unverified deployment is
			// the state in which the September 2026 outage went unnoticed.
			entry.Warn("deployed, but nobody checked whether the service picked it up",
				slog.String("hint", "set verify_address to have this confirmed"))
		default:
			entry.Info("deployed", slog.String("detail", outcome.Message))
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d certificate(s) failed", failures)
	}
	return nil
}

// ensureIdentity returns a usable identity, obtaining one if there is none.
//
// This is what makes a host recoverable without anybody logging into it. The
// case it exists for is mundane: a machine switched off over a holiday comes
// back after its identity has expired. Before ADR-18 that host was stuck —
// an expired certificate cannot authenticate to ask for its replacement, and
// a bootstrap token would have expired too. With a device key it simply asks
// again.
// The bool reports whether the identity returned was just issued.
func ensureIdentity(ctx context.Context, cfg *agent.Config, log *slog.Logger) (*agent.Identity, bool, error) {
	id, err := agent.LoadIdentity(cfg.IdentityDir)
	switch {
	case err == nil && !id.ExpiredAt(time.Now()):
		return id, false, nil
	case err != nil && !errors.Is(err, agent.ErrNotEnrolled):
		// A broken or unreadable identity is not the same as a missing one
		// and must not be papered over by fetching a replacement.
		return nil, false, err
	}

	caFile := agent.CAPath(cfg.IdentityDir)
	if _, statErr := os.Stat(devicekey.Path(cfg.IdentityDir)); statErr != nil {
		if err == nil {
			return nil, false, fmt.Errorf("this host's identity expired on %s and it has no device key "+
				"to ask for another — enrol it again with a token, and run `keygen` while you are "+
				"there so this cannot happen twice",
				id.Certificate.NotAfter.UTC().Format(time.RFC3339))
		}
		return nil, false, err
	}
	if _, statErr := os.Stat(caFile); statErr != nil {
		return nil, false, fmt.Errorf("this host has a device key but not the broker's CA certificate, "+
			"so it cannot verify the broker: run `enrol -broker-ca <file>` once (%s)", caFile)
	}

	if err == nil {
		log.Warn("this host's identity has expired; asking for a new one with the device key",
			slog.Time("expired", id.Certificate.NotAfter))
	} else {
		log.Info("no identity yet; asking for one with the device key")
	}
	if err := enrolWithDeviceKey(ctx, cfg, caFile, log); err != nil {
		return nil, false, err
	}
	fresh, err := agent.LoadIdentity(cfg.IdentityDir)
	return fresh, true, err
}

// collect fetches or requests one certificate, depending on the mode.
func collect(ctx context.Context, client *agent.Client, t agent.CertificateTarget) (*agent.Certificate, error) {
	if t.Mode == "share" {
		return client.Fetch(ctx, t.Name)
	}
	// issue: generate a key here, send only the request. The names must match
	// what the broker has configured exactly — it refuses a subset as firmly
	// as an extra name.
	keyPEM, csrPEM, err := agent.NewCSRForNames(t.Domains)
	if err != nil {
		return nil, err
	}
	cert, err := client.Issue(ctx, t.Name, string(csrPEM))
	if err != nil {
		return nil, err
	}
	// The key never travelled; pair it up here for deployment.
	cert.PrivateKeyPEM = string(keyPEM)
	return cert, nil
}

func renewIdentity(ctx context.Context, cfg *agent.Config, client *agent.Client, log *slog.Logger) error {
	keyPEM, csrPEM, err := agent.NewKeyAndCSR("agent")
	if err != nil {
		return err
	}
	certPEM, err := client.RenewIdentity(ctx, string(csrPEM))
	if err != nil {
		return err
	}
	// The CA certificate is unchanged, so it is not rewritten here.
	id, err := agent.SaveIdentity(cfg.IdentityDir, []byte(certPEM), keyPEM, nil)
	if err != nil {
		return err
	}
	log.Info("identity renewed", slog.Time("expires", id.Certificate.NotAfter))
	return nil
}

func cmdStatus(cfg *agent.Config) error {
	id, err := agent.LoadIdentity(cfg.IdentityDir)
	if errors.Is(err, agent.ErrNotEnrolled) {
		fmt.Printf("not enrolled\ndevice:   %s\nbroker:   %s\n",
			describeDeviceKey(cfg), cfg.Broker)
		return nil
	}
	if err != nil {
		return err
	}

	now := time.Now()
	fmt.Printf("agent:    %s\n", id.Name())
	fmt.Printf("identity: expires %s (%s)\n",
		id.Certificate.NotAfter.UTC().Format(time.RFC3339),
		describeIdentity(id, now, hasDeviceKey(cfg)))
	fmt.Printf("device:   %s\n", describeDeviceKey(cfg))
	fmt.Printf("broker:   %s\n\n", cfg.Broker)

	for _, t := range cfg.Certificates {
		fmt.Printf("%-24s %-6s -> %s\n", t.Name, t.Mode, t.CertPath)
		if t.VerifyAddress == "" {
			fmt.Printf("%-24s %s\n", "", "! no verify_address: deployments cannot be confirmed")
		}
	}
	return nil
}

func describeIdentity(id *agent.Identity, now time.Time, recoverable bool) string {
	switch {
	case id.ExpiredAt(now) && recoverable:
		// Worth stating plainly: with a device key an expired identity is an
		// inconvenience, not the dead end it used to be.
		return "expired — the next run will ask for a new one with the device key"
	case id.ExpiredAt(now):
		return "EXPIRED and no device key — this host must be enrolled again with a token"
	case id.NeedsRenewalAt(now):
		return "renewal due"
	default:
		return "current"
	}
}

func hasDeviceKey(cfg *agent.Config) bool {
	_, err := os.Stat(devicekey.Path(cfg.IdentityDir))
	return err == nil
}

// describeDeviceKey shows the fingerprint, because the question status is
// usually asked to answer is "why will this host not get in" — and the
// answer is often that this value is not in the broker's configuration.
func describeDeviceKey(cfg *agent.Config) string {
	key, err := devicekey.Load(cfg.IdentityDir)
	if err != nil {
		return "no device key — run `keygen`, then add the fingerprint to the broker"
	}
	fp, err := key.Fingerprint()
	if err != nil {
		return "device key present but unreadable: " + err.Error()
	}
	return fp
}
