package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/acme"
	"github.com/Ollornog/FlyingCerts/internal/agentca"
	"github.com/Ollornog/FlyingCerts/internal/atomicfile"
	"github.com/Ollornog/FlyingCerts/internal/brokerapi"
	"github.com/Ollornog/FlyingCerts/internal/certstore"
	"github.com/Ollornog/FlyingCerts/internal/config"
	"github.com/Ollornog/FlyingCerts/internal/enroll"
	"github.com/Ollornog/FlyingCerts/internal/lifetime"
	"github.com/Ollornog/FlyingCerts/internal/registry"
	"github.com/Ollornog/FlyingCerts/internal/version"
)

// Defaults for the review thresholds.
//
// Silent after a week: an agent runs from a timer, so a week of silence means
// the timer stopped. Warn five days before the identity runs out: the agent
// renews at two thirds of a 30-day life, so five days is well past the point
// where it should have renewed itself and still leaves time to act.
const (
	defaultSilentAfter = 7 * 24 * time.Hour
	defaultWarnBefore  = 5 * 24 * time.Hour
)

// brokerParts are the pieces the agent-facing side needs.
type brokerParts struct {
	ca     *agentca.CA
	tokens *enroll.Store
	agents *registry.Registry
	certs  *certstore.Store
	audit  *brokerapi.FileAuditor
}

// openBroker assembles the agent-facing side from the configuration.
func openBroker(cfg *config.Config, certs *certstore.Store) (*brokerParts, error) {
	if cfg.Broker.StateDir == "" {
		return nil, errors.New("broker.state_dir is not configured")
	}
	ca, err := agentca.OpenOrCreate(filepath.Join(cfg.Broker.StateDir, "ca"))
	if err != nil {
		return nil, err
	}
	tokens, err := enroll.NewStore(filepath.Join(cfg.Broker.StateDir, "tokens"))
	if err != nil {
		return nil, err
	}

	agents := make([]registry.Agent, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		agents = append(agents, registry.Agent{
			Name:             a.Name,
			Certificates:     a.Certificates,
			Mode:             registry.DeliveryMode(a.Mode),
			PublicKey:        a.PublicKey,
			IdentityLifetime: a.IdentityLifetime,
		})
	}
	reg, err := registry.New(agents,
		registry.NewFileState(filepath.Join(cfg.Broker.StateDir, "agents.json")))
	if err != nil {
		return nil, err
	}

	parts := &brokerParts{ca: ca, tokens: tokens, agents: reg, certs: certs}
	if cfg.Broker.AuditLog != "" {
		if parts.audit, err = brokerapi.NewFileAuditor(cfg.Broker.AuditLog); err != nil {
			return nil, err
		}
	}
	return parts, nil
}

// cmdServe runs the agent-facing endpoint.
func cmdServe(ctx context.Context, cfg *config.Config, certs *certstore.Store,
	accounts *acme.AccountStore, clientOpts acme.ClientOptions, log *slog.Logger) error {

	if cfg.Broker.Listen == "" {
		return errors.New("broker.listen is not configured — nothing to serve")
	}
	parts, err := openBroker(cfg, certs)
	if err != nil {
		return err
	}
	if parts.audit != nil {
		defer parts.audit.Close()
	}

	// The issue mode needs a way to reach the CA. Without an ACME account
	// there is none, and the route says so rather than failing oddly.
	var issuer brokerapi.Issuer
	if accounts.Exists() {
		iss, err := acme.NewIssuer(acme.IssuerConfig{
			Accounts:    accounts,
			Client:      clientOpts,
			DNSProvider: cfg.DNS.Provider,
			DNS: acme.DNSOptions{
				PropagationWait:      cfg.DNS.PropagationWait,
				SkipPropagationCheck: cfg.DNS.SkipPropagationCheck,
			},
			Secrets: cfg.Secrets(),
			Log:     log,
		})
		if err != nil {
			return err
		}
		issuer = iss
	} else {
		log.Warn("no ACME account, so the issue mode is unavailable; run `register` first")
	}

	var auditor brokerapi.Auditor
	if parts.audit != nil {
		auditor = parts.audit
	}
	api, err := brokerapi.New(brokerapi.Config{
		CA: parts.ca, Tokens: parts.tokens, Agents: parts.agents, Certs: parts.certs,
		Audit: auditor, Log: log, Lifetime: cfg.Broker.IdentityLifetime,
		Specs: cfg, Issuer: issuer,
	})
	if err != nil {
		return err
	}

	serverCert, err := brokerServerCertificate(cfg, parts.ca, log)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Broker.Listen,
		Handler:           api.Handler(),
		TLSConfig:         api.TLSConfig(serverCert),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Housekeeping that nobody misses until the disk is full: spent tokens and
	// rate-limit counters both grow without it. Both step-ca and Cert Warden
	// have open issues for exactly this omission.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if n, err := parts.tokens.Prune(now.Add(-24 * time.Hour)); err == nil && n > 0 {
					log.Debug("pruned spent tokens", slog.Int("count", n))
				}
				api.PruneRateLimiter(now)
			}
		}
	}()

	log.Info("serving agents",
		slog.String("address", cfg.Broker.Listen),
		slog.String("version", version.Version),
		slog.Int("agents", len(cfg.Agents)))

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// brokerServerCertificate loads the endpoint's TLS certificate, issuing one
// from the agent CA when none is configured.
//
// Issuing it ourselves is the sensible default: agents verify the broker with
// the CA they were given at enrolment, so a certificate from that CA is
// exactly what they can check. A public certificate would tie the endpoint to
// a public name for no gain.
func brokerServerCertificate(cfg *config.Config, ca *agentca.CA, log *slog.Logger) (tlsCertificate, error) {
	if cfg.Broker.ServerCert != "" && cfg.Broker.ServerKey != "" {
		return loadKeyPair(cfg.Broker.ServerCert, cfg.Broker.ServerKey)
	}

	certPath := filepath.Join(cfg.Broker.StateDir, "broker.crt")
	keyPath := filepath.Join(cfg.Broker.StateDir, "broker.key")
	if pair, err := loadKeyPair(certPath, keyPath); err == nil {
		return pair, nil
	}

	host := hostOf(cfg.Broker.Listen)
	if host == "" {
		return tlsCertificate{}, fmt.Errorf(
			"cannot tell which name to put in the broker's certificate from listen %q — "+
				"set broker.server_cert and broker.server_key", cfg.Broker.Listen)
	}
	log.Info("issuing the broker's own TLS certificate from the agent CA",
		slog.String("name", host))

	certPEM, keyPEM, err := agentca.SignServer(ca, []string{host}, 365*24*time.Hour)
	if err != nil {
		return tlsCertificate{}, err
	}
	if err := atomicfile.WritePublic(certPath, certPEM); err != nil {
		return tlsCertificate{}, err
	}
	if err := atomicfile.WriteSecret(keyPath, keyPEM); err != nil {
		return tlsCertificate{}, err
	}
	return loadKeyPair(certPath, keyPath)
}

// cmdToken issues a bootstrap token for an agent.
func cmdToken(cfg *config.Config, certs *certstore.Store, agentName string, lifetime time.Duration) error {
	parts, err := openBroker(cfg, certs)
	if err != nil {
		return err
	}
	if parts.audit != nil {
		defer parts.audit.Close()
	}
	if _, err := parts.agents.Lookup(agentName); err != nil {
		return fmt.Errorf("%w — add it to the agents section first", err)
	}

	tok, rec, err := enroll.NewToken(agentName, nil, parts.ca.Fingerprint(), lifetime, time.Now())
	if err != nil {
		return err
	}
	if err := parts.tokens.Put(rec); err != nil {
		return err
	}

	// The token goes to stdout alone, so it can be piped without the
	// surrounding explanation coming with it.
	fmt.Println(tok.String())
	fmt.Fprintf(os.Stderr,
		"\nFor %s, valid until %s. Single use.\n"+
			"The agent also needs the CA certificate to verify this broker:\n  %s\n",
		agentName, rec.NotAfter.UTC().Format(time.RFC3339),
		filepath.Join(cfg.Broker.StateDir, "ca", "agent-ca.crt"))
	return nil
}

// cmdAgents shows what the broker knows about each agent.
func cmdAgents(cfg *config.Config, certs *certstore.Store) error {
	parts, err := openBroker(cfg, certs)
	if err != nil {
		return err
	}
	if parts.audit != nil {
		defer parts.audit.Close()
	}

	agents := parts.agents.Agents()
	if len(agents) == 0 {
		fmt.Println("no agents configured")
		return nil
	}

	now := time.Now()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "AGENT\tMODE\tLAST SEEN\tLIFETIME\tIDENTITY\tCERTIFICATES")
	for _, a := range agents {
		st := parts.agents.StateOf(a.Name)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n",
			a.Name, a.Mode, describeSeen(st.LastSeen, now),
			describeConfiguredLifetime(a, cfg.Broker.IdentityLifetime),
			describeIdentity(a, st, now), len(a.Certificates))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return nil
}

// cmdCheck is the one meant for a timer: it reports what needs attention and
// exits non-zero when something does.
//
// A monitoring command that always exits 0 is decoration. The exit code is
// the interface here; the text is for whoever reads the mail afterwards.
func cmdCheck(cfg *config.Config, certs *certstore.Store) error {
	parts, err := openBroker(cfg, certs)
	if err != nil {
		return err
	}
	if parts.audit != nil {
		defer parts.audit.Close()
	}

	now := time.Now()
	findings := parts.agents.Review(now, defaultSilentAfter, defaultWarnBefore)

	// Certificates near expiry belong in the same report: an operator wants
	// one place to look, not two.
	metas, broken, err := parts.certs.List()
	if err != nil {
		return err
	}
	var certConcerns []string
	for _, m := range metas {
		if left := m.NotAfter.Sub(now); left < defaultWarnBefore {
			certConcerns = append(certConcerns,
				fmt.Sprintf("%s: %s", m.Name, describeRemaining(left)))
		}
	}

	// Findings that need action decide the exit code; the rest are printed
	// and ignored by it. A standing state that fails every run teaches people
	// to stop reading the output.
	actionable := 0
	for _, f := range findings {
		if f.Concern.NeedsAction() {
			actionable++
		}
	}
	if actionable == 0 && len(certConcerns) == 0 && len(broken) == 0 {
		fmt.Printf("all %d agent(s) and %d certificate(s) in order\n",
			len(parts.agents.Agents()), len(metas))
		for _, f := range findings {
			fmt.Printf("  note: %s — %s\n", f.Agent, f.Detail)
		}
		return nil
	}

	for _, f := range findings {
		fmt.Printf("%-24s %-26s %s\n", f.Agent, f.Concern, f.Detail)
	}
	for _, c := range certConcerns {
		fmt.Printf("%-24s %-26s %s\n", "", "certificate expiring", c)
	}
	for _, name := range broken {
		fmt.Printf("%-24s %-26s %s\n", name, "unreadable", "check the stored files")
	}
	return fmt.Errorf("%d finding(s)", actionable+len(certConcerns)+len(broken))
}

func describeSeen(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return describeAgo(now.Sub(t))
}

// describeConfiguredLifetime shows what was asked for, resolving the fallback
// so the column never says "default" and leaves the reader to go looking.
func describeConfiguredLifetime(a registry.Agent, brokerWide lifetime.Span) string {
	span := a.IdentityLifetime.Or(brokerWide)
	if !span.Set() {
		return agentca.DefaultAgentLifetime.String()
	}
	return span.String()
}

// describeIdentity shows what the agent actually holds.
//
// An unlimited identity still has a date — it runs until the CA does, because
// no certificate is truly endless. Showing "unlimited" alone would hide that,
// so it shows both: the intent and the date it really stops.
func describeIdentity(a registry.Agent, st registry.State, now time.Time) string {
	switch {
	case st.RevokedAt != nil:
		return "revoked"
	case st.IdentityExpires.IsZero():
		return "none"
	case !now.Before(st.IdentityExpires):
		return "EXPIRED"
	case a.IdentityLifetime.IsUnlimited():
		return "until CA (" + st.IdentityExpires.UTC().Format("2006-01-02") + ")"
	default:
		return describeRemaining(st.IdentityExpires.Sub(now))
	}
}

// cmdRevoke shuts an agent out.
//
// It takes effect on that agent's next request, not at the next restart —
// every request consults the registry and nothing is cached per connection.
func cmdRevoke(cfg *config.Config, certs *certstore.Store, agentName, reason string) error {
	parts, err := openBroker(cfg, certs)
	if err != nil {
		return err
	}
	if parts.audit != nil {
		defer parts.audit.Close()
	}
	if reason == "" {
		// Recorded and shown to whoever asks later. "Why is this host shut
		// out" is the question nobody can answer three months on.
		reason = "no reason given"
	}
	if err := parts.agents.Revoke(agentName, reason, time.Now()); err != nil {
		return err
	}
	fmt.Printf("%s is revoked (%s); it will be refused on its next request\n", agentName, reason)
	return nil
}

// cmdRestore lifts a revocation.
func cmdRestore(cfg *config.Config, certs *certstore.Store, agentName string) error {
	parts, err := openBroker(cfg, certs)
	if err != nil {
		return err
	}
	if parts.audit != nil {
		defer parts.audit.Close()
	}
	if !parts.agents.Revoked(agentName) {
		fmt.Printf("%s is not revoked; nothing to do\n", agentName)
		return nil
	}
	if err := parts.agents.Restore(agentName); err != nil {
		return err
	}
	fmt.Printf("%s may collect again — its identity was never invalidated, only refused\n", agentName)
	return nil
}
