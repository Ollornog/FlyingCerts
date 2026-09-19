// Command flying-certs-agent runs on an internal host: it enrols once with a
// bootstrap token, then collects its certificates from the broker and puts
// them where the local service will find them.
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
	"github.com/Ollornog/FlyingCerts/internal/version"
)

const usage = `flying-certs-agent %s — collect certificates from a FlyingCerts broker

Usage:
  flying-certs-agent [-config PATH] <command>

Commands:
  enrol     redeem a bootstrap token and obtain this host's identity
  run       collect every configured certificate and deploy what changed
  status    show the identity and what is deployed
  version   print the version

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
	token := sub.String("token", "", "bootstrap token (enrol)")
	caFile := sub.String("broker-ca", "", "the broker's CA certificate (enrol)")
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

func cmdEnrol(ctx context.Context, cfg *agent.Config, token, caFile string, log *slog.Logger) error {
	if token == "" {
		return errors.New("-token is required to enrol")
	}
	if caFile == "" {
		return errors.New("-broker-ca is required: without the broker's certificate there is " +
			"nothing to verify the first handshake against")
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

func cmdRun(ctx context.Context, cfg *agent.Config, log *slog.Logger) error {
	id, err := agent.LoadIdentity(cfg.IdentityDir)
	if err != nil {
		return err
	}
	client, err := agent.NewClient(cfg.Broker, id, cfg.Timeout)
	if err != nil {
		return err
	}

	// Renew the identity first. Everything below needs it, and an identity
	// that expires is the one failure with no way back (ADR-7).
	if id.NeedsRenewalAt(time.Now()) {
		if err := renewIdentity(ctx, cfg, client, log); err != nil {
			// Not fatal yet: the current identity still works, so the
			// certificates can still be collected. But it must be loud.
			log.Error("could not renew this host's identity — it will lock itself out if this keeps failing",
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
		fmt.Println("not enrolled — run `enrol` with a bootstrap token")
		return nil
	}
	if err != nil {
		return err
	}

	now := time.Now()
	fmt.Printf("agent:    %s\n", id.Name())
	fmt.Printf("identity: expires %s (%s)\n",
		id.Certificate.NotAfter.UTC().Format(time.RFC3339),
		describeIdentity(id, now))
	fmt.Printf("broker:   %s\n\n", cfg.Broker)

	for _, t := range cfg.Certificates {
		fmt.Printf("%-24s %-6s -> %s\n", t.Name, t.Mode, t.CertPath)
		if t.VerifyAddress == "" {
			fmt.Printf("%-24s %s\n", "", "! no verify_address: deployments cannot be confirmed")
		}
	}
	return nil
}

func describeIdentity(id *agent.Identity, now time.Time) string {
	switch {
	case id.ExpiredAt(now):
		return "EXPIRED — this host must be enrolled again"
	case id.NeedsRenewalAt(now):
		return "renewal due"
	default:
		return "current"
	}
}
