// Command flying-certs-server is the broker: it obtains certificates from an
// ACME CA on behalf of hosts that cannot reach one themselves.
//
// It is both a set of commands and a service. `obtain` and `renew` run from a
// timer and keep the certificates current; `serve` runs the mTLS endpoint that
// agents collect them from. A broker with no agents needs only the timer.
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
	"text/tabwriter"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/acme"
	"github.com/Ollornog/FlyingCerts/internal/certinfo"
	"github.com/Ollornog/FlyingCerts/internal/certstore"
	"github.com/Ollornog/FlyingCerts/internal/config"
	"github.com/Ollornog/FlyingCerts/internal/version"
	"github.com/go-acme/lego/v5/certcrypto"
)

const usage = `flying-certs-server %s — obtain certificates for hosts that cannot reach a CA

Usage:
  flying-certs-server [-config PATH] <command>

Commands:
  register    create the ACME account (once, before anything else)
  obtain      fetch every configured certificate that is not stored yet
  renew       renew what is due, asking the CA when it prefers (ARI)
  list        show what is stored and how much life is left

  serve       run the endpoint agents talk to
  token       issue a single-use bootstrap token for an agent
  agents      show what the broker knows about each agent
  check       report what needs attention; exits non-zero when something does
  revoke      shut an agent out at once (-agent NAME -reason TEXT)
  restore     lift a revocation (-agent NAME)

  backup         save everything that cannot be recreated (-out FILE [-redact])
  backup-info    say whether an archive could actually be restored (-in FILE)
  restore-backup put an archive back (-in FILE [-force])

  providers   list the DNS providers compiled into this build
  version     print the version

Flags:
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "flying-certs-server: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "/etc/flying-certs/config.yaml", "path to the configuration file")
		verbose    = flag.Bool("verbose", false, "log debug detail")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage, version.Version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		return errors.New("a command is expected")
	}
	command := flag.Arg(0)

	// Flags that belong to a subcommand are parsed here, after the command
	// name. Go's flag package stops at the first non-flag argument, so
	// `token -agent gateway` would otherwise be read as "the command token
	// plus two stray arguments" — which is exactly how a person types it.
	sub := flag.NewFlagSet(command, flag.ContinueOnError)
	sub.SetOutput(os.Stderr)
	agentName := sub.String("agent", "", "which agent (token, revoke, restore)")
	tokenLife := sub.Duration("token-lifetime", 0, "how long a bootstrap token stays usable (token)")
	reason := sub.String("reason", "", "why (revoke)")
	out := sub.String("out", "", "file to write (backup)")
	in_ := sub.String("in", "", "file to read (restore, backup-info)")
	redact := sub.Bool("redact", false, "leave keys out; the result cannot be restored (backup)")
	force := sub.Bool("force", false, "renew although nothing is due, or restore over existing state")
	if err := sub.Parse(flag.Args()[1:]); err != nil {
		return err
	}
	if sub.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q after %q", sub.Arg(0), command)
	}

	// Two commands need no configuration, so they work on a fresh machine.
	switch command {
	case "version":
		fmt.Println(version.Version)
		return nil
	case "providers":
		for _, p := range acme.SupportedProviders() {
			fmt.Println(p)
		}
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	accounts, err := acme.NewAccountStore(cfg.Storage.AccountDir)
	if err != nil {
		return err
	}
	certs, err := certstore.New(cfg.Storage.CertificateDir)
	if err != nil {
		return err
	}
	clientOpts := acme.ClientOptions{
		DirectoryURL:    cfg.ACME.Directory,
		FinalizeTimeout: cfg.ACME.FinalizeTimeout,
		UserAgent:       "FlyingCerts/" + version.Version,
	}

	// Ctrl-C and SIGTERM cancel the work in flight instead of killing it
	// mid-write: an order that is abandoned cleanly can be retried, a process
	// shot during a file write leaves questions.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch command {
	case "register":
		return cmdRegister(ctx, accounts, clientOpts, cfg, log)
	case "obtain":
		return cmdObtainOrRenew(ctx, accounts, certs, clientOpts, cfg, log, false, *force)
	case "renew":
		return cmdObtainOrRenew(ctx, accounts, certs, clientOpts, cfg, log, true, *force)
	case "list":
		return cmdList(certs)
	case "serve":
		return cmdServe(ctx, cfg, certs, accounts, clientOpts, log)
	case "token":
		if *agentName == "" {
			return errors.New("-agent is required: a token is issued for one named agent")
		}
		return cmdToken(cfg, certs, *agentName, *tokenLife)
	case "agents":
		return cmdAgents(cfg, certs)
	case "check":
		return cmdCheck(cfg, certs)
	case "revoke":
		if *agentName == "" {
			return errors.New("-agent is required")
		}
		return cmdRevoke(cfg, certs, *agentName, *reason)
	case "restore":
		if *agentName == "" {
			return errors.New("-agent is required")
		}
		return cmdRestore(cfg, certs, *agentName)
	case "backup":
		return cmdBackup(cfg, *out, *redact)
	case "backup-info":
		return cmdBackupInfo(*in_)
	case "restore-backup":
		return cmdRestoreBackup(cfg, *in_, *force)
	default:
		flag.Usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func cmdRegister(ctx context.Context, accounts *acme.AccountStore, opts acme.ClientOptions,
	cfg *config.Config, log *slog.Logger) error {

	if accounts.Exists() {
		// Not an error worth a non-zero exit: running register twice is a
		// reasonable thing to try, and the answer is simply "already done".
		log.Info("an ACME account is already stored; nothing to do",
			slog.String("dir", cfg.Storage.AccountDir))
		return nil
	}
	log.Info("registering a new ACME account",
		slog.String("directory", cfg.ACME.Directory), slog.String("email", cfg.ACME.Email))

	if _, err := accounts.Register(ctx, opts, cfg.ACME.Email, certcrypto.EC256); err != nil {
		return err
	}
	log.Info("account registered and stored", slog.String("dir", cfg.Storage.AccountDir))
	return nil
}

func cmdObtainOrRenew(ctx context.Context, accounts *acme.AccountStore, certs *certstore.Store,
	opts acme.ClientOptions, cfg *config.Config, log *slog.Logger, renewMode, force bool) error {

	if !accounts.Exists() {
		return errors.New("no ACME account stored — run `register` first")
	}

	issuer, err := acme.NewIssuer(acme.IssuerConfig{
		Accounts:    accounts,
		Client:      opts,
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

	now := time.Now()
	var failures int

	for _, want := range cfg.Certificates {
		entry := log.With(slog.String("certificate", want.Name))

		_, _, pair, err := certs.Load(want.Name)
		switch {
		case errors.Is(err, certstore.ErrNotFound):
			if renewMode && !force {
				entry.Info("not stored yet; `obtain` will fetch it")
				continue
			}
		case err != nil:
			// Something is there and broken. Do not paper over it by fetching
			// a replacement: that turns a visible fault into a silent one, and
			// an unbounded issuance loop if it keeps failing (ADR-12).
			entry.Error("stored certificate is unusable; not replacing it automatically",
				slog.String("error", err.Error()))
			failures++
			continue
		default:
			decision := acme.DecideRenewal(ctx, ariFetcher(issuer, pair), pair.Leaf, now, time.Hour)
			if !force && !decision.Due {
				entry.Info("nothing to do",
					slog.String("reason", decision.Reason),
					slog.String("remaining", certinfo.DescribeRemaining(certinfo.RemainingAt(pair.Leaf, now))))
				continue
			}
			if force {
				entry.Warn("renewing although nothing is due (--force)")
			} else {
				entry.Info("renewing", slog.String("reason", decision.Reason),
					slog.String("decided_by", string(decision.Source)))
			}
		}

		req := acme.Request{Domains: want.Domains, Profile: want.Profile}
		if pair != nil {
			// Naming the predecessor exempts this renewal from rate limits
			// (RFC 9773 §5).
			req.Replaces = pair.Leaf
		}

		res, err := issuer.Obtain(ctx, req)
		if err != nil {
			// The previous certificate is untouched — that is the point of not
			// writing anything until the new one is in hand.
			entry.Error("could not obtain certificate; the stored one is unchanged",
				slog.String("error", err.Error()))
			failures++
			continue
		}
		meta, err := certs.Save(want.Name, res.CertificatePEM, res.PrivateKeyPEM)
		if err != nil {
			entry.Error("obtained but could not store", slog.String("error", err.Error()))
			failures++
			continue
		}
		entry.Info("stored",
			slog.Time("not_after", meta.NotAfter),
			slog.String("valid_for", certinfo.DescribeRemaining(time.Until(meta.NotAfter))))
	}

	if failures > 0 {
		return fmt.Errorf("%d certificate(s) failed", failures)
	}
	return nil
}

// ariFetcher asks the CA when it would like this certificate renewed.
//
// Returning nil when there is nothing to ask about keeps DecideRenewal's
// fallback path clean.
func ariFetcher(issuer *acme.Issuer, pair *certinfo.Pair) func(context.Context) (acme.RenewalInfoFetcher, error) {
	if pair == nil {
		return nil
	}
	return func(ctx context.Context) (acme.RenewalInfoFetcher, error) {
		return issuer.RenewalInfo(ctx, pair.Leaf)
	}
}

func cmdList(certs *certstore.Store) error {
	metas, broken, err := certs.List()
	if err != nil {
		return err
	}
	if len(metas) == 0 && len(broken) == 0 {
		fmt.Println("no certificates stored")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDOMAINS\tEXPIRES\tREMAINING")
	now := time.Now()
	for _, m := range metas {
		domains := ""
		for i, d := range m.Domains {
			if i > 0 {
				domains += ", "
			}
			domains += d
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.Name, domains,
			m.NotAfter.UTC().Format("2006-01-02"),
			certinfo.DescribeRemaining(m.NotAfter.Sub(now)))
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Broken entries are listed, not hidden: a certificate that quietly
	// disappears from the output is worse than one flagged as needing help.
	for _, name := range broken {
		fmt.Fprintf(os.Stderr, "\n! %s: directory present but unreadable — check %s/%s\n",
			name, certs.Dir(), name)
	}
	if len(broken) > 0 {
		return fmt.Errorf("%d unreadable entr(y/ies)", len(broken))
	}
	return nil
}
