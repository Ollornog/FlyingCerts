package backup_test

// The test T-3 exists for.
//
// One project's backup chain failed four times in a row, and the last failure
// is the one this file is built around: after a restore, every renewal failed
// permanently (certmate#410). The backups themselves had been checked — the
// files came back — so nothing looked wrong until a certificate was actually
// due.
//
// So this test does not stop at "the bytes are back". It destroys the broker's
// entire state, restores it, opens everything again *from disk*, and then does
// the two things a broker exists to do: renew against the CA, and hand the
// result to an agent that enrolled before the disaster.
//
// Each of those catches a different way a restore can be hollow:
//
//   - The renewal needs the ACME account key. Without it the CA does not know
//     us and no renewal will ever work again — #410 exactly.
//   - The delivery needs the agent CA's key and the registry. Without the key
//     the broker cannot prove itself to an agent that already trusts a CA;
//     without the registry the agent is a stranger. Either way the host is
//     locked out with no way back (ADR-7), which is worse than a failed
//     renewal because it needs a human at the other end.

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/acme"
	"github.com/Ollornog/FlyingCerts/internal/agent"
	"github.com/Ollornog/FlyingCerts/internal/agentca"
	"github.com/Ollornog/FlyingCerts/internal/backup"
	"github.com/Ollornog/FlyingCerts/internal/brokerapi"
	"github.com/Ollornog/FlyingCerts/internal/certinfo"
	"github.com/Ollornog/FlyingCerts/internal/certstore"
	"github.com/Ollornog/FlyingCerts/internal/config"
	"github.com/Ollornog/FlyingCerts/internal/enroll"
	"github.com/Ollornog/FlyingCerts/internal/pebbletest"
	"github.com/Ollornog/FlyingCerts/internal/registry"
	"github.com/go-acme/lego/v5/certcrypto"
)

const (
	agentName = "gateway"
	certName  = "gateway-cert"
	// A domain of this suite's own. The challenge server is shared by every
	// package, go test runs packages concurrently, and CleanUp deletes the TXT
	// record by name — so two suites on one name delete each other's answer and
	// the CA sees nothing. The same collision the zone lock prevents inside one
	// process (ADR-9), here across two test binaries, where no lock reaches.
	domain = "restore.backup.example.com"
)

// broker is everything the endpoint needs, opened from a set of paths.
//
// It is a function rather than a fixture on purpose: the second call, after
// the restore, must read the same files a freshly started process would.
// Reusing the objects from before the disaster would let the test pass with
// the state still in memory and nothing on disk.
type broker struct {
	ca     *agentca.CA
	tokens *enroll.Store
	certs  *certstore.Store
	agents *registry.Registry
	audit  *brokerapi.FileAuditor
}

func openBroker(t *testing.T, cfg *config.Config) *broker {
	t.Helper()
	ca, err := agentca.OpenOrCreate(filepath.Join(cfg.Broker.StateDir, "ca"))
	if err != nil {
		t.Fatalf("agent CA: %v", err)
	}
	tokens, err := enroll.NewStore(filepath.Join(cfg.Broker.StateDir, "tokens"))
	if err != nil {
		t.Fatalf("token store: %v", err)
	}
	certs, err := certstore.New(cfg.Storage.CertificateDir)
	if err != nil {
		t.Fatalf("certificate store: %v", err)
	}
	reg, err := registry.New([]registry.Agent{
		{Name: agentName, Certificates: []string{certName}, Mode: registry.ModeShare},
	}, registry.NewFileState(filepath.Join(cfg.Broker.StateDir, "agents.json")))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	audit, err := brokerapi.NewFileAuditor(cfg.Broker.AuditLog)
	if err != nil {
		t.Fatalf("auditor: %v", err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	return &broker{ca: ca, tokens: tokens, certs: certs, agents: reg, audit: audit}
}

// serve starts a real TLS endpoint for this broker and returns its URL.
func (b *broker) serve(t *testing.T, cfg *config.Config) string {
	t.Helper()
	srv, err := brokerapi.New(brokerapi.Config{
		CA: b.ca, Tokens: b.tokens, Agents: b.agents, Certs: b.certs,
		Audit: b.audit, Specs: cfg,
	})
	if err != nil {
		t.Fatalf("brokerapi: %v", err)
	}
	certPEM, keyPEM, err := agentca.SignServer(b.ca, []string{"127.0.0.1", "localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("SignServer: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("server pair: %v", err)
	}
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = srv.TLSConfig(pair)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.URL
}

func newIssuer(t *testing.T, cfg *config.Config) (*acme.AccountStore, *acme.Issuer) {
	t.Helper()
	accounts, err := acme.NewAccountStore(cfg.Storage.AccountDir)
	if err != nil {
		t.Fatalf("account store: %v", err)
	}
	opts := acme.ClientOptions{
		DirectoryURL: pebbletest.DirectoryURL,
		HTTPClient:   pebbletest.HTTPClient(),
		UserAgent:    "FlyingCerts-backup-test",
	}
	if !accounts.Exists() {
		return accounts, nil
	}
	issuer, err := acme.NewIssuer(acme.IssuerConfig{
		Accounts:    accounts,
		Client:      opts,
		DNSProvider: pebbletest.ProviderName,
		Provider:    pebbletest.Provider{},
		DNS:         acme.DNSOptions{SkipPropagationCheck: true},
		Log:         slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return accounts, issuer
}

func TestRestoredBrokerRenewsAndDelivers(t *testing.T) {
	pebbletest.Require(t)

	root := t.TempDir()
	cfg := &config.Config{
		Certificates: []config.CertificateConfig{{Name: certName, Domains: []string{domain}}},
		Agents:       []config.AgentSpec{{Name: agentName, Certificates: []string{certName}, Mode: "share"}},
	}
	cfg.Storage.AccountDir = filepath.Join(root, "account")
	cfg.Storage.CertificateDir = filepath.Join(root, "certs")
	cfg.Broker.StateDir = filepath.Join(root, "state")
	cfg.Broker.AuditLog = filepath.Join(root, "audit.log")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// --- 1. a working broker: an account, a certificate, an enrolled agent --
	accounts, _ := newIssuer(t, cfg)
	opts := acme.ClientOptions{
		DirectoryURL: pebbletest.DirectoryURL,
		HTTPClient:   pebbletest.HTTPClient(),
		UserAgent:    "FlyingCerts-backup-test",
	}
	if _, err := accounts.Register(ctx, opts, "admin@example.com", certcrypto.EC256); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, issuer := newIssuer(t, cfg)

	b := openBroker(t, cfg)
	res, err := issuer.Obtain(ctx, acme.Request{Domains: []string{domain}})
	if err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	if _, err := b.certs.Save(certName, res.CertificatePEM, res.PrivateKeyPEM); err != nil {
		t.Fatalf("Save: %v", err)
	}
	originalPair, err := certinfo.LoadPair(res.CertificatePEM, res.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	url := b.serve(t, cfg)
	identityDir := filepath.Join(root, "agent")
	enrolAgent(t, ctx, b, url, identityDir)

	// The agent can collect before the disaster. Without this the test could
	// not tell a restore that broke something from a setup that never worked.
	if got := fetchSerial(t, ctx, url, identityDir); got != originalPair.Leaf.SerialNumber.String() {
		t.Fatalf("before the backup the agent got serial %s, want %s",
			got, originalPair.Leaf.SerialNumber)
	}

	// --- 2. back it up ------------------------------------------------------
	// Outside the tree that is about to be destroyed, which is the whole point
	// of a backup and easy to get wrong in a test.
	archivePath := filepath.Join(t.TempDir(), "broker.tar.gz")
	writeArchive(t, archivePath, cfg)

	// --- 3. lose everything -------------------------------------------------
	for _, gone := range []string{
		cfg.Storage.AccountDir, cfg.Storage.CertificateDir, cfg.Broker.StateDir, cfg.Broker.AuditLog,
	} {
		if err := os.RemoveAll(gone); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.Storage.AccountDir, "account.key")); err == nil {
		t.Fatal("the disaster did not happen; the rest of this test would prove nothing")
	}

	// --- 4. restore ---------------------------------------------------------
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	man, err := backup.Restore(f, backup.PathsFor(cfg))
	f.Close()
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(man.Areas) != 4 {
		t.Errorf("restored areas %v, expected account, certificates, state and audit", man.Areas)
	}

	// --- 5. renew, from what came off the disk ------------------------------
	// Everything is opened again here. Reusing the objects from step 1 would
	// test the test.
	restoredAccounts, restoredIssuer := newIssuer(t, cfg)
	if !restoredAccounts.Exists() {
		t.Fatal("the ACME account did not come back — every renewal from here on would fail")
	}
	renewed, err := restoredIssuer.Obtain(ctx, acme.Request{
		Domains:  []string{domain},
		Replaces: originalPair.Leaf,
	})
	if err != nil {
		t.Fatalf("renewal after the restore failed — this is certmate#410: %v", err)
	}
	renewedPair, err := certinfo.LoadPair(renewed.CertificatePEM, renewed.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if renewedPair.Leaf.SerialNumber.Cmp(originalPair.Leaf.SerialNumber) == 0 {
		t.Fatal("the renewal returned the same certificate")
	}

	// --- 6. deliver it to the agent that enrolled before the disaster -------
	restored := openBroker(t, cfg)
	if _, err := restored.certs.Save(certName, renewed.CertificatePEM, renewed.PrivateKeyPEM); err != nil {
		t.Fatalf("storing the renewal: %v", err)
	}
	if restored.ca.Fingerprint() != b.ca.Fingerprint() {
		t.Fatal("the agent CA came back as a different CA — every agent is now locked out " +
			"and cannot enrol its way back (ADR-7)")
	}
	restoredURL := restored.serve(t, cfg)

	// The agent is untouched by all of this: same identity, same stored CA.
	got := fetchSerial(t, ctx, restoredURL, identityDir)
	if got != renewedPair.Leaf.SerialNumber.String() {
		t.Errorf("after the restore the agent got serial %s, want the renewed %s",
			got, renewedPair.Leaf.SerialNumber)
	}

	// --- 7. the record survived too -----------------------------------------
	// M-5's promise is that the broker knows who collected what. A restore
	// that silently drops the audit trail keeps the service running and loses
	// the only thing that answers "who had this key".
	auditData, err := os.ReadFile(cfg.Broker.AuditLog)
	if err != nil {
		t.Fatalf("the audit log did not come back: %v", err)
	}
	if !strings.Contains(string(auditData), agentName) {
		t.Error("the restored audit log has no record of the agent that enrolled before the backup")
	}
	if state := restored.agents.StateOf(agentName); state.LastSeen.IsZero() {
		t.Error("the registry came back without knowing the agent had ever been seen")
	}
}

// A redacted archive is not a recovery point, and the operator learns that
// from the archive rather than from a failed restore at three in the morning.
func TestRedactedArchiveOfARealBrokerIsNotARecoveryPoint(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.AccountDir = filepath.Join(root, "account")
	cfg.Storage.CertificateDir = filepath.Join(root, "certs")
	cfg.Broker.StateDir = filepath.Join(root, "state")

	// A real agent CA, so the redaction meets a key it did not plant itself.
	if _, err := agentca.Create(filepath.Join(cfg.Broker.StateDir, "ca")); err != nil {
		t.Fatal(err)
	}

	var archive bytes.Buffer
	man, err := backup.Create(&archive, backup.PathsFor(cfg), backup.Options{Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if man.ContainsSecrets || man.Restorable {
		t.Errorf("redacted manifest is wrong: %+v", man)
	}
	if len(man.RedactedFiles) == 0 {
		t.Error("the CA key was not recognised as key material")
	}
	if _, err := backup.Restore(bytes.NewReader(archive.Bytes()), backup.PathsFor(cfg)); err == nil {
		t.Error("a redacted archive was accepted as a restore source")
	}
}

func writeArchive(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	man, err := backup.Create(f, backup.PathsFor(cfg), backup.Options{Tool: "FlyingCerts-test"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !man.ContainsSecrets {
		t.Error("a backup holding the ACME account key must say it contains secrets")
	}
}

// enrolAgent walks a host with nothing through its first contact.
func enrolAgent(t *testing.T, ctx context.Context, b *broker, url, identityDir string) {
	t.Helper()
	tok, rec, err := enroll.NewToken(agentName, nil, b.ca.Fingerprint(), 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.tokens.Put(rec); err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := agent.NewKeyAndCSR(agentName)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.NewEnrolmentClient(url, b.ca.CertificatePEM(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Enrol(ctx, tok.String(), string(csrPEM))
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if _, err := agent.SaveIdentity(identityDir,
		[]byte(res.CertificatePEM), keyPEM, []byte(res.CAPem)); err != nil {
		t.Fatal(err)
	}
}

// fetchSerial collects the shared certificate over mTLS and returns its
// serial, which is how this test tells one certificate from another.
func fetchSerial(t *testing.T, ctx context.Context, url, identityDir string) string {
	t.Helper()
	id, err := agent.LoadIdentity(identityDir)
	if err != nil {
		t.Fatalf("the agent cannot load its identity: %v", err)
	}
	client, err := agent.NewClient(url, id, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := client.Fetch(ctx, certName)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	pair, err := certinfo.LoadPair([]byte(cert.CertificatePEM), []byte(cert.PrivateKeyPEM))
	if err != nil {
		t.Fatalf("what the broker handed over is unusable: %v", err)
	}
	return pair.Leaf.SerialNumber.String()
}
