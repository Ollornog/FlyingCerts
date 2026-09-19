package agent_test

// The round trip: a host with nothing, a broker, and a real mTLS connection
// between them.
//
// Every package here is tested on its own. This file is the one that would
// notice if they were wired together wrongly — an identity that is issued but
// not accepted, a certificate that arrives but cannot be deployed, a mode that
// means one thing on each side.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/agent"
	"github.com/Ollornog/FlyingCerts/internal/agentca"
	"github.com/Ollornog/FlyingCerts/internal/brokerapi"
	"github.com/Ollornog/FlyingCerts/internal/certstore"
	"github.com/Ollornog/FlyingCerts/internal/deploy"
	"github.com/Ollornog/FlyingCerts/internal/enroll"
	"github.com/Ollornog/FlyingCerts/internal/lifetime"
	"github.com/Ollornog/FlyingCerts/internal/registry"
)

type broker struct {
	url    string
	ca     *agentca.CA
	tokens *enroll.Store
	certs  *certstore.Store
	agents *registry.Registry
}

// startBroker brings up a real TLS server with client-certificate support.
func startBroker(t *testing.T, agents []registry.Agent) *broker {
	t.Helper()
	dir := t.TempDir()

	ca, err := agentca.Create(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	tokens, err := enroll.NewStore(filepath.Join(dir, "tokens"))
	if err != nil {
		t.Fatalf("tokens: %v", err)
	}
	certs, err := certstore.New(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatalf("certs: %v", err)
	}
	reg, err := registry.New(agents, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	srv, err := brokerapi.New(brokerapi.Config{CA: ca, Tokens: tokens, Agents: reg, Certs: certs})
	if err != nil {
		t.Fatalf("brokerapi: %v", err)
	}

	// The broker's own TLS certificate, signed by the agent CA — which is how
	// an agent can verify it with nothing but what enrolment gave it.
	serverCert := serverCertificate(t, ca)
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = srv.TLSConfig(serverCert)
	ts.StartTLS()
	t.Cleanup(ts.Close)

	return &broker{url: ts.URL, ca: ca, tokens: tokens, certs: certs, agents: reg}
}

// serverCertificate issues the broker's TLS certificate from the agent CA —
// the same call the broker makes in production, so an agent can verify it
// with nothing but what enrolment gave it.
func serverCertificate(t *testing.T, ca *agentca.CA) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := agentca.SignServer(ca, []string{"127.0.0.1", "localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("SignServer: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	return pair
}

// storeSharedCertificate puts a certificate in the broker's store.
func storeSharedCertificate(t *testing.T, b *broker, name string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name + ".example.com"},
		DNSNames:     []string{name + ".example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if _, err := b.certs.Save(name,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Fatalf("store %s: %v", name, err)
	}
}

func TestAgentEnrolsFetchesAndDeploys(t *testing.T) {
	b := startBroker(t, []registry.Agent{
		{Name: "gateway", Certificates: []string{"gateway-cert"}, Mode: registry.ModeShare},
	})
	storeSharedCertificate(t, b, "gateway-cert")

	dir := t.TempDir()
	cfg := &agent.Config{Broker: b.url, IdentityDir: filepath.Join(dir, "identity")}
	ctx := context.Background()

	// --- 1. nothing yet ---------------------------------------------------
	if _, err := agent.LoadIdentity(cfg.IdentityDir); err == nil {
		t.Fatal("a fresh host already has an identity")
	}

	// --- 2. enrol ---------------------------------------------------------
	tok, rec, err := enroll.NewToken("gateway", nil, b.ca.Fingerprint(), 0, time.Now())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := b.tokens.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	enrolClient, err := agent.NewEnrolmentClient(b.url, b.ca.CertificatePEM(), 0)
	if err != nil {
		t.Fatalf("NewEnrolmentClient: %v", err)
	}
	keyPEM, csrPEM, err := agent.NewKeyAndCSR("agent")
	if err != nil {
		t.Fatalf("NewKeyAndCSR: %v", err)
	}
	res, err := enrolClient.Enrol(ctx, tok.String(), string(csrPEM))
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	id, err := agent.SaveIdentity(cfg.IdentityDir, []byte(res.CertificatePEM), keyPEM, []byte(res.CAPem))
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if id.Name() != "gateway" {
		t.Errorf("the broker named us %q", id.Name())
	}

	// --- 3. the identity actually works over mTLS -------------------------
	client, err := agent.NewClient(b.url, id, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	who, err := client.Whoami(ctx)
	if err != nil {
		t.Fatalf("Whoami over mTLS: %v", err)
	}
	if who["agent"] != "gateway" {
		t.Errorf("the broker sees us as %v", who["agent"])
	}

	// --- 4. collect and deploy -------------------------------------------
	cert, err := client.Fetch(ctx, "gateway-cert")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if cert.PrivateKeyPEM == "" {
		t.Fatal("share mode returned no private key")
	}

	certPath := filepath.Join(dir, "fullchain.pem")
	out, err := deploy.Deploy(deploy.Target{
		CertPath: certPath,
		KeyPath:  filepath.Join(dir, "privkey.pem"),
	}, []byte(cert.CertificatePEM), []byte(cert.PrivateKeyPEM))
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if !out.Changed {
		t.Error("the first deployment changed nothing")
	}
	if on, err := os.ReadFile(certPath); err != nil || len(on) == 0 {
		t.Errorf("nothing landed on disk: %v", err)
	}

	// --- 5. the token is spent -------------------------------------------
	if _, err := enrolClient.Enrol(ctx, tok.String(), string(csrPEM)); err == nil {
		t.Error("the same token enrolled a second time")
	}
}

// An agent must not be able to collect something that is not its own, over a
// real connection and not just in a handler test.
func TestAgentCannotCollectAnotherAgentsCertificateOverTheWire(t *testing.T) {
	b := startBroker(t, []registry.Agent{
		{Name: "gateway", Certificates: []string{"gateway-cert"}, Mode: registry.ModeShare},
		{Name: "storage", Certificates: []string{"storage-cert"}, Mode: registry.ModeShare},
	})
	storeSharedCertificate(t, b, "gateway-cert")
	storeSharedCertificate(t, b, "storage-cert")

	id := enrolAs(t, b, "gateway")
	client, err := agent.NewClient(b.url, id, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Fetch(context.Background(), "storage-cert"); err == nil {
		t.Fatal("an agent collected another agent's certificate")
	}
}

// Revocation must bite on the next request, over a live connection.
func TestRevokedAgentIsCutOffImmediately(t *testing.T) {
	b := startBroker(t, []registry.Agent{
		{Name: "gateway", Certificates: []string{"gateway-cert"}, Mode: registry.ModeShare},
	})
	storeSharedCertificate(t, b, "gateway-cert")

	id := enrolAs(t, b, "gateway")
	client, err := agent.NewClient(b.url, id, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Fetch(context.Background(), "gateway-cert"); err != nil {
		t.Fatalf("setup fetch: %v", err)
	}

	if err := b.agents.Revoke("gateway", "test", time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Same client, same connection pool — the identity is unchanged and still
	// cryptographically valid. Only the broker's answer changes.
	_, err = client.Fetch(context.Background(), "gateway-cert")
	if err == nil {
		t.Fatal("a revoked agent still collected its certificate")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// An agent with an identity from another CA must not get in at all — the
// handshake itself has to fail, not a check inside a handler.
func TestIdentityFromAnotherCAIsRejectedAtTheHandshake(t *testing.T) {
	b := startBroker(t, []registry.Agent{
		{Name: "gateway", Certificates: []string{"gateway-cert"}, Mode: registry.ModeShare},
	})

	// A perfectly valid identity — from the wrong authority.
	strangerDir := t.TempDir()
	stranger, err := agentca.Create(filepath.Join(strangerDir, "ca"))
	if err != nil {
		t.Fatalf("stranger CA: %v", err)
	}
	keyPEM, csrPEM, _ := agent.NewKeyAndCSR("gateway")
	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	certPEM, _, err := agentca.SignAgent(stranger, "gateway", csr, lifetime.Of(time.Hour))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Store it together with the real broker's CA so the client trusts the
	// server; only the client certificate is foreign.
	id, err := agent.SaveIdentity(filepath.Join(strangerDir, "identity"),
		certPEM, keyPEM, b.ca.CertificatePEM())
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	client, err := agent.NewClient(b.url, id, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Whoami(context.Background()); err == nil {
		t.Fatal("an identity from another CA was accepted")
	}
}

func enrolAs(t *testing.T, b *broker, name string) *agent.Identity {
	t.Helper()
	tok, rec, err := enroll.NewToken(name, nil, b.ca.Fingerprint(), 0, time.Now())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := b.tokens.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	client, err := agent.NewEnrolmentClient(b.url, b.ca.CertificatePEM(), 0)
	if err != nil {
		t.Fatalf("NewEnrolmentClient: %v", err)
	}
	keyPEM, csrPEM, _ := agent.NewKeyAndCSR("agent")
	res, err := client.Enrol(context.Background(), tok.String(), string(csrPEM))
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	id, err := agent.SaveIdentity(t.TempDir(), []byte(res.CertificatePEM), keyPEM, []byte(res.CAPem))
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	return id
}
