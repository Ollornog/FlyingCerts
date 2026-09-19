package agent_test

// The scenario this whole mechanism exists for, run end to end:
//
//	"I go on holiday and shut a server down. It gets no certificates and
//	 locks itself out."
//
// Before the device key that was accurate and had no remedy: an expired
// identity cannot authenticate to ask for its replacement, and a bootstrap
// token would have expired long before. These tests hold that door open.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
	"github.com/Ollornog/FlyingCerts/internal/devicekey"
	"github.com/Ollornog/FlyingCerts/internal/enroll"
	"github.com/Ollornog/FlyingCerts/internal/keyfp"
	"github.com/Ollornog/FlyingCerts/internal/lifetime"
	"github.com/Ollornog/FlyingCerts/internal/registry"
)

// deviceBroker starts a broker that authorises one agent by device key.
func deviceBroker(t *testing.T, fingerprint string, span lifetime.Span) (*broker, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := agentca.Create(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := enroll.NewStore(filepath.Join(dir, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certstore.New(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.New([]registry.Agent{{
		Name: "gateway", Certificates: []string{"gateway-cert"}, Mode: registry.ModeShare,
		PublicKey: fingerprint, IdentityLifetime: span,
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := brokerapi.New(brokerapi.Config{CA: ca, Tokens: tokens, Agents: reg, Certs: certs})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = srv.TLSConfig(serverCertificate(t, ca))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return &broker{url: ts.URL, ca: ca, tokens: tokens, certs: certs, agents: reg}, ts.URL
}

func fingerprintOf(t *testing.T, dir string) (*devicekey.Key, string) {
	t.Helper()
	key, err := devicekey.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := key.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return key, fp
}

// requestIdentity asks with the device key and returns both the answer and
// the key the identity was issued for, so the caller can store a usable pair.
func requestIdentity(t *testing.T, key *devicekey.Key, b *broker, url string) (*agent.EnrolResult, []byte) {
	t.Helper()
	client := deviceClient(t, key, b, url)
	keyPEM, csrPEM, err := agent.NewKeyAndCSR("agent")
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.RequestIdentity(context.Background(), string(csrPEM))
	if err != nil {
		t.Fatalf("RequestIdentity: %v", err)
	}
	return res, keyPEM
}

func deviceClient(t *testing.T, key *devicekey.Key, b *broker, url string) *agent.Client {
	t.Helper()
	clientCert, err := key.ClientCertificate("device")
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.NewDeviceClient(url, b.ca.CertificatePEM(), clientCert, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// A host with an authorised device key gets an identity, and the broker
// works out who it is from the key — the request never says a name.
func TestAnAuthorisedDeviceKeyGetsAnIdentity(t *testing.T) {
	dir := t.TempDir()
	key, fp := fingerprintOf(t, dir)
	b, url := deviceBroker(t, fp, lifetime.Of(24*time.Hour))

	res, _ := requestIdentity(t, key, b, url)
	if res.AgentName != "gateway" {
		t.Errorf("AgentName = %q, want gateway", res.AgentName)
	}
	if res.CertificatePEM == "" || res.CAPem == "" {
		t.Error("the response is missing the certificate or the CA")
	}
	if state := b.agents.StateOf("gateway"); state.IdentityExpires.IsZero() {
		t.Error("the broker did not record when this identity runs out")
	}
}

// The whole point: an identity that has already expired does not stop the
// host from getting a new one.
func TestAnExpiredIdentityIsNoObstacle(t *testing.T) {
	dir := t.TempDir()
	key, fp := fingerprintOf(t, dir)
	// One second, so it is genuinely expired a moment later rather than
	// merely backdated by the test.
	b, url := deviceBroker(t, fp, lifetime.Of(time.Second))

	first, firstKey := requestIdentity(t, key, b, url)
	if _, err := agent.SaveIdentity(dir,
		[]byte(first.CertificatePEM), firstKey, []byte(first.CAPem)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)

	id, err := agent.LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !id.ExpiredAt(time.Now()) {
		t.Fatal("test setup: the identity has not expired")
	}
	// mTLS is closed to it now — that is correct and is what used to be the
	// end of the road.
	if _, err := agent.NewClient(url, id, time.Second); err == nil {
		t.Error("an expired identity was accepted for mTLS")
	}
	// The device key still opens the door.
	second, _ := requestIdentity(t, key, b, url)
	if second.CertificatePEM == first.CertificatePEM {
		t.Error("the broker handed back the same expired certificate")
	}
}

// An unauthorised key is refused, and the message names the fingerprint so
// somebody can authorise it if it should be let in.
func TestAnUnauthorisedDeviceKeyIsRefused(t *testing.T) {
	authorised := t.TempDir()
	_, fp := fingerprintOf(t, authorised)
	b, url := deviceBroker(t, fp, lifetime.Of(24*time.Hour))

	stranger, _ := fingerprintOf(t, t.TempDir())
	client := deviceClient(t, stranger, b, url)
	_, csrPEM, err := agent.NewKeyAndCSR("agent")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RequestIdentity(context.Background(), string(csrPEM))
	if err == nil {
		t.Fatal("an unauthorised device key was given an identity")
	}
	if !strings.Contains(err.Error(), "public_key") {
		t.Errorf("the refusal does not say how to authorise it: %v", err)
	}
}

// A revoked agent stays out, device key or not. Otherwise revocation would
// mean nothing for exactly the hosts that hold a long-lived credential.
func TestARevokedAgentIsRefusedDespiteItsDeviceKey(t *testing.T) {
	dir := t.TempDir()
	key, fp := fingerprintOf(t, dir)
	b, url := deviceBroker(t, fp, lifetime.Of(24*time.Hour))

	requestIdentity(t, key, b, url) // works before
	if err := b.agents.Revoke("gateway", "decommissioned", time.Now()); err != nil {
		t.Fatal(err)
	}

	client := deviceClient(t, key, b, url)
	_, csrPEM, err := agent.NewKeyAndCSR("agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RequestIdentity(context.Background(), string(csrPEM)); err == nil {
		t.Error("a revoked agent got an identity with its device key")
	}
}

// Connecting without any certificate is refused on this route — it is not an
// open one, even though it is reachable without an identity.
func TestTheDeviceRouteNeedsACertificate(t *testing.T) {
	dir := t.TempDir()
	_, fp := fingerprintOf(t, dir)
	b, url := deviceBroker(t, fp, lifetime.Of(24*time.Hour))

	client, err := agent.NewEnrolmentClient(url, b.ca.CertificatePEM(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := agent.NewKeyAndCSR("agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RequestIdentity(context.Background(), string(csrPEM)); err == nil {
		t.Error("the device route answered a caller with no certificate")
	}
}

// The identity must not reuse the device key. Keeping them apart is what
// keeps the long-lived secret out of daily traffic.
func TestTheIdentityMayNotReuseTheDeviceKey(t *testing.T) {
	dir := t.TempDir()
	key, fp := fingerprintOf(t, dir)
	b, url := deviceBroker(t, fp, lifetime.Of(24*time.Hour))

	client := deviceClient(t, key, b, url)
	// A CSR built on the device key itself, read off disk the way an
	// over-clever operator might have wired it up.
	csrPEM := csrForDeviceKey(t, dir)
	_, err := client.RequestIdentity(context.Background(), csrPEM)
	if err == nil {
		t.Fatal("an identity was issued for the device key itself")
	}
	if !strings.Contains(err.Error(), "own key") {
		t.Errorf("the refusal does not explain what to do instead: %v", err)
	}
}

// A device key is not created twice: overwriting it would silently throw
// away the only thing that can get this host back in.
func TestADeviceKeyIsNeverReplacedSilently(t *testing.T) {
	dir := t.TempDir()
	first, fp := fingerprintOf(t, dir)
	_ = first
	if _, err := devicekey.Create(dir); err == nil {
		t.Fatal("a second device key overwrote the first")
	}
	again, created, err := devicekey.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("LoadOrCreate created a key although one existed")
	}
	if got, _ := again.Fingerprint(); got != fp {
		t.Errorf("fingerprint changed: %s -> %s", fp, got)
	}
}

// The fingerprint follows the key, not the certificate — the agent mints a
// fresh certificate for every connection, and the value in the broker's
// configuration must not go stale because of it.
func TestTheFingerprintSurvivesAFreshCertificate(t *testing.T) {
	dir := t.TempDir()
	key, fp := fingerprintOf(t, dir)

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		cert, err := key.ClientCertificate("device")
		if err != nil {
			t.Fatal(err)
		}
		seen[string(cert.Leaf.Raw)] = true
		got, err := keyfp.Of(cert.Leaf.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if got != fp {
			t.Errorf("fingerprint %s does not match the key's %s", got, fp)
		}
	}
	if len(seen) != 3 {
		t.Error("the certificates were not distinct — the test proves nothing")
	}
}

// csrForDeviceKey builds a certificate request signed with the device key
// itself, which the broker must refuse.
func csrForDeviceKey(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(devicekey.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		t.Fatalf("the device key is a %T", parsed)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
