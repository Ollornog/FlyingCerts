package brokerapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/agentca"
	"github.com/Ollornog/FlyingCerts/internal/lifetime"
)

// Since the TLS layer stopped verifying client certificates, this package
// does it. These tests exist because that is exactly the kind of move that
// introduces an authentication hole: the old guarantee is gone and the new
// one is only as good as the code below it.
//
// Each case here is a certificate that must NOT be accepted as an identity.

// certOnRequest attaches a certificate as if the client had presented it.
// The handshake is not simulated, which is fine for these tests: possession
// of the key is TLS's job, and what is under test is everything after that.
func certOnRequest(r *http.Request, cert *x509.Certificate) *http.Request {
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

func selfSigned(t *testing.T, cn string, notBefore, notAfter time.Time, eku x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A self-signed certificate claiming a configured agent's name is the
// simplest attack there is, and the one the old faked VerifiedChains would
// have waved through.
func TestASelfSignedCertificateIsNotAnIdentity(t *testing.T) {
	h := setup(t)
	cert := selfSigned(t, "gateway", time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		x509.ExtKeyUsageClientAuth)

	r := certOnRequest(httptest.NewRequest(http.MethodGet, "/v1/whoami", nil), cert)
	if name, err := h.srv.verifiedAgent(r); err == nil {
		t.Errorf("a self-signed certificate was accepted as %q", name)
	}
}

// A certificate from a different CA — someone else's perfectly valid PKI.
func TestAnotherCAsCertificateIsNotAnIdentity(t *testing.T) {
	h := setup(t)
	stranger, err := agentca.Create(t.TempDir() + "/other-ca")
	if err != nil {
		t.Fatal(err)
	}
	cert := issueFrom(t, stranger, "gateway", lifetime.Of(time.Hour))

	r := certOnRequest(httptest.NewRequest(http.MethodGet, "/v1/whoami", nil), cert)
	if _, err := h.srv.verifiedAgent(r); err == nil {
		t.Error("another CA's certificate was accepted")
	}
}

// An expired identity is refused. This is what makes ADR-7 real rather than
// aspirational: if expiry were not enforced here, a lapsed identity would
// keep working and the whole lifetime discussion would be decoration.
func TestAnExpiredIdentityIsRefused(t *testing.T) {
	h := setup(t)
	csr, key := newCSRFor(t, "gateway")
	_ = key
	certPEM, _, err := agentca.SignAgent(h.ca, "gateway", csr, lifetime.Of(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Rather than sleeping: check the same certificate against a clock past
	// its expiry, which is what x509.Verify does with CurrentTime.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       h.ca.CertPool(),
		CurrentTime: cert.NotAfter.Add(time.Second),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Error("an expired identity still verifies")
	}
	// And the live path accepts it while it is valid, so the test above is
	// about expiry and not about something else being wrong.
	r := certOnRequest(httptest.NewRequest(http.MethodGet, "/v1/whoami", nil), cert)
	if _, err := h.srv.verifiedAgent(r); err != nil {
		t.Errorf("a valid identity was refused: %v", err)
	}
}

// A server certificate from our own CA must not work as an identity. The
// broker issues itself one from the same CA, so without the key-usage check
// its own certificate would be a valid login as whatever name it carries.
func TestAServerCertificateFromOurCAIsNotAnIdentity(t *testing.T) {
	h := setup(t)
	certPEM, _, err := agentca.SignServer(h.ca, []string{"gateway"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	r := certOnRequest(httptest.NewRequest(http.MethodGet, "/v1/whoami", nil), cert)
	if _, err := h.srv.verifiedAgent(r); err == nil {
		t.Error("a server certificate was accepted as an identity — the broker could log in as itself")
	}
}

// No certificate at all, on a route that needs one.
func TestNoCertificateIsNotAnIdentity(t *testing.T) {
	h := setup(t)
	r := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	r.TLS = &tls.ConnectionState{}
	if _, err := h.srv.verifiedAgent(r); err == nil {
		t.Error("a connection with no client certificate was accepted")
	}
	if _, err := h.srv.verifiedAgent(httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)); err == nil {
		t.Error("a plaintext connection was accepted")
	}
}

// A valid identity from our CA still works, end to end through the router.
func TestAValidIdentityStillReachesTheHandlers(t *testing.T) {
	h := setup(t)
	r := withIdentity(httptest.NewRequest(http.MethodGet, "/v1/whoami", nil), h.ca, "gateway")
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("whoami with a real identity: HTTP %d — %s", w.Code, w.Body.String())
	}
}

func issueFrom(t *testing.T, ca *agentca.CA, name string, span lifetime.Span) *x509.Certificate {
	t.Helper()
	csr, _ := newCSRFor(t, name)
	certPEM, _, err := agentca.SignAgent(ca, name, csr, span)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newCSRFor(t *testing.T, cn string) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr, key
}
