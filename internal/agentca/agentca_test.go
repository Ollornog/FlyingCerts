package agentca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/Ollornog/flying-certs/internal/lifetime"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func csrFor(t *testing.T, cn string) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	return csr, key
}

func TestCreateThenOpen(t *testing.T) {
	dir := t.TempDir()
	created, err := Create(dir)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	opened, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if created.Fingerprint() != opened.Fingerprint() {
		t.Error("the reopened CA is a different one")
	}
	if !opened.Certificate().IsCA {
		t.Error("the CA certificate is not marked as a CA")
	}
	// A root that can sign intermediates lets a stolen agent key mint more
	// certificates. This one signs leaves only.
	if !opened.Certificate().MaxPathLenZero {
		t.Error("the CA may sign intermediates — it must sign leaves only")
	}
}

func TestOpenEmptyReportsErrNoRoot(t *testing.T) {
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrNoRoot) {
		t.Errorf("err = %v, want ErrNoRoot", err)
	}
}

// A second root would leave every enrolled agent holding an identity the
// broker no longer recognises — silently, at the next handshake.
func TestCreateRefusesSecondRoot(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "agent-ca.key"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := Create(dir); err == nil {
		t.Fatal("a second CA was created")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "agent-ca.key"))
	if string(before) != string(after) {
		t.Error("the existing CA key was overwritten")
	}
}

// A certificate without its key cannot sign. Reporting "no CA" would invite
// the caller to create a second root.
func TestCertificateWithoutKeyIsAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "agent-ca.key")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	_, err := Open(dir)
	if err == nil {
		t.Fatal("a CA without its key opened fine")
	}
	if errors.Is(err, ErrNoRoot) {
		t.Error("reported as ErrNoRoot — that invites a second root")
	}
}

func TestCAKeyIsOwnerReadableOnly(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	if _, err := Create(dir); err != nil {
		t.Fatalf("Create: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "agent-ca.key"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("CA key mode = %o, want 600 — this key is the whole trust anchor", got)
	}
}

func TestSignAgentProducesAClientCertificate(t *testing.T) {
	ca, err := Create(t.TempDir())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	csr, _ := csrFor(t, "whatever-the-agent-asked-for")

	certPEM, _, err := SignAgent(ca, "gateway", csr, lifetime.Span{})
	if err != nil {
		t.Fatalf("SignAgent: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The name comes from the broker, never from the request: a CSR is
	// attacker-controlled input.
	if cert.Subject.CommonName != "gateway" {
		t.Errorf("CommonName = %q, want the name the broker assigned", cert.Subject.CommonName)
	}
	if cert.IsCA {
		t.Error("an agent certificate may not be a CA")
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Errorf("the identity carries names it should not: %v %v", cert.DNSNames, cert.IPAddresses)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want client auth only — it must not be usable to serve", cert.ExtKeyUsage)
	}

	// And it must actually verify against the CA.
	pool := ca.CertPool()
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("the signed certificate does not verify against its own CA: %v", err)
	}
}

// The signature on a CSR is the proof that the asker holds the private key.
// Without checking it, anyone could enrol using someone else's public key.
func TestSignAgentRejectsUnsignedRequest(t *testing.T) {
	ca, _ := Create(t.TempDir())
	csr, _ := csrFor(t, "gateway")

	// Break the signature while leaving everything else intact.
	tampered := *csr
	tampered.Signature = append([]byte(nil), csr.Signature...)
	tampered.Signature[0] ^= 0xff

	if _, _, err := SignAgent(ca, "gateway", &tampered, lifetime.Span{}); err == nil {
		t.Fatal("a request with a broken signature was signed")
	}
}

func TestSignAgentRejectsEmptyName(t *testing.T) {
	ca, _ := Create(t.TempDir())
	csr, _ := csrFor(t, "gateway")
	if _, _, err := SignAgent(ca, "", csr, lifetime.Span{}); err == nil {
		t.Error("an agent certificate without a name was issued")
	}
}

func TestSignAgentRejectsLifetimeBeyondTheCA(t *testing.T) {
	ca, _ := Create(t.TempDir())
	csr, _ := csrFor(t, "gateway")
	if _, _, err := SignAgent(ca, "gateway", csr, lifetime.Of(20*365*24*time.Hour)); err == nil {
		t.Error("a certificate outliving its CA was issued")
	}
}

func TestDefaultLifetimeIsShort(t *testing.T) {
	ca, _ := Create(t.TempDir())
	csr, _ := csrFor(t, "gateway")
	certPEM, _, err := SignAgent(ca, "gateway", csr, lifetime.Span{})
	if err != nil {
		t.Fatalf("SignAgent: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	life := cert.NotAfter.Sub(cert.NotBefore)
	// Expiry is the sweeping mechanism; a year-long identity would make the
	// revocation list the only defence, and Go checks no CRL in the handshake.
	if life > 45*24*time.Hour {
		t.Errorf("default lifetime is %v — too long for expiry to do the sweeping", life)
	}
}

// Two CAs must be distinguishable, otherwise a token bound to one broker could
// be redeemed against another.
func TestFingerprintsDiffer(t *testing.T) {
	a, _ := Create(t.TempDir())
	b, _ := Create(t.TempDir())
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("two independently created CAs share a fingerprint")
	}
	if len(a.Fingerprint()) != 64 {
		t.Errorf("fingerprint %q is not a SHA-256 hex digest", a.Fingerprint())
	}
}

func TestCertificatePEMCarriesNoKey(t *testing.T) {
	ca, _ := Create(t.TempDir())
	out := string(ca.CertificatePEM())
	if strings.Contains(out, "PRIVATE KEY") {
		t.Error("the handed-out CA certificate contains a private key")
	}
	if !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Error("CertificatePEM is not a PEM certificate")
	}
}
