package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// issueIdentity makes a CA and an identity signed by it, as the broker would.
func issueIdentity(t *testing.T, name string, lifetime time.Duration) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test agent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-lifetime / 2),
		NotAfter:     time.Now().Add(lifetime / 2),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func TestSaveThenLoadIdentity(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, caPEM := issueIdentity(t, "gateway", 30*24*time.Hour)

	saved, err := SaveIdentity(dir, certPEM, keyPEM, caPEM)
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if saved.Name() != "gateway" {
		t.Errorf("Name = %q", saved.Name())
	}

	loaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded.Name() != "gateway" {
		t.Errorf("reloaded Name = %q", loaded.Name())
	}
	if _, err := loaded.TLSConfig(); err != nil {
		t.Errorf("the stored identity does not form a TLS configuration: %v", err)
	}
}

func TestLoadWithoutIdentityIsErrNotEnrolled(t *testing.T) {
	if _, err := LoadIdentity(t.TempDir()); !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("err = %v, want ErrNotEnrolled", err)
	}
}

// A certificate without its key is broken, not absent. Reporting "not
// enrolled" would make the agent enrol again over the top and hide it.
func TestCertificateWithoutKeyIsNotReportedAsUnenrolled(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, caPEM := issueIdentity(t, "gateway", time.Hour)
	if _, err := SaveIdentity(dir, certPEM, keyPEM, caPEM); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "agent.key")); err != nil {
		t.Fatalf("remove: %v", err)
	}

	_, err := LoadIdentity(dir)
	if err == nil {
		t.Fatal("a certificate without its key loaded fine")
	}
	if errors.Is(err, ErrNotEnrolled) {
		t.Error("reported as ErrNotEnrolled — the agent would enrol over the top")
	}
}

func TestIdentityKeyIsOwnerReadableOnly(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	certPEM, keyPEM, caPEM := issueIdentity(t, "gateway", time.Hour)
	if _, err := SaveIdentity(dir, certPEM, keyPEM, caPEM); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key mode = %o, want 600", got)
	}
}

// The renewal fraction has to fire long before expiry, or the host locks
// itself out (ADR-7).
func TestRenewalIsDueWellBeforeExpiry(t *testing.T) {
	dir := t.TempDir()
	// Lifetime 30 days, already half gone.
	certPEM, keyPEM, caPEM := issueIdentity(t, "gateway", 30*24*time.Hour)
	id, err := SaveIdentity(dir, certPEM, keyPEM, caPEM)
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	now := time.Now()
	if id.ExpiredAt(now) {
		t.Fatal("a fresh identity is already expired")
	}
	if id.NeedsRenewalAt(now) {
		t.Error("renewal is due at half the lifetime — too early to be useful")
	}
	// Two thirds in, it must be due — with days to spare before expiry.
	twoThirds := id.Certificate.NotBefore.Add(
		time.Duration(float64(id.Certificate.NotAfter.Sub(id.Certificate.NotBefore)) * 0.7))
	if !id.NeedsRenewalAt(twoThirds) {
		t.Error("renewal is not due at 70% of the lifetime")
	}
	if id.ExpiredAt(twoThirds) {
		t.Error("the identity is already expired when renewal becomes due — no slack at all")
	}
}

// An expired identity has exactly one remedy, and the error must name it
// rather than surfacing as a confusing handshake failure.
func TestExpiredIdentityIsRefusedWithAClearError(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, caPEM := issueIdentity(t, "gateway", -2*time.Hour) // already over
	id, err := SaveIdentity(dir, certPEM, keyPEM, caPEM)
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if !id.ExpiredAt(time.Now()) {
		t.Fatal("test setup wrong: the identity is not expired")
	}

	_, err = NewClient("https://broker.example.com", id, 0)
	if !errors.Is(err, ErrIdentityExpired) {
		t.Fatalf("err = %v, want ErrIdentityExpired", err)
	}
	if !strings.Contains(err.Error(), "enrol this host again") {
		t.Errorf("the error does not say what to do: %v", err)
	}
}

func TestNewCSRForNamesCoversExactlyThose(t *testing.T) {
	_, csrPEM, err := NewCSRForNames([]string{"a.example.com", "b.example.com"})
	if err != nil {
		t.Fatalf("NewCSRForNames: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("the request is not correctly signed: %v", err)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("DNSNames = %v, want exactly the two asked for", csr.DNSNames)
	}
	if _, _, err := NewCSRForNames(nil); err == nil {
		t.Error("a request without names was created")
	}
}

// The key generated for a CSR must be a real, usable key that never leaves —
// the entire justification for the issue mode.
func TestGeneratedKeyStaysUsableLocally(t *testing.T) {
	keyPEM, csrPEM, err := NewCSRForNames([]string{"gateway.example.com"})
	if err != nil {
		t.Fatalf("NewCSRForNames: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("no private key was produced")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("the key is not usable: %v", err)
	}
	if strings.Contains(string(csrPEM), "PRIVATE KEY") {
		t.Error("the certificate request contains the private key")
	}
}

func TestEnrolmentClientNeedsTheBrokerCA(t *testing.T) {
	if _, err := NewEnrolmentClient("https://broker.example.com", nil, 0); err == nil {
		t.Error("an enrolment client without the broker CA was built — it would trust anything")
	}
	if _, err := NewEnrolmentClient("https://broker.example.com", []byte("not pem"), 0); err == nil {
		t.Error("an unreadable CA certificate was accepted")
	}
}
