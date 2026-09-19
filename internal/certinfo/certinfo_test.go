package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// issue builds a self-signed certificate valid over the given window, plus its
// key, both PEM-encoded.
func issue(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestLoadPairAcceptsMatching(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := issue(t, now.Add(-time.Hour), now.Add(time.Hour))

	pair, err := LoadPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadPair: %v", err)
	}
	if pair.Leaf.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q", pair.Leaf.Subject.CommonName)
	}
}

func TestLoadPairRejectsMismatch(t *testing.T) {
	// The exact failure CertMate shipped twice (#608, #830): a certificate
	// without its matching key must never pass as healthy.
	now := time.Now()
	certPEM, _ := issue(t, now.Add(-time.Hour), now.Add(time.Hour))
	_, otherKeyPEM := issue(t, now.Add(-time.Hour), now.Add(time.Hour))

	if _, err := LoadPair(certPEM, otherKeyPEM); err == nil {
		t.Fatal("a certificate paired with a foreign key was accepted")
	}
}

func TestParseChainRejectsEmptyInput(t *testing.T) {
	if _, err := ParseChain([]byte("not pem at all")); err != ErrNoCertificate {
		t.Errorf("err = %v, want ErrNoCertificate", err)
	}
}

func TestParseChainKeepsOrderAndSkipsKeys(t *testing.T) {
	now := time.Now()
	leafPEM, keyPEM := issue(t, now, now.Add(time.Hour))
	interPEM, _ := issue(t, now, now.Add(2*time.Hour))

	// A key block in the middle must be ignored, not abort the parse.
	combined := append(append(append([]byte{}, leafPEM...), keyPEM...), interPEM...)
	chain, err := ParseChain(combined)
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("len(chain) = %d, want 2", len(chain))
	}
	if !chain[0].NotAfter.Before(chain[1].NotAfter) {
		t.Error("chain order changed: the leaf must stay first")
	}
}

// This is the regression guard for ADR-11. Truncating to days would report a
// still-valid certificate as expired.
func TestShortLivedCertificateIsNotReportedExpired(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := issue(t, now.Add(-5*time.Hour), now.Add(3*time.Hour))
	pair, err := LoadPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadPair: %v", err)
	}

	if ExpiredAt(pair.Leaf, now) {
		t.Error("a certificate with 3 hours left counts as expired")
	}
	remaining := RemainingAt(pair.Leaf, now)
	if remaining <= 0 {
		t.Errorf("RemainingAt = %v, want positive", remaining)
	}
	if got := int(remaining.Hours() / 24); got != 0 {
		t.Fatalf("test setup wrong: whole days = %d, want 0", got)
	}
	// The point: as whole days this is 0 — truncation would call it expired.
	if remaining < 2*time.Hour {
		t.Errorf("RemainingAt = %v, want roughly 3h", remaining)
	}
}

func TestRemainingIsNegativeAfterExpiry(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := issue(t, now.Add(-48*time.Hour), now.Add(-2*time.Hour))
	pair, err := LoadPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadPair: %v", err)
	}
	if !ExpiredAt(pair.Leaf, now) {
		t.Error("an expired certificate is not reported as expired")
	}
	if got := RemainingAt(pair.Leaf, now); got > 0 {
		t.Errorf("RemainingAt = %v, want negative so callers can tell how long ago", got)
	}
}

func TestRenewAfterScalesWithLifetime(t *testing.T) {
	// The same fraction has to be sensible for a six-day certificate and for a
	// ninety-day one. A fixed "30 days before expiry" would be due before issue
	// for the short one.
	cases := []struct {
		name     string
		lifetime time.Duration
		wantLeft time.Duration // roughly how much life remains when renewal is due
	}{
		{"six days", 6 * 24 * time.Hour, 2 * 24 * time.Hour},
		{"ninety days", 90 * 24 * time.Hour, 30 * 24 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			certPEM, keyPEM := issue(t, start, start.Add(c.lifetime))
			pair, err := LoadPair(certPEM, keyPEM)
			if err != nil {
				t.Fatalf("LoadPair: %v", err)
			}
			due := RenewAfter(pair.Leaf, DefaultRenewalFraction)
			left := pair.Leaf.NotAfter.Sub(due)
			if diff := left - c.wantLeft; diff > time.Hour || diff < -time.Hour {
				t.Errorf("renewal leaves %v, want about %v", left, c.wantLeft)
			}
			if !due.After(start) {
				t.Error("renewal is due before the certificate was issued")
			}
			if NeedsRenewalAt(pair.Leaf, start, DefaultRenewalFraction) {
				t.Error("a freshly issued certificate already needs renewal")
			}
			if !NeedsRenewalAt(pair.Leaf, due.Add(time.Minute), DefaultRenewalFraction) {
				t.Error("renewal is not due just after the computed moment")
			}
		})
	}
}

func TestNeedsRenewalForExpiredCertificate(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM := issue(t, now.Add(-48*time.Hour), now.Add(-time.Hour))
	pair, _ := LoadPair(certPEM, keyPEM)
	if !NeedsRenewalAt(pair.Leaf, now, DefaultRenewalFraction) {
		t.Error("an expired certificate does not need renewal")
	}
}

func TestDescribeRemainingIsForHumansOnly(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * 24 * time.Hour, "5 days left"},
		{3 * time.Hour, "3 hours left"},
		{30 * time.Second, "less than a minute left"},
		{-2 * time.Hour, "expired 2 hours ago"},
	}
	for _, c := range cases {
		if got := DescribeRemaining(c.d); got != c.want {
			t.Errorf("DescribeRemaining(%v) = %q, want %q", c.d, got, c.want)
		}
	}
	// A sub-day duration must never render as "0 days".
	if got := DescribeRemaining(3 * time.Hour); strings.Contains(got, "0 days") {
		t.Errorf("DescribeRemaining(3h) = %q — rounding to days is exactly the bug", got)
	}
}
