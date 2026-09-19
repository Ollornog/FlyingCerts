package certstore

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

func issue(t *testing.T, cn string, lifetime time.Duration) (chainPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    now,
		NotAfter:     now.Add(lifetime),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestSaveThenLoad(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	chain, key := issue(t, "host.example.com", 48*time.Hour)

	meta, err := s.Save("host", chain, key)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if meta.Domains[0] != "host.example.com" {
		t.Errorf("Domains = %v", meta.Domains)
	}
	if meta.Serial == "" {
		t.Error("metadata carries no serial — revocation and ARI need it")
	}

	gotChain, gotKey, pair, err := s.Load("host")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(gotChain) != string(chain) || string(gotKey) != string(key) {
		t.Error("what came back is not what went in")
	}
	if pair.Leaf.Subject.CommonName != "host.example.com" {
		t.Errorf("CommonName = %q", pair.Leaf.Subject.CommonName)
	}
}

// The failure CertMate shipped twice (#608, #830): a chain stored with a key
// that does not belong to it looks healthy until the TLS handshake.
func TestSaveRejectsMismatchedPair(t *testing.T) {
	s, _ := New(t.TempDir())
	chain, _ := issue(t, "host.example.com", time.Hour)
	_, otherKey := issue(t, "other.example.com", time.Hour)

	if _, err := s.Save("host", chain, otherKey); err == nil {
		t.Fatal("a chain was stored with a foreign key")
	}
	// And nothing may be left behind from the rejected attempt.
	if _, err := os.Stat(filepath.Join(s.Dir(), "host", "fullchain.pem")); err == nil {
		t.Error("the rejected certificate was written anyway")
	}
}

func TestLoadMissingIsErrNotFound(t *testing.T) {
	s, _ := New(t.TempDir())
	if _, _, _, err := s.Load("absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// A chain without its key must NOT read as "not stored" — that would invite a
// caller to obtain a second certificate while a half-written one sits there.
func TestChainWithoutKeyIsNotReportedAsMissing(t *testing.T) {
	s, _ := New(t.TempDir())
	chain, key := issue(t, "host.example.com", time.Hour)
	if _, err := s.Save("host", chain, key); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Remove(filepath.Join(s.Dir(), "host", "privkey.pem")); err != nil {
		t.Fatalf("remove key: %v", err)
	}

	_, _, _, err := s.Load("host")
	if err == nil {
		t.Fatal("a chain without its key loaded fine")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("reported as ErrNotFound — a caller would obtain a duplicate instead of fixing this")
	}
}

func TestKeyIsOwnerReadableOnly(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	s, _ := New(t.TempDir())
	chain, key := issue(t, "host.example.com", time.Hour)
	if _, err := s.Save("host", chain, key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(filepath.Join(s.Dir(), "host", "privkey.pem"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key mode = %o, want 600", got)
	}
	// The chain is public information, but the directory must not be open.
	dirInfo, _ := os.Stat(s.Dir())
	if got := dirInfo.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("store directory mode = %o, want no group/other access", got)
	}
}

func TestExistingWideOpenStoreIsNarrowed(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	if _, err := New(dir); err != nil {
		t.Fatalf("New: %v", err)
	}
	info, _ := os.Stat(dir)
	if got := info.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("mode = %o — an existing directory must be narrowed", got)
	}
}

// Names become path elements. A name that escapes the directory must be
// rejected outright, not quietly rewritten: sanitising means the caller asks
// for one certificate and silently gets another.
func TestDangerousNamesAreRejected(t *testing.T) {
	s, _ := New(t.TempDir())
	chain, key := issue(t, "host.example.com", time.Hour)

	for _, bad := range []string{
		"../escape", "sub/dir", "/absolute", "..", ".", "",
		"UPPERCASE", "trailing-", "-leading", strings.Repeat("x", 65),
	} {
		if _, err := s.Save(bad, chain, key); err == nil {
			t.Errorf("name %q was accepted", bad)
		}
		if _, _, _, err := s.Load(bad); err == nil {
			t.Errorf("name %q was accepted on load", bad)
		}
	}
	// And the sane ones still work.
	for _, good := range []string{"host", "host.example.com", "web_1", "a"} {
		if err := ValidateName(good); err != nil {
			t.Errorf("name %q was rejected: %v", good, err)
		}
	}
}

func TestListSortsAndReportsBroken(t *testing.T) {
	s, _ := New(t.TempDir())
	for _, n := range []string{"zeta", "alpha"} {
		chain, key := issue(t, n+".example.com", time.Hour)
		if _, err := s.Save(n, chain, key); err != nil {
			t.Fatalf("Save %s: %v", n, err)
		}
	}
	// A directory with no metadata at all.
	if err := os.Mkdir(filepath.Join(s.Dir(), "rubble"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	metas, broken, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 2 || metas[0].Name != "alpha" || metas[1].Name != "zeta" {
		t.Errorf("metas = %v, want alpha then zeta", metas)
	}
	if len(broken) != 1 || broken[0] != "rubble" {
		t.Errorf("broken = %v, want [rubble] — a broken entry must surface, not vanish", broken)
	}
}

func TestSaveReplacesPreviousCertificate(t *testing.T) {
	s, _ := New(t.TempDir())
	first, firstKey := issue(t, "host.example.com", time.Hour)
	if _, err := s.Save("host", first, firstKey); err != nil {
		t.Fatalf("Save: %v", err)
	}
	second, secondKey := issue(t, "host.example.com", 72*time.Hour)
	if _, err := s.Save("host", second, secondKey); err != nil {
		t.Fatalf("Save again: %v", err)
	}

	chain, key, pair, err := s.Load("host")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(chain) != string(second) || string(key) != string(secondKey) {
		t.Error("the renewal did not replace the previous certificate")
	}
	if time.Until(pair.Leaf.NotAfter) < 48*time.Hour {
		t.Error("the loaded certificate is still the short-lived first one")
	}
}
