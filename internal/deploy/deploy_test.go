package deploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func makePair(t *testing.T, cn string) (chainPEM, keyPEM []byte, tlsCert tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	chainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err = tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	return chainPEM, keyPEM, tlsCert
}

// tlsService is a stand-in for the service being reloaded. What it serves can
// be swapped — or deliberately not swapped, which is the interesting case.
type tlsService struct {
	ln      net.Listener
	current atomic.Pointer[tls.Certificate]
}

func startService(t *testing.T, cert tls.Certificate) *tlsService {
	t.Helper()
	s := &tlsService{}
	s.current.Store(&cert)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.current.Load(), nil
		},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.ln = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				// Force the handshake, then hang up: the test only needs the
				// certificate the service presents.
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = conn.Close()
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *tlsService) addr() string { return s.ln.Addr().String() }

func (s *tlsService) serve(cert tls.Certificate) { s.current.Store(&cert) }

func TestDeployWritesReloadsAndConfirms(t *testing.T) {
	dir := t.TempDir()
	chain, key, cert := makePair(t, "gateway.example.com")
	svc := startService(t, cert)

	marker := filepath.Join(dir, "reloaded")
	out, err := Deploy(Target{
		CertPath:         filepath.Join(dir, "fullchain.pem"),
		KeyPath:          filepath.Join(dir, "privkey.pem"),
		ReloadCommand:    []string{"touch", marker},
		VerifyAddress:    svc.addr(),
		VerifyServerName: "gateway.example.com",
	}, chain, key)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if !out.Changed || !out.Reloaded || !out.Verified {
		t.Errorf("outcome = %+v, want all three true", out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("the reload command did not run")
	}
}

// The caddy case: the reload command succeeds, and the service keeps serving
// the old certificate. Everything "worked" and nothing happened.
func TestReloadThatDidNothingIsCaught(t *testing.T) {
	dir := t.TempDir()
	oldChain, oldKey, oldCert := makePair(t, "gateway.example.com")
	newChain, newKey, _ := makePair(t, "gateway.example.com")

	// The service keeps serving the OLD certificate no matter what.
	svc := startService(t, oldCert)
	_ = oldChain
	_ = oldKey

	out, err := Deploy(Target{
		CertPath: filepath.Join(dir, "fullchain.pem"),
		KeyPath:  filepath.Join(dir, "privkey.pem"),
		// Exits 0 and changes nothing — exactly what `caddy reload` does when
		// only a certificate file changed.
		ReloadCommand:    []string{"true"},
		VerifyAddress:    svc.addr(),
		VerifyServerName: "gateway.example.com",
	}, newChain, newKey)

	if err == nil {
		t.Fatal("a reload that did nothing was reported as success — this is the bug the package exists for")
	}
	if !errors.Is(err, ErrNotServing) {
		t.Errorf("err = %v, want ErrNotServing", err)
	}
	// The message has to explain the trap, or the next person debugs the
	// wrong thing for a week.
	if !strings.Contains(err.Error(), "exits 0") {
		t.Errorf("the error does not explain what happened: %v", err)
	}
	if out.Verified {
		t.Error("Verified is true although the service serves something else")
	}

	// And once the service really picks it up, the same deployment confirms.
	newCert, _ := tls.X509KeyPair(newChain, newKey)
	svc.serve(newCert)
	out, err = Deploy(Target{
		CertPath:         filepath.Join(dir, "fullchain.pem"),
		KeyPath:          filepath.Join(dir, "privkey.pem"),
		VerifyAddress:    svc.addr(),
		VerifyServerName: "gateway.example.com",
	}, newChain, newKey)
	if err != nil {
		t.Fatalf("second Deploy: %v", err)
	}
	if out.Changed {
		t.Error("the files were rewritten although they were already current")
	}
}

// Nothing new means nothing happens: no write, no reload. An agent that
// reloads on every run turns a five-minute timer into a restart every five
// minutes.
func TestUnchangedCertificateDoesNothing(t *testing.T) {
	dir := t.TempDir()
	chain, key, _ := makePair(t, "gateway.example.com")
	target := Target{
		CertPath: filepath.Join(dir, "fullchain.pem"),
		KeyPath:  filepath.Join(dir, "privkey.pem"),
	}
	if _, err := Deploy(target, chain, key); err != nil {
		t.Fatalf("first Deploy: %v", err)
	}

	marker := filepath.Join(dir, "reloaded")
	target.ReloadCommand = []string{"touch", marker}
	out, err := Deploy(target, chain, key)
	if err != nil {
		t.Fatalf("second Deploy: %v", err)
	}
	if out.Changed || out.Reloaded {
		t.Errorf("outcome = %+v, want nothing to have happened", out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the reload ran although nothing changed")
	}
}

// Without a verify address the result must say "not confirmed", not "fine".
func TestMissingVerifyAddressIsReportedNotAssumed(t *testing.T) {
	dir := t.TempDir()
	chain, key, _ := makePair(t, "gateway.example.com")

	out, err := Deploy(Target{
		CertPath: filepath.Join(dir, "fullchain.pem"),
		KeyPath:  filepath.Join(dir, "privkey.pem"),
	}, chain, key)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if out.Verified {
		t.Error("Verified is true although nothing was checked")
	}
	if !out.VerifySkipped {
		t.Error("VerifySkipped is false — the caller cannot tell it was not checked")
	}
	if !strings.Contains(out.Message, "not confirmed") {
		t.Errorf("the message claims more than was checked: %q", out.Message)
	}
}

func TestMismatchedPairIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	dir := t.TempDir()
	chain, _, _ := makePair(t, "gateway.example.com")
	_, otherKey, _ := makePair(t, "other.example.com")

	certPath := filepath.Join(dir, "fullchain.pem")
	if _, err := Deploy(Target{CertPath: certPath, KeyPath: filepath.Join(dir, "privkey.pem")},
		chain, otherKey); err == nil {
		t.Fatal("a mismatched pair was deployed")
	}
	if _, err := os.Stat(certPath); err == nil {
		t.Error("the certificate was written although the pair was refused")
	}
}

func TestFailingReloadIsAnError(t *testing.T) {
	dir := t.TempDir()
	chain, key, _ := makePair(t, "gateway.example.com")

	_, err := Deploy(Target{
		CertPath:      filepath.Join(dir, "fullchain.pem"),
		KeyPath:       filepath.Join(dir, "privkey.pem"),
		ReloadCommand: []string{"false"},
	}, chain, key)
	if err == nil {
		t.Fatal("a failing reload was reported as success")
	}
	// The files ARE in place — the message must say so, or the operator
	// assumes nothing happened and redeploys.
	if !strings.Contains(err.Error(), "written") {
		t.Errorf("the error does not say the files were written: %v", err)
	}
}

func TestReloadTimeoutIsEnforced(t *testing.T) {
	dir := t.TempDir()
	chain, key, _ := makePair(t, "gateway.example.com")

	start := time.Now()
	_, err := Deploy(Target{
		CertPath:      filepath.Join(dir, "fullchain.pem"),
		KeyPath:       filepath.Join(dir, "privkey.pem"),
		ReloadCommand: []string{"sleep", "30"},
		ReloadTimeout: 300 * time.Millisecond,
	}, chain, key)
	if err == nil {
		t.Fatal("a hanging reload was not stopped")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the timeout took %v to fire", elapsed)
	}
	if !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("err = %v", err)
	}
}

// No shell: an argument with a space stays one argument, and nothing gets
// interpreted. step-ca has an open issue about exactly this quoting problem.
func TestReloadCommandTakesArgvNotAShell(t *testing.T) {
	dir := t.TempDir()
	chain, key, _ := makePair(t, "gateway.example.com")
	awkward := filepath.Join(dir, "a file with spaces")

	if _, err := Deploy(Target{
		CertPath:      filepath.Join(dir, "fullchain.pem"),
		KeyPath:       filepath.Join(dir, "privkey.pem"),
		ReloadCommand: []string{"touch", awkward},
	}, chain, key); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if _, err := os.Stat(awkward); err != nil {
		t.Errorf("the argument with spaces was split: %v", err)
	}

	// And shell syntax is not interpreted — it is just an argument.
	dir2 := t.TempDir()
	chain2, key2, _ := makePair(t, "gateway.example.com")
	sentinel := filepath.Join(dir2, "should-not-exist")
	_, _ = Deploy(Target{
		CertPath:      filepath.Join(dir2, "fullchain.pem"),
		KeyPath:       filepath.Join(dir2, "privkey.pem"),
		ReloadCommand: []string{"echo", "hello; touch " + sentinel},
	}, chain2, key2)
	if _, err := os.Stat(sentinel); err == nil {
		t.Error("shell syntax in an argument was executed")
	}
}

func TestKeyIsWrittenOwnerOnlyByDefault(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	chain, key, _ := makePair(t, "gateway.example.com")
	keyPath := filepath.Join(dir, "privkey.pem")

	if _, err := Deploy(Target{CertPath: filepath.Join(dir, "fullchain.pem"), KeyPath: keyPath},
		chain, key); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("key mode = %o, want 600", got)
	}
}

func TestKeyModeIsConfigurable(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	chain, key, _ := makePair(t, "gateway.example.com")
	keyPath := filepath.Join(dir, "privkey.pem")

	// 0640 is the usual widening: a service running as its own user needs to
	// read the key through a shared group.
	if _, err := Deploy(Target{
		CertPath: filepath.Join(dir, "fullchain.pem"),
		KeyPath:  keyPath,
		KeyMode:  0o640,
	}, chain, key); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	info, _ := os.Stat(keyPath)
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("key mode = %o, want 640", got)
	}
}

func TestUnreachableServiceIsReportedAsUnchecked(t *testing.T) {
	dir := t.TempDir()
	chain, key, _ := makePair(t, "gateway.example.com")

	out, err := Deploy(Target{
		CertPath: filepath.Join(dir, "fullchain.pem"),
		KeyPath:  filepath.Join(dir, "privkey.pem"),
		// Port 1 on loopback: nothing listens there.
		VerifyAddress: "127.0.0.1:1",
		VerifyTimeout: time.Second,
	}, chain, key)

	if err == nil {
		t.Fatal("an unverifiable deployment was reported as success")
	}
	if out.Verified {
		t.Error("Verified is true although the service was unreachable")
	}
	// It must be distinguishable from "serving the wrong certificate".
	if errors.Is(err, ErrNotServing) {
		t.Error("an unreachable service was reported as serving the wrong certificate")
	}
}
