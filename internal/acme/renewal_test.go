package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	legoapi "github.com/go-acme/lego/v5/acme/api"
)

func testCert(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "host.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

// fakeARI stands in for the CA's advice.
type fakeARI struct{ at *time.Time }

func (f fakeARI) ShouldRenewAt(time.Time, time.Duration) *time.Time { return f.at }

func TestARIWinsWhenTheCAIsWilling(t *testing.T) {
	now := time.Now()
	cert := testCert(t, now.Add(-time.Hour), now.Add(80*24*time.Hour))
	when := now
	fetch := func(context.Context) (renewalInfoFetcher, error) {
		return fakeARI{at: &when}, nil
	}

	got := DecideRenewal(context.Background(), fetch, cert, now, time.Hour)
	if !got.Due {
		t.Error("ARI said renew now, decision says no")
	}
	if got.Source != SourceARI {
		t.Errorf("Source = %q, want %q", got.Source, SourceARI)
	}
	// Decisive: the fraction alone would say "not yet" here (barely any of the
	// lifetime has elapsed), so this proves ARI actually overrode it.
	if fallback := DecideRenewal(context.Background(), nil, cert, now, time.Hour); fallback.Due {
		t.Error("test is not conclusive: the fallback would have renewed anyway")
	}
}

func TestARIDeferralIsRespected(t *testing.T) {
	now := time.Now()
	cert := testCert(t, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	fetch := func(context.Context) (renewalInfoFetcher, error) {
		return fakeARI{at: nil}, nil // nil = not yet
	}

	got := DecideRenewal(context.Background(), fetch, cert, now, 6*time.Hour)
	if got.Due {
		t.Error("ARI deferred, decision renewed anyway")
	}
	if got.Source != SourceARI {
		t.Errorf("Source = %q, want %q", got.Source, SourceARI)
	}
	// Decisive the other way round: the fraction WOULD have renewed here, so
	// this proves the CA's deferral is honoured rather than merely agreed with.
	if fallback := DecideRenewal(context.Background(), nil, cert, now, time.Hour); !fallback.Due {
		t.Error("test is not conclusive: the fallback would have deferred too")
	}
	if got.NextCheck.IsZero() {
		t.Error("a deferral must say when to look again")
	}
}

func TestFallsBackWhenCADoesNotSupportARI(t *testing.T) {
	now := time.Now()
	cert := testCert(t, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	fetch := func(context.Context) (renewalInfoFetcher, error) {
		return nil, legoapi.ErrNoARI
	}

	got := DecideRenewal(context.Background(), fetch, cert, now, time.Hour)
	if !got.Due {
		t.Error("no ARI and 89% of the lifetime gone — renewal should be due")
	}
	if got.Source != SourceLifetimeFraction {
		t.Errorf("Source = %q, want %q", got.Source, SourceLifetimeFraction)
	}
}

// A broken ARI endpoint must not block renewal — but it must not be mistaken
// for advice either.
func TestFallsBackWhenARIFails(t *testing.T) {
	now := time.Now()
	cert := testCert(t, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	fetch := func(context.Context) (renewalInfoFetcher, error) {
		return nil, errors.New("connection reset")
	}

	got := DecideRenewal(context.Background(), fetch, cert, now, time.Hour)
	if !got.Due {
		t.Error("a failing ARI lookup blocked renewal")
	}
	if got.Source != SourceLifetimeFraction {
		t.Errorf("Source = %q, want the fallback, not %q", SourceLifetimeFraction, got.Source)
	}
}

func TestExpiredIsDueRegardlessOfARI(t *testing.T) {
	now := time.Now()
	cert := testCert(t, now.Add(-90*24*time.Hour), now.Add(-time.Hour))
	// Even if the CA were to defer, an expired certificate is due.
	fetch := func(context.Context) (renewalInfoFetcher, error) {
		return fakeARI{at: nil}, nil
	}

	got := DecideRenewal(context.Background(), fetch, cert, now, time.Hour)
	if !got.Due {
		t.Error("an expired certificate was not due for renewal")
	}
	if got.Source != SourceExpired {
		t.Errorf("Source = %q, want %q", got.Source, SourceExpired)
	}
	if !strings.Contains(got.Reason, "expired") {
		t.Errorf("Reason = %q, want it to say the certificate expired", got.Reason)
	}
}

// The reason must never render a sub-day remainder as "0 days" (ADR-11).
func TestShortLivedCertificateReadsSensibly(t *testing.T) {
	now := time.Now()
	cert := testCert(t, now.Add(-5*24*time.Hour), now.Add(4*time.Hour))

	got := DecideRenewal(context.Background(), nil, cert, now, time.Hour)
	if !got.Due {
		t.Error("a six-day certificate with 4 hours left is not due — the fraction is wrong")
	}
	if strings.Contains(got.Reason, "0 days") {
		t.Errorf("Reason = %q — rounding to whole days is exactly the bug", got.Reason)
	}
}

func TestZoneLockSerialisesSameKey(t *testing.T) {
	zl := NewZoneLock()
	var mu sync.Mutex
	var concurrent, peak int
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release := zl.Acquire("_acme-challenge.shared.example.com")
			defer release()

			mu.Lock()
			concurrent++
			if concurrent > peak {
				peak = concurrent
			}
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			concurrent--
			mu.Unlock()
		}()
	}
	wg.Wait()

	if peak != 1 {
		t.Errorf("up to %d goroutines held the same challenge record at once, want 1", peak)
	}
}

func TestZoneLockDoesNotBlockDifferentKeys(t *testing.T) {
	zl := NewZoneLock()
	first := zl.Acquire("_acme-challenge.a.example.com")
	defer first()

	done := make(chan struct{})
	go func() {
		release := zl.Acquire("_acme-challenge.b.example.com")
		release()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("a different challenge record was blocked — the lock is too coarse")
	}
}
