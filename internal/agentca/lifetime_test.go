package agentca

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/Ollornog/flying-certs/internal/lifetime"
)

func newCA(t *testing.T) *CA {
	t.Helper()
	ca, err := Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func signed(t *testing.T, ca *CA, span lifetime.Span) (*x509.Certificate, time.Time, error) {
	t.Helper()
	csr, _ := csrFor(t, "gateway")
	certPEM, notAfter, err := SignAgent(ca, "gateway", csr, span)
	if err != nil {
		return nil, time.Time{}, err
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, notAfter, nil
}

// The three cases the Span type keeps apart must stay apart here too.
func TestLifetimeIsHonouredExactly(t *testing.T) {
	ca := newCA(t)

	cert, _, err := signed(t, ca, lifetime.Of(lifetime.Day))
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(cert.NotAfter).Round(time.Hour); got != 24*time.Hour {
		t.Errorf("a 1d identity is valid for %v", got)
	}

	cert, _, err = signed(t, ca, lifetime.Span{})
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(cert.NotAfter).Round(time.Hour); got != DefaultAgentLifetime {
		t.Errorf("an unset lifetime gave %v, want the default %v", got, DefaultAgentLifetime)
	}
}

// "unlimited" runs until the CA does — not until some large number somebody
// picked. There is no certificate without an expiry, and pretending otherwise
// would mean the identity outlives its issuer and fails for no visible reason.
func TestUnlimitedRunsExactlyAsLongAsTheCA(t *testing.T) {
	ca := newCA(t)
	cert, notAfter, err := signed(t, ca, lifetime.Forever())
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(ca.Certificate().NotAfter) {
		t.Errorf("unlimited identity expires %s, the CA expires %s",
			cert.NotAfter, ca.Certificate().NotAfter)
	}
	if !notAfter.Equal(cert.NotAfter) {
		t.Errorf("the returned expiry %s does not match the certificate's %s", notAfter, cert.NotAfter)
	}
	if !cert.NotAfter.After(time.Now().Add(9 * 365 * 24 * time.Hour)) {
		t.Error("an unlimited identity should still have most of the CA's decade left")
	}
}

// A lifetime that would outlive the CA is refused rather than quietly
// shortened: the configuration would then say one thing and the certificate
// another, and nobody would find out until the identity stopped working.
func TestALifetimeThatOutlivesTheCAIsRefusedWithTheDate(t *testing.T) {
	ca := newCA(t)
	_, _, err := signed(t, ca, lifetime.Of(20*365*24*time.Hour))
	if err == nil {
		t.Fatal("a 20-year identity was issued from a 10-year CA")
	}
	// The message has to carry the date, otherwise the reader cannot tell
	// what lifetime would have fitted.
	if !strings.Contains(err.Error(), ca.Certificate().NotAfter.UTC().Format("2006-01-02")) {
		t.Errorf("the error does not say when the CA expires: %v", err)
	}
	if !strings.Contains(err.Error(), lifetime.Unlimited) {
		t.Errorf("the error does not offer %q as the way to say it: %v", lifetime.Unlimited, err)
	}
}

// The check is against the CA's real expiry, not against the span it was
// created with. A CA issued years ago has less left than its nominal life,
// and that is exactly when this matters.
func TestTheLimitFollowsTheCAsRealExpiryNotItsNominalOne(t *testing.T) {
	ca := newCA(t)
	// Move the CA's expiry to a week from now, as if it had been in service
	// for nearly a decade.
	ca.cert.NotAfter = time.Now().Add(7 * 24 * time.Hour).Truncate(time.Second).UTC()

	if _, _, err := signed(t, ca, lifetime.Of(30*lifetime.Day)); err == nil {
		t.Error("a 30d identity was issued from a CA with a week left")
	}
	cert, _, err := signed(t, ca, lifetime.Of(2*lifetime.Day))
	if err != nil {
		t.Fatalf("a 2d identity should still fit: %v", err)
	}
	if cert.NotAfter.After(ca.cert.NotAfter) {
		t.Error("the identity outlives its issuer")
	}
	// And unlimited lands on that near date rather than on a decade.
	cert, _, err = signed(t, ca, lifetime.Forever())
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(ca.cert.NotAfter) {
		t.Errorf("unlimited gave %s, the CA ends %s", cert.NotAfter, ca.cert.NotAfter)
	}
}

// An expired CA issues nothing, and says why. Without this the certificate
// would be born invalid and the failure would surface somewhere else.
func TestAnExpiredCAIssuesNothing(t *testing.T) {
	ca := newCA(t)
	ca.cert.NotAfter = time.Now().Add(-time.Hour).Truncate(time.Second).UTC()
	if _, _, err := signed(t, ca, lifetime.Of(lifetime.Day)); err == nil {
		t.Fatal("an expired CA issued an identity")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the error does not name the cause: %v", err)
	}
}
