package brokerapi

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/agentca"
	"github.com/Ollornog/FlyingCerts/internal/certstore"
	"github.com/Ollornog/FlyingCerts/internal/enroll"
	"github.com/Ollornog/FlyingCerts/internal/lifetime"
	"github.com/Ollornog/FlyingCerts/internal/registry"
)

// lifetimeHarness is the ordinary setup with three agents that want three
// different lifetimes, plus a broker-wide default for the one that does not.
func lifetimeHarness(t *testing.T, brokerWide lifetime.Span) *harness {
	t.Helper()
	dir := t.TempDir()
	ca, err := agentca.Create(dir + "/ca")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := enroll.NewStore(dir + "/tokens")
	if err != nil {
		t.Fatal(err)
	}
	agents, err := registry.New([]registry.Agent{
		{Name: "nightly", Certificates: []string{"c"}, Mode: registry.ModeIssue,
			IdentityLifetime: lifetime.Of(lifetime.Day)},
		{Name: "appliance", Certificates: []string{"c"}, Mode: registry.ModeIssue,
			IdentityLifetime: lifetime.Forever()},
		{Name: "ordinary", Certificates: []string{"c"}, Mode: registry.ModeIssue},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certstore.New(dir + "/certs")
	if err != nil {
		t.Fatal(err)
	}
	audit := &recordingAuditor{}
	srv, err := New(Config{CA: ca, Tokens: tokens, Agents: agents, Certs: certs,
		Audit: audit, Lifetime: brokerWide})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{srv: srv, ca: ca, tokens: tokens, agents: agents, certs: certs, audit: audit}
}

// enrolAs walks one agent through enrolment and returns its certificate.
func enrolAs(t *testing.T, h *harness, agentName string) *x509.Certificate {
	t.Helper()
	tok, rec, err := enroll.NewToken(agentName, nil, h.ca.Fingerprint(), 5*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.tokens.Put(rec); err != nil {
		t.Fatal(err)
	}
	csrPEM, _ := newCSR(t)
	body, _ := json.Marshal(map[string]string{"token": tok.String(), "csr": csrPEM})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("enrol %s: HTTP %d — %s", agentName, w.Code, w.Body.String())
	}
	var out struct {
		CertificatePEM string `json:"certificate_pem"`
		NotAfter       string `json:"not_after"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(out.CertificatePEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// The date in the response must be the date in the certificate. Two
	// places computing it separately is how they come to disagree.
	stated, err := time.Parse(time.RFC3339, out.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	if !stated.Equal(cert.NotAfter) {
		t.Errorf("%s: the response says %s, the certificate says %s",
			agentName, stated, cert.NotAfter)
	}
	return cert
}

// Each agent gets the lifetime it was configured with, and the one that was
// not configured gets the broker's.
func TestEachAgentGetsItsOwnLifetime(t *testing.T) {
	h := lifetimeHarness(t, lifetime.Of(10*lifetime.Day))

	if got := time.Until(enrolAs(t, h, "nightly").NotAfter).Round(time.Hour); got != 24*time.Hour {
		t.Errorf("nightly got %v, want 1d", got)
	}
	if got := time.Until(enrolAs(t, h, "ordinary").NotAfter).Round(time.Hour); got != 240*time.Hour {
		t.Errorf("ordinary got %v, want the broker-wide 10d", got)
	}
	appliance := enrolAs(t, h, "appliance")
	if !appliance.NotAfter.Equal(h.ca.Certificate().NotAfter) {
		t.Errorf("appliance got %s, want the CA's own expiry %s",
			appliance.NotAfter, h.ca.Certificate().NotAfter)
	}
}

// With no broker-wide setting either, the package default applies — and an
// agent's own setting still wins over it.
func TestTheFallbackChainEndsAtTheDefault(t *testing.T) {
	h := lifetimeHarness(t, lifetime.Span{})

	if got := time.Until(enrolAs(t, h, "ordinary").NotAfter).Round(time.Hour); got != agentca.DefaultAgentLifetime {
		t.Errorf("ordinary got %v, want the default %v", got, agentca.DefaultAgentLifetime)
	}
	if got := time.Until(enrolAs(t, h, "nightly").NotAfter).Round(time.Hour); got != 24*time.Hour {
		t.Errorf("nightly got %v — its own setting must win over the default", got)
	}
}

// The recorded expiry is the certificate's, not a recomputation. Getting this
// wrong would be invisible until a warning fired on the wrong day — and for
// an unlimited identity it would be wrong by a decade.
func TestTheRecordedExpiryIsTheCertificatesOwn(t *testing.T) {
	h := lifetimeHarness(t, lifetime.Of(10*lifetime.Day))

	for _, name := range []string{"nightly", "appliance", "ordinary"} {
		cert := enrolAs(t, h, name)
		state := h.agents.StateOf(name)
		if !state.IdentityExpires.Equal(cert.NotAfter) {
			t.Errorf("%s: registry recorded %s, the certificate expires %s",
				name, state.IdentityExpires, cert.NotAfter)
		}
	}
}

// Renewal follows the same rule as enrolment. An agent whose lifetime was
// changed in the configuration picks the new one up when it next renews,
// without anybody touching the host.
func TestRenewalUsesTheCurrentConfiguredLifetime(t *testing.T) {
	h := lifetimeHarness(t, lifetime.Of(10*lifetime.Day))
	enrolAs(t, h, "ordinary")

	csrPEM, _ := newCSR(t)
	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	req := httptest.NewRequest(http.MethodPost, "/v1/identity/renew", strings.NewReader(string(body)))
	req = withIdentity(req, h.ca, "ordinary")
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("renew: HTTP %d — %s", w.Code, w.Body.String())
	}
	var out struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(out.CertificatePEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Until(cert.NotAfter).Round(time.Hour); got != 240*time.Hour {
		t.Errorf("the renewed identity is valid for %v, want the configured 10d", got)
	}
}
