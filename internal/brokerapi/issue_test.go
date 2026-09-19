package brokerapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ollornog/FlyingCerts/internal/acme"
)

// fixedSpecs is the configured set of names per certificate.
type fixedSpecs map[string][]string

func (f fixedSpecs) DomainsFor(name string) ([]string, bool) {
	d, ok := f[name]
	return d, ok
}

// recordingIssuer stands in for the CA and remembers what it was asked.
type recordingIssuer struct {
	calls   int
	lastCSR *x509.CertificateRequest
	lastReq acme.Request
	err     error
}

func (r *recordingIssuer) ObtainForCSR(_ context.Context, csr *x509.CertificateRequest, req acme.Request) (*acme.Result, error) {
	r.calls++
	r.lastCSR, r.lastReq = csr, req
	if r.err != nil {
		return nil, r.err
	}
	return &acme.Result{CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nissued\n-----END CERTIFICATE-----\n")}, nil
}

func issueHarness(t *testing.T, specs fixedSpecs, iss Issuer) *harness {
	t.Helper()
	h := setup(t)
	srv, err := New(Config{
		CA: h.ca, Tokens: h.tokens, Agents: h.agents, Certs: h.certs,
		Audit: h.audit, Specs: specs, Issuer: iss,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.srv = srv
	return h
}

func csrWithNames(t *testing.T, names ...string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{}, DNSNames: names}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func postIssue(t *testing.T, h *harness, agent, certName, csrPEM string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	req := withIdentity(httptest.NewRequest("POST", "/v1/certificates/"+certName+"/issue",
		bytes.NewReader(body)), h.ca, agent)
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)
	return w
}

func TestIssueAcceptsTheExactNames(t *testing.T) {
	iss := &recordingIssuer{}
	h := issueHarness(t, fixedSpecs{"gateway-cert": {"gateway.example.com"}}, iss)

	w := postIssue(t, h, "gateway", "gateway-cert", csrWithNames(t, "gateway.example.com"))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	var resp issueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(resp.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Error("no certificate in the answer")
	}
	// The mode exists so that no private key is anywhere near this path.
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Error("a private key appears in an issue-mode answer")
	}
	if iss.calls != 1 {
		t.Errorf("the CA was asked %d times, want 1", iss.calls)
	}
}

// The check the whole project is built around, at the HTTP boundary.
func TestIssueRefusesExtraNamesAndSaysWhich(t *testing.T) {
	iss := &recordingIssuer{}
	h := issueHarness(t, fixedSpecs{"gateway-cert": {"gateway.example.com"}}, iss)

	w := postIssue(t, h, "gateway", "gateway-cert",
		csrWithNames(t, "gateway.example.com", "admin.example.com"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "admin.example.com") {
		t.Errorf("the answer does not name the offending entry: %s", w.Body.String())
	}
	// And nothing was ordered — the refusal happens before the CA is touched,
	// so a rejected request costs nothing and cannot hit a rate limit.
	if iss.calls != 0 {
		t.Error("the CA was contacted for a request that should have been refused")
	}
	if h.audit.last().Allowed {
		t.Error("a refused issue was audited as allowed")
	}
}

func TestIssueRefusesSubsetOfNames(t *testing.T) {
	iss := &recordingIssuer{}
	h := issueHarness(t, fixedSpecs{"gateway-cert": {"a.example.com", "b.example.com"}}, iss)

	w := postIssue(t, h, "gateway", "gateway-cert", csrWithNames(t, "a.example.com"))
	if w.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403 for a subset", w.Code)
	}
	if iss.calls != 0 {
		t.Error("the CA was contacted for a subset request")
	}
}

func TestIssueRefusesAnotherAgentsCertificate(t *testing.T) {
	iss := &recordingIssuer{}
	h := issueHarness(t, fixedSpecs{"shared-cert": {"shared.example.com"}}, iss)

	w := postIssue(t, h, "gateway", "shared-cert", csrWithNames(t, "shared.example.com"))
	if w.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", w.Code)
	}
	if iss.calls != 0 {
		t.Error("the CA was contacted for an unauthorised certificate")
	}
}

// An agent configured for share must not use the issue route: the two modes
// mean different things and silently accepting both hides which is in effect.
func TestIssueRefusesShareModeAgent(t *testing.T) {
	iss := &recordingIssuer{}
	h := issueHarness(t, fixedSpecs{"shared-cert": {"shared.example.com"}}, iss)

	w := postIssue(t, h, "storage", "shared-cert", csrWithNames(t, "shared.example.com"))
	if w.Code != http.StatusConflict {
		t.Errorf("code = %d, want 409", w.Code)
	}
}

func TestIssueRefusesUnsignedCSR(t *testing.T) {
	iss := &recordingIssuer{}
	h := issueHarness(t, fixedSpecs{"gateway-cert": {"gateway.example.com"}}, iss)

	// Flip a byte in the encoded request so its signature no longer matches
	// the contents. Mutating the parsed struct would not work: the signature
	// is checked against the original bytes, which the struct keeps in Raw.
	valid := csrWithNames(t, "gateway.example.com")
	block, _ := pem.Decode([]byte(valid))
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-1] ^= 0xff
	w := postIssue(t, h, "gateway", "gateway-cert",
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})))

	if w.Code == http.StatusOK {
		t.Error("a tampered certificate request was accepted")
	}
	if iss.calls != 0 {
		t.Error("the CA was contacted for a tampered request")
	}
}

func TestIssueReportsCAFailureWithoutLeakingDetail(t *testing.T) {
	iss := &recordingIssuer{err: errors.New("rate limit exceeded for account 12345")}
	h := issueHarness(t, fixedSpecs{"gateway-cert": {"gateway.example.com"}}, iss)

	w := postIssue(t, h, "gateway", "gateway-cert", csrWithNames(t, "gateway.example.com"))
	if w.Code != http.StatusBadGateway {
		t.Errorf("code = %d, want 502", w.Code)
	}
	// The detail belongs in the broker's log, not in an answer to an agent.
	if strings.Contains(w.Body.String(), "12345") {
		t.Errorf("the CA's message leaked to the caller: %s", w.Body.String())
	}
}

func TestIssueWithoutConfiguredIssuingSaysSo(t *testing.T) {
	h := setup(t) // no Specs, no Issuer
	w := postIssue(t, h, "gateway", "gateway-cert", csrWithNames(t, "gateway.example.com"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("code = %d, want 503", w.Code)
	}
}

// A renewal must name its predecessor, or it loses the rate-limit exemption
// in RFC 9773 §5 — silently, until the limit bites.
func TestIssueNamesThePredecessorWhenOneExists(t *testing.T) {
	iss := &recordingIssuer{}
	h := issueHarness(t, fixedSpecs{"gateway-cert": {"gateway-cert.example.com"}}, iss)
	storeCertificate(t, h, "gateway-cert")

	w := postIssue(t, h, "gateway", "gateway-cert", csrWithNames(t, "gateway-cert.example.com"))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	if iss.lastReq.Replaces == nil {
		t.Error("the renewal did not name the stored certificate as its predecessor")
	}
}
