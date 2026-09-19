package brokerapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ollornog/flying-certs/internal/agentca"
	"github.com/Ollornog/flying-certs/internal/certstore"
	"github.com/Ollornog/flying-certs/internal/enroll"
	"github.com/Ollornog/flying-certs/internal/registry"
)

// recordingAuditor keeps what was audited so tests can check it.
type recordingAuditor struct {
	mu     sync.Mutex
	events []Event
}

func (a *recordingAuditor) Record(e Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
}

func (a *recordingAuditor) last() Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return Event{}
	}
	return a.events[len(a.events)-1]
}

type harness struct {
	srv     *Server
	ca      *agentca.CA
	tokens  *enroll.Store
	agents  *registry.Registry
	certs   *certstore.Store
	audit   *recordingAuditor
	certDir string
}

func setup(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()

	ca, err := agentca.Create(dir + "/ca")
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	tokens, err := enroll.NewStore(dir + "/tokens")
	if err != nil {
		t.Fatalf("tokens: %v", err)
	}
	agents, err := registry.New([]registry.Agent{
		{Name: "gateway", Certificates: []string{"gateway-cert"}, Mode: registry.ModeIssue},
		{Name: "storage", Certificates: []string{"shared-cert"}, Mode: registry.ModeShare},
	}, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	certs, err := certstore.New(dir + "/certs")
	if err != nil {
		t.Fatalf("certs: %v", err)
	}
	audit := &recordingAuditor{}
	srv, err := New(Config{CA: ca, Tokens: tokens, Agents: agents, Certs: certs, Audit: audit})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{srv: srv, ca: ca, tokens: tokens, agents: agents, certs: certs,
		audit: audit, certDir: dir + "/certs"}
}

func newCSR(t *testing.T) (csrPEM string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

// withIdentity fakes a verified mTLS connection carrying agentName.
func withIdentity(r *http.Request, ca *agentca.CA, agentName string) *http.Request {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: agentName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	return r
}

func storeCertificate(t *testing.T, h *harness, name string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name + ".example.com"},
		DNSNames:     []string{name + ".example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := h.certs.Save(name, chain, keyPEM); err != nil {
		t.Fatalf("store %s: %v", name, err)
	}
}

// The guard that makes the design safe: walk every route without a client
// certificate and prove that only the intended one answers. A new route that
// someone forgets to think about shows up here, not in production.
func TestEveryRouteButEnrolRequiresAClientCertificate(t *testing.T) {
	h := setup(t)

	routes := []struct{ method, path string }{
		{"POST", "/v1/enroll"},
		{"GET", "/v1/certificates/gateway-cert"},
		{"POST", "/v1/certificates/gateway-cert/issue"},
		{"POST", "/v1/identity/renew"},
		{"GET", "/v1/whoami"},
	}
	open := map[string]bool{"/v1/enroll": true}

	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(rec, req)

		// The distinction that matters: a 401 for a missing certificate, not a
		// 401 for a missing token. Checking only the status code would let a
		// route pass because it happens to reject empty input.
		gated := strings.Contains(rec.Body.String(), ErrNeedClientCert)

		if open[rt.path] {
			if gated {
				t.Errorf("%s %s: the open route demanded a certificate", rt.method, rt.path)
			}
			continue
		}
		if !gated {
			t.Errorf("%s %s: answered %d (%s) without a client certificate — the mTLS gate did not fire",
				rt.method, rt.path, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}

	// And the server's own idea of which routes are open must match.
	if got := h.srv.OpenPaths(); len(got) != 1 || got[0] != "/v1/enroll" {
		t.Errorf("OpenPaths() = %v, want exactly [/v1/enroll]", got)
	}
}

func TestEnrolIssuesAnIdentity(t *testing.T) {
	h := setup(t)
	tok, rec, err := enroll.NewToken("gateway", nil, h.ca.Fingerprint(), 0, time.Now())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := h.tokens.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	csrPEM, _ := newCSR(t)

	body, _ := json.Marshal(enrolRequest{Token: tok.String(), CSR: csrPEM})
	req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	var resp enrolResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AgentName != "gateway" {
		t.Errorf("AgentName = %q", resp.AgentName)
	}

	block, _ := pem.Decode([]byte(resp.CertificatePEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if cert.Subject.CommonName != "gateway" {
		t.Errorf("the identity names %q", cert.Subject.CommonName)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     h.ca.CertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("the issued identity does not verify: %v", err)
	}
	if !h.audit.last().Allowed {
		t.Error("a successful enrolment was not audited as allowed")
	}

	// The token is spent: a second attempt with the same one fails.
	req2 := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
	w2 := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w2, req2)
	if w2.Code == http.StatusOK {
		t.Error("the same token enrolled twice")
	}
}

// A token for a name nobody configured must not create an agent out of thin
// air. The token says "someone meant to let this host in", not "this host may
// have things".
func TestEnrolRefusesUnconfiguredAgent(t *testing.T) {
	h := setup(t)
	tok, rec, _ := enroll.NewToken("ghost", nil, h.ca.Fingerprint(), 0, time.Now())
	if err := h.tokens.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	csrPEM, _ := newCSR(t)

	body, _ := json.Marshal(enrolRequest{Token: tok.String(), CSR: csrPEM})
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body)))

	if w.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", w.Code)
	}
}

func TestEnrolRejectsBadTokenUniformly(t *testing.T) {
	h := setup(t)
	csrPEM, _ := newCSR(t)

	// A malformed token and an unknown one must be indistinguishable.
	var bodies [][]byte
	for _, tokenValue := range []string{"garbage", "aaaabbbb.ccccdddd"} {
		b, _ := json.Marshal(enrolRequest{Token: tokenValue, CSR: csrPEM})
		bodies = append(bodies, b)
	}
	var answers []string
	for _, b := range bodies {
		w := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(b)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", w.Code)
		}
		answers = append(answers, w.Body.String())
	}
	if answers[0] != answers[1] {
		t.Errorf("a malformed token (%s) is distinguishable from an unknown one (%s)",
			answers[0], answers[1])
	}
}

func TestFetchHonoursTheDeliveryMode(t *testing.T) {
	h := setup(t)
	storeCertificate(t, h, "gateway-cert")
	storeCertificate(t, h, "shared-cert")

	// issue mode: no private key may travel.
	req := withIdentity(httptest.NewRequest("GET", "/v1/certificates/gateway-cert", nil), h.ca, "gateway")
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	var issued fetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if issued.PrivateKeyPEM != "" {
		t.Error("issue mode handed out a private key")
	}
	if !strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Error("no certificate in the answer")
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Error("a private key appears in an issue-mode answer")
	}

	// share mode: the key does travel, by configuration.
	req = withIdentity(httptest.NewRequest("GET", "/v1/certificates/shared-cert", nil), h.ca, "storage")
	w = httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	var shared fetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &shared); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if shared.PrivateKeyPEM == "" {
		t.Error("share mode withheld the private key")
	}
}

// The gap none of the comparable projects closes: an agent asking for
// something that is not its own.
func TestAgentCannotFetchAnotherAgentsCertificate(t *testing.T) {
	h := setup(t)
	storeCertificate(t, h, "shared-cert")

	req := withIdentity(httptest.NewRequest("GET", "/v1/certificates/shared-cert", nil), h.ca, "gateway")
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", w.Code)
	}
	// 404 rather than 403 on purpose: otherwise an agent can map what else
	// the broker holds by watching which name gives which answer.
	missing := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(missing,
		withIdentity(httptest.NewRequest("GET", "/v1/certificates/does-not-exist", nil), h.ca, "gateway"))
	if missing.Body.String() != w.Body.String() {
		t.Errorf("a forbidden certificate (%s) is distinguishable from a missing one (%s)",
			w.Body.String(), missing.Body.String())
	}
	if h.audit.last().Allowed {
		t.Error("a refused fetch was audited as allowed")
	}
}

func TestRevokedAgentIsRefusedEverywhere(t *testing.T) {
	h := setup(t)
	storeCertificate(t, h, "gateway-cert")
	if err := h.agents.Revoke("gateway", "test", time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	for _, path := range []string{"/v1/certificates/gateway-cert", "/v1/whoami"} {
		w := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(w, withIdentity(httptest.NewRequest("GET", path, nil), h.ca, "gateway"))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: code = %d, want 403 for a revoked agent", path, w.Code)
		}
	}
}

// Renewal must take the name from the certificate, never from the request —
// otherwise it is a way to become someone else.
func TestIdentityRenewalCannotChangeTheName(t *testing.T) {
	h := setup(t)
	csrPEM, _ := newCSR(t)
	body, _ := json.Marshal(map[string]string{"csr": csrPEM, "agent_name": "storage"})

	req := withIdentity(httptest.NewRequest("POST", "/v1/identity/renew", bytes.NewReader(body)), h.ca, "gateway")
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}

	var resp renewResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	block, _ := pem.Decode([]byte(resp.CertificatePEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.Subject.CommonName != "gateway" {
		t.Errorf("renewal produced an identity for %q — the request changed the name",
			cert.Subject.CommonName)
	}
}

func TestAuditRecordsRemoteAddressAndOutcome(t *testing.T) {
	h := setup(t)
	storeCertificate(t, h, "gateway-cert")
	req := withIdentity(httptest.NewRequest("GET", "/v1/certificates/gateway-cert", nil), h.ca, "gateway")
	req.RemoteAddr = "198.51.100.7:40000"
	h.srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	ev := h.audit.last()
	if ev.Agent != "gateway" || ev.Certificate != "gateway-cert" || !ev.Allowed {
		t.Errorf("event = %+v", ev)
	}
	if ev.RemoteAddr != "198.51.100.7:40000" {
		t.Errorf("RemoteAddr = %q", ev.RemoteAddr)
	}
	if ev.At.IsZero() {
		t.Error("the event carries no time")
	}
}

// The identity comes from the certificate. A header claiming otherwise must
// change nothing.
func TestIdentityCannotBeSpoofedByHeader(t *testing.T) {
	h := setup(t)
	storeCertificate(t, h, "shared-cert")

	req := withIdentity(httptest.NewRequest("GET", "/v1/certificates/shared-cert", nil), h.ca, "gateway")
	req.Header.Set("X-Agent-Name", "storage")
	req.Header.Set("Authorization", "Bearer storage")
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("a header changed who the caller was taken to be")
	}
}

func TestOversizedBodyIsRefused(t *testing.T) {
	h := setup(t)
	huge := bytes.Repeat([]byte("a"), 1<<20)
	body, _ := json.Marshal(enrolRequest{Token: "x.y", CSR: string(huge)})

	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body)))
	if w.Code == http.StatusOK {
		t.Error("an oversized body was accepted")
	}
}

func TestTLSConfigDemandsOurCA(t *testing.T) {
	h := setup(t)
	cfg := h.srv.TLSConfig(tls.Certificate{})
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("no client CA pool — any certificate would verify")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
}

func TestNewRejectsIncompleteConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("an empty configuration was accepted")
	}
}

var _ = io.Discard
