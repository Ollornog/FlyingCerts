// Package brokerapi is the endpoint agents talk to.
//
// Two kinds of request arrive here, and they must not be confused:
//
//   - Enrolment. A host with no identity yet presents a bootstrap token and
//     receives its first certificate. Exactly one route, and the only one that
//     works without a client certificate.
//   - Everything else. Requires mTLS, and the identity comes from the
//     certificate — never from a header, a query parameter or the body. An
//     audit trail built on something the caller can set is worth nothing.
//
// Go's TLS stack cannot demand a client certificate on one route and waive it
// on another, so the server asks for one when offered
// (tls.VerifyClientCertIfGiven) and the routing enforces the rest. That puts
// the burden on us, which is why routes are registered through two explicit
// constructors — mTLSRoute and openRoute — and a test walks every registered
// route without a certificate to prove only the intended one answers. Forget
// to think about it and a route simply will not be reachable.
package brokerapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Ollornog/flying-certs/internal/acme"
	"github.com/Ollornog/flying-certs/internal/agentca"
	"github.com/Ollornog/flying-certs/internal/certstore"
	"github.com/Ollornog/flying-certs/internal/enroll"
	"github.com/Ollornog/flying-certs/internal/registry"
)

// ErrNeedClientCert is the exact wording the mTLS gate answers with.
//
// Exported so the route-coverage test can tell "no client certificate" apart
// from a business-level 401 such as a bad token. Without that distinction the
// test would pass on a route that is unreachable for entirely the wrong reason.
const ErrNeedClientCert = "a client certificate is required"

// Specs answers what a certificate is configured to cover. The `issue` mode
// needs it to know which names an agent may put in its request.
//
// An interface rather than the configuration struct: the handler should not be
// able to reach anything else about the configuration, and a test should not
// have to build one.
type Specs interface {
	// DomainsFor returns the configured names for a certificate, and whether
	// it is configured at all.
	DomainsFor(certName string) ([]string, bool)
}

// Issuer obtains certificates from the CA. Narrow on purpose: the handler can
// ask for a certificate and nothing else.
type Issuer interface {
	ObtainForCSR(ctx context.Context, csr *x509.CertificateRequest, req acme.Request) (*acme.Result, error)
}

// Auditor records what happened. Every decision that matters goes through it.
type Auditor interface {
	Record(event Event)
}

// Event is one audited decision.
type Event struct {
	At          time.Time `json:"at"`
	Action      string    `json:"action"`
	Agent       string    `json:"agent,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	RemoteAddr  string    `json:"remote_addr,omitempty"`
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason,omitempty"`
}

// Server serves the agent-facing API.
type Server struct {
	ca       *agentca.CA
	tokens   *enroll.Store
	agents   *registry.Registry
	certs    *certstore.Store
	audit    Auditor
	log      *slog.Logger
	lifetime time.Duration
	specs    Specs
	issuer   Issuer

	mux       *http.ServeMux
	openPaths map[string]bool // routes reachable without a client certificate
	enrolRate *RateLimiter
}

// Config assembles a Server.
type Config struct {
	CA     *agentca.CA
	Tokens *enroll.Store
	Agents *registry.Registry
	Certs  *certstore.Store
	Audit  Auditor
	Log    *slog.Logger

	// Specs and Issuer power the `issue` mode. Left nil, that route answers
	// "not configured" rather than failing in some surprising way.
	Specs  Specs
	Issuer Issuer

	Lifetime time.Duration // agent identity lifetime; zero means the CA default

	// EnrolLimit caps enrolment attempts per remote address per hour.
	// Zero means DefaultEnrolRate; a negative value disables the limit and is
	// only sensible in tests.
	EnrolLimit int
}

// New builds the server and registers its routes.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.CA == nil:
		return nil, errors.New("no agent CA")
	case cfg.Tokens == nil:
		return nil, errors.New("no token store")
	case cfg.Agents == nil:
		return nil, errors.New("no agent registry")
	case cfg.Certs == nil:
		return nil, errors.New("no certificate store")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	audit := cfg.Audit
	if audit == nil {
		audit = discardAuditor{}
	}

	s := &Server{
		ca: cfg.CA, tokens: cfg.Tokens, agents: cfg.Agents, certs: cfg.Certs,
		audit: audit, log: log, lifetime: cfg.Lifetime,
		specs: cfg.Specs, issuer: cfg.Issuer,
		mux:       http.NewServeMux(),
		openPaths: map[string]bool{},
	}

	limit := cfg.EnrolLimit
	if limit == 0 {
		limit = DefaultEnrolRate
	}
	s.enrolRate = NewRateLimiter(limit, DefaultEnrolWindow)

	// The only route a host without an identity may reach — and therefore the
	// only one that needs a limit keyed on the address rather than on a
	// verified name.
	s.openRoute("POST /v1/enroll", s.rateLimited(s.handleEnrol))

	s.mTLSRoute("GET /v1/certificates/{name}", s.handleFetch)
	s.mTLSRoute("POST /v1/certificates/{name}/issue", s.handleIssue)
	s.mTLSRoute("POST /v1/identity/renew", s.handleRenewIdentity)
	s.mTLSRoute("GET /v1/whoami", s.handleWhoami)

	return s, nil
}

// openRoute registers a route reachable without a client certificate. Every
// call is a decision that has to be defended; there is currently one.
func (s *Server) openRoute(pattern string, h http.HandlerFunc) {
	s.openPaths[pathOf(pattern)] = true
	s.mux.HandleFunc(pattern, h)
}

// mTLSRoute registers a route that requires a verified client certificate.
func (s *Server) mTLSRoute(pattern string, h func(http.ResponseWriter, *http.Request, string)) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		name, err := agentFromRequest(r)
		if err != nil {
			s.audit.Record(Event{
				At: time.Now().UTC(), Action: "authenticate", RemoteAddr: r.RemoteAddr,
				Allowed: false, Reason: err.Error(),
			})
			writeError(w, http.StatusUnauthorized, ErrNeedClientCert)
			return
		}
		// Revocation is checked on every request, so withdrawing an agent
		// takes effect at once rather than at its next restart.
		if s.agents.Revoked(name) {
			s.audit.Record(Event{
				At: time.Now().UTC(), Action: "authenticate", Agent: name,
				RemoteAddr: r.RemoteAddr, Allowed: false, Reason: "revoked",
			})
			writeError(w, http.StatusForbidden, "this identity has been revoked")
			return
		}
		h(w, r, name)
	})
}

// rateLimited wraps a handler with the enrolment limit.
//
// The key is the remote address, which the caller cannot pick freely. Keying
// on anything from the request — a token, a name, a header — means every
// attempt looks like a new caller and the limit never applies.
func (s *Server) rateLimited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := limiterKey(r)
		if !s.enrolRate.Allow(key, time.Now()) {
			s.audit.Record(Event{
				At: time.Now().UTC(), Action: "enrol", RemoteAddr: r.RemoteAddr,
				Allowed: false, Reason: "rate limit",
			})
			w.Header().Set("Retry-After", "3600")
			writeError(w, http.StatusTooManyRequests, "too many enrolment attempts")
			return
		}
		h(w, r)
	}
}

// PruneRateLimiter drops aged-out counters. Call it from a timer.
func (s *Server) PruneRateLimiter(now time.Time) int { return s.enrolRate.Prune(now) }

// Handler returns the router, for tests and for embedding.
func (s *Server) Handler() http.Handler { return s.mux }

// OpenPaths lists the routes reachable without a client certificate.
func (s *Server) OpenPaths() []string {
	out := make([]string, 0, len(s.openPaths))
	for p := range s.openPaths {
		out = append(out, p)
	}
	return out
}

// TLSConfig returns the server's TLS settings.
//
// VerifyClientCertIfGiven rather than RequireAndVerify, because enrolment has
// to work without one. What it does guarantee: a certificate that IS presented
// must verify against our CA, so a handler that sees one can trust it.
func (s *Server) TLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.ca.CertPool(),
		MinVersion:   tls.VersionTLS12,
	}
}

// agentFromRequest reads the agent name out of the verified client certificate.
//
// VerifiedChains, not PeerCertificates: the latter is merely what the client
// sent. With VerifyClientCertIfGiven an unverified certificate never reaches
// here, but relying on that would make this function wrong the day someone
// changes the TLS configuration.
func agentFromRequest(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("not a TLS connection")
	}
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", errors.New("no verified client certificate")
	}
	leaf := r.TLS.VerifiedChains[0][0]
	name := registry.NormaliseName(leaf.Subject.CommonName)
	if name == "" {
		return "", errors.New("client certificate carries no name")
	}
	return name, nil
}

func pathOf(pattern string) string {
	if _, path, found := strings.Cut(pattern, " "); found {
		return path
	}
	return pattern
}

type discardAuditor struct{}

func (discardAuditor) Record(Event) {}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// parseCSR decodes a PEM certificate request from a request body field.
func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := decodePEM(pemBytes)
	if block == nil {
		return nil, errors.New("not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	return csr, nil
}
