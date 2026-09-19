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

	"github.com/Ollornog/FlyingCerts/internal/acme"
	"github.com/Ollornog/FlyingCerts/internal/agentca"
	"github.com/Ollornog/FlyingCerts/internal/certstore"
	"github.com/Ollornog/FlyingCerts/internal/enroll"
	"github.com/Ollornog/FlyingCerts/internal/keyfp"
	"github.com/Ollornog/FlyingCerts/internal/lifetime"
	"github.com/Ollornog/FlyingCerts/internal/registry"
)

// ErrNeedClientCert is the exact wording the mTLS gate answers with.
//
// Exported so the route-coverage test can tell "no client certificate" apart
// from a business-level 401 such as a bad token. Without that distinction the
// test would pass on a route that is unreachable for entirely the wrong reason.
const ErrNeedClientCert = "a client certificate is required"

// ErrNeedDeviceCert is the same guarantee for the device-key route, worded
// separately because the remedy is different: not "get an identity" but
// "present your device key". A test asserts on both, so a route cannot pass
// for rejecting an empty body rather than for rejecting a stranger.
const ErrNeedDeviceCert = "a certificate holding your device key is required"

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
	ca              *agentca.CA
	tokens          *enroll.Store
	agents          *registry.Registry
	certs           *certstore.Store
	audit           Auditor
	log             *slog.Logger
	defaultLifetime lifetime.Span
	specs           Specs
	issuer          Issuer

	mux         *http.ServeMux
	openPaths   map[string]bool // reachable without any client certificate
	devicePaths map[string]bool // authenticated by device key, not by our CA
	enrolRate   *RateLimiter
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

	// Lifetime is the broker-wide agent identity lifetime, used for agents
	// that do not set their own. Unset means the CA default.
	Lifetime lifetime.Span

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
		audit: audit, log: log, defaultLifetime: cfg.Lifetime,
		specs: cfg.Specs, issuer: cfg.Issuer,
		mux:         http.NewServeMux(),
		openPaths:   map[string]bool{},
		devicePaths: map[string]bool{},
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

	// The ordinary way in, and the way back after an identity has lapsed: a
	// host proves it holds the device key the configuration names (ADR-18).
	// Rate-limited like enrolment, because it is reachable without an
	// identity and is therefore somewhere to guess at.
	s.deviceRoute("POST /v1/identity/request", s.rateLimited(s.handleIdentityRequest))

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

// deviceRoute registers a route authenticated by device key rather than by
// an identity from our CA.
//
// It is tracked separately from the open routes so the coverage test can
// state which routes need what: open, device key, or identity. A route that
// is none of the three is a route nobody decided about.
func (s *Server) deviceRoute(pattern string, h http.HandlerFunc) {
	s.devicePaths[pathOf(pattern)] = true
	s.mux.HandleFunc(pattern, h)
}

// DevicePaths lists the routes authenticated by device key.
func (s *Server) DevicePaths() []string {
	out := make([]string, 0, len(s.devicePaths))
	for p := range s.devicePaths {
		out = append(out, p)
	}
	return out
}

// mTLSRoute registers a route that requires a verified client certificate.
func (s *Server) mTLSRoute(pattern string, h func(http.ResponseWriter, *http.Request, string)) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		name, err := s.verifiedAgent(r)
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
// RequestClientCert, and the verification moved into this package. That is a
// deliberate step down from what the TLS layer would do on its own, and it
// needs justifying, because "we check it ourselves" is how authentication
// bugs are introduced.
//
// Three kinds of caller arrive on this endpoint:
//
//   - Enrolment, with no certificate at all.
//   - An agent with an identity signed by our CA.
//   - A host presenting its device key, in a self-signed certificate that is
//     deliberately NOT from our CA (ADR-18).
//
// VerifyClientCertIfGiven cannot express the third: it aborts the handshake
// on any certificate that fails to chain to ClientCAs, so the device key
// would never reach a handler. Requiring nothing and checking per route is
// the only shape that fits all three.
//
// What the TLS layer still guarantees, and what this therefore does not have
// to re-check: whoever presented a certificate proved possession of its
// private key. Go verifies the CertificateVerify signature whenever a client
// certificate is sent, in every ClientAuth mode. A stolen certificate — and
// certificates are public — is useless without the key.
//
// What this package must now do, and did not before: verify the chain. Both
// verifiedAgent and deviceFingerprint below do it explicitly, and a route is
// wired to exactly one of them.
func (s *Server) TLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}

// verifiedAgent reads the agent name out of a client certificate issued by
// our CA, verifying it here because the TLS layer no longer does.
//
// That day the old comment on this function warned about — "relying on the
// TLS configuration would make this wrong the day someone changes it" — is
// the day ADR-18 was implemented. So the check is explicit and local:
//
//   - the chain must reach our CA, and nothing else;
//   - the certificate must be valid now, which is what makes an expired
//     identity stop working (ADR-7) rather than merely look old;
//   - it must be a client certificate, so a server certificate issued by the
//     same CA cannot be turned into an identity.
func (s *Server) verifiedAgent(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("not a TLS connection")
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}
	// PeerCertificates[0] is what the client sent. Possession of its key is
	// already proven by the handshake; everything else is checked here.
	leaf := r.TLS.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, c := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         s.ca.CertPool(),
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", fmt.Errorf("client certificate is not a valid identity: %w", err)
	}
	name := registry.NormaliseName(leaf.Subject.CommonName)
	if name == "" {
		return "", errors.New("client certificate carries no name")
	}
	return name, nil
}

// deviceFingerprint returns the fingerprint of the key the caller proved it
// holds, whatever certificate it was wrapped in.
//
// The certificate is not verified against anything and is not meant to be:
// it is a container for a public key, and the handshake already established
// that the caller has the matching private key. Authorisation happens against
// the fingerprints in the configuration, one step further on.
func deviceFingerprint(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("not a TLS connection")
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}
	return keyfp.Of(r.TLS.PeerCertificates[0].PublicKey)
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
