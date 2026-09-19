package brokerapi

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ollornog/flying-certs/internal/agentca"
	"github.com/Ollornog/flying-certs/internal/certstore"
	"github.com/Ollornog/flying-certs/internal/enroll"
	"github.com/Ollornog/flying-certs/internal/registry"
)

// maxBody bounds a request. A CSR is a couple of kilobytes; anything larger is
// either a mistake or an attempt to make the broker allocate.
const maxBody = 64 << 10

type enrolRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

type enrolResponse struct {
	AgentName      string `json:"agent_name"`
	CertificatePEM string `json:"certificate_pem"`
	CAPem          string `json:"ca_pem"`
	NotAfter       string `json:"not_after"`
}

// handleEnrol turns a bootstrap token into an identity. The one route that
// works without a client certificate.
func (s *Server) handleEnrol(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	ev := Event{At: now, Action: "enrol", RemoteAddr: r.RemoteAddr}

	var req enrolRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&req); err != nil {
		ev.Reason = "malformed request"
		s.audit.Record(ev)
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}

	id, secret, err := enroll.ParseToken(req.Token)
	if err != nil {
		ev.Reason = "malformed token"
		s.audit.Record(ev)
		// Deliberately the same wording as an unknown token below: telling a
		// caller which part was wrong helps only someone guessing.
		writeError(w, http.StatusUnauthorized, "token is not valid")
		return
	}

	csr, err := parseCSR([]byte(req.CSR))
	if err != nil {
		ev.Reason = "bad csr"
		s.audit.Record(ev)
		writeError(w, http.StatusBadRequest, "certificate request could not be read")
		return
	}

	// Redeem first, sign second. The token is spent the moment it is claimed,
	// so a failure further down cannot leave it reusable — and two callers
	// racing cannot both get an identity.
	rec, err := s.tokens.Redeem(id, secret, s.ca.Fingerprint(), r.RemoteAddr, now)
	if err != nil {
		ev.Reason = err.Error()
		s.audit.Record(ev)
		switch {
		case errors.Is(err, enroll.ErrNotYetValid), errors.Is(err, enroll.ErrExpired):
			// Worth telling apart: this is almost always a clock problem or a
			// token that sat in a chat window too long, and the operator can
			// fix both once they know which.
			writeError(w, http.StatusUnauthorized, err.Error())
		default:
			writeError(w, http.StatusUnauthorized, "token is not valid")
		}
		return
	}
	ev.Agent = rec.AgentName

	// An agent must be configured before it can enrol. A token alone does not
	// create permissions — it only proves someone meant to let this host in.
	if _, err := s.agents.Lookup(rec.AgentName); err != nil {
		ev.Reason = "token names an agent that is not configured"
		s.audit.Record(ev)
		writeError(w, http.StatusForbidden, "this agent is not configured")
		return
	}
	if s.agents.Revoked(rec.AgentName) {
		ev.Reason = "revoked"
		s.audit.Record(ev)
		writeError(w, http.StatusForbidden, "this identity has been revoked")
		return
	}

	certPEM, err := agentca.SignAgent(s.ca, rec.AgentName, csr, s.lifetime)
	if err != nil {
		ev.Reason = "signing failed: " + err.Error()
		s.audit.Record(ev)
		s.log.Error("could not sign an agent identity",
			slog.String("agent", rec.AgentName), slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "could not issue an identity")
		return
	}

	ev.Allowed = true
	s.audit.Record(ev)
	if err := s.agents.Seen(rec.AgentName, now); err != nil {
		s.log.Warn("could not record the enrolment", slog.String("error", err.Error()))
	}

	writeJSON(w, http.StatusOK, enrolResponse{
		AgentName:      rec.AgentName,
		CertificatePEM: string(certPEM),
		// The agent needs the CA certificate to verify the broker on later
		// calls. It is public information — but see ADR-15: it must never end
		// up in a bundle the agent serves to visitors.
		CAPem:    string(s.ca.CertificatePEM()),
		NotAfter: now.Add(agentLifetime(s.lifetime)).Format(time.RFC3339),
	})
}

type fetchResponse struct {
	Name           string   `json:"name"`
	CertificatePEM string   `json:"certificate_pem"`
	PrivateKeyPEM  string   `json:"private_key_pem,omitempty"`
	Domains        []string `json:"domains"`
	NotAfter       string   `json:"not_after"`
}

// handleFetch hands over a stored certificate.
//
// Whether the private key travels depends on the agent's mode: in `issue` it
// never does, in `share` it does and the documentation says what that costs
// (ADR-3).
func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request, agentName string) {
	now := time.Now().UTC()
	certName := r.PathValue("name")
	ev := Event{At: now, Action: "fetch", Agent: agentName,
		Certificate: certName, RemoteAddr: r.RemoteAddr}

	agent, err := s.agents.Authorise(agentName, certName)
	if err != nil {
		ev.Reason = err.Error()
		s.audit.Record(ev)
		// One answer for "not permitted" and "no such certificate": otherwise
		// an agent can map what else the broker holds.
		writeError(w, http.StatusNotFound, "no such certificate for this agent")
		return
	}

	chainPEM, keyPEM, pair, err := s.certs.Load(certName)
	if err != nil {
		ev.Reason = err.Error()
		s.audit.Record(ev)
		if errors.Is(err, certstore.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such certificate for this agent")
			return
		}
		s.log.Error("a stored certificate is unusable",
			slog.String("certificate", certName), slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "the stored certificate is unusable")
		return
	}

	resp := fetchResponse{
		Name:           certName,
		CertificatePEM: string(chainPEM),
		Domains:        pair.Leaf.DNSNames,
		NotAfter:       pair.Leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	if agent.Mode == registry.ModeShare {
		resp.PrivateKeyPEM = string(keyPEM)
	}

	ev.Allowed = true
	ev.Reason = string(agent.Mode)
	s.audit.Record(ev)
	if err := s.agents.Delivered(agentName, certName, now); err != nil {
		s.log.Warn("could not record a delivery", slog.String("error", err.Error()))
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleIssue is the `issue` mode: the agent sends a CSR and the broker
// obtains a certificate for it. Wired up in M-3; the route exists now so the
// route-coverage test cannot be satisfied by simply not having it.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request, agentName string) {
	certName := r.PathValue("name")
	if _, err := s.agents.Authorise(agentName, certName); err != nil {
		s.audit.Record(Event{At: time.Now().UTC(), Action: "issue", Agent: agentName,
			Certificate: certName, RemoteAddr: r.RemoteAddr, Reason: err.Error()})
		writeError(w, http.StatusNotFound, "no such certificate for this agent")
		return
	}
	writeError(w, http.StatusNotImplemented, "issuing per agent arrives with M-3")
}

type renewResponse struct {
	CertificatePEM string `json:"certificate_pem"`
	NotAfter       string `json:"not_after"`
}

// handleRenewIdentity issues a fresh identity to an agent that still has a
// valid one.
//
// This is what keeps an agent from locking itself out, and why it must work
// long before expiry. Once the identity has expired there is no way back
// through this route — by design (ADR-7): an expired certificate cannot
// authenticate to ask for its own replacement.
func (s *Server) handleRenewIdentity(w http.ResponseWriter, r *http.Request, agentName string) {
	now := time.Now().UTC()
	ev := Event{At: now, Action: "renew-identity", Agent: agentName, RemoteAddr: r.RemoteAddr}

	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&req); err != nil {
		ev.Reason = "malformed request"
		s.audit.Record(ev)
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	csr, err := parseCSR([]byte(req.CSR))
	if err != nil {
		ev.Reason = "bad csr"
		s.audit.Record(ev)
		writeError(w, http.StatusBadRequest, "certificate request could not be read")
		return
	}

	// The name comes from the existing certificate, never from the request.
	// Otherwise renewal would be a way to become someone else.
	certPEM, err := agentca.SignAgent(s.ca, agentName, csr, s.lifetime)
	if err != nil {
		ev.Reason = err.Error()
		s.audit.Record(ev)
		writeError(w, http.StatusInternalServerError, "could not issue an identity")
		return
	}

	ev.Allowed = true
	s.audit.Record(ev)
	if err := s.agents.Seen(agentName, now); err != nil {
		s.log.Warn("could not record a renewal", slog.String("error", err.Error()))
	}
	writeJSON(w, http.StatusOK, renewResponse{
		CertificatePEM: string(certPEM),
		NotAfter:       now.Add(agentLifetime(s.lifetime)).Format(time.RFC3339),
	})
}

// handleWhoami tells an agent what the broker thinks it is. Useful when
// something is wrong and the question is whether the identity is the problem.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request, agentName string) {
	agent, err := s.agents.Lookup(agentName)
	if err != nil {
		writeError(w, http.StatusForbidden, "this agent is not configured")
		return
	}
	state := s.agents.StateOf(agentName)
	writeJSON(w, http.StatusOK, map[string]any{
		"agent":        agent.Name,
		"mode":         agent.Mode,
		"certificates": agent.Certificates,
		"last_seen":    state.LastSeen,
	})
}

func agentLifetime(configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	return agentca.DefaultAgentLifetime
}

// decodePEM returns the DER bytes of the first PEM block.
func decodePEM(data []byte) ([]byte, []byte) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, rest
	}
	return block.Bytes, rest
}
