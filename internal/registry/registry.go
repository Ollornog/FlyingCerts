// Package registry answers the question every request comes down to: is this
// agent allowed to have this certificate?
//
// The answer is a lookup, never an inference. No wildcards over agent names,
// no "if the names look similar", no falling back to "allow when unsure". A
// permission that has to be reasoned about is one that gets reasoned about
// wrongly under pressure.
//
// This is the piece none of the comparable projects has. acme-manager, the
// nearest relative, puts only a username and a scope in its token — any token
// with `create` can ask for any syntactically valid name. Cert Warden binds
// keys one-to-one to certificates, which does not scale and still says nothing
// about who may ask.
package registry

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrUnknownAgent reports an agent nobody configured.
	ErrUnknownAgent = errors.New("unknown agent")
	// ErrRevoked reports an agent whose identity was withdrawn.
	ErrRevoked = errors.New("agent is revoked")
	// ErrNotPermitted reports an agent asking for something not its own.
	ErrNotPermitted = errors.New("agent is not permitted this certificate")
)

// Agent is one configured host.
type Agent struct {
	// Name identifies the agent and appears in its identity certificate.
	Name string
	// Certificates are the store names this agent may fetch. Exact matches,
	// no patterns.
	Certificates []string
	// Mode says what the agent receives: the certificate alone, or the
	// certificate with its private key.
	Mode DeliveryMode
}

// DeliveryMode is the choice from ADR-3.
type DeliveryMode string

const (
	// ModeIssue gives the agent a certificate of its own: it sends a CSR, its
	// private key never travels. The recommended mode.
	ModeIssue DeliveryMode = "issue"
	// ModeShare hands out a shared certificate together with its private key.
	// Simpler, weaker, and named so in the documentation.
	ModeShare DeliveryMode = "share"
)

// Valid reports whether m is a known mode.
func (m DeliveryMode) Valid() bool { return m == ModeIssue || m == ModeShare }

// State is what the broker learns about an agent while running: when it last
// collected something, and whether it has been shut out.
type State struct {
	// LastSeen is the last successful authenticated request.
	LastSeen time.Time `json:"last_seen,omitempty"`
	// LastDelivered maps certificate name to when it was last handed over.
	LastDelivered map[string]time.Time `json:"last_delivered,omitempty"`
	// IdentityExpires is when this agent's identity stops working.
	//
	// Kept here rather than derived on demand, because the broker has no way
	// to ask an agent for its certificate — it only learns this at the moment
	// it issues one. Without recording it, the warning that matters most
	// ("this host is about to lock itself out") cannot be given at all.
	IdentityExpires time.Time `json:"identity_expires,omitempty"`
	// RevokedAt, when set, shuts the agent out immediately.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// RevokedReason is shown to whoever asks why.
	RevokedReason string `json:"revoked_reason,omitempty"`
}

// Registry holds the configured agents and their running state.
//
// It is safe for concurrent use: the broker serves many agents at once, and
// every one of them both reads a permission and writes a timestamp.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]Agent
	state  map[string]*State
	store  StateStore
}

// StateStore persists the part that outlives a restart. Left nil, the registry
// still works — it simply forgets when agents were last seen.
type StateStore interface {
	Load() (map[string]*State, error)
	Save(map[string]*State) error
}

// New builds a registry from the configured agents.
func New(agents []Agent, store StateStore) (*Registry, error) {
	r := &Registry{
		agents: make(map[string]Agent, len(agents)),
		state:  make(map[string]*State, len(agents)),
		store:  store,
	}
	for _, a := range agents {
		if a.Name == "" {
			return nil, errors.New("an agent without a name")
		}
		if _, dup := r.agents[a.Name]; dup {
			return nil, fmt.Errorf("agent %q is configured twice", a.Name)
		}
		if !a.Mode.Valid() {
			return nil, fmt.Errorf("agent %q has mode %q, want %q or %q",
				a.Name, a.Mode, ModeIssue, ModeShare)
		}
		if len(a.Certificates) == 0 {
			return nil, fmt.Errorf("agent %q is permitted no certificates — then it has no reason to exist",
				a.Name)
		}
		a.Certificates = append([]string(nil), a.Certificates...)
		sort.Strings(a.Certificates)
		r.agents[a.Name] = a
	}

	if store != nil {
		loaded, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("load agent state: %w", err)
		}
		// State for an agent that is no longer configured is dropped, but a
		// revocation is kept: removing an agent from the file must not quietly
		// un-revoke it if it comes back under the same name.
		for name, st := range loaded {
			if _, known := r.agents[name]; known || st.RevokedAt != nil {
				r.state[name] = st
			}
		}
	}
	return r, nil
}

// Lookup returns the configured agent.
func (r *Registry) Lookup(name string) (Agent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[name]
	if !ok {
		return Agent{}, fmt.Errorf("%q: %w", name, ErrUnknownAgent)
	}
	return a, nil
}

// Authorise decides whether agentName may have certName.
//
// Revocation is checked before permission, so a withdrawn agent hears the same
// thing whatever it asks for — and the answer arrives without consulting its
// permissions at all.
func (r *Registry) Authorise(agentName, certName string) (Agent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if st, ok := r.state[agentName]; ok && st.RevokedAt != nil {
		return Agent{}, fmt.Errorf("%q: %w (%s)", agentName, ErrRevoked, st.RevokedReason)
	}
	a, ok := r.agents[agentName]
	if !ok {
		return Agent{}, fmt.Errorf("%q: %w", agentName, ErrUnknownAgent)
	}
	for _, permitted := range a.Certificates {
		if permitted == certName {
			return a, nil
		}
	}
	return Agent{}, fmt.Errorf("%q may not have %q: %w", agentName, certName, ErrNotPermitted)
}

// Revoked reports whether an agent is shut out.
func (r *Registry) Revoked(agentName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.state[agentName]
	return ok && st.RevokedAt != nil
}

// Revoke shuts an agent out. The effect is immediate, because every request
// consults this and nothing is cached per connection.
func (r *Registry) Revoke(agentName, reason string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[agentName]; !ok {
		// Revoking an unconfigured agent is allowed on purpose: the name may
		// have been removed from the file already while its identity is still
		// valid and out there.
		if _, seen := r.state[agentName]; !seen {
			r.state[agentName] = &State{}
		}
	}
	st := r.ensure(agentName)
	stamp := now.UTC()
	st.RevokedAt = &stamp
	st.RevokedReason = reason
	return r.persist()
}

// Restore lifts a revocation.
func (r *Registry) Restore(agentName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.state[agentName]
	if !ok || st.RevokedAt == nil {
		return nil
	}
	st.RevokedAt = nil
	st.RevokedReason = ""
	return r.persist()
}

// Enrolled records that an identity was issued, and when it runs out.
func (r *Registry) Enrolled(agentName string, expires, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.ensure(agentName)
	st.IdentityExpires = expires.UTC()
	st.LastSeen = now.UTC()
	return r.persist()
}

// Seen records a successful authenticated request.
func (r *Registry) Seen(agentName string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensure(agentName).LastSeen = now.UTC()
	return r.persist()
}

// Delivered records that a certificate was handed over.
func (r *Registry) Delivered(agentName, certName string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.ensure(agentName)
	if st.LastDelivered == nil {
		st.LastDelivered = make(map[string]time.Time)
	}
	st.LastDelivered[certName] = now.UTC()
	st.LastSeen = now.UTC()
	return r.persist()
}

// StateOf returns a copy of an agent's running state.
func (r *Registry) StateOf(agentName string) State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.state[agentName]
	if !ok {
		return State{}
	}
	out := *st
	if st.LastDelivered != nil {
		out.LastDelivered = make(map[string]time.Time, len(st.LastDelivered))
		for k, v := range st.LastDelivered {
			out.LastDelivered[k] = v
		}
	}
	return out
}

// Agents lists the configured agents, sorted.
func (r *Registry) Agents() []Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Agent, 0, len(r.agents))
	for _, a := range r.agents {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Silent lists agents that have not been seen since cutoff. An agent that was
// never seen counts as silent.
func (r *Registry) Silent(cutoff time.Time) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for name := range r.agents {
		st, ok := r.state[name]
		if !ok || st.LastSeen.IsZero() || st.LastSeen.Before(cutoff) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Concern is a reason to look at an agent, in the order that matters.
type Concern int

const (
	// ConcernNone means nothing to report.
	ConcernNone Concern = iota
	// ConcernNeverEnrolled means the agent is configured but has never
	// collected an identity. Usually a host that was set up and forgotten.
	ConcernNeverEnrolled
	// ConcernSilent means the agent has an identity but has not been heard
	// from for a while. It may be fine; it may be a timer that stopped.
	ConcernSilent
	// ConcernLockoutSoon means the identity runs out sooner than the agent is
	// likely to come back. This is the warning that has to arrive in time,
	// because after expiry there is no way back (ADR-7).
	ConcernLockoutSoon
	// ConcernLockedOut means the identity has expired. The host must be
	// enrolled again; nothing it does on its own will fix this.
	ConcernLockedOut
)

func (c Concern) String() string {
	switch c {
	case ConcernNeverEnrolled:
		return "never enrolled"
	case ConcernSilent:
		return "silent"
	case ConcernLockoutSoon:
		return "about to lock itself out"
	case ConcernLockedOut:
		return "locked out"
	default:
		return "ok"
	}
}

// Finding is one agent worth looking at.
type Finding struct {
	Agent   string
	Concern Concern
	Detail  string
}

// Review reports which agents need attention.
//
// The lockout warning is the point of this whole milestone. An agent renews
// its identity at two thirds of its life; if it has not been seen since well
// before that, it is not going to renew itself, and after expiry nobody can
// fix it remotely. The warning must therefore arrive while the identity is
// still valid — a report that says "locked out" is a report that came too late.
func (r *Registry) Review(now time.Time, silentAfter, warnBefore time.Duration) []Finding {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []Finding
	for name := range r.agents {
		st, ok := r.state[name]
		switch {
		case !ok || st.LastSeen.IsZero():
			out = append(out, Finding{name, ConcernNeverEnrolled,
				"configured but has never collected an identity"})
			continue
		case st.RevokedAt != nil:
			continue // revoked on purpose; not a concern
		}

		switch {
		case !st.IdentityExpires.IsZero() && !now.Before(st.IdentityExpires):
			out = append(out, Finding{name, ConcernLockedOut,
				fmt.Sprintf("identity expired %s — this host must be enrolled again",
					st.IdentityExpires.UTC().Format(time.RFC3339))})
		case !st.IdentityExpires.IsZero() && now.Add(warnBefore).After(st.IdentityExpires):
			out = append(out, Finding{name, ConcernLockoutSoon,
				fmt.Sprintf("identity expires %s and it was last seen %s",
					st.IdentityExpires.UTC().Format(time.RFC3339),
					st.LastSeen.UTC().Format(time.RFC3339))})
		case st.LastSeen.Before(now.Add(-silentAfter)):
			out = append(out, Finding{name, ConcernSilent,
				fmt.Sprintf("last seen %s", st.LastSeen.UTC().Format(time.RFC3339))})
		}
	}
	// Most urgent first, then by name: a report read from the top starts with
	// what cannot wait.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Concern != out[j].Concern {
			return out[i].Concern > out[j].Concern
		}
		return out[i].Agent < out[j].Agent
	})
	return out
}

// ensure must be called with the write lock held.
func (r *Registry) ensure(name string) *State {
	st, ok := r.state[name]
	if !ok {
		st = &State{}
		r.state[name] = st
	}
	return st
}

// persist must be called with the write lock held.
func (r *Registry) persist() error {
	if r.store == nil {
		return nil
	}
	return r.store.Save(r.state)
}

// NormaliseName lowercases an agent name for comparison. Agent names come out
// of certificates, and a case difference must not create a second identity.
func NormaliseName(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
