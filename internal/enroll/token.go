// Package enroll issues and redeems bootstrap tokens — the one-time credential
// that turns a nameless host into an agent with its own identity.
//
// The token is opaque: a long random string, with everything that matters kept
// on the broker. No self-describing, signed blob. That is a deliberate choice
// over the JWT-shaped alternative, for two reasons:
//
//   - The broker needs a durable record anyway, to stop a token being redeemed
//     twice. Once that record exists, putting the same facts inside the token
//     as well only adds a second place they can disagree.
//   - A signed blob invites the classic mistakes — accepting "alg: none",
//     confusing signing with encryption, leaking claims to anyone who can read
//     the string. An opaque random value has none of those failure modes.
//
// What the token is bound to, and why that list is shorter than step-ca's, is
// argued in ADR-6.
package enroll

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultLifetime is how long a freshly issued token can be redeemed.
//
// Five minutes, the value step-ca settled on. Long enough to paste a token into
// a terminal, short enough that one left in a chat log is usually worthless by
// the time anyone finds it.
const DefaultLifetime = 5 * time.Minute

// ClockSkew is how far the broker's and the caller's clocks may disagree.
//
// One minute, as go-jose uses for JWT validation. Clock problems must produce
// their own error: step-ca has an open issue about exactly this (#2055), where
// the only remedy is a blunt on/off switch and the message never says that the
// clocks are the problem.
const ClockSkew = time.Minute

// tokenBytes is the entropy of the secret half. 32 bytes is far past guessing.
const tokenBytes = 32

var (
	// ErrUnknownToken covers both "never existed" and "already used", on
	// purpose: telling them apart would let someone probe which tokens once
	// existed.
	ErrUnknownToken = errors.New("unknown or already redeemed token")
	// ErrExpired reports a token past its window.
	ErrExpired = errors.New("token has expired")
	// ErrNotYetValid reports a token from the future, which in practice means
	// the clocks disagree.
	ErrNotYetValid = errors.New("token is not valid yet — the clocks of broker and caller disagree")
	// ErrWrongCA reports a token issued by a different broker.
	ErrWrongCA = errors.New("token was issued for a different broker")
)

// Token is what an operator hands to a host.
type Token struct {
	// ID identifies the record. It travels in the clear, inside the token.
	ID string
	// Secret is the part that must not leak.
	Secret string
	// AgentName is the identity this token will hand out.
	AgentName string
	// CAFingerprint pins the token to one broker.
	CAFingerprint string
	// NotBefore and NotAfter bound the redemption window.
	NotBefore time.Time
	NotAfter  time.Time
}

// String renders the token in the form a human copies: "id.secret".
//
// The separator is a dot so the whole thing survives being pasted anywhere,
// and so the id can be read off without knowing the secret — the broker needs
// the id to find the record before it can compare the secret.
func (t Token) String() string { return t.ID + "." + t.Secret }

// GoString keeps a token out of %#v output, which is where secrets like to
// appear in debug logs.
func (t Token) GoString() string { return fmt.Sprintf("enroll.Token{AgentName:%q, ...}", t.AgentName) }

// Record is what the broker keeps about an issued token.
//
// The secret is stored hashed. A stolen store then yields no usable tokens —
// and because the secret is 32 random bytes, a plain SHA-256 is enough: there
// is no dictionary to run against it, which is the only thing a slow hash buys.
type Record struct {
	ID            string    `json:"id"`
	SecretHash    string    `json:"secret_hash"`
	AgentName     string    `json:"agent_name"`
	Domains       []string  `json:"domains"`
	CAFingerprint string    `json:"ca_fingerprint"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	IssuedAt      time.Time `json:"issued_at"`

	// RedeemedAt marks a spent token. The record is kept rather than deleted,
	// so "already used" stays distinguishable from "never existed" in the
	// audit trail — even though the caller is told the same thing either way.
	RedeemedAt *time.Time `json:"redeemed_at,omitempty"`
	// RedeemedBy notes where the redemption came from.
	RedeemedBy string `json:"redeemed_by,omitempty"`
}

// Spent reports whether this record has already been used.
func (r *Record) Spent() bool { return r.RedeemedAt != nil }

// NewToken mints a token and the record to go with it.
func NewToken(agentName string, domains []string, caFingerprint string, lifetime time.Duration, now time.Time) (Token, *Record, error) {
	if agentName == "" {
		return Token{}, nil, errors.New("no agent name")
	}
	if caFingerprint == "" {
		return Token{}, nil, errors.New("no CA fingerprint — a token must name the broker it belongs to")
	}
	if lifetime <= 0 {
		lifetime = DefaultLifetime
	}

	id, err := randomString(9)
	if err != nil {
		return Token{}, nil, err
	}
	secret, err := randomString(tokenBytes)
	if err != nil {
		return Token{}, nil, err
	}

	tok := Token{
		ID:            id,
		Secret:        secret,
		AgentName:     agentName,
		CAFingerprint: caFingerprint,
		NotBefore:     now.Add(-ClockSkew),
		NotAfter:      now.Add(lifetime),
	}
	rec := &Record{
		ID:            id,
		SecretHash:    hashSecret(secret),
		AgentName:     agentName,
		Domains:       append([]string(nil), domains...),
		CAFingerprint: caFingerprint,
		NotBefore:     tok.NotBefore,
		NotAfter:      tok.NotAfter,
		IssuedAt:      now,
	}
	return tok, rec, nil
}

// ParseToken splits the "id.secret" form.
func ParseToken(s string) (id, secret string, err error) {
	s = strings.TrimSpace(s)
	id, secret, found := strings.Cut(s, ".")
	if !found || id == "" || secret == "" {
		return "", "", errors.New("token is malformed (expected id.secret)")
	}
	return id, secret, nil
}

// Verify checks a presented secret against a record at a given moment.
//
// It does not mark the token as used — that has to happen atomically in the
// store, or two simultaneous redemptions both succeed.
func Verify(rec *Record, secret, caFingerprint string, now time.Time) error {
	if rec == nil {
		return ErrUnknownToken
	}
	if rec.Spent() {
		return ErrUnknownToken
	}
	// Constant time: a byte-by-byte comparison leaks how much of the secret
	// was right, which over enough attempts is a guessing aid.
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(rec.SecretHash)) != 1 {
		return ErrUnknownToken
	}
	// The CA check comes before the clock check so "wrong broker" is never
	// reported as "expired", which would send the reader down the wrong path.
	if caFingerprint != "" && rec.CAFingerprint != caFingerprint {
		return ErrWrongCA
	}
	if now.Before(rec.NotBefore) {
		return fmt.Errorf("%w (valid from %s, now %s)",
			ErrNotYetValid, rec.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if now.After(rec.NotAfter) {
		return fmt.Errorf("%w (expired %s, now %s)",
			ErrExpired, rec.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	// RawURLEncoding: no padding, no characters that need quoting in a shell,
	// a URL or a YAML file.
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
