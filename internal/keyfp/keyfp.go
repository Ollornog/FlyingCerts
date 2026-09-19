// Package keyfp computes the fingerprint of a public key.
//
// Of a key, not of a certificate. A certificate has an expiry, a serial and a
// subject, all of which change when it is reissued; the key underneath does
// not. Fingerprinting the certificate would mean the value written in the
// broker's configuration goes stale every time the host mints a fresh one —
// which it does on every connection.
//
// The format follows OpenSSH (`SHA256:` and unpadded base64) because that is
// what people recognise, and what they will compare by eye against what the
// agent printed.
package keyfp

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Prefix marks the hash that follows.
const Prefix = "SHA256:"

// Of returns the fingerprint of a public key.
//
// The hash is over the SubjectPublicKeyInfo encoding — the same bytes a
// certificate carries — so the value is reproducible from a key file, from a
// certificate, or from the far end of a TLS handshake.
func Of(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("cannot fingerprint this key: %w", err)
	}
	sum := sha256.Sum256(der)
	return Prefix + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// Equal compares two fingerprints.
//
// Written out rather than using ==, because a value that came from a
// configuration file may have picked up whitespace, and because the prefix is
// optional when somebody types it. No constant-time comparison: a fingerprint
// is a public value, and the secret is the private key that nobody here has.
func Equal(a, b string) bool {
	return normalise(a) == normalise(b) && normalise(a) != ""
}

// Canonical returns the comparable form, for use as a map key.
func Canonical(s string) string { return normalise(s) }

func normalise(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, Prefix)
	// Padding is optional in what people paste, and tolerating it costs
	// nothing next to refusing a fingerprint that is correct.
	return strings.TrimRight(s, "=")
}

// Validate reports whether a configured fingerprint could ever match.
//
// Checked at load time rather than at the first connection: a typo here means
// a host that cannot get in, and finding that out during an outage is the
// worst possible moment.
func Validate(s string) error {
	body := normalise(s)
	if body == "" {
		return errors.New("empty fingerprint")
	}
	raw, err := base64.RawStdEncoding.DecodeString(body)
	if err != nil {
		return fmt.Errorf("%q is not a %s fingerprint: expected unpadded base64 after the prefix",
			s, Prefix)
	}
	if len(raw) != sha256.Size {
		return fmt.Errorf("%q decodes to %d bytes, a SHA-256 fingerprint is %d",
			s, len(raw), sha256.Size)
	}
	return nil
}
