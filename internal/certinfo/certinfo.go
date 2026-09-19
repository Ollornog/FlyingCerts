// Package certinfo inspects certificates: whether a certificate and key belong
// together, how much life a certificate has left, and when it should be renewed.
//
// One rule runs through all of it: remaining lifetime is a duration, never a
// number of whole days. Truncating to days is a real bug with a real victim —
// CertMate computed (expiry - now).days, which truncates, so every certificate
// with under 24 hours left was reported as already expired and its renewal
// scheduler treated it as permanently due. That bites exactly the short-lived
// certificates, and those are becoming the norm: Let's Encrypt offers six-day
// certificates and is shortening its regular lifetimes in steps.
//
// Days may be used to tell a human what is going on. They are never used to
// decide anything.
package certinfo

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// ErrNoCertificate reports PEM input that held no CERTIFICATE block.
var ErrNoCertificate = errors.New("no certificate found in PEM input")

// Pair is a certificate chain together with its private key, already checked
// for belonging together.
type Pair struct {
	// Leaf is the end-entity certificate: the first one in the chain.
	Leaf *x509.Certificate
	// Chain holds every certificate found, leaf first.
	Chain []*x509.Certificate
}

// LoadPair parses a certificate chain and a private key and verifies that they
// match.
//
// The matching check is not hand-written: tls.X509KeyPair already compares the
// public keys and reports "tls: private key does not match public key". Fewer
// lines, and fewer chances to get a security check subtly wrong.
func LoadPair(certPEM, keyPEM []byte) (*Pair, error) {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("certificate and key do not form a pair: %w", err)
	}
	chain, err := ParseChain(certPEM)
	if err != nil {
		return nil, err
	}
	return &Pair{Leaf: chain[0], Chain: chain}, nil
}

// ParseChain decodes every CERTIFICATE block in certPEM, leaf first.
func ParseChain(certPEM []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, ErrNoCertificate
	}
	return chain, nil
}

// RemainingAt reports how much validity is left at the given moment.
//
// The result is negative once the certificate has expired, which lets callers
// distinguish "just expired" from "expired last month" instead of collapsing
// both into a boolean.
func RemainingAt(cert *x509.Certificate, now time.Time) time.Duration {
	return cert.NotAfter.Sub(now)
}

// ExpiredAt reports whether the certificate is no longer valid at that moment.
func ExpiredAt(cert *x509.Certificate, now time.Time) bool {
	return !now.Before(cert.NotAfter)
}

// Lifetime is the full span the certificate was issued for.
func Lifetime(cert *x509.Certificate) time.Duration {
	return cert.NotAfter.Sub(cert.NotBefore)
}

// DefaultRenewalFraction is how much of the lifetime elapses before renewal is
// due, when the CA offers no advice of its own.
//
// Two thirds is what step-ca uses, and it holds up across wildly different
// lifetimes: six days leaves two days of slack, ninety days leaves thirty.
// A fixed "renew 30 days before expiry" would be nonsense for a six-day
// certificate — it would be due before it was issued.
const DefaultRenewalFraction = 2.0 / 3.0

// RenewAfter reports the moment renewal becomes due, as a fraction of the
// certificate's lifetime. It is the fallback for CAs that do not support ARI;
// where ARI is available, the CA's own window wins.
func RenewAfter(cert *x509.Certificate, fraction float64) time.Time {
	elapsed := time.Duration(float64(Lifetime(cert)) * fraction)
	return cert.NotBefore.Add(elapsed)
}

// NeedsRenewalAt reports whether renewal is due at the given moment.
//
// An already expired certificate also needs renewal — the caller decides what
// that means. For the broker's own certificates it means "fetch a new one"; for
// an agent's client certificate it means "this host has locked itself out and
// must be enrolled again", which is a different situation entirely.
func NeedsRenewalAt(cert *x509.Certificate, now time.Time, fraction float64) bool {
	return !now.Before(RenewAfter(cert, fraction))
}

// DescribeRemaining renders a remaining lifetime for humans.
//
// This is the only place where days appear, and it is deliberately separate
// from every function that decides something.
func DescribeRemaining(d time.Duration) string {
	switch {
	case d < 0:
		return fmt.Sprintf("expired %s ago", roughly(-d))
	case d < time.Minute:
		return "less than a minute left"
	default:
		return roughly(d) + " left"
	}
}

func roughly(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%.0f hours", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	default:
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	}
}
