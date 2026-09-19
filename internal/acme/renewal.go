package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/Ollornog/flying-certs/internal/certinfo"
	legoapi "github.com/go-acme/lego/v5/acme/api"
)

// RenewalDecision says whether a certificate should be renewed now, and why.
//
// The reason is carried along because "why did it renew at 3am" is a question
// operators actually ask, and reconstructing it afterwards from timestamps is
// guesswork.
type RenewalDecision struct {
	// Due is true when renewal should be attempted now.
	Due bool
	// Reason is a short human-readable explanation.
	Reason string
	// Source records who decided: the CA (via ARI) or our own fallback.
	Source RenewalSource
	// NextCheck is when to look again, when renewal is not yet due.
	NextCheck time.Time
}

// RenewalSource distinguishes the CA's advice from our own arithmetic.
type RenewalSource string

const (
	// SourceARI means the CA told us when, per RFC 9773.
	SourceARI RenewalSource = "ari"
	// SourceLifetimeFraction means we fell back to a fraction of the lifetime.
	SourceLifetimeFraction RenewalSource = "lifetime-fraction"
	// SourceExpired means the certificate is already past its end.
	SourceExpired RenewalSource = "expired"
)

// RenewalInfoFetcher is the slice of lego we need, kept small so the decision
// logic can be tested without a CA — and exported so callers can hand in the
// real thing.
type RenewalInfoFetcher interface {
	ShouldRenewAt(now time.Time, willingToSleep time.Duration) *time.Time
}

// DecideRenewal works out whether cert should be renewed at the given moment.
//
// ARI first, arithmetic second. Where the CA offers renewal information it
// knows things we cannot: an early revocation, a shortened lifetime, load
// spreading. lego's ShouldRenewAt already picks a uniformly random point inside
// the suggested window, so the protection against a whole fleet knocking at
// once comes for free.
//
// Where ARI is unavailable, a fraction of the lifetime is used instead. Never a
// fixed number of days — that would be nonsense for a six-day certificate, and
// those are becoming normal.
func DecideRenewal(ctx context.Context, fetch func(context.Context) (RenewalInfoFetcher, error),
	cert *x509.Certificate, now time.Time, willingToSleep time.Duration) RenewalDecision {

	// An expired certificate needs no advice from anyone.
	if certinfo.ExpiredAt(cert, now) {
		return RenewalDecision{
			Due:    true,
			Reason: fmt.Sprintf("certificate %s", certinfo.DescribeRemaining(certinfo.RemainingAt(cert, now))),
			Source: SourceExpired,
		}
	}

	if fetch != nil {
		info, err := fetch(ctx)
		switch {
		case err == nil && info != nil:
			at := info.ShouldRenewAt(now, willingToSleep)
			if at != nil {
				return RenewalDecision{
					Due:    true,
					Reason: "the CA's renewal window has been reached",
					Source: SourceARI,
				}
			}
			return RenewalDecision{
				Due:       false,
				Reason:    "the CA's renewal window lies ahead",
				Source:    SourceARI,
				NextCheck: now.Add(willingToSleep),
			}
		case errors.Is(err, legoapi.ErrNoARI):
			// Expected for CAs that do not implement RFC 9773. Fall through to
			// the fraction below without making noise about it.
		case err != nil:
			// A real failure: do not let it block renewal, but do not pretend
			// the CA said anything either.
		}
	}

	due := certinfo.RenewAfter(cert, certinfo.DefaultRenewalFraction)
	if !now.Before(due) {
		return RenewalDecision{
			Due: true,
			Reason: fmt.Sprintf("%.0f%% of the lifetime has elapsed (%s)",
				certinfo.DefaultRenewalFraction*100,
				certinfo.DescribeRemaining(certinfo.RemainingAt(cert, now))),
			Source: SourceLifetimeFraction,
		}
	}
	return RenewalDecision{
		Due:       false,
		Reason:    fmt.Sprintf("renewal due at %s", due.UTC().Format(time.RFC3339)),
		Source:    SourceLifetimeFraction,
		NextCheck: due,
	}
}
