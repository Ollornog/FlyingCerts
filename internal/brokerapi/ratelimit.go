package brokerapi

import (
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Rate limiting, keyed on something the caller cannot choose.
//
// CertMate keyed its limiter on the SHA-256 of the presented bearer token —
// computed *before* the token was validated (#420). Every random string then
// opens its own bucket, so the limit never bites, and the bucket map itself
// becomes the thing under attack.
//
// The rule here: the key is either a verified identity, or the remote address.
// Never a value from the body, a header, or an unvalidated token. And the map
// is bounded, because an unbounded counter store is a memory leak with an
// attacker holding the tap.

// DefaultEnrolRate is how many enrolment attempts one address may make.
//
// Enrolment is rare — a handful per host, ever. Ten an hour is generous for
// the real case and unhelpful for guessing, especially against a 32-byte
// random secret.
const (
	DefaultEnrolRate   = 10
	DefaultEnrolWindow = time.Hour
)

// maxBuckets bounds the counter store. Past this, new keys are refused rather
// than admitted: an attacker who can create unlimited keys would otherwise
// decide how much memory the broker uses.
const maxBuckets = 4096

type bucket struct {
	count int
	first time.Time
}

// RateLimiter counts attempts per key inside a sliding window.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   int
	window  time.Duration
}

// NewRateLimiter builds a limiter. A limit of zero disables it, which is only
// sensible in tests.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if window <= 0 {
		window = DefaultEnrolWindow
	}
	return &RateLimiter{buckets: make(map[string]*bucket), limit: limit, window: window}
}

// Allow records an attempt and reports whether it is within the limit.
func (r *RateLimiter) Allow(key string, now time.Time) bool {
	if r.limit <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[key]
	if !ok {
		if len(r.buckets) >= maxBuckets {
			// Try to make room by dropping what has aged out. If the store is
			// still full afterwards, refuse — bounded memory beats serving a
			// caller who is very likely the reason it filled up.
			r.evictExpiredLocked(now)
			if len(r.buckets) >= maxBuckets {
				return false
			}
		}
		r.buckets[key] = &bucket{count: 1, first: now}
		return true
	}
	if now.Sub(b.first) > r.window {
		b.count, b.first = 1, now
		return true
	}
	b.count++
	return b.count <= r.limit
}

// evictExpiredLocked drops buckets whose window has passed.
func (r *RateLimiter) evictExpiredLocked(now time.Time) {
	for k, b := range r.buckets {
		if now.Sub(b.first) > r.window {
			delete(r.buckets, k)
		}
	}
}

// Prune drops aged-out buckets. Call it from a timer so the store shrinks in
// quiet periods too, not only under pressure.
func (r *RateLimiter) Prune(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	before := len(r.buckets)
	r.evictExpiredLocked(now)
	return before - len(r.buckets)
}

// Size reports how many keys are held, for tests and for a metric.
func (r *RateLimiter) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

// Keys lists the tracked keys, sorted. For tests.
func (r *RateLimiter) Keys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.buckets))
	for k := range r.buckets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// limiterKey derives the counting key for a request.
//
// The host part of the remote address, without the port: a caller gets a new
// port for every connection, so counting per port would count nothing.
func limiterKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
