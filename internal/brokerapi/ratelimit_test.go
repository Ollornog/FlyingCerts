package brokerapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterCountsWithinAWindow(t *testing.T) {
	rl := NewRateLimiter(3, time.Hour)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !rl.Allow("198.51.100.1", now) {
			t.Fatalf("attempt %d was refused inside the limit", i+1)
		}
	}
	if rl.Allow("198.51.100.1", now) {
		t.Error("the fourth attempt was allowed")
	}
	// A different caller is unaffected.
	if !rl.Allow("198.51.100.2", now) {
		t.Error("a different address was caught by another's limit")
	}
	// And the window eventually reopens.
	if !rl.Allow("198.51.100.1", now.Add(2*time.Hour)) {
		t.Error("the window never reopened")
	}
}

// The failure CertMate shipped (#420): keying on attacker-chosen input means
// every attempt opens a fresh bucket and the limit never applies — while the
// bucket store grows without bound.
func TestLimiterStoreCannotBeGrownWithoutBound(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour)
	now := time.Now()
	for i := 0; i < maxBuckets*2; i++ {
		rl.Allow(fmt.Sprintf("attacker-key-%d", i), now)
	}
	if got := rl.Size(); got > maxBuckets {
		t.Errorf("the store holds %d keys, want at most %d", got, maxBuckets)
	}
}

func TestPruneDropsAgedBuckets(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	now := time.Now()
	rl.Allow("a", now)
	rl.Allow("b", now)

	if dropped := rl.Prune(now); dropped != 0 {
		t.Errorf("pruned %d fresh buckets", dropped)
	}
	if dropped := rl.Prune(now.Add(2 * time.Minute)); dropped != 2 {
		t.Errorf("pruned %d, want 2", dropped)
	}
	if rl.Size() != 0 {
		t.Errorf("%d buckets survived pruning", rl.Size())
	}
}

// The end-to-end shape: repeated enrolment attempts from one address are cut
// off, and the key is the address rather than anything from the request.
func TestEnrolIsRateLimitedPerAddress(t *testing.T) {
	h := setup(t)
	csrPEM, _ := newCSR(t)

	attempt := func(addr, token string) int {
		body, _ := json.Marshal(enrolRequest{Token: token, CSR: csrPEM})
		req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(w, req)
		return w.Code
	}

	// Every attempt carries a different token, which is exactly the case that
	// defeated CertMate's limiter.
	var limited bool
	for i := 0; i < DefaultEnrolRate+3; i++ {
		code := attempt("203.0.113.5:40000", fmt.Sprintf("aaaabbbb.token-number-%d", i))
		if code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("a caller could try unlimited tokens from one address")
	}

	// Another address is not affected by the first one's limit.
	if code := attempt("203.0.113.6:40000", "aaaabbbb.some-other-token"); code == http.StatusTooManyRequests {
		t.Error("a different address inherited the limit")
	}

	// The port must not create a new bucket — a caller gets a fresh one per
	// connection, so counting per port would count nothing.
	if code := attempt("203.0.113.5:55555", "aaaabbbb.yet-another-token"); code != http.StatusTooManyRequests {
		t.Errorf("a new source port escaped the limit (code %d)", code)
	}
}

func TestRateLimitAnswerTellsTheCallerToWait(t *testing.T) {
	h := setup(t)
	csrPEM, _ := newCSR(t)
	body, _ := json.Marshal(enrolRequest{Token: "aaaabbbb.cccc", CSR: csrPEM})

	var last *httptest.ResponseRecorder
	for i := 0; i < DefaultEnrolRate+2; i++ {
		req := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.9:40000"
		last = httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(last, req)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After — the caller cannot know when to come back")
	}
}
