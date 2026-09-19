package enroll

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const caFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func issued(t *testing.T, store *Store, name string) (Token, *Record) {
	t.Helper()
	tok, rec, err := NewToken(name, []string{name + ".example.com"}, caFP, 0, time.Now())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := store.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return tok, rec
}

func TestRedeemOnce(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	tok, _ := issued(t, store, "gateway")

	id, secret, err := ParseToken(tok.String())
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	rec, err := store.Redeem(id, secret, caFP, "192.0.2.10", time.Now())
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if rec.AgentName != "gateway" {
		t.Errorf("AgentName = %q", rec.AgentName)
	}
	if !rec.Spent() {
		t.Error("the redeemed record is not marked as spent")
	}

	// The second attempt must fail, and must not say why in a way that
	// distinguishes "used" from "never existed".
	if _, err := store.Redeem(id, secret, caFP, "192.0.2.11", time.Now()); !errors.Is(err, ErrUnknownToken) {
		t.Errorf("second redemption: err = %v, want ErrUnknownToken", err)
	}
}

// The guarantee that matters: two callers at the same instant, exactly one
// wins. A read-check-write implementation passes every sequential test and
// fails this one.
func TestConcurrentRedemptionYieldsExactlyOneWinner(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	tok, _ := issued(t, store, "gateway")
	id, secret, _ := ParseToken(tok.String())

	const racers = 24
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
		others  []error
		start   = make(chan struct{})
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start // line them all up on the same instant
			_, err := store.Redeem(id, secret, caFP, fmt.Sprintf("caller-%d", n), time.Now())
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners++
			} else {
				others = append(others, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Fatalf("%d callers redeemed the same token, want exactly 1", winners)
	}
	for _, err := range others {
		if !errors.Is(err, ErrUnknownToken) {
			t.Errorf("a loser got an unexpected error: %v", err)
		}
	}
}

// Single use has to survive a restart. step-ca's default store keeps this in
// memory, so a restart makes every spent token usable again.
func TestSingleUseSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	tok, _ := issued(t, store, "gateway")
	id, secret, _ := ParseToken(tok.String())

	if _, err := store.Redeem(id, secret, caFP, "first", time.Now()); err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	// A brand-new Store over the same directory is the restart.
	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := reopened.Redeem(id, secret, caFP, "after restart", time.Now()); !errors.Is(err, ErrUnknownToken) {
		t.Errorf("after a restart the token was usable again: err = %v", err)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	past := time.Now().Add(-2 * time.Hour)
	tok, rec, err := NewToken("gateway", nil, caFP, time.Minute, past)
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := store.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	id, secret, _ := ParseToken(tok.String())

	_, err = store.Redeem(id, secret, caFP, "", time.Now())
	if !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	// The message must carry both moments, or nobody can tell a stale token
	// from a broken clock.
	if !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "now") {
		t.Errorf("the error does not show both times: %v", err)
	}
}

// A clock problem must announce itself as one. step-ca's equivalent says only
// that the token is invalid, and the cause stays hidden (their issue #2055).
func TestClockSkewHasItsOwnError(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	// The caller's clock runs an hour behind the broker's.
	future := time.Now().Add(time.Hour)
	tok, rec, _ := NewToken("gateway", nil, caFP, DefaultLifetime, future)
	if err := store.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	id, secret, _ := ParseToken(tok.String())

	_, err := store.Redeem(id, secret, caFP, "", time.Now())
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("err = %v, want ErrNotYetValid", err)
	}
	if !strings.Contains(err.Error(), "clocks") {
		t.Errorf("the error does not name the clocks as the cause: %v", err)
	}
}

// A minute of disagreement is tolerated, because clocks always disagree a
// little and failing on that would be useless strictness.
func TestSmallSkewIsTolerated(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	slightlyAhead := time.Now().Add(30 * time.Second)
	tok, rec, _ := NewToken("gateway", nil, caFP, DefaultLifetime, slightlyAhead)
	if err := store.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	id, secret, _ := ParseToken(tok.String())

	if _, err := store.Redeem(id, secret, caFP, "", time.Now()); err != nil {
		t.Errorf("30 seconds of skew was rejected: %v", err)
	}
}

// A token must not work against a different installation, even one that knows
// the same agent name.
func TestTokenIsBoundToItsBroker(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	tok, _ := issued(t, store, "gateway")
	id, secret, _ := ParseToken(tok.String())

	const otherCA = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err := func() error {
		_, err := store.Redeem(id, secret, otherCA, "", time.Now())
		return err
	}(); !errors.Is(err, ErrWrongCA) {
		t.Errorf("err = %v, want ErrWrongCA", err)
	}
}

func TestWrongSecretIsIndistinguishableFromUnknown(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	tok, _ := issued(t, store, "gateway")
	id, _, _ := ParseToken(tok.String())

	wrong := store.mustErr(t, id, "definitely-not-the-secret")
	absent := store.mustErr(t, "aaaabbbbccccdddd", "whatever")
	if wrong.Error() != absent.Error() {
		t.Errorf("a wrong secret (%v) is distinguishable from an unknown id (%v) — that is a probing aid",
			wrong, absent)
	}
}

func (s *Store) mustErr(t *testing.T, id, secret string) error {
	t.Helper()
	_, err := s.Redeem(id, secret, caFP, "", time.Now())
	if err == nil {
		t.Fatal("expected an error")
	}
	return err
}

// Secrets are stored hashed, so a stolen store yields nothing usable.
func TestStoredRecordHoldsNoUsableSecret(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	tok, rec := issued(t, store, "gateway")

	raw, err := os.ReadFile(filepath.Join(dir, "pending", rec.ID+".json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), tok.Secret) {
		t.Error("the secret is stored in the clear")
	}
	if !strings.Contains(string(raw), rec.SecretHash) {
		t.Error("the record does not hold the hash it should")
	}
}

func TestRecordFilesAreOwnerReadableOnly(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	store, _ := NewStore(dir)
	_, rec := issued(t, store, "gateway")

	info, err := os.Stat(filepath.Join(dir, "pending", rec.ID+".json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("record mode = %o, want 600", got)
	}
}

// Printing a token must not spill the secret into a debug log.
func TestTokenDoesNotRevealItselfInGoString(t *testing.T) {
	tok, _, _ := NewToken("gateway", nil, caFP, 0, time.Now())
	if strings.Contains(fmt.Sprintf("%#v", tok), tok.Secret) {
		t.Error("printing with the verbose verb revealed the secret")
	}
}

func TestParseTokenRejectsRubbish(t *testing.T) {
	for _, bad := range []string{"", "no-dot", ".secret", "id.", "   "} {
		if _, _, err := ParseToken(bad); err == nil {
			t.Errorf("ParseToken(%q) was accepted", bad)
		}
	}
}

// Ids become filenames; nothing may escape the directory.
func TestDangerousIDsAreRejected(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	for _, bad := range []string{"../escape", "sub/dir", "..", "a", strings.Repeat("x", 65)} {
		if _, err := store.Redeem(bad, "secret", caFP, "", time.Now()); !errors.Is(err, ErrUnknownToken) {
			t.Errorf("id %q: err = %v, want ErrUnknownToken", bad, err)
		}
	}
}

func TestPruneRemovesStaleRecords(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	long, recLong, _ := NewToken("keep", nil, caFP, 24*time.Hour, time.Now())
	_ = long
	if err := store.Put(recLong); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, recOld, _ := NewToken("drop", nil, caFP, time.Minute, time.Now().Add(-2*time.Hour))
	if err := store.Put(recOld); err != nil {
		t.Fatalf("Put: %v", err)
	}

	removed, err := store.Prune(time.Now())
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed %d records, want 1", removed)
	}
	if _, err := store.Get(recLong.ID); err != nil {
		t.Errorf("the still-valid token was pruned: %v", err)
	}
	if _, err := store.Get(recOld.ID); !errors.Is(err, ErrUnknownToken) {
		t.Error("the stale token survived pruning")
	}
}

func TestNewTokenRequiresNameAndBroker(t *testing.T) {
	if _, _, err := NewToken("", nil, caFP, 0, time.Now()); err == nil {
		t.Error("a token without an agent name was issued")
	}
	if _, _, err := NewToken("gateway", nil, "", 0, time.Now()); err == nil {
		t.Error("a token without a broker fingerprint was issued — it would work anywhere")
	}
}
