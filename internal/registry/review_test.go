package registry

import (
	"testing"
	"time"
)

func reviewFleet(t *testing.T) *Registry {
	t.Helper()
	r, err := New([]Agent{
		{Name: "healthy", Certificates: []string{"c"}, Mode: ModeIssue},
		{Name: "quiet", Certificates: []string{"c"}, Mode: ModeIssue},
		{Name: "expiring", Certificates: []string{"c"}, Mode: ModeIssue},
		{Name: "gone", Certificates: []string{"c"}, Mode: ModeIssue},
		{Name: "fresh-install", Certificates: []string{"c"}, Mode: ModeIssue},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func concernOf(findings []Finding, agent string) Concern {
	for _, f := range findings {
		if f.Agent == agent {
			return f.Concern
		}
	}
	return ConcernNone
}

func TestReviewSeparatesTheFourSituations(t *testing.T) {
	r := reviewFleet(t)
	now := time.Now()

	// Seen an hour ago, identity good for another three weeks.
	mustEnrol(t, r, "healthy", now.Add(21*24*time.Hour), now.Add(-time.Hour))
	// Not heard from in two weeks, identity still good for two.
	mustEnrol(t, r, "quiet", now.Add(14*24*time.Hour), now.Add(-14*24*time.Hour))
	// Identity runs out in two days and it has not been back for a month.
	mustEnrol(t, r, "expiring", now.Add(2*24*time.Hour), now.Add(-30*24*time.Hour))
	// Already over.
	mustEnrol(t, r, "gone", now.Add(-time.Hour), now.Add(-40*24*time.Hour))
	// "fresh-install" was never enrolled at all.

	findings := r.Review(now, 7*24*time.Hour, 5*24*time.Hour)

	want := map[string]Concern{
		"healthy":       ConcernNone,
		"quiet":         ConcernSilent,
		"expiring":      ConcernLockoutSoon,
		"gone":          ConcernLockedOut,
		"fresh-install": ConcernNeverEnrolled,
	}
	for agent, expected := range want {
		if got := concernOf(findings, agent); got != expected {
			t.Errorf("%s: concern = %v, want %v", agent, got, expected)
		}
	}
}

// The warning has to arrive while the identity still works. A report that
// only says "locked out" came too late to be useful (ADR-7).
func TestLockoutIsWarnedBeforeItHappens(t *testing.T) {
	r := reviewFleet(t)
	now := time.Now()
	expires := now.Add(3 * 24 * time.Hour)
	mustEnrol(t, r, "expiring", expires, now.Add(-20*24*time.Hour))

	findings := r.Review(now, 7*24*time.Hour, 5*24*time.Hour)
	if got := concernOf(findings, "expiring"); got != ConcernLockoutSoon {
		t.Fatalf("concern = %v, want a warning before the lockout", got)
	}
	// And the identity must still be valid at the moment of warning —
	// otherwise the warning is a post-mortem.
	if !now.Before(expires) {
		t.Fatal("test setup wrong")
	}
	for _, f := range findings {
		if f.Agent == "expiring" && f.Detail == "" {
			t.Error("the warning carries no detail to act on")
		}
	}
}

// The most urgent entry has to be first: a report read from the top should
// start with what cannot wait.
func TestFindingsAreOrderedByUrgency(t *testing.T) {
	r := reviewFleet(t)
	now := time.Now()
	mustEnrol(t, r, "quiet", now.Add(20*24*time.Hour), now.Add(-14*24*time.Hour))
	mustEnrol(t, r, "gone", now.Add(-time.Hour), now.Add(-40*24*time.Hour))
	mustEnrol(t, r, "expiring", now.Add(2*24*time.Hour), now.Add(-30*24*time.Hour))
	mustEnrol(t, r, "healthy", now.Add(20*24*time.Hour), now.Add(-time.Hour))

	findings := r.Review(now, 7*24*time.Hour, 5*24*time.Hour)
	if len(findings) < 3 {
		t.Fatalf("got %d findings, want at least 3", len(findings))
	}
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Concern < findings[i].Concern {
			t.Errorf("finding %d (%v) is less urgent than the one after it (%v)",
				i-1, findings[i-1].Concern, findings[i].Concern)
		}
	}
	if findings[0].Agent != "gone" {
		t.Errorf("the report starts with %q, want the locked-out agent", findings[0].Agent)
	}
}

// A revoked agent is not a concern: it is shut out on purpose, and listing it
// would bury the ones that need attention.
func TestRevokedAgentIsNotReportedAsAProblem(t *testing.T) {
	r := reviewFleet(t)
	now := time.Now()
	mustEnrol(t, r, "gone", now.Add(-time.Hour), now.Add(-40*24*time.Hour))
	if err := r.Revoke("gone", "decommissioned", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if got := concernOf(r.Review(now, 7*24*time.Hour, 5*24*time.Hour), "gone"); got != ConcernNone {
		t.Errorf("a deliberately revoked agent is reported as %v", got)
	}
}

func TestEnrolledIsRemembered(t *testing.T) {
	r := reviewFleet(t)
	now := time.Now()
	expires := now.Add(30 * 24 * time.Hour)
	mustEnrol(t, r, "healthy", expires, now)

	st := r.StateOf("healthy")
	if !st.IdentityExpires.Equal(expires.UTC()) {
		t.Errorf("IdentityExpires = %v, want %v", st.IdentityExpires, expires.UTC())
	}
	if st.LastSeen.IsZero() {
		t.Error("enrolling did not count as being seen")
	}
}

func mustEnrol(t *testing.T, r *Registry, name string, expires, seen time.Time) {
	t.Helper()
	if err := r.Enrolled(name, expires, seen); err != nil {
		t.Fatalf("Enrolled(%s): %v", name, err)
	}
}
