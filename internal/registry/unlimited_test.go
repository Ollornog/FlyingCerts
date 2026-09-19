package registry

import (
	"strings"
	"testing"
	"time"

	"github.com/Ollornog/flying-certs/internal/lifetime"
)

func reviewOf(t *testing.T, agents []Agent, setup func(*Registry, time.Time), now time.Time) []Finding {
	t.Helper()
	r, err := New(agents, nil)
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(r, now)
	}
	return r.Review(now, 7*24*time.Hour, 5*24*time.Hour)
}

// An identity that does not expire is reported — and never fails the check.
// Both halves matter: silence would hide a standing credential, and failing
// would teach whoever reads `check` to stop reading it.
func TestUnlimitedIsReportedButNeedsNoAction(t *testing.T) {
	now := time.Now()
	findings := reviewOf(t,
		[]Agent{{Name: "gw", Certificates: []string{"cert"}, Mode: ModeIssue, IdentityLifetime: lifetime.Forever()}},
		func(r *Registry, now time.Time) {
			if err := r.Enrolled("gw", now.Add(9*365*24*time.Hour), now); err != nil {
				t.Fatal(err)
			}
		}, now)

	if len(findings) != 1 {
		t.Fatalf("findings = %v, want exactly one", findings)
	}
	if findings[0].Concern != ConcernUnlimited {
		t.Errorf("concern = %v, want ConcernUnlimited", findings[0].Concern)
	}
	if findings[0].Concern.NeedsAction() {
		t.Error("an unlimited identity is a configured choice, not something to act on")
	}
	// The detail has to name the only way back, or the reader is left with a
	// statement and no lever.
	if want := "revocation"; !strings.Contains(findings[0].Detail, want) {
		t.Errorf("detail %q does not mention %q", findings[0].Detail, want)
	}
}

// A real problem outranks the standing note. An unlimited agent that has gone
// silent is a silent agent first.
func TestARealProblemOutranksTheUnlimitedNote(t *testing.T) {
	now := time.Now()
	findings := reviewOf(t,
		[]Agent{{Name: "gw", Certificates: []string{"cert"}, Mode: ModeIssue, IdentityLifetime: lifetime.Forever()}},
		func(r *Registry, now time.Time) {
			if err := r.Enrolled("gw", now.Add(9*365*24*time.Hour), now.Add(-30*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
		}, now)

	if len(findings) != 1 || findings[0].Concern != ConcernSilent {
		t.Fatalf("findings = %v, want a single silent finding", findings)
	}
	if !findings[0].Concern.NeedsAction() {
		t.Error("a silent agent needs action")
	}
}

// An unlimited identity still runs until the CA does, so the lockout warning
// stays live for it. When the CA is running out, every unlimited agent is
// about to stop working at once — which is precisely when a warning is worth
// having.
func TestAnExpiringCAStillWarnsUnlimitedAgents(t *testing.T) {
	now := time.Now()
	findings := reviewOf(t,
		[]Agent{{Name: "gw", Certificates: []string{"cert"}, Mode: ModeIssue, IdentityLifetime: lifetime.Forever()}},
		func(r *Registry, now time.Time) {
			// The CA — and with it this identity — ends in two days.
			if err := r.Enrolled("gw", now.Add(2*24*time.Hour), now); err != nil {
				t.Fatal(err)
			}
		}, now)

	if len(findings) != 1 || findings[0].Concern != ConcernLockoutSoon {
		t.Fatalf("findings = %v, want a lockout warning", findings)
	}
}

// Ordering: the note sits at the bottom, under everything actionable.
func TestTheNoteSortsBelowEverythingActionable(t *testing.T) {
	now := time.Now()
	findings := reviewOf(t, []Agent{
		{Name: "forever", Certificates: []string{"cert"}, Mode: ModeIssue, IdentityLifetime: lifetime.Forever()},
		{Name: "quiet", Certificates: []string{"cert"}, Mode: ModeIssue},
		{Name: "fresh", Certificates: []string{"cert"}, Mode: ModeIssue},
	}, func(r *Registry, now time.Time) {
		if err := r.Enrolled("forever", now.Add(9*365*24*time.Hour), now); err != nil {
			t.Fatal(err)
		}
		if err := r.Enrolled("quiet", now.Add(300*24*time.Hour), now.Add(-30*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}, now)

	if len(findings) != 3 {
		t.Fatalf("findings = %v", findings)
	}
	if findings[len(findings)-1].Concern != ConcernUnlimited {
		t.Errorf("the standing note is not last: %v", findings)
	}
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Concern < findings[i].Concern {
			t.Errorf("findings are not ordered by urgency: %v", findings)
		}
	}
}

// Revoked wins over everything, including never having enrolled. An agent
// shut out on purpose is not a problem to report, whatever else is true.
func TestRevokedBeatsEveryOtherState(t *testing.T) {
	now := time.Now()
	findings := reviewOf(t,
		[]Agent{{Name: "gone", Certificates: []string{"cert"}, Mode: ModeIssue, IdentityLifetime: lifetime.Forever()}},
		func(r *Registry, now time.Time) {
			if err := r.Revoke("gone", "decommissioned", now); err != nil {
				t.Fatal(err)
			}
		}, now)
	if len(findings) != 0 {
		t.Errorf("a revoked agent was reported: %v", findings)
	}
}
