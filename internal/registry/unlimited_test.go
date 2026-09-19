package registry

import (
	"strings"
	"testing"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/lifetime"
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

// A short lifetime must not mean a permanent warning.
//
// This is the bug v0.1.0 shipped with: the threshold was a fixed five days,
// so an agent on a one-day identity was "about to lock itself out" from the
// second it enrolled. `check` was red for the recommended configuration, and
// a check that is always red is one nobody reads.
func TestAShortLifetimeIsNotAPermanentWarning(t *testing.T) {
	now := time.Now()
	findings := reviewOf(t,
		[]Agent{{Name: "nightly", Certificates: []string{"cert"}, Mode: ModeIssue,
			IdentityLifetime: lifetime.Of(24 * time.Hour)}},
		func(r *Registry, now time.Time) {
			// Just enrolled: a full day left.
			if err := r.Enrolled("nightly", now.Add(24*time.Hour), now); err != nil {
				t.Fatal(err)
			}
		}, now)
	if len(findings) != 0 {
		t.Errorf("a freshly enrolled agent was reported: %v", findings)
	}
}

// The warning still arrives for a short lifetime — later, in proportion. The
// agent renews at two thirds, so past that point it has missed its renewal.
func TestTheWarningStillArrivesForAShortLifetime(t *testing.T) {
	now := time.Now()
	findings := reviewOf(t,
		[]Agent{{Name: "nightly", Certificates: []string{"cert"}, Mode: ModeIssue,
			IdentityLifetime: lifetime.Of(24 * time.Hour)}},
		func(r *Registry, now time.Time) {
			// Four hours left of a day: past two thirds, so it should have
			// renewed by now and did not.
			if err := r.Enrolled("nightly", now.Add(4*time.Hour), now.Add(-20*time.Hour)); err != nil {
				t.Fatal(err)
			}
		}, now)
	if len(findings) != 1 || findings[0].Concern != ConcernLockoutSoon {
		t.Errorf("findings = %v, want a lockout warning", findings)
	}
}

// A host with a device key cannot lock itself out, so it is not warned about
// — it asks for a new identity on its next run (ADR-18).
func TestAHostWithADeviceKeyIsNotWarnedAboutExpiry(t *testing.T) {
	now := time.Now()
	agents := []Agent{{Name: "gw", Certificates: []string{"cert"}, Mode: ModeIssue,
		PublicKey:        "SHA256:3zCYV58KfoUQglgefqPRMl1I+EvvbaaGpYAUuLjK8Y4",
		IdentityLifetime: lifetime.Of(24 * time.Hour)}}

	// Expired outright, and seen recently enough not to count as silent.
	findings := reviewOf(t, agents, func(r *Registry, now time.Time) {
		if err := r.Enrolled("gw", now.Add(-time.Hour), now.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}, now)
	if len(findings) != 0 {
		t.Errorf("a recoverable host was reported as a problem: %v", findings)
	}

	// But if it also stopped checking in, that IS worth reporting — the
	// device key only helps a host that still runs its timer.
	findings = reviewOf(t, agents, func(r *Registry, now time.Time) {
		if err := r.Enrolled("gw", now.Add(-20*24*time.Hour), now.Add(-21*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}, now)
	if len(findings) != 1 || findings[0].Concern != ConcernSilent {
		t.Errorf("findings = %v, want a silent finding", findings)
	}
}

// Without a device key the old behaviour stands: expiry is a dead end and is
// reported as one.
func TestWithoutADeviceKeyExpiryIsStillReported(t *testing.T) {
	now := time.Now()
	findings := reviewOf(t,
		[]Agent{{Name: "gw", Certificates: []string{"cert"}, Mode: ModeIssue,
			IdentityLifetime: lifetime.Of(30 * 24 * time.Hour)}},
		func(r *Registry, now time.Time) {
			if err := r.Enrolled("gw", now.Add(-time.Hour), now.Add(-2*time.Hour)); err != nil {
				t.Fatal(err)
			}
		}, now)
	if len(findings) != 1 || findings[0].Concern != ConcernLockedOut {
		t.Errorf("findings = %v, want locked out", findings)
	}
}

// The configured threshold stays the ceiling: a long lifetime does not get a
// wider warning window than the operator asked for.
func TestTheConfiguredThresholdIsTheCeiling(t *testing.T) {
	cases := []struct {
		span lifetime.Span
		want time.Duration
	}{
		{lifetime.Of(24 * time.Hour), 8 * time.Hour},           // a third
		{lifetime.Of(30 * 24 * time.Hour), 5 * 24 * time.Hour}, // the ceiling
		{lifetime.Forever(), 5 * 24 * time.Hour},               // nothing to scale
		{lifetime.Span{}, 5 * 24 * time.Hour},                  // unknown
	}
	for _, c := range cases {
		if got := effectiveWarnBefore(5*24*time.Hour, c.span); got != c.want {
			t.Errorf("effectiveWarnBefore(5d, %v) = %v, want %v", c.span, got, c.want)
		}
	}
}
