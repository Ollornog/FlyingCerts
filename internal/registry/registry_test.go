package registry

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fleet() []Agent {
	return []Agent{
		{Name: "gateway", Certificates: []string{"gateway-cert"}, Mode: ModeIssue},
		{Name: "storage", Certificates: []string{"storage-cert", "shared-wildcard"}, Mode: ModeShare},
	}
}

func TestAuthorisePermitsOnlyWhatIsListed(t *testing.T) {
	r, err := New(fleet(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := r.Authorise("gateway", "gateway-cert"); err != nil {
		t.Errorf("an agent was refused its own certificate: %v", err)
	}
	// The whole point of this package: no inference, no near-misses.
	for _, other := range []string{"storage-cert", "shared-wildcard", "gateway-cert-2", "GATEWAY-CERT", ""} {
		if _, err := r.Authorise("gateway", other); !errors.Is(err, ErrNotPermitted) {
			t.Errorf("gateway got %q: err = %v, want ErrNotPermitted", other, err)
		}
	}
}

func TestUnknownAgentIsRefused(t *testing.T) {
	r, _ := New(fleet(), nil)
	if _, err := r.Authorise("stranger", "gateway-cert"); !errors.Is(err, ErrUnknownAgent) {
		t.Errorf("err = %v, want ErrUnknownAgent", err)
	}
}

// Revocation must take effect on the next request, not on the next restart.
func TestRevocationIsImmediateAndBeatsPermission(t *testing.T) {
	r, _ := New(fleet(), nil)
	if _, err := r.Authorise("gateway", "gateway-cert"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := r.Revoke("gateway", "key suspected leaked", time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err := r.Authorise("gateway", "gateway-cert")
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("err = %v, want ErrRevoked — revocation must outrank permission", err)
	}
	if !r.Revoked("gateway") {
		t.Error("Revoked() disagrees with Authorise()")
	}
	if err := r.Restore("gateway"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := r.Authorise("gateway", "gateway-cert"); err != nil {
		t.Errorf("after Restore the agent is still shut out: %v", err)
	}
}

// A revocation must survive a restart, and must survive the agent being taken
// out of the configuration — otherwise removing a line from a file quietly
// un-revokes a certificate that is still out there.
func TestRevocationSurvivesRestartAndDeconfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agents.json")
	store := NewFileState(path)

	r, err := New(fleet(), store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Revoke("gateway", "stolen laptop", time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Restart with gateway removed from the configuration entirely.
	reduced := []Agent{{Name: "storage", Certificates: []string{"storage-cert"}, Mode: ModeShare}}
	r2, err := New(reduced, store)
	if err != nil {
		t.Fatalf("New after restart: %v", err)
	}
	if !r2.Revoked("gateway") {
		t.Error("the revocation vanished when the agent left the configuration")
	}
}

func TestSeenAndDeliveredAreRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agents.json")
	r, err := New(fleet(), NewFileState(path))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	if err := r.Delivered("gateway", "gateway-cert", now); err != nil {
		t.Fatalf("Delivered: %v", err)
	}

	st := r.StateOf("gateway")
	if st.LastSeen.IsZero() {
		t.Error("a delivery did not count as being seen")
	}
	if got, ok := st.LastDelivered["gateway-cert"]; !ok || got.IsZero() {
		t.Error("the delivery was not recorded")
	}

	// And it must be on disk, not only in memory.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(raw) == 0 {
		t.Error("the state file is empty")
	}
}

// StateOf must hand out a copy: a caller that mutates what it gets back must
// not silently rewrite the registry.
func TestStateOfReturnsACopy(t *testing.T) {
	r, _ := New(fleet(), nil)
	if err := r.Delivered("gateway", "gateway-cert", time.Now()); err != nil {
		t.Fatalf("Delivered: %v", err)
	}
	st := r.StateOf("gateway")
	st.LastDelivered["gateway-cert"] = time.Unix(0, 0)
	st.RevokedReason = "tampered"

	fresh := r.StateOf("gateway")
	if fresh.LastDelivered["gateway-cert"].Equal(time.Unix(0, 0)) {
		t.Error("mutating the returned state changed the registry")
	}
	if fresh.RevokedReason == "tampered" {
		t.Error("mutating the returned state changed the registry")
	}
}

// Silence is how the broker warns before an agent locks itself out (ADR-7).
func TestSilentListsAgentsThatHaveNotBeenSeen(t *testing.T) {
	r, _ := New(fleet(), nil)
	now := time.Now()
	if err := r.Seen("gateway", now); err != nil {
		t.Fatalf("Seen: %v", err)
	}

	silent := r.Silent(now.Add(-time.Hour))
	if len(silent) != 1 || silent[0] != "storage" {
		t.Errorf("Silent = %v, want [storage] — never seen counts as silent", silent)
	}
	// Move the cutoff past the recent sighting and both fall silent.
	if got := r.Silent(now.Add(time.Hour)); len(got) != 2 {
		t.Errorf("Silent = %v, want both agents", got)
	}
}

func TestConfigurationIsValidated(t *testing.T) {
	cases := []struct {
		name   string
		agents []Agent
	}{
		{"no name", []Agent{{Certificates: []string{"c"}, Mode: ModeIssue}}},
		{"duplicate", []Agent{
			{Name: "a", Certificates: []string{"c"}, Mode: ModeIssue},
			{Name: "a", Certificates: []string{"d"}, Mode: ModeIssue},
		}},
		{"bad mode", []Agent{{Name: "a", Certificates: []string{"c"}, Mode: "whatever"}}},
		{"no certificates", []Agent{{Name: "a", Mode: ModeIssue}}},
	}
	for _, c := range cases {
		if _, err := New(c.agents, nil); err == nil {
			t.Errorf("%s: an invalid configuration was accepted", c.name)
		}
	}
}

// A corrupted state file must stop the broker, not silently reset every
// revocation to "not revoked".
func TestCorruptStateFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agents.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := New(fleet(), NewFileState(path)); err == nil {
		t.Fatal("a corrupt state file was accepted — that would un-revoke everyone")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	r, _ := New(fleet(), nil)
	done := make(chan struct{})
	for i := 0; i < 16; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				_, _ = r.Authorise("gateway", "gateway-cert")
				_ = r.Delivered("gateway", "gateway-cert", time.Now())
				_ = r.StateOf("gateway")
				_ = r.Silent(time.Now())
			}
		}()
	}
	for i := 0; i < 16; i++ {
		<-done
	}
}

func TestNormaliseName(t *testing.T) {
	for in, want := range map[string]string{
		"Gateway": "gateway", "  gateway  ": "gateway", "GATEWAY": "gateway",
	} {
		if got := NormaliseName(in); got != want {
			t.Errorf("NormaliseName(%q) = %q, want %q", in, got, want)
		}
	}
}
