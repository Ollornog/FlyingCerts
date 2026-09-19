package config

import (
	"strings"
	"testing"

	"github.com/Ollornog/FlyingCerts/internal/lifetime"
)

const withLifetimes = valid + `
broker:
  listen: ":8443"
  state_dir: /var/lib/flying-certs/state
  identity_lifetime: 30d
agents:
  - name: nightly
    certificates: [gateway]
    mode: issue
    identity_lifetime: 1d
  - name: appliance
    certificates: [gateway]
    mode: issue
    identity_lifetime: unlimited
  - name: ordinary
    certificates: [gateway]
    mode: issue
`

// Per agent, with the broker-wide value as the fallback. Hosts differ: one
// rebuilt from an image every night wants a day, one rarely touched wants
// longer, and most want whatever the broker says.
func TestIdentityLifetimeIsPerAgentWithAFallback(t *testing.T) {
	cfg, err := Load(write(t, withLifetimes))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Broker.IdentityLifetime; got.Duration() != 30*lifetime.Day {
		t.Errorf("broker-wide lifetime = %v", got)
	}

	byName := map[string]AgentSpec{}
	for _, a := range cfg.Agents {
		byName[a.Name] = a
	}
	if got := byName["nightly"].IdentityLifetime; got.Duration() != lifetime.Day {
		t.Errorf("nightly = %v, want 1d", got)
	}
	if got := byName["appliance"].IdentityLifetime; !got.IsUnlimited() {
		t.Errorf("appliance = %v, want unlimited", got)
	}
	// Unset, so it falls back — and the fallback is resolved where it is
	// used, not baked in at load time, so a changed broker default reaches
	// every agent that did not opt out.
	ordinary := byName["ordinary"].IdentityLifetime
	if ordinary.Set() {
		t.Errorf("ordinary = %v, want unset", ordinary)
	}
	if got := ordinary.Or(cfg.Broker.IdentityLifetime); got.Duration() != 30*lifetime.Day {
		t.Errorf("ordinary falls back to %v, want the broker's 30d", got)
	}
}

// The mistakes worth catching at load time, each with the line number.
func TestBadLifetimesAreRefusedAtLoad(t *testing.T) {
	for _, bad := range []string{"30", "0", "-1d", "never", "30 d"} {
		body := strings.Replace(withLifetimes, "identity_lifetime: 1d",
			"identity_lifetime: "+bad, 1)
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("identity_lifetime: %s was accepted", bad)
		}
	}
}

// An unknown key stays an error even inside an agent, which is the rule the
// whole package is built on — a typo must not leave a setting at its default
// with everybody convinced it took effect.
func TestATypoInTheLifetimeKeyIsStillAnError(t *testing.T) {
	body := strings.Replace(withLifetimes, "identity_lifetime: 1d", "identitiy_lifetime: 1d", 1)
	if _, err := Load(write(t, body)); err == nil {
		t.Error("a misspelt key was accepted")
	}
}
