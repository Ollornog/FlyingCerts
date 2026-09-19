package config

import (
	"strings"
	"testing"
)

const withAgents = `
acme:
  directory: staging
  email: admin@example.com
storage:
  account_dir: /var/lib/flying-certs/account
  certificate_dir: /var/lib/flying-certs/certs
dns:
  provider: rfc2136
broker:
  listen: ":8443"
  state_dir: /var/lib/flying-certs/broker
certificates:
  - name: gateway-cert
    domains: [gateway.example.com]
agents:
  - name: gateway
    certificates: [gateway-cert]
    mode: issue
`

func TestAgentsLoad(t *testing.T) {
	cfg, err := Load(write(t, withAgents))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Agents) != 1 || cfg.Agents[0].Name != "gateway" {
		t.Fatalf("Agents = %+v", cfg.Agents)
	}
	domains, ok := cfg.DomainsFor("gateway-cert")
	if !ok || len(domains) != 1 || domains[0] != "gateway.example.com" {
		t.Errorf("DomainsFor = %v, %v", domains, ok)
	}
	if _, ok := cfg.DomainsFor("nope"); ok {
		t.Error("DomainsFor invented a certificate")
	}
}

// An agent permitted a certificate that does not exist is always a typo. It
// must surface at startup, not when the host asks at three in the morning.
func TestAgentPermittedUnknownCertificateIsRejected(t *testing.T) {
	body := strings.Replace(withAgents, "certificates: [gateway-cert]", "certificates: [typo-cert]", 1)
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("an agent permitted a non-existent certificate was accepted")
	}
	if !strings.Contains(err.Error(), "typo-cert") {
		t.Errorf("the error does not name the offender: %v", err)
	}
}

func TestAgentValidation(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		mustSay string
	}{
		{"bad mode", strings.Replace(withAgents, "mode: issue", "mode: whatever", 1), "mode"},
		{"no mode", strings.Replace(withAgents, "    mode: issue\n", "", 1), "mode"},
		{"no name", strings.Replace(withAgents, "  - name: gateway\n", "  - \n", 1), "name"},
		{"listen without state_dir",
			strings.Replace(withAgents, "  state_dir: /var/lib/flying-certs/broker\n", "", 1), "state_dir"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(write(t, c.body))
			if err == nil {
				t.Fatal("an invalid agent section was accepted")
			}
			if !strings.Contains(err.Error(), c.mustSay) {
				t.Errorf("error should mention %q: %v", c.mustSay, err)
			}
		})
	}
}

func TestDuplicateAgentIsRejected(t *testing.T) {
	body := withAgents + `  - name: gateway
    certificates: [gateway-cert]
    mode: share
`
	if _, err := Load(write(t, body)); err == nil {
		t.Error("the same agent twice was accepted — one would shadow the other")
	}
}

// A broker without an endpoint and without agents is a valid setup: it just
// runs from a timer.
func TestTimerOnlyBrokerNeedsNoAgents(t *testing.T) {
	if _, err := Load(write(t, valid)); err != nil {
		t.Errorf("a timer-driven configuration was refused: %v", err)
	}
}
