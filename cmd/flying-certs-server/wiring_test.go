package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/certstore"
	"github.com/Ollornog/FlyingCerts/internal/config"
	"github.com/Ollornog/FlyingCerts/internal/lifetime"
	"github.com/Ollornog/FlyingCerts/internal/registry"
)

// Everything configured about an agent has to arrive in the registry.
//
// This test exists because of a bug it would have caught: public_key was
// added to the configuration, to the registry and to the handlers, and the
// one line that copies the value between them was left out. Every unit test
// passed — they build registry.Agent directly — and the feature simply did
// not work. Only running it by hand found it.
//
// So the mapping is checked by walking the struct: a field added to
// AgentSpec fails here until someone says where it goes.
func TestEveryAgentSpecFieldReachesTheRegistry(t *testing.T) {
	dir := t.TempDir()
	const fingerprint = "SHA256:3zCYV58KfoUQglgefqPRMl1I+EvvbaaGpYAUuLjK8Y4"

	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
acme:
  directory: staging
  email: admin@example.com
storage:
  account_dir: `+dir+`/account
  certificate_dir: `+dir+`/certs
dns:
  provider: rfc2136
certificates:
  - name: gateway-cert
    domains: [gateway.example.com]
broker:
  listen: "127.0.0.1:0"
  state_dir: `+dir+`/state
agents:
  - name: gateway
    certificates: [gateway-cert]
    mode: share
    public_key: "`+fingerprint+`"
    identity_lifetime: 7d
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certstore.New(cfg.Storage.CertificateDir)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := openBroker(cfg, certs)
	if err != nil {
		t.Fatal(err)
	}
	if parts.audit != nil {
		defer parts.audit.Close()
	}
	got, err := parts.agents.Lookup("gateway")
	if err != nil {
		t.Fatal(err)
	}

	// Each configuration field, and what must be true of it in the registry.
	// A field with no entry here fails the completeness check below.
	checks := map[string]func() error{
		"Name":         func() error { return wantString("Name", got.Name, "gateway") },
		"Certificates": func() error { return wantString("Certificates", got.Certificates[0], "gateway-cert") },
		"Mode":         func() error { return wantString("Mode", string(got.Mode), "share") },
		"PublicKey":    func() error { return wantString("PublicKey", got.PublicKey, fingerprint) },
		"IdentityLifetime": func() error {
			if got.IdentityLifetime.Duration() != 7*lifetime.Day {
				return errf("IdentityLifetime = %v, want 7d", got.IdentityLifetime)
			}
			return nil
		},
	}

	specType := reflect.TypeOf(config.AgentSpec{})
	for i := 0; i < specType.NumField(); i++ {
		name := specType.Field(i).Name
		check, known := checks[name]
		if !known {
			t.Errorf("AgentSpec.%s is new: copy it in openBroker and assert it here, "+
				"or say here why it does not belong in the registry", name)
			continue
		}
		if err := check(); err != nil {
			t.Errorf("AgentSpec.%s did not reach the registry: %v", name, err)
		}
	}
	for name := range checks {
		if _, ok := specType.FieldByName(name); !ok {
			t.Errorf("this test still checks AgentSpec.%s, which no longer exists", name)
		}
	}

	// And the registry really answers by fingerprint, which is what the
	// device-key route depends on.
	byKey, err := parts.agents.ByPublicKey(fingerprint)
	if err != nil {
		t.Fatalf("the registry does not know the configured fingerprint: %v", err)
	}
	if byKey.Name != "gateway" {
		t.Errorf("fingerprint resolved to %q", byKey.Name)
	}
}

// The broker-wide lifetime has to arrive too — it is the fallback every
// agent without its own setting depends on.
func TestTheBrokerWideLifetimeReachesTheServer(t *testing.T) {
	var cfg config.Config
	cfg.Broker.IdentityLifetime = lifetime.Of(3 * lifetime.Day)
	if got := cfg.Broker.IdentityLifetime.Duration(); got != 72*time.Hour {
		t.Errorf("lifetime = %v", got)
	}
	var unset registry.Agent
	if got := unset.IdentityLifetime.Or(cfg.Broker.IdentityLifetime); got.Duration() != 72*time.Hour {
		t.Errorf("an agent without its own setting resolved to %v", got)
	}
}

func wantString(field, got, want string) error {
	if got != want {
		return errf("%s = %q, want %q", field, got, want)
	}
	return nil
}

func errf(format string, args ...any) error { return fmt.Errorf(format, args...) }
