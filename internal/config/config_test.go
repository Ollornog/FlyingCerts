package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const valid = `
acme:
  directory: staging
  email: admin@example.com
storage:
  account_dir: /var/lib/flying-certs/account
  certificate_dir: /var/lib/flying-certs/certs
dns:
  provider: rfc2136
certificates:
  - name: gateway
    domains: [gateway.example.com]
`

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(write(t, valid))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ACME.Directory != LetsEncryptStaging {
		t.Errorf("Directory = %q, want the staging URL — the shorthand must resolve", cfg.ACME.Directory)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Name != "gateway" {
		t.Errorf("Certificates = %+v", cfg.Certificates)
	}
}

// A typo in a key must not silently leave a setting at its default.
func TestUnknownFieldIsRejected(t *testing.T) {
	body := strings.Replace(valid, "  provider: rfc2136", "  provider: rfc2136\n  propogation_wait: 30s", 1)
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("a misspelled key was accepted — the operator would think it took effect")
	}
	if !strings.Contains(err.Error(), "propogation_wait") {
		t.Errorf("the error does not name the offending key: %v", err)
	}
}

func TestDurationsParse(t *testing.T) {
	body := strings.Replace(valid, "  provider: rfc2136",
		"  provider: rfc2136\n  propagation_wait: 45s", 1)
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DNS.PropagationWait != 45*time.Second {
		t.Errorf("PropagationWait = %v, want 45s", cfg.DNS.PropagationWait)
	}
}

func TestRejects(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		mustSay string
	}{
		{"no directory", strings.Replace(valid, "  directory: staging", "", 1), "acme.directory"},
		{"plain http", strings.Replace(valid, "  directory: staging", "  directory: http://ca.example.com/dir", 1), "https"},
		{"no email", strings.Replace(valid, "  email: admin@example.com", "", 1), "acme.email"},
		{"bad email", strings.Replace(valid, "admin@example.com", "not-an-address", 1), "not an address"},
		{"no provider", strings.Replace(valid, "  provider: rfc2136", "", 1), "dns.provider"},
		{"unknown provider", strings.Replace(valid, "  provider: rfc2136", "  provider: some-registrar", 1), "rfc2136"},
		{"no certificates", strings.Split(valid, "certificates:")[0], "no certificates"},
		{"bad cert name", strings.Replace(valid, "name: gateway", "name: ../escape", 1), "certificate name"},
		{"no domains", strings.Replace(valid, "    domains: [gateway.example.com]", "    domains: []", 1), "no domains"},
		{"same directories",
			strings.Replace(valid, "  certificate_dir: /var/lib/flying-certs/certs",
				"  certificate_dir: /var/lib/flying-certs/account", 1), "same directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(write(t, c.body))
			if err == nil {
				t.Fatalf("accepted an invalid config (%s)", c.name)
			}
			if !strings.Contains(err.Error(), c.mustSay) {
				t.Errorf("error should mention %q but says: %v", c.mustSay, err)
			}
		})
	}
}

func TestDuplicateCertificateNameIsRejected(t *testing.T) {
	body := valid + `  - name: gateway
    domains: [other.example.com]
`
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("two certificates with the same name were accepted — one would overwrite the other")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("error = %v", err)
	}
}

// Credentials come from the environment, never from the file — the file is
// something an operator might paste into a bug report.
func TestSecretsComeFromEnvironment(t *testing.T) {
	body := strings.Replace(valid, "  provider: rfc2136",
		"  provider: rfc2136\n  secret_env: [FC_TEST_TSIG, FC_TEST_ABSENT]", 1)
	t.Setenv("FC_TEST_TSIG", "PLACEHOLDER-tsig-value")

	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Secrets()
	if len(got) != 1 || got[0] != "PLACEHOLDER-tsig-value" {
		t.Errorf("Secrets() = %v, want exactly the one that is set", got)
	}
}

func TestMissingFileSaysSo(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("err = %v, want a clear read error", err)
	}
}
