package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const agentConfig = `
broker: https://broker.example.com:8443
identity_dir: /var/lib/flying-certs-agent
certificates:
  - name: gateway-cert
    mode: issue
    domains: [gateway.example.com]
    cert_path: /etc/ssl/gateway/fullchain.pem
    key_path: /etc/ssl/gateway/privkey.pem
    reload: [systemctl, reload, nginx]
    verify_address: 127.0.0.1:443
`

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestAgentConfigLoads(t *testing.T) {
	cfg, err := LoadConfig(writeCfg(t, agentConfig))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %+v", cfg.Certificates)
	}
	got := cfg.Certificates[0]
	if len(got.Reload) != 3 || got.Reload[0] != "systemctl" {
		t.Errorf("Reload = %v, want argv as a list", got.Reload)
	}
}

// Plain HTTP would hand the certificates — and in share mode the keys — to
// anyone on the path.
func TestPlainHTTPBrokerIsRefused(t *testing.T) {
	body := strings.Replace(agentConfig, "https://", "http://", 1)
	if _, err := LoadConfig(writeCfg(t, body)); err == nil {
		t.Error("a plain-HTTP broker address was accepted")
	}
}

func TestUnknownKeyIsRejected(t *testing.T) {
	body := strings.Replace(agentConfig, "    mode: issue", "    mode: issue\n    relaod: [true]", 1)
	_, err := LoadConfig(writeCfg(t, body))
	if err == nil {
		t.Fatal("a misspelled key was accepted")
	}
	if !strings.Contains(err.Error(), "relaod") {
		t.Errorf("the error does not name the key: %v", err)
	}
}

func TestModeSpecificValidation(t *testing.T) {
	cases := []struct {
		name, body, mustSay string
	}{
		{"issue without domains",
			strings.Replace(agentConfig, "    domains: [gateway.example.com]\n", "", 1), "domains"},
		{"issue without key_path",
			strings.Replace(agentConfig, "    key_path: /etc/ssl/gateway/privkey.pem\n", "", 1), "key_path"},
		{"share with domains",
			strings.Replace(agentConfig, "    mode: issue", "    mode: share", 1), "meaningless"},
		{"unknown mode",
			strings.Replace(agentConfig, "    mode: issue", "    mode: whatever", 1), "mode"},
		{"no cert_path",
			strings.Replace(agentConfig, "    cert_path: /etc/ssl/gateway/fullchain.pem\n", "", 1), "cert_path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadConfig(writeCfg(t, c.body))
			if err == nil {
				t.Fatal("an invalid configuration was accepted")
			}
			if !strings.Contains(err.Error(), c.mustSay) {
				t.Errorf("error should mention %q: %v", c.mustSay, err)
			}
		})
	}
}

func TestDuplicateCertificateIsRejected(t *testing.T) {
	body := agentConfig + `  - name: gateway-cert
    mode: share
    cert_path: /etc/ssl/other.pem
`
	if _, err := LoadConfig(writeCfg(t, body)); err == nil {
		t.Error("the same certificate twice was accepted")
	}
}
