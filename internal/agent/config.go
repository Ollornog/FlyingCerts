package agent

import (
	"fmt"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Config is the agent's configuration file.
//
// Strict parsing, same as the broker: an unknown key is an error, because a
// typo that silently leaves a setting at its default is the worst kind of
// configuration bug.
type Config struct {
	// Broker is the base URL of the endpoint, e.g. "https://broker.example.com:8443".
	Broker string `yaml:"broker"`
	// IdentityDir holds this host's identity and the broker's CA certificate.
	IdentityDir string `yaml:"identity_dir"`
	// Timeout bounds one call. Zero means DefaultTimeout.
	Timeout time.Duration `yaml:"timeout"`
	// Certificates are what this host collects and where each one goes.
	Certificates []CertificateTarget `yaml:"certificates"`
}

// CertificateTarget is one certificate and what to do with it.
type CertificateTarget struct {
	// Name is the certificate's name at the broker.
	Name string `yaml:"name"`
	// Mode is "issue" (we generate the key and send a CSR) or "share" (the
	// broker sends the key with the certificate).
	Mode string `yaml:"mode"`
	// Domains are the names to request, in issue mode. They must match what
	// the broker has configured exactly — it refuses anything else.
	Domains []string `yaml:"domains"`

	// CertPath and KeyPath are where the files land.
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
	// Owner, Group and KeyMode control who may read the key.
	Owner   string `yaml:"owner"`
	Group   string `yaml:"group"`
	KeyMode uint32 `yaml:"key_mode"`

	// Reload is the command to run after a change, as a list — no shell.
	Reload []string `yaml:"reload"`
	// ReloadTimeout bounds it.
	ReloadTimeout time.Duration `yaml:"reload_timeout"`

	// VerifyAddress is where to confirm the service picked it up, e.g.
	// "127.0.0.1:443". Leaving it out means deployments cannot be confirmed,
	// and the agent says so on every run rather than staying quiet.
	VerifyAddress    string `yaml:"verify_address"`
	VerifyServerName string `yaml:"verify_server_name"`
}

// LoadConfig reads and validates the agent configuration.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Broker == "" {
		return fmt.Errorf("broker is empty")
	}
	if !strings.HasPrefix(c.Broker, "https://") {
		// Plain HTTP would hand the certificates — and in share mode the keys
		// — to anyone on the path.
		return fmt.Errorf("broker %q must be an https URL", c.Broker)
	}
	if c.IdentityDir == "" {
		return fmt.Errorf("identity_dir is empty")
	}
	if len(c.Certificates) == 0 {
		return fmt.Errorf("no certificates configured — nothing to do")
	}

	seen := make(map[string]bool, len(c.Certificates))
	for i, t := range c.Certificates {
		where := fmt.Sprintf("certificates[%d]", i)
		if t.Name == "" {
			return fmt.Errorf("%s: no name", where)
		}
		if seen[t.Name] {
			return fmt.Errorf("%s: %q appears twice", where, t.Name)
		}
		seen[t.Name] = true
		switch t.Mode {
		case "issue":
			if len(t.Domains) == 0 {
				return fmt.Errorf("%s (%s): issue mode needs the domains to request", where, t.Name)
			}
			if t.KeyPath == "" {
				return fmt.Errorf("%s (%s): issue mode needs key_path — the key is generated here",
					where, t.Name)
			}
		case "share":
			if len(t.Domains) > 0 {
				return fmt.Errorf("%s (%s): share mode takes what the broker has; domains is meaningless here",
					where, t.Name)
			}
		default:
			return fmt.Errorf("%s (%s): mode is %q, want \"issue\" or \"share\"", where, t.Name, t.Mode)
		}
		if t.CertPath == "" {
			return fmt.Errorf("%s (%s): no cert_path", where, t.Name)
		}
		if t.KeyMode > 0o777 {
			return fmt.Errorf("%s (%s): key_mode %o is not a permission", where, t.Name, t.KeyMode)
		}
	}
	return nil
}
