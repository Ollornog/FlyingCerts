// Package config reads the broker's configuration file.
//
// Two rules run through this package:
//
// Unknown fields are an error. A typo in a key would otherwise leave the
// setting at its default and the operator convinced it took effect — the worst
// kind of configuration bug, because everything looks fine until it matters.
//
// Nothing is migrated. Cert Warden carried a hand-written config migration
// beside its database migration; the weaker of the two crashed on an unquoted
// YAML line (#41). A config that cannot be read is reported, not repaired.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ollornog/flying-certs/internal/acme"
	"github.com/Ollornog/flying-certs/internal/certstore"
	"go.yaml.in/yaml/v3"
)

// LetsEncryptProduction and LetsEncryptStaging are offered as names so nobody
// has to paste a URL, and so "staging" is easy to reach for.
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Config is the whole configuration file.
type Config struct {
	// ACME describes the CA and the account.
	ACME ACMEConfig `yaml:"acme"`
	// Storage says where things live.
	Storage StorageConfig `yaml:"storage"`
	// DNS configures the challenge provider.
	DNS DNSConfig `yaml:"dns"`
	// Certificates are the certificates this broker keeps.
	Certificates []CertificateConfig `yaml:"certificates"`
	// Agents are the hosts allowed to ask, and what each may have.
	Agents []AgentSpec `yaml:"agents"`
	// Broker configures the agent-facing endpoint.
	Broker BrokerConfig `yaml:"broker"`
}

// BrokerConfig configures the endpoint agents talk to.
type BrokerConfig struct {
	// Listen is the address to serve on, e.g. ":8443". Empty disables the
	// endpoint, which is the state before M-2 was built and still useful for
	// a broker driven only from a timer.
	Listen string `yaml:"listen"`
	// StateDir holds the agent CA, the token store and the agent state.
	StateDir string `yaml:"state_dir"`
	// AuditLog is where decisions are recorded.
	AuditLog string `yaml:"audit_log"`
	// IdentityLifetime is how long an agent identity is valid. Zero means the
	// package default, which is deliberately short.
	IdentityLifetime time.Duration `yaml:"identity_lifetime"`
	// ServerCert and ServerKey are the endpoint's own TLS files. Agents verify
	// the broker with the agent CA, so these are normally issued by it.
	ServerCert string `yaml:"server_cert"`
	ServerKey  string `yaml:"server_key"`
}

// ACMEConfig describes the certificate authority and our account with it.
type ACMEConfig struct {
	// Directory is the ACME directory URL, or the shorthand "production" or
	// "staging" for Let's Encrypt.
	Directory string `yaml:"directory"`
	// Email is the account contact address. The CA uses it for expiry warnings.
	Email string `yaml:"email"`
	// FinalizeTimeout bounds one order. Empty means the package default, which
	// is deliberately more generous than lego's 30 seconds.
	FinalizeTimeout time.Duration `yaml:"finalize_timeout"`
}

// StorageConfig says where state is kept.
type StorageConfig struct {
	// AccountDir holds the ACME account key. Losing it is a recovery case.
	AccountDir string `yaml:"account_dir"`
	// CertificateDir holds one directory per certificate.
	CertificateDir string `yaml:"certificate_dir"`
}

// DNSConfig configures the DNS-01 challenge.
type DNSConfig struct {
	// Provider is one of the compiled-in provider names.
	Provider string `yaml:"provider"`
	// PropagationWait is how long to wait for a DNS change to spread. Zero
	// leaves lego's own behaviour in place.
	PropagationWait time.Duration `yaml:"propagation_wait"`
	// SkipPropagationCheck stops lego from polling nameservers itself, which
	// is needed with split-horizon DNS where lego sees a different answer
	// than the CA will.
	SkipPropagationCheck bool `yaml:"skip_propagation_check"`
	// SecretEnv names environment variables whose values must never appear in
	// a log line. The provider credentials belong here.
	SecretEnv []string `yaml:"secret_env"`
}

// CertificateConfig is one certificate the broker keeps current.
type CertificateConfig struct {
	// Name is the store key and the directory name.
	Name string `yaml:"name"`
	// Domains are the names it must cover.
	Domains []string `yaml:"domains"`
	// Profile optionally selects a CA issuance profile, e.g. "shortlived".
	Profile string `yaml:"profile"`
}

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a typo must not pass as a default
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.normaliseAndValidate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) normaliseAndValidate() error {
	switch c.ACME.Directory {
	case "":
		return fmt.Errorf("acme.directory is empty — name the CA explicitly, " +
			"there is no default (use \"staging\" while trying things out)")
	case "production":
		c.ACME.Directory = LetsEncryptProduction
	case "staging":
		c.ACME.Directory = LetsEncryptStaging
	}
	if !strings.HasPrefix(c.ACME.Directory, "https://") {
		return fmt.Errorf("acme.directory %q must be an https URL", c.ACME.Directory)
	}
	if c.ACME.Email == "" {
		return fmt.Errorf("acme.email is empty — the CA needs a contact address")
	}
	if !strings.Contains(c.ACME.Email, "@") {
		return fmt.Errorf("acme.email %q is not an address", c.ACME.Email)
	}
	if c.ACME.FinalizeTimeout < 0 {
		return fmt.Errorf("acme.finalize_timeout is negative")
	}

	if c.Storage.AccountDir == "" {
		return fmt.Errorf("storage.account_dir is empty")
	}
	if c.Storage.CertificateDir == "" {
		return fmt.Errorf("storage.certificate_dir is empty")
	}
	c.Storage.AccountDir = filepath.Clean(c.Storage.AccountDir)
	c.Storage.CertificateDir = filepath.Clean(c.Storage.CertificateDir)
	if c.Storage.AccountDir == c.Storage.CertificateDir {
		return fmt.Errorf("storage.account_dir and storage.certificate_dir are the same directory")
	}

	if c.DNS.Provider == "" {
		return fmt.Errorf("dns.provider is empty — available: %v", acme.SupportedProviders())
	}
	if !slicesContains(acme.SupportedProviders(), c.DNS.Provider) {
		return fmt.Errorf("dns.provider %q is not compiled into this build; available: %v. "+
			"For an unlisted provider use rfc2136 or acmedns",
			c.DNS.Provider, acme.SupportedProviders())
	}
	if c.DNS.PropagationWait < 0 {
		return fmt.Errorf("dns.propagation_wait is negative")
	}

	if len(c.Certificates) == 0 {
		return fmt.Errorf("no certificates configured — nothing to do")
	}
	seen := make(map[string]bool, len(c.Certificates))
	for i, cert := range c.Certificates {
		where := fmt.Sprintf("certificates[%d]", i)
		if err := certstore.ValidateName(cert.Name); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if seen[cert.Name] {
			return fmt.Errorf("%s: name %q is used twice", where, cert.Name)
		}
		seen[cert.Name] = true
		if len(cert.Domains) == 0 {
			return fmt.Errorf("%s (%s): no domains", where, cert.Name)
		}
		for _, d := range cert.Domains {
			if d == "" || strings.ContainsAny(d, " \t") {
				return fmt.Errorf("%s (%s): %q is not a domain name", where, cert.Name, d)
			}
		}
	}
	if err := c.validateAgents(); err != nil {
		return err
	}
	return nil
}

// validateAgents checks the agent section against the configured certificates.
//
// An agent permitted a certificate that does not exist is refused at startup
// rather than at three in the morning: it is always a typo, and the only
// question is whether it is found now or when the host asks.
func (c *Config) validateAgents() error {
	if c.Broker.Listen == "" && len(c.Agents) == 0 {
		return nil // no endpoint, no agents — a timer-driven broker
	}
	known := make(map[string]bool, len(c.Certificates))
	for _, cert := range c.Certificates {
		known[cert.Name] = true
	}
	seen := make(map[string]bool, len(c.Agents))
	for i, a := range c.Agents {
		where := fmt.Sprintf("agents[%d]", i)
		if a.Name == "" {
			return fmt.Errorf("%s: no name", where)
		}
		if seen[a.Name] {
			return fmt.Errorf("%s: agent %q is configured twice", where, a.Name)
		}
		seen[a.Name] = true
		if a.Mode != "issue" && a.Mode != "share" {
			return fmt.Errorf("%s (%s): mode is %q, want \"issue\" or \"share\"", where, a.Name, a.Mode)
		}
		if len(a.Certificates) == 0 {
			return fmt.Errorf("%s (%s): permitted no certificates", where, a.Name)
		}
		for _, certName := range a.Certificates {
			if !known[certName] {
				return fmt.Errorf("%s (%s): permitted %q, which is not a configured certificate",
					where, a.Name, certName)
			}
		}
	}
	if c.Broker.Listen != "" && c.Broker.StateDir == "" {
		return fmt.Errorf("broker.state_dir is empty, but broker.listen is set")
	}
	return nil
}

// Secrets collects the values that must be kept out of the log.
//
// They are read from the environment rather than written in the config file,
// which is lego's convention for provider credentials and keeps them out of
// something an operator might paste into an issue.
func (c *Config) Secrets() []string {
	var out []string
	for _, name := range c.DNS.SecretEnv {
		if v := os.Getenv(name); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func slicesContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// DomainsFor implements brokerapi.Specs: which names a configured certificate
// covers. The `issue` mode compares an agent's request against exactly this.
func (c *Config) DomainsFor(certName string) ([]string, bool) {
	for _, cert := range c.Certificates {
		if cert.Name == certName {
			return cert.Domains, true
		}
	}
	return nil, false
}

// AgentSpecs is the agent section of the configuration.
type AgentSpec struct {
	// Name is the agent's identity, as it appears in its certificate.
	Name string `yaml:"name"`
	// Certificates are the store names this agent may have. Exact names.
	Certificates []string `yaml:"certificates"`
	// Mode is "issue" (recommended) or "share".
	Mode string `yaml:"mode"`
}
