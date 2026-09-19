package backup

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/Ollornog/flying-certs/internal/config"
)

// Every configuration field that names a place on disk is either in the backup
// scope or deliberately out of it — and this test knows which.
//
// This is the guard for #409, where a backup shipped without the CA key
// because the scope was a hand-written list nobody revisited. A new field
// added to the configuration fails here until someone decides where it
// belongs, which is the only moment the decision is cheap.
func TestEveryConfigurationFieldIsClassified(t *testing.T) {
	// The value is the reason, so the table reads as a decision record rather
	// than as a list of names.
	classified := map[string]string{
		"Storage.AccountDir":       "in scope: the ACME account key, the one thing that cannot be recreated",
		"Storage.CertificateDir":   "in scope: the certificates and their keys",
		"Broker.StateDir":          "in scope: the agent CA, the token store, the registry",
		"Broker.AuditLog":          "in scope: the record of who collected what",
		"Broker.ServerCert":        "in scope when configured outside the state directory",
		"Broker.ServerKey":         "in scope when configured outside the state directory",
		"Broker.Listen":            "not a path",
		"Broker.IdentityLifetime":  "not a path; a lifetime",
		"ACME.Directory":           "not a path on this host",
		"ACME.Email":               "not a path",
		"ACME.FinalizeTimeout":     "not a path",
		"DNS.Provider":             "not a path",
		"DNS.PropagationWait":      "not a path",
		"DNS.SkipPropagationCheck": "not a path",
		"DNS.SecretEnv":            "names environment variables, not files",
	}

	// A type that parses itself from YAML is a value, not a section, so the
	// walk stops there. Without this it would descend into the unexported
	// innards of something like a lifetime and demand they be classified,
	// which says nothing about what belongs in a backup.
	unmarshaler := reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()
	isLeaf := func(t reflect.Type) bool {
		return t.Implements(unmarshaler) || reflect.PointerTo(t).Implements(unmarshaler)
	}

	var walk func(prefix string, t2 reflect.Type)
	var found []string
	walk = func(prefix string, rt reflect.Type) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			name := prefix + f.Name
			if isLeaf(f.Type) {
				found = append(found, name)
				continue
			}
			switch f.Type.Kind() {
			case reflect.Struct:
				walk(name+".", f.Type)
			case reflect.Slice:
				// Certificates and Agents are the work to do, not state kept
				// on disk; they come from the configuration file itself.
				if name == "Certificates" || name == "Agents" {
					continue
				}
				found = append(found, name)
			default:
				found = append(found, name)
			}
		}
	}
	walk("", reflect.TypeOf(config.Config{}))

	for _, name := range found {
		if _, ok := classified[name]; !ok {
			t.Errorf("configuration field %s is new and unclassified: decide whether it belongs "+
				"in a backup, add it to PathsFor if it does, and record the decision in this table",
				name)
		}
	}
	for name := range classified {
		var present bool
		for _, f := range found {
			if f == name {
				present = true
				break
			}
		}
		if !present {
			t.Errorf("the table still classifies %s, which no longer exists in the configuration", name)
		}
	}
}

// A configured path reaches the scope. Trivial to state, and the assertion
// that turns the table above from prose into a check.
func TestConfiguredPathsReachTheScope(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.AccountDir = "/srv/account"
	cfg.Storage.CertificateDir = "/srv/certs"
	cfg.Broker.StateDir = "/srv/state"
	cfg.Broker.AuditLog = "/var/log/fc/audit.log"
	cfg.Broker.ServerCert = "/etc/tls/broker.crt"
	cfg.Broker.ServerKey = "/etc/tls/broker.key"

	p := PathsFor(cfg)
	for _, area := range []Area{AreaAccount, AreaCertificates, AreaState} {
		if p.Dirs[area] == "" {
			t.Errorf("area %s is configured but not in the scope", area)
		}
	}
	if p.Files[AreaAudit]["audit.log"] != "/var/log/fc/audit.log" {
		t.Errorf("audit log not in scope: %v", p.Files[AreaAudit])
	}
	if p.Files[AreaServer]["broker.key"] != "/etc/tls/broker.key" {
		t.Errorf("external server key not in scope: %v", p.Files[AreaServer])
	}
}

// A broker with no endpoint backs up cleanly. The state directory does not
// exist in that case, and "nothing there" is not a failure.
func TestBackupWorksWithoutAnEndpoint(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.AccountDir = filepath.Join(dir, "account")
	cfg.Storage.CertificateDir = filepath.Join(dir, "certs")
	if err := os.MkdirAll(cfg.Storage.AccountDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Storage.AccountDir, "account.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf writeCounter
	man, err := Create(&buf, PathsFor(cfg), Options{Tool: "test"})
	if err != nil {
		t.Fatalf("backup of a broker without an endpoint failed: %v", err)
	}
	if len(man.Areas) != 1 || man.Areas[0] != AreaAccount {
		t.Errorf("areas = %v, want just [account]", man.Areas)
	}
}

type writeCounter struct{ n int }

func (w *writeCounter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }
