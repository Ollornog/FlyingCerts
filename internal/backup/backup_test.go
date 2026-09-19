package backup

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestKey returns a real private key in PEM.
//
// Generated rather than pasted, for two reasons. A PEM key block committed to
// a repository is the thing every secret scanner exists to find, and rightly
// so — including this repository's own, which caught the first version of this
// file. And a generated key means the redaction check runs against genuine key
// material instead of against a string that merely says "secret".
func newTestKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// buildState lays out a broker's state directory tree and returns its Paths
// together with the key material it planted, so a test can look for it.
func buildState(t *testing.T) (root string, p Paths, planted string) {
	t.Helper()
	root = t.TempDir()
	planted = newTestKey(t)
	write := func(rel string, mode fs.FileMode, content string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("account/account.key", 0o600, planted)
	write("account/account.json", 0o644, `{"email":"a@example.com"}`)
	write("certs/gateway/chain.pem", 0o644, "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n")
	write("certs/gateway/key.pem", 0o600, planted)
	write("state/ca/agent-ca.key", 0o600, planted)
	write("state/ca/agent-ca.crt", 0o644, "-----BEGIN CERTIFICATE-----\nY2E=\n-----END CERTIFICATE-----\n")
	write("state/agents.json", 0o600, `{"gateway":{"last_seen":"2026-09-19T00:00:00Z"}}`)
	write("audit.log", 0o600, `{"event":"deliver","agent":"gateway"}`+"\n")

	return root, Paths{
		Dirs: map[Area]string{
			AreaAccount:      filepath.Join(root, "account"),
			AreaCertificates: filepath.Join(root, "certs"),
			AreaState:        filepath.Join(root, "state"),
		},
		Files: map[Area]map[string]string{
			AreaAudit: {"audit.log": filepath.Join(root, "audit.log")},
		},
	}, planted
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out[rel] = info.Mode().Perm().String() + "|" + string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The round trip: back up, destroy everything, restore, and end up with the
// same bytes and the same permissions.
func TestRestoreBringsBackEveryByteAndEveryMode(t *testing.T) {
	root, paths, _ := buildState(t)
	before := snapshot(t, root)

	var archive bytes.Buffer
	man, err := Create(&archive, paths, Options{Tool: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !man.ContainsSecrets {
		t.Error("a full backup holds three private keys and must say so")
	}
	if !man.Restorable {
		t.Error("a full backup must be restorable")
	}

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(bytes.NewReader(archive.Bytes()), paths); err != nil {
		t.Fatalf("restore: %v", err)
	}

	after := snapshot(t, root)
	for name, want := range before {
		got, ok := after[name]
		if !ok {
			t.Errorf("%s did not come back", name)
			continue
		}
		if got != want {
			t.Errorf("%s came back different:\n got %q\nwant %q", name, got, want)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("%s appeared out of nowhere", name)
		}
	}
}

// A redacted archive holds no key material at all — checked against the bytes
// of the archive, not against a flag in the manifest.
//
// This is the guard for #595, where a backup advertised as safe to share
// carried private keys.
func TestRedactedArchiveContainsNoKeyMaterial(t *testing.T) {
	_, paths, planted := buildState(t)

	var archive bytes.Buffer
	man, err := Create(&archive, paths, Options{Tool: "test", Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if man.ContainsSecrets {
		t.Error("a redacted archive must not claim to contain secrets")
	}
	if len(man.RedactedFiles) != 3 {
		t.Errorf("redacted %v, expected the account key, the certificate key and the CA key",
			man.RedactedFiles)
	}

	// Search the compressed bytes after expanding them: a scan of the gzip
	// stream would pass for the wrong reason.
	plain := expand(t, archive.Bytes())
	if bytes.Contains(plain, []byte("PRIVATE KEY")) {
		t.Error("a redacted archive still contains a PEM private key block")
	}
	// The body of the key that was actually planted, not a guess at what one
	// looks like: a middle line, so neither header nor footer can carry it.
	lines := strings.Split(strings.TrimSpace(planted), "\n")
	body := lines[len(lines)/2]
	if bytes.Contains(plain, []byte(body)) {
		t.Error("a redacted archive still contains the bytes of the planted key")
	}
}

// And the other half of #655: a redacted archive is refused as a restore
// source, clearly, before anything on disk is touched.
func TestRedactedArchiveIsRefusedAsARecoveryPoint(t *testing.T) {
	root, paths, _ := buildState(t)
	var archive bytes.Buffer
	if _, err := Create(&archive, paths, Options{Tool: "test", Redact: true}); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(root, "account", "account.key")
	if err := os.WriteFile(marker, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Restore(bytes.NewReader(archive.Bytes()), paths)
	if !errors.Is(err, ErrNotRestorable) {
		t.Fatalf("restore of a redacted archive returned %v, want ErrNotRestorable", err)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "untouched" {
		t.Error("the refusal must come before anything on disk is written")
	}

	// Inspect says the same thing without unpacking, which is what a periodic
	// check of the backup directory would use.
	man, err := Inspect(bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if man.Restorable {
		t.Error("Inspect must report a redacted archive as not restorable")
	}
}

// An archive is data from outside. It does not get to choose where this
// process writes.
func TestArchiveCannotEscapeTheRestoreTarget(t *testing.T) {
	paths := Paths{Dirs: map[Area]string{AreaState: "/srv/state"}}
	for _, name := range []string{
		"../../etc/passwd",
		"state/../../etc/passwd",
		"/etc/passwd",
		"state/",
	} {
		if _, err := destinationFor(name, paths); err == nil {
			t.Errorf("archive entry %q was accepted", name)
		}
	}
	// An area this host does not configure is skipped, not invented.
	dest, err := destinationFor("certificates/gateway/key.pem", paths)
	if err != nil {
		t.Fatal(err)
	}
	if dest != "" {
		t.Errorf("unconfigured area produced %q, want it skipped", dest)
	}
}

// A key restored into a directory somebody left wide open comes out narrow
// anyway — the same trap that already caught the certificate store.
func TestRestoreNarrowsPermissionsItFinds(t *testing.T) {
	root, paths, _ := buildState(t)
	var archive bytes.Buffer
	if _, err := Create(&archive, paths, Options{Tool: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "account")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "account"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "account"), 0o777); err != nil {
		t.Fatal(err)
	}

	if _, err := Restore(bytes.NewReader(archive.Bytes()), paths); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "account"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o007 != 0 {
		t.Errorf("account directory left at %v — a restore must not keep a wide directory wide",
			info.Mode().Perm())
	}
	key, err := os.Stat(filepath.Join(root, "account", "account.key"))
	if err != nil {
		t.Fatal(err)
	}
	if key.Mode().Perm() != 0o600 {
		t.Errorf("restored key is %v, want 0600", key.Mode().Perm())
	}
}

// An archive from a version this build does not understand is reported, not
// guessed at.
func TestUnknownFormatIsRefused(t *testing.T) {
	_, paths, _ := buildState(t)
	var archive bytes.Buffer
	if _, err := Create(&archive, paths, Options{Tool: "test"}); err != nil {
		t.Fatal(err)
	}
	broken := bytes.Replace(expand(t, archive.Bytes()),
		[]byte(`"format": 1`), []byte(`"format": 9`), 1)
	if !bytes.Contains(broken, []byte(`"format": 9`)) {
		t.Fatal("test setup: could not bump the format in the manifest")
	}
	if _, err := Inspect(bytes.NewReader(recompress(t, broken))); err == nil ||
		!strings.Contains(err.Error(), "format 9") {
		t.Errorf("Inspect accepted a format-9 archive: %v", err)
	}
}

// The manifest records when the backup was taken, from the clock it was
// given, so the operator can tell a fresh recovery point from a stale one.
func TestManifestRecordsWhenItWasTaken(t *testing.T) {
	_, paths, _ := buildState(t)
	at := time.Date(2026, 9, 20, 3, 14, 15, 0, time.UTC)
	var archive bytes.Buffer
	man, err := Create(&archive, paths, Options{Tool: "FlyingCerts/test", Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	if !man.CreatedAt.Equal(at) {
		t.Errorf("CreatedAt = %v, want %v", man.CreatedAt, at)
	}
	read, err := Inspect(bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !read.CreatedAt.Equal(at) || read.Tool != "FlyingCerts/test" {
		t.Errorf("manifest read back as %+v", read)
	}
}
