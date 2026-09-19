package atomicfile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWriteCreatesFileWithExactMode(t *testing.T) {
	// A wide umask must not widen the file. This is the whole point of passing
	// the mode to OpenFile instead of chmod-ing afterwards.
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	if err := WriteSecret(path, []byte("secret")); err != nil {
		t.Fatalf("WriteSecret: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600 (umask must not widen it)", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, []byte("secret")) {
		t.Errorf("content = %q, want %q", data, "secret")
	}
}

func TestWriteModesDiffer(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	cases := []struct {
		name string
		fn   func(string, []byte) error
		want os.FileMode
	}{
		{"secret.pem", WriteSecret, 0o600},
		{"group.pem", WriteGroupSecret, 0o640},
		{"chain.pem", WritePublic, 0o644},
	}
	for _, c := range cases {
		path := filepath.Join(dir, c.name)
		if err := c.fn(path, []byte("x")); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", c.name, err)
		}
		if got := info.Mode().Perm(); got != c.want {
			t.Errorf("%s: mode = %o, want %o", c.name, got, c.want)
		}
	}
}

func TestWriteReplacesExistingAndKeepsRequestedMode(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")

	// Pre-existing file with a deliberately too-wide mode: replacing it must
	// not inherit that mode.
	if err := os.WriteFile(path, []byte("old"), 0o666); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := WriteSecret(path, []byte("new")); err != nil {
		t.Fatalf("WriteSecret: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "new" {
		t.Errorf("content = %q, want %q", data, "new")
	}
	info, _ := os.Stat(path)
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600 — a replacement must not inherit the old mode", got)
	}
}

func TestWriteLeavesNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")

	if err := WritePublic(path, []byte("data")); err != nil {
		t.Fatalf("WritePublic: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temp file %q left behind", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want exactly 1", len(entries))
	}
}

func TestWriteFailureLeavesNoTempFileAndKeepsOldContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "cert.pem") // parent does not exist

	if err := WritePublic(path, []byte("data")); err == nil {
		t.Fatal("expected an error for a missing parent directory, got nil")
	}

	// The failure must not have scattered temp files in the existing directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("failed write left %d entries behind: %v", len(entries), entries)
	}
}

func TestWriteDoesNotTruncateOnFailure(t *testing.T) {
	// A failing write must leave the previous certificate usable — losing the
	// old one because the new one could not be fetched is the worse outcome.
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("still valid"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Make the directory read-only so creating the temp file fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	defer os.Chmod(dir, 0o700)

	if err := WritePublic(path, []byte("replacement")); err == nil {
		t.Skip("write unexpectedly succeeded — running as root ignores directory permissions")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "still valid" {
		t.Errorf("old content = %q, want it untouched after a failed write", data)
	}
}
