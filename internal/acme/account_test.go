package acme

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
)

// storedAccount puts a usable account on disk without talking to any CA.
func storedAccount(t *testing.T, dir string) *AccountStore {
	t.Helper()
	store, err := NewAccountStore(dir)
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	acct := &Account{
		Email:        "admin@example.com",
		Registration: &acme.ExtendedAccount{Location: "https://ca.example.com/acct/1"},
		key:          key,
	}
	if err := store.Save(acct); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return store
}

func TestLoadReturnsErrNoAccountWhenEmpty(t *testing.T) {
	store, err := NewAccountStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	if store.Exists() {
		t.Error("Exists reports an account in an empty directory")
	}
	_, err = store.Load()
	if !errors.Is(err, ErrNoAccount) {
		t.Errorf("err = %v, want ErrNoAccount — a first run must be distinguishable from a loss", err)
	}
}

func TestSaveThenLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := storedAccount(t, dir)

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Email != "admin@example.com" {
		t.Errorf("Email = %q", loaded.Email)
	}
	if loaded.GetRegistration().Location != "https://ca.example.com/acct/1" {
		t.Errorf("Location = %q", loaded.GetRegistration().Location)
	}
	if loaded.GetPrivateKey() == nil {
		t.Fatal("the key did not survive the round trip")
	}
	// The key must be the same one, not merely some key.
	original, err := os.ReadFile(filepath.Join(dir, "account.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !strings.Contains(string(original), "PRIVATE KEY") {
		t.Errorf("stored key is not PEM: %q", original[:min(40, len(original))])
	}
	reencoded := certcrypto.PEMEncode(loaded.GetPrivateKey())
	if string(reencoded) != string(original) {
		t.Error("loaded key differs from the stored one")
	}
}

func TestAccountKeyIsOwnerReadableOnly(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := t.TempDir()
	storedAccount(t, dir)

	for _, name := range []string{"account.key", "account.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, got)
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("account directory mode = %o, want no group/other access", got)
	}
}

// os.MkdirAll applies its mode only to directories it creates. A directory that
// already exists keeps whatever mode it had — so requesting 0700 is not the
// same as having 0700, and the key would sit in a world-readable directory
// while looking perfectly safe at 0600.
func TestExistingWideOpenDirectoryIsNarrowed(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	dir := filepath.Join(t.TempDir(), "accounts")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("pre-create wide open: %v", err)
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o777 {
		t.Fatalf("setup failed: mode = %o, want 777", info.Mode().Perm())
	}

	if _, err := NewAccountStore(dir); err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("mode = %o — an existing directory must be narrowed, not accepted as is", got)
	}
}

// A key without metadata must be an error. Treating it as "no account" would
// make a caller register the same key material a second time.
func TestKeyWithoutMetadataIsAnError(t *testing.T) {
	dir := t.TempDir()
	store := storedAccount(t, dir)
	if err := os.Remove(filepath.Join(dir, "account.json")); err != nil {
		t.Fatalf("remove metadata: %v", err)
	}

	_, err := store.Load()
	if err == nil {
		t.Fatal("a key without metadata loaded without error")
	}
	if errors.Is(err, ErrNoAccount) {
		t.Error("a key without metadata reported as ErrNoAccount — that invites a duplicate registration")
	}
	if !store.Exists() {
		t.Error("Exists must still report the key that is lying there")
	}
}

func TestMetadataWithoutRegistrationURLIsAnError(t *testing.T) {
	dir := t.TempDir()
	store := storedAccount(t, dir)

	// Metadata that parses but says nothing: the account was never registered.
	bad, _ := json.Marshal(Account{Email: "admin@example.com"})
	if err := os.WriteFile(filepath.Join(dir, "account.json"), bad, 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Error("metadata without a registration URL loaded without error")
	}
}

// The central rule of ADR-10, proved mechanically: an existing key blocks
// registration. Without this, a caller looping "load, on error register" would
// mint a new account whenever the CA hiccups.
func TestRegisterRefusesWhenAKeyExists(t *testing.T) {
	dir := t.TempDir()
	store := storedAccount(t, dir)

	before, err := os.ReadFile(filepath.Join(dir, "account.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	// The URL points nowhere on purpose: the refusal has to happen before any
	// network call, so this must fail fast rather than time out.
	_, err = store.Register(context.Background(),
		ClientOptions{DirectoryURL: "https://ca.invalid/directory"},
		"admin@example.com", certcrypto.EC256)
	if err == nil {
		t.Fatal("Register succeeded although an account key already existed")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v, want it to name the existing key", err)
	}

	after, err := os.ReadFile(filepath.Join(dir, "account.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(before) != string(after) {
		t.Error("the existing account key was overwritten")
	}
}

func TestSaveRefusesAccountWithoutKey(t *testing.T) {
	store, err := NewAccountStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	if err := store.Save(&Account{Email: "admin@example.com"}); err == nil {
		t.Error("an account without a key was saved")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
