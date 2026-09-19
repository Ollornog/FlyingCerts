// Package acme talks to an ACME certificate authority on behalf of hosts that
// cannot reach one themselves.
//
// This file holds the account. It is the part that is easiest to get wrong in a
// way that only hurts later, so the rules are stated here rather than left to
// the reader:
//
// One account, kept. Two comparable projects create a brand new ACME account
// for every single issuance. That costs twice: Let's Encrypt limits how many
// accounts an IP may register, and — worse — a revocation signed by an account
// that never ordered the certificate is invalid under RFC 8555 §7.6. So the
// account key is loaded if it exists and is never silently replaced.
//
// A missing key is loud, not convenient. If the account file is gone, this
// package says so instead of quietly registering a new account. Losing the
// account is a recovery situation a human should know about.
package acme

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Ollornog/FlyingCerts/internal/atomicfile"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/registration"
)

// ErrNoAccount reports that no account exists at the given location yet.
// Callers decide whether that is a first run (register) or a loss (stop).
var ErrNoAccount = errors.New("no ACME account stored")

// Account is a registered ACME account together with its key.
//
// It satisfies lego's registration.User interface, which is why the getters
// look the way they do. Note GetPrivateKey returns crypto.Signer: that changed
// in lego v5, and code written against v4 will not compile.
type Account struct {
	Email        string                `json:"email"`
	Registration *acme.ExtendedAccount `json:"registration"`

	key crypto.Signer
}

func (a *Account) GetEmail() string                       { return a.Email }
func (a *Account) GetRegistration() *acme.ExtendedAccount { return a.Registration }
func (a *Account) GetPrivateKey() crypto.Signer           { return a.key }

// AccountStore keeps one account per directory.
type AccountStore struct {
	dir string
}

// NewAccountStore stores an account under dir, creating it if needed.
//
// The directory mode is enforced, not merely requested. os.MkdirAll takes a
// mode only for directories it creates — on one that already exists it changes
// nothing. Without the extra step, a directory someone left at 0777 would keep
// that mode while we write a 0600 key into it and feel safe about it.
func NewAccountStore(dir string) (*AccountStore, error) {
	// 0700: nobody but the owner has any business in the directory holding an
	// account key, not even listing it.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create account directory %s: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat account directory %s: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, perm&^0o077); err != nil {
			return nil, fmt.Errorf("account directory %s is mode %o and could not be narrowed: %w", dir, perm, err)
		}
	}
	return &AccountStore{dir: dir}, nil
}

func (s *AccountStore) keyPath() string  { return filepath.Join(s.dir, "account.key") }
func (s *AccountStore) metaPath() string { return filepath.Join(s.dir, "account.json") }

// Exists reports whether an account key is already stored.
func (s *AccountStore) Exists() bool {
	_, err := os.Stat(s.keyPath())
	return err == nil
}

// Load reads the stored account. It returns ErrNoAccount if there is none.
//
// A stored key with missing metadata is an error, not a reason to start over:
// the key is the identity, and registering it again would create a second
// account for the same key material.
func (s *AccountStore) Load() (*Account, error) {
	keyPEM, err := os.ReadFile(s.keyPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoAccount
	}
	if err != nil {
		return nil, fmt.Errorf("read account key: %w", err)
	}
	key, err := certcrypto.ParsePEMPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}

	metaJSON, err := os.ReadFile(s.metaPath())
	if err != nil {
		return nil, fmt.Errorf("account key exists but its metadata does not (%s): %w", s.metaPath(), err)
	}
	var acct Account
	if err := json.Unmarshal(metaJSON, &acct); err != nil {
		return nil, fmt.Errorf("parse account metadata: %w", err)
	}
	if acct.Registration == nil || acct.Registration.Location == "" {
		return nil, fmt.Errorf("account metadata in %s carries no registration URL", s.metaPath())
	}
	acct.key = key
	return &acct, nil
}

// Save writes key and metadata, replacing any earlier metadata for the same key.
func (s *AccountStore) Save(a *Account) error {
	if a.key == nil {
		return errors.New("refusing to save an account without its key")
	}
	keyPEM := certcrypto.PEMEncode(a.key)
	if err := atomicfile.WriteSecret(s.keyPath(), keyPEM); err != nil {
		return fmt.Errorf("write account key: %w", err)
	}
	metaJSON, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("encode account metadata: %w", err)
	}
	// The metadata carries no secret, but it sits next to one — no reason to
	// make it world-readable.
	if err := atomicfile.WriteSecret(s.metaPath(), append(metaJSON, '\n')); err != nil {
		return fmt.Errorf("write account metadata: %w", err)
	}
	return nil
}

// Register creates a new account at the CA and stores it.
//
// It refuses to run when an account key already exists. That refusal is the
// whole point: a caller that loops "load, on error register" would otherwise
// create a fresh account whenever the CA is briefly unreachable.
func (s *AccountStore) Register(ctx context.Context, opts ClientOptions, email string, keyType certcrypto.KeyType) (*Account, error) {
	if s.Exists() {
		return nil, fmt.Errorf("an account key already exists at %s — refusing to register a second account", s.keyPath())
	}
	key, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}
	acct := &Account{Email: email, key: key}

	client, err := newClient(acct, opts)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("register account at %s: %w", opts.DirectoryURL, err)
	}
	acct.Registration = reg

	if err := s.Save(acct); err != nil {
		// The account now exists at the CA but not on disk. Say so plainly —
		// a retry would create a second one.
		return nil, fmt.Errorf("account was registered at %s but could not be stored (%w) — "+
			"do not retry blindly, that would register another account", opts.DirectoryURL, err)
	}
	return acct, nil
}
