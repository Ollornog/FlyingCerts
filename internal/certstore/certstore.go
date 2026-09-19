// Package certstore keeps obtained certificates on disk.
//
// One certificate is three files under a directory named after it: the chain,
// the private key, and a small metadata file. The layout is deliberately plain
// — an operator should be able to look at it with ls and understand what is
// there, and point any service at the files directly.
//
// Nothing here ever writes a half-finished state: every file goes through
// atomicfile, and a certificate is only considered present when chain and key
// are both there and belong together.
package certstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/Ollornog/flying-certs/internal/atomicfile"
	"github.com/Ollornog/flying-certs/internal/certinfo"
)

// ErrNotFound reports that no certificate is stored under that name.
var ErrNotFound = errors.New("certificate not stored")

// safeName limits names to what is safe as a single path element. Anything
// else is rejected rather than sanitised: silently rewriting a name means the
// caller asks for one certificate and gets another.
var safeName = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// Metadata travels next to a certificate so the broker can answer questions
// about it without parsing the chain every time.
type Metadata struct {
	// Name is the store key.
	Name string `json:"name"`
	// Domains are the names the certificate covers.
	Domains []string `json:"domains"`
	// NotBefore and NotAfter mirror the certificate, for cheap listing.
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// ObtainedAt is when we fetched it.
	ObtainedAt time.Time `json:"obtained_at"`
	// Serial identifies the certificate at the CA, for revocation and ARI.
	Serial string `json:"serial"`
}

// Store holds certificates under a base directory.
type Store struct {
	dir string
}

// New opens (and if needed creates) a store at dir.
//
// The directory mode is enforced rather than requested: os.MkdirAll only
// applies its mode to directories it creates, so an existing one keeps
// whatever it had — including world-readable.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create certificate directory %s: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat certificate directory %s: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, perm&^0o077); err != nil {
			return nil, fmt.Errorf("certificate directory %s is mode %o and could not be narrowed: %w",
				dir, perm, err)
		}
	}
	return &Store{dir: dir}, nil
}

// ValidateName reports whether name is usable as a store key.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("empty certificate name")
	}
	if len(name) > 64 {
		return fmt.Errorf("certificate name %q is longer than 64 characters", name)
	}
	if !safeName.MatchString(name) {
		return fmt.Errorf("certificate name %q must be lowercase letters, digits, dot, dash or underscore, "+
			"starting and ending with a letter or digit", name)
	}
	return nil
}

func (s *Store) pathFor(name, file string) string {
	return filepath.Join(s.dir, name, file)
}

// Save writes a certificate, its key and metadata.
//
// The pair is verified before anything is written. Storing a chain that does
// not match its key produces a certificate that looks healthy in a listing and
// fails at the TLS handshake — the exact shape of CertMate #608 and #830.
func (s *Store) Save(name string, chainPEM, keyPEM []byte) (*Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	pair, err := certinfo.LoadPair(chainPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("refusing to store %q: %w", name, err)
	}

	dir := filepath.Join(s.dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}

	meta := &Metadata{
		Name:       name,
		Domains:    pair.Leaf.DNSNames,
		NotBefore:  pair.Leaf.NotBefore,
		NotAfter:   pair.Leaf.NotAfter,
		ObtainedAt: time.Now().UTC(),
		Serial:     pair.Leaf.SerialNumber.String(),
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}

	// Key first: if writing the chain fails afterwards, a stale key alone is
	// harmless, whereas a new chain without its key would look complete in a
	// listing and break at the handshake.
	if err := atomicfile.WriteSecret(s.pathFor(name, "privkey.pem"), keyPEM); err != nil {
		return nil, fmt.Errorf("write key for %q: %w", name, err)
	}
	if err := atomicfile.WritePublic(s.pathFor(name, "fullchain.pem"), chainPEM); err != nil {
		return nil, fmt.Errorf("write chain for %q: %w", name, err)
	}
	if err := atomicfile.WritePublic(s.pathFor(name, "metadata.json"), append(metaJSON, '\n')); err != nil {
		return nil, fmt.Errorf("write metadata for %q: %w", name, err)
	}
	return meta, nil
}

// Load reads a stored certificate and verifies that chain and key match.
func (s *Store) Load(name string) (chainPEM, keyPEM []byte, pair *certinfo.Pair, err error) {
	if err := ValidateName(name); err != nil {
		return nil, nil, nil, err
	}
	chainPEM, err = os.ReadFile(s.pathFor(name, "fullchain.pem"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("%q: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read chain for %q: %w", name, err)
	}
	keyPEM, err = os.ReadFile(s.pathFor(name, "privkey.pem"))
	if errors.Is(err, os.ErrNotExist) {
		// Deliberately not ErrNotFound: something IS there, and it is broken.
		// Reporting "not stored" would invite a caller to obtain a second
		// certificate while the first one sits there half-written.
		return nil, nil, nil, fmt.Errorf("chain for %q exists but its key does not", name)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read key for %q: %w", name, err)
	}
	pair, err = certinfo.LoadPair(chainPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("stored certificate %q is unusable: %w", name, err)
	}
	return chainPEM, keyPEM, pair, nil
}

// List returns the metadata of every stored certificate, sorted by name.
//
// A directory whose contents are broken is reported through brokenNames rather
// than dropped: a certificate that silently disappears from a listing is worse
// than one that shows up as needing attention.
func (s *Store) List() (metas []*Metadata, brokenNames []string, err error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", s.dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		metaJSON, err := os.ReadFile(s.pathFor(name, "metadata.json"))
		if err != nil {
			brokenNames = append(brokenNames, name)
			continue
		}
		var m Metadata
		if err := json.Unmarshal(metaJSON, &m); err != nil {
			brokenNames = append(brokenNames, name)
			continue
		}
		metas = append(metas, &m)
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].Name < metas[j].Name })
	sort.Strings(brokenNames)
	return metas, brokenNames, nil
}

// Dir reports the base directory, for messages and tests.
func (s *Store) Dir() string { return s.dir }
