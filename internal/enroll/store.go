package enroll

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
)

// safeID guards the one place a caller-supplied string becomes a filename.
var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)

// Store keeps token records on disk.
//
// Redemption is made single-use by os.Rename, not by a flag in a file. The
// rename of a file within one directory is atomic: of two processes trying it
// at the same moment, exactly one succeeds and the other gets ENOENT. Read the
// record, check a flag, write it back — the obvious implementation — has a
// window between read and write in which both callers see an unused token.
//
// This matters more than it sounds. step-ca falls back to an in-memory map
// when no database is configured (db/simple.go), so its replay protection is
// gone after a restart and never shared between instances. Nothing here is
// ever "just in memory": the guarantee is the filesystem's.
type Store struct {
	dir string
}

// NewStore opens or creates a token store.
func NewStore(dir string) (*Store, error) {
	for _, sub := range []string{"", "pending", "redeemed"} {
		p := filepath.Join(dir, sub)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", p, err)
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, perm&^0o077); err != nil {
			return nil, fmt.Errorf("%s is mode %o and could not be narrowed: %w", dir, perm, err)
		}
	}
	return &Store{dir: dir}, nil
}

func (s *Store) pendingPath(id string) string  { return filepath.Join(s.dir, "pending", id+".json") }
func (s *Store) redeemedPath(id string) string { return filepath.Join(s.dir, "redeemed", id+".json") }

// Put stores a freshly issued record.
func (s *Store) Put(rec *Record) error {
	if !safeID.MatchString(rec.ID) {
		return fmt.Errorf("token id %q is not usable as a filename", rec.ID)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode token record: %w", err)
	}
	return atomicfile.WriteSecret(s.pendingPath(rec.ID), append(data, '\n'))
}

// Get reads a record, whether pending or already redeemed.
func (s *Store) Get(id string) (*Record, error) {
	if !safeID.MatchString(id) {
		return nil, ErrUnknownToken
	}
	for _, path := range []string{s.pendingPath(id), s.redeemedPath(id)} {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read token record: %w", err)
		}
		var rec Record
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("parse token record %s: %w", id, err)
		}
		return &rec, nil
	}
	return nil, ErrUnknownToken
}

// Redeem verifies the secret and marks the token used, atomically.
//
// The order is the point: the rename happens *before* anything is issued. If
// two callers race, the loser fails here and no certificate is signed twice.
func (s *Store) Redeem(id, secret, caFingerprint, by string, now time.Time) (*Record, error) {
	if !safeID.MatchString(id) {
		return nil, ErrUnknownToken
	}
	rec, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if err := Verify(rec, secret, caFingerprint, now); err != nil {
		return nil, err
	}

	// Claim it. Exactly one caller can move the file out of pending; everyone
	// else finds it gone. This is the whole single-use guarantee — there is no
	// read-check-write window to lose.
	tmp := s.redeemedPath(id) + ".claiming"
	if err := os.Rename(s.pendingPath(id), tmp); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Either never existed or another caller was quicker. Both look
			// the same to the loser, which is correct.
			return nil, ErrUnknownToken
		}
		return nil, fmt.Errorf("claim token: %w", err)
	}

	stamp := now.UTC()
	rec.RedeemedAt = &stamp
	rec.RedeemedBy = by
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode redeemed record: %w", err)
	}
	if err := atomicfile.WriteSecret(s.redeemedPath(id), append(data, '\n')); err != nil {
		return nil, fmt.Errorf("write redeemed record: %w", err)
	}
	_ = os.Remove(tmp)
	return rec, nil
}

// List returns every record, newest issue first.
func (s *Store) List() ([]*Record, error) {
	var out []*Record
	for _, sub := range []string{"pending", "redeemed"} {
		entries, err := os.ReadDir(filepath.Join(s.dir, sub))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", sub, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || filepath.Ext(name) != ".json" {
				continue
			}
			rec, err := s.Get(name[:len(name)-len(".json")])
			if err != nil {
				continue // a broken record must not hide the rest
			}
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out, nil
}

// Prune deletes records that expired before cutoff and were never redeemed,
// and redeemed ones older than cutoff.
//
// Without this the store grows forever. Both step-ca and Cert Warden have open
// issues for exactly that omission, which is a good hint that it is easier to
// build now than to retrofit.
func (s *Store) Prune(cutoff time.Time) (removed int, err error) {
	recs, err := s.List()
	if err != nil {
		return 0, err
	}
	for _, rec := range recs {
		stale := rec.NotAfter.Before(cutoff)
		if rec.Spent() {
			stale = rec.RedeemedAt.Before(cutoff)
		}
		if !stale {
			continue
		}
		for _, p := range []string{s.pendingPath(rec.ID), s.redeemedPath(rec.ID)} {
			if err := os.Remove(p); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}
