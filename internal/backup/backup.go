// Package backup saves and restores everything the broker cannot recreate.
//
// The design is a reaction to one project's backup chain failing in four
// separate ways, all of them the same mistake in different clothes:
//
//   - A backup advertised as safe to share contained private keys (#595).
//   - A masked backup could not be restored at all, so the newest recovery
//     point was a decoy (#655).
//   - The scope left out the CA's own key (#409).
//   - After a restore, every renewal failed for good (#410).
//
// What connects them is that each backup was tested for "the file came back",
// never for "the system works afterwards". So:
//
//   - There are two kinds and they are never confused. An Archive is complete
//     and contains keys; Restore takes only this. A Redacted archive is for
//     diagnosis, is marked as not restorable, and Restore refuses it by name
//     rather than failing halfway through.
//   - The scope is one list in one place, and a test walks the configuration
//     struct to prove every path is either in that list or deliberately out.
//   - The archive stores logical areas, not host paths, so a restore onto a
//     machine that keeps its state elsewhere still lands in the right places.
//   - The end-to-end test restores and then renews and delivers.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FormatVersion is the archive layout. Restore refuses what it does not know:
// a backup from a future version is likelier to be misread than read.
const FormatVersion = 1

// MaxEntrySize bounds one file taken out of an archive. Without it a crafted
// archive could fill the disk while being unpacked.
const MaxEntrySize = 256 << 20 // 256 MiB

// Area names a logical part of the broker's state. The archive stores these,
// not the host's paths, so a restore can land somewhere else.
type Area string

const (
	// AreaAccount is the ACME account key and its metadata. Without it the
	// broker cannot renew anything — this is the one thing that matters most.
	AreaAccount Area = "account"
	// AreaCertificates is the certificate store.
	AreaCertificates Area = "certificates"
	// AreaState is the agent CA, the token store and the agent registry.
	AreaState Area = "state"
	// AreaServer is the endpoint's own TLS pair, when it is kept outside the
	// state directory.
	AreaServer Area = "server"
	// AreaAudit is the record of who collected what. It is not needed to make
	// the broker work again, and is included anyway: it is the evidence, and
	// a backup that drops the evidence is not a backup of this program.
	AreaAudit Area = "audit"
)

// Paths says where each area lives on this host.
//
// Building it from a configuration is the caller's job (see FromConfig in the
// server command) so that this package stays free of the config type and can
// be tested without one.
type Paths struct {
	// Dirs maps an area to a directory that is copied whole.
	Dirs map[Area]string
	// Files maps an area to individual files, keyed by their name inside the
	// archive.
	Files map[Area]map[string]string
}

// Manifest describes an archive. It is the first entry, so a reader learns
// what it is holding before unpacking anything.
type Manifest struct {
	// Format is FormatVersion.
	Format int `json:"format"`
	// CreatedAt is when the archive was written, in UTC.
	CreatedAt time.Time `json:"created_at"`
	// Tool is the program and version that wrote it.
	Tool string `json:"tool"`
	// Areas lists what is inside.
	Areas []Area `json:"areas"`
	// Restorable is false for a redacted archive. Restore checks this before
	// touching anything on disk.
	Restorable bool `json:"restorable"`
	// ContainsSecrets is true when private keys are inside — which is the
	// normal case, and says plainly that this file is not shareable.
	ContainsSecrets bool `json:"contains_secrets"`
	// RedactedFiles lists what was replaced in a redacted archive, so the
	// gap is visible rather than silent.
	RedactedFiles []string `json:"redacted_files,omitempty"`
}

// Options control what Create writes.
type Options struct {
	// Redact leaves private keys out. The result is for diagnosis and cannot
	// be restored; Create marks it so and Restore honours the mark.
	Redact bool
	// Tool identifies the writer, e.g. "FlyingCerts/0.1.0".
	Tool string
	// Now overrides the clock in tests.
	Now func() time.Time
}

// redactedPlaceholder replaces a secret in a redacted archive. It is not valid
// PEM, on purpose: anything that tries to use it fails loudly at once.
const redactedPlaceholder = "[redacted by FlyingCerts backup -redact: this archive cannot be restored]\n"

// Create writes an archive of everything in paths to w.
//
// The return value is the manifest as written, which is what a caller reports
// to the operator: how many areas, whether it holds secrets, what was masked.
func Create(w io.Writer, paths Paths, opts Options) (*Manifest, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	man := &Manifest{
		Format:     FormatVersion,
		CreatedAt:  now().UTC(),
		Tool:       opts.Tool,
		Restorable: !opts.Redact,
	}

	// Collect first, write second. A half-written archive that stops at the
	// area with the unreadable file is worse than no archive, because it looks
	// like one.
	type entry struct {
		name string
		mode fs.FileMode
		data []byte
	}
	var entries []entry
	seen := map[Area]bool{}

	add := func(area Area, archiveName string, src string) error {
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("backup %s: %w", archiveName, err)
		}
		info, err := os.Stat(src)
		if err != nil {
			return fmt.Errorf("backup %s: %w", archiveName, err)
		}
		if secret := looksSecret(data); secret {
			if opts.Redact {
				man.RedactedFiles = append(man.RedactedFiles, archiveName)
				data = []byte(redactedPlaceholder)
			} else {
				man.ContainsSecrets = true
			}
		}
		seen[area] = true
		entries = append(entries, entry{name: archiveName, mode: info.Mode().Perm(), data: data})
		return nil
	}

	for _, area := range orderedAreas(paths.Dirs) {
		root := paths.Dirs[area]
		if root == "" {
			continue
		}
		if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
			// Nothing there yet is not a failure: a broker with no agents has
			// no state directory, and backing that up should still work.
			continue
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !d.Type().IsRegular() {
				// Symlinks and sockets are skipped deliberately: nothing this
				// program writes is one, so a link here is either a mistake or
				// someone's idea of a shortcut out of the archive.
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			return add(area, path.Join(string(area), filepath.ToSlash(rel)), p)
		})
		if err != nil {
			return nil, err
		}
	}

	for _, area := range orderedAreas(paths.Files) {
		for name, src := range paths.Files[area] {
			if src == "" {
				continue
			}
			if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err := add(area, path.Join(string(area), name), src); err != nil {
				return nil, err
			}
		}
	}

	for area := range seen {
		man.Areas = append(man.Areas, area)
	}
	sort.Slice(man.Areas, func(i, j int) bool { return man.Areas[i] < man.Areas[j] })
	sort.Strings(man.RedactedFiles)
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	manJSON, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return nil, err
	}
	manJSON = append(manJSON, '\n')
	if err := writeEntry(tw, manifestName, 0o644, man.CreatedAt, manJSON); err != nil {
		return nil, err
	}
	for _, e := range entries {
		if err := writeEntry(tw, e.name, e.mode, man.CreatedAt, e.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return man, nil
}

const manifestName = "manifest.json"

func writeEntry(tw *tar.Writer, name string, mode fs.FileMode, modTime time.Time, data []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     int64(mode.Perm()),
		Size:     int64(len(data)),
		ModTime:  modTime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// looksSecret reports whether the bytes hold private key material.
//
// PEM is what everything here writes, so matching the block type is exact
// rather than a guess. The ACME account key and the CA key both land in this
// branch, which is the point of #409.
func looksSecret(data []byte) bool {
	return bytes.Contains(data, []byte("PRIVATE KEY-----"))
}

func orderedAreas[T any](m map[Area]T) []Area {
	areas := make([]Area, 0, len(m))
	for a := range m {
		areas = append(areas, a)
	}
	sort.Slice(areas, func(i, j int) bool { return areas[i] < areas[j] })
	return areas
}

// ErrNotRestorable is returned for a redacted archive.
//
// It names the reason rather than letting the restore fail later on an
// unparseable key, because "your newest recovery point is not one" is
// something an operator must learn before the emergency, not during it.
var ErrNotRestorable = errors.New(
	"this archive was written with -redact and has had its keys removed: it is for diagnosis, " +
		"not recovery — restore from a full backup instead")

// Inspect reads only the manifest.
//
// Being able to ask "what is this file, and could I restore from it?" without
// unpacking is what makes a periodic check of the backups cheap enough to run.
func Inspect(r io.Reader) (*Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a FlyingCerts backup: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("not a FlyingCerts backup: %w", err)
	}
	if hdr.Name != manifestName {
		return nil, fmt.Errorf("not a FlyingCerts backup: first entry is %q, expected %q",
			hdr.Name, manifestName)
	}
	var man Manifest
	if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&man); err != nil {
		return nil, fmt.Errorf("unreadable manifest: %w", err)
	}
	if man.Format != FormatVersion {
		return nil, fmt.Errorf("archive format %d, this build understands %d",
			man.Format, FormatVersion)
	}
	return &man, nil
}

// Restore unpacks an archive into the paths given.
//
// It refuses a redacted archive before writing anything, and it maps areas to
// the paths of *this* host rather than the ones the archive was made on.
func Restore(r io.Reader, paths Paths) (*Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a FlyingCerts backup: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != manifestName {
		return nil, errors.New("not a FlyingCerts backup: no manifest")
	}
	var man Manifest
	if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&man); err != nil {
		return nil, fmt.Errorf("unreadable manifest: %w", err)
	}
	if man.Format != FormatVersion {
		return nil, fmt.Errorf("archive format %d, this build understands %d",
			man.Format, FormatVersion)
	}
	if !man.Restorable {
		return nil, ErrNotRestorable
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dest, err := destinationFor(hdr.Name, paths)
		if err != nil {
			return nil, err
		}
		if dest == "" {
			continue
		}
		if hdr.Size > MaxEntrySize {
			return nil, fmt.Errorf("entry %s is %d bytes, over the %d limit",
				hdr.Name, hdr.Size, int64(MaxEntrySize))
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxEntrySize+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > MaxEntrySize {
			return nil, fmt.Errorf("entry %s is over the %d byte limit", hdr.Name, int64(MaxEntrySize))
		}
		if err := writeRestored(dest, data, fs.FileMode(hdr.Mode).Perm(), looksSecret(data)); err != nil {
			return nil, err
		}
	}
	return &man, nil
}

// destinationFor maps an archive entry to a path on this host.
//
// It returns an empty path for an area this host does not configure, which is
// how a restore onto a broker without an endpoint skips the agent state
// instead of inventing a directory for it.
func destinationFor(name string, paths Paths) (string, error) {
	clean := path.Clean(name)
	if clean != name || strings.HasPrefix(clean, "/") || clean == ".." ||
		strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		// An archive is data, and data from outside decides nothing about
		// where this process writes.
		return "", fmt.Errorf("refusing archive entry %q: it points outside the restore target", name)
	}
	area, rest, ok := strings.Cut(clean, "/")
	if !ok || rest == "" {
		return "", fmt.Errorf("refusing archive entry %q: no area", name)
	}

	if files, ok := paths.Files[Area(area)]; ok {
		if dest, ok := files[rest]; ok {
			return dest, nil
		}
	}
	root, ok := paths.Dirs[Area(area)]
	if !ok || root == "" {
		return "", nil
	}
	return filepath.Join(root, filepath.FromSlash(rest)), nil
}

// writeRestored writes one file, narrowing the mode as it goes.
//
// The mode comes from the archive but is never trusted to widen anything: a
// key is 0600 no matter what the header says, and nothing is ever group- or
// world-writable. An archive that travelled through a careless tar should not
// be able to loosen permissions on restore.
func writeRestored(dest string, data []byte, archived fs.FileMode, secret bool) error {
	mode := archived & 0o644
	if secret {
		mode = 0o600
	}
	if mode == 0 {
		mode = 0o600
	}
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// MkdirAll leaves an existing directory's mode alone, so an already-wide
	// directory would keep a key readable. Narrow it explicitly.
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm()&0o007 != 0 {
		if err := os.Chmod(dir, info.Mode().Perm()&^0o007); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, ".fc-restore-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
