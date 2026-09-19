// Package atomicfile writes files so that a reader never sees a partial one,
// and never sees one with wider permissions than intended.
//
// Both properties matter here because this program writes private keys.
//
// The permission trap is not the umask. A umask can only remove permission
// bits, never add them, so requesting 0600 directly from os.OpenFile always
// yields at most 0600. The dangerous pattern is os.Create (which asks for
// 0666) followed by a later Chmod: in between, the file sits on disk readable
// by everyone the umask did not exclude. So the mode goes into OpenFile, and
// there is no Chmod afterwards.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write creates or replaces name with data, using perm for the file mode.
//
// The replacement is atomic: data lands in a temporary file in the *same*
// directory, is flushed to disk, and is then renamed over the target. A reader
// opening the path at any moment sees either the old content or the new one.
//
// The temporary file must share a directory with the target, because rename is
// only atomic within one filesystem.
func Write(name string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(name)

	// O_EXCL: never reuse a leftover temp file, which might have been left
	// behind by a crashed run and could have the wrong mode or owner.
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(name)+"-")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	// From here on every failure must remove the temp file, otherwise a failed
	// write leaves key material lying around under a predictable-ish name.
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	// CreateTemp always uses 0600. Widening to perm is safe because the file is
	// not yet reachable under its final name; narrowing is the common case.
	if err = tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	// Flush before the rename. Filesystem ordering guarantees are not a
	// substitute for this: without the sync, a crash can leave the renamed
	// file present but empty.
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmpName, name); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, name, err)
	}

	// Durability of the *directory entry* needs its own flush. Best effort:
	// some filesystems do not support it, and a certificate that survives as
	// the older version is a far smaller problem than a failed write.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// WriteSecret writes data readable only by the owner. Use it for private keys.
func WriteSecret(name string, data []byte) error {
	return Write(name, data, 0o600)
}

// WriteGroupSecret writes data readable by the owner and the group. Use it when
// a service running under its own user must read the key — that is a deliberate
// widening, so it has its own name rather than hiding in a mode argument.
func WriteGroupSecret(name string, data []byte) error {
	return Write(name, data, 0o640)
}

// WritePublic writes data that carries no secret, such as a certificate chain.
func WritePublic(name string, data []byte) error {
	return Write(name, data, 0o644)
}
