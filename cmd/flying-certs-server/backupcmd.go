package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/backup"
	"github.com/Ollornog/FlyingCerts/internal/config"
	"github.com/Ollornog/FlyingCerts/internal/version"
)

// cmdBackup writes an archive of everything the broker cannot recreate.
func cmdBackup(cfg *config.Config, out string, redact bool) error {
	if out == "" {
		return errors.New("-out is required: name the file to write")
	}

	// A backup that lands inside the state it is backing up is not one. It is
	// also the kind of mistake that only shows up when the disk is gone.
	if inside, area := withinState(cfg, out); inside {
		return fmt.Errorf("refusing to write the backup to %s: that is inside the %s area, "+
			"so it would be lost together with what it is supposed to save", out, area)
	}

	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists — backups are not overwritten, "+
				"so a working recovery point cannot be replaced by a failed run", out)
		}
		return err
	}
	// Remove a half-written file rather than leave something that looks like a
	// recovery point. Success clears this.
	complete := false
	defer func() {
		f.Close()
		if !complete {
			_ = os.Remove(out)
		}
	}()

	man, err := backup.Create(f, backup.PathsFor(cfg), backup.Options{
		Redact: redact,
		Tool:   "FlyingCerts/" + version.Version,
	})
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	complete = true

	areas := make([]string, 0, len(man.Areas))
	for _, a := range man.Areas {
		areas = append(areas, string(a))
	}
	fmt.Printf("wrote %s\n  areas:      %s\n", out, strings.Join(areas, ", "))
	if cfg.Storage.AccountDir != "" && !hasArea(man.Areas, backup.AreaAccount) {
		// Not an error: a broker that has not registered yet has nothing to
		// save. It is worth saying out loud, because this is the one file
		// whose absence turns a restore into a dead end (certmate#410).
		fmt.Printf("  note:       no ACME account was found in %s, so this archive cannot renew "+
			"anything on its own\n", cfg.Storage.AccountDir)
	}
	switch {
	case man.Restorable && man.ContainsSecrets:
		fmt.Printf("  restorable: yes\n" +
			"  contents:   private keys — treat this file like the keys themselves\n")
	case man.Restorable:
		fmt.Printf("  restorable: yes\n  contents:   no private keys were found\n")
	default:
		fmt.Printf("  restorable: NO — keys were removed (%d file(s))\n"+
			"  contents:   for diagnosis only; keep a full backup as the recovery point\n",
			len(man.RedactedFiles))
	}
	return nil
}

// cmdBackupInfo reads an archive's manifest without unpacking it.
//
// This is what a periodic check of the backup directory runs: it answers
// "could I actually restore from this" in a second, which is the question
// nobody asks until it is too late to change the answer.
func cmdBackupInfo(in string) error {
	if in == "" {
		return errors.New("-in is required: name the archive to inspect")
	}
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()

	man, err := backup.Inspect(f)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n  taken:      %s (%s)\n  written by: %s\n",
		in, man.CreatedAt.Format("2006-01-02 15:04:05 MST"), describeAgo(time.Since(man.CreatedAt)), man.Tool)
	areas := make([]string, 0, len(man.Areas))
	for _, a := range man.Areas {
		areas = append(areas, string(a))
	}
	fmt.Printf("  areas:      %s\n", strings.Join(areas, ", "))
	if man.Restorable {
		fmt.Println("  restorable: yes")
		return nil
	}
	fmt.Printf("  restorable: NO — %d file(s) were redacted:\n", len(man.RedactedFiles))
	for _, name := range man.RedactedFiles {
		fmt.Printf("                %s\n", name)
	}
	// Non-zero, so a cron job that inspects the newest archive notices that
	// the newest recovery point is not one.
	return errors.New("this archive cannot be used to restore")
}

// cmdRestore unpacks an archive over this host's state.
func cmdRestoreBackup(cfg *config.Config, in string, force bool) error {
	if in == "" {
		return errors.New("-in is required: name the archive to restore")
	}
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()

	man, err := backup.Inspect(f)
	if err != nil {
		return err
	}
	if !man.Restorable {
		return backup.ErrNotRestorable
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	// Restoring over a live broker replaces its account key and its agent CA.
	// Doing that by accident locks out every agent, so it takes a second word.
	if existing := statePresent(cfg); existing != "" && !force {
		return fmt.Errorf("%s already holds state (%s): restoring would replace the account key "+
			"and the agent CA, which locks out every agent that trusts the current one — "+
			"pass -force if that is what you mean", cfg.Broker.StateDir, existing)
	}

	restored, err := backup.Restore(f, backup.PathsFor(cfg))
	if err != nil {
		return err
	}
	areas := make([]string, 0, len(restored.Areas))
	for _, a := range restored.Areas {
		areas = append(areas, string(a))
	}
	fmt.Printf("restored %s from %s\n  taken: %s\n\n",
		strings.Join(areas, ", "), in, restored.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Println("Now prove it worked, because a restore that only put the files back is the" +
		"\nfailure this program is built to avoid:")
	fmt.Println("  flying-certs-server list       # the certificates are readable")
	fmt.Println("  flying-certs-server agents     # the registry knows who enrolled")
	fmt.Println("  flying-certs-server renew      # the ACME account still works")
	return nil
}

// withinState reports whether a path sits inside one of the directories that
// hold state.
func withinState(cfg *config.Config, path string) (bool, string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, ""
	}
	for name, dir := range map[string]string{
		"account":      cfg.Storage.AccountDir,
		"certificates": cfg.Storage.CertificateDir,
		"state":        cfg.Broker.StateDir,
	} {
		if dir == "" {
			continue
		}
		root, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return true, name
	}
	return false, ""
}

// statePresent names the first thing a restore would overwrite, or "".
func statePresent(cfg *config.Config) string {
	for what, path := range map[string]string{
		"an ACME account": filepath.Join(cfg.Storage.AccountDir, "account.key"),
		"an agent CA":     filepath.Join(cfg.Broker.StateDir, "ca", "agent-ca.key"),
	} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return what
		}
	}
	return ""
}

// hasArea reports whether an area made it into an archive.
func hasArea(areas []backup.Area, want backup.Area) bool {
	for _, a := range areas {
		if a == want {
			return true
		}
	}
	return false
}
