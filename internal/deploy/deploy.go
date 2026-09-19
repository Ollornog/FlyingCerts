// Package deploy writes a certificate where a service will find it, reloads
// that service, and then checks whether the reload actually did anything.
//
// The last part is the whole point, and it is what no comparable tool does.
//
// "The command exited 0" does not mean "the service now uses the new
// certificate". A documented example: `caddy reload` compares the *configuration*.
// Swap a certificate file on disk and the configuration is unchanged, so it
// logs "config is unchanged", does nothing, and exits 0. The old certificate
// stays in memory until the process restarts
// (caddyserver/caddy#6948). An agent that trusts the exit code reports success
// and stays quiet — for weeks, until the old certificate actually expires, at
// which point nothing in the logs points at the reload that never happened.
//
// step-ca has the mirror-image version: its daemon caches the private key at
// start, so replacing the file externally leaves it signing with the old one,
// silently (smallstep/cli#1632).
//
// So this package finishes by opening a TLS connection to the service and
// comparing the fingerprint of what is actually served against what was just
// written. Anything less is a hope, not a check.
package deploy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/atomicfile"
	"github.com/Ollornog/FlyingCerts/internal/certinfo"
)

// Target describes where a certificate goes and how to make it take effect.
type Target struct {
	// CertPath and KeyPath are where the files land. KeyPath may be empty in
	// the issue mode, where the key is already on the host.
	CertPath string
	KeyPath  string

	// Owner and Group set the key's ownership, for a service running as
	// another user. Empty leaves it as it is.
	Owner string
	Group string

	// KeyMode is the private key's permission. Zero means 0600.
	KeyMode os.FileMode

	// ReloadCommand is run after a change, as argv — no shell.
	//
	// No shell on purpose: it removes the injection surface entirely, and it
	// removes the quoting mistakes that come with it. step-ca has an open
	// issue about exactly that (smallstep/cli#1538), and acme-manager splits
	// its command on spaces, which breaks any argument containing one.
	ReloadCommand []string

	// ReloadTimeout bounds the command. Zero means DefaultReloadTimeout.
	ReloadTimeout time.Duration

	// VerifyAddress is where to check the result, e.g. "127.0.0.1:443".
	// Empty means the deployment cannot be confirmed, and the result says so
	// rather than claiming success.
	VerifyAddress string

	// VerifyServerName is the SNI to use. Empty means the address's host.
	VerifyServerName string

	// VerifyTimeout bounds the check. Zero means DefaultVerifyTimeout.
	VerifyTimeout time.Duration
}

// Defaults for the two operations that can hang.
const (
	DefaultReloadTimeout = 30 * time.Second
	DefaultVerifyTimeout = 10 * time.Second
)

// Outcome is what happened, in enough detail to act on.
type Outcome struct {
	// Changed reports whether anything was written.
	Changed bool
	// Reloaded reports whether the reload command ran.
	Reloaded bool
	// Verified reports whether the service was seen serving the new
	// certificate.
	Verified bool
	// VerifySkipped reports that no check was possible, because no address
	// was configured. Distinct from "checked and failed".
	VerifySkipped bool
	// Message is a one-line summary for a log.
	Message string
}

// ErrNotServing reports that the service is not serving what was deployed.
//
// This is the error that would have caught the caddy case: everything
// succeeded, and the service still answers with the old certificate.
var ErrNotServing = errors.New("the service is not serving the deployed certificate")

// Deploy writes the certificate, reloads, and verifies.
//
// Nothing happens when the files already hold this certificate: an agent that
// rewrites and reloads on every run turns a five-minute timer into a service
// restart every five minutes.
func Deploy(t Target, chainPEM, keyPEM []byte) (Outcome, error) {
	var out Outcome

	if t.CertPath == "" {
		return out, errors.New("no certificate path")
	}
	// Refuse to write a pair that does not belong together — that is how a
	// service ends up unable to start after what looked like a clean renewal.
	if len(keyPEM) > 0 {
		if _, err := certinfo.LoadPair(chainPEM, keyPEM); err != nil {
			return out, fmt.Errorf("refusing to deploy: %w", err)
		}
	}

	changed, err := writeIfDifferent(t, chainPEM, keyPEM)
	if err != nil {
		return out, err
	}
	out.Changed = changed
	if !changed {
		out.Message = "already current; nothing written"
		return out, nil
	}

	if len(t.ReloadCommand) > 0 {
		if err := runReload(t); err != nil {
			// The files are in place but the service does not know. Say so
			// plainly: this is a state someone has to look at.
			return out, fmt.Errorf("certificate written but the reload failed: %w", err)
		}
		out.Reloaded = true
	}

	if t.VerifyAddress == "" {
		out.VerifySkipped = true
		out.Message = "deployed and reloaded, but not confirmed — no verify_address configured"
		return out, nil
	}

	served, err := servedFingerprint(t)
	if err != nil {
		return out, fmt.Errorf("certificate written and reloaded, but the service could not be checked: %w", err)
	}
	want, err := fingerprintOfPEM(chainPEM)
	if err != nil {
		return out, err
	}
	if served != want {
		// The caddy case, caught.
		return out, fmt.Errorf("%w: it answers with %s, the deployed one is %s "+
			"(a reload that exits 0 does not mean the service reread the files)",
			ErrNotServing, short(served), short(want))
	}

	out.Verified = true
	out.Message = "deployed, reloaded, and confirmed being served"
	return out, nil
}

// writeIfDifferent writes only when the content actually differs.
func writeIfDifferent(t Target, chainPEM, keyPEM []byte) (bool, error) {
	same, err := fileHas(t.CertPath, chainPEM)
	if err != nil {
		return false, err
	}
	keySame := true
	if t.KeyPath != "" && len(keyPEM) > 0 {
		keySame, err = fileHas(t.KeyPath, keyPEM)
		if err != nil {
			return false, err
		}
	}
	if same && keySame {
		return false, nil
	}

	// Key first: if the chain write fails afterwards, a stale key alone is
	// harmless, while a new chain without its key looks complete and breaks
	// at the handshake.
	if t.KeyPath != "" && len(keyPEM) > 0 {
		mode := t.KeyMode
		if mode == 0 {
			mode = 0o600
		}
		if err := atomicfile.Write(t.KeyPath, keyPEM, mode); err != nil {
			return false, fmt.Errorf("write key: %w", err)
		}
		if err := applyOwnership(t.KeyPath, t.Owner, t.Group); err != nil {
			return false, err
		}
	}
	if err := atomicfile.WritePublic(t.CertPath, chainPEM); err != nil {
		return false, fmt.Errorf("write certificate: %w", err)
	}
	if err := applyOwnership(t.CertPath, t.Owner, t.Group); err != nil {
		return false, err
	}
	return true, nil
}

func fileHas(path string, want []byte) (bool, error) {
	got, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	return string(got) == string(want), nil
}

// applyOwnership sets owner and group when configured.
//
// A failure here is fatal rather than a warning: the usual reason to set an
// owner is that the service runs as another user, and getting it wrong means
// the service silently cannot read its key.
func applyOwnership(path, owner, group string) error {
	if owner == "" && group == "" {
		return nil
	}
	uid, gid := -1, -1
	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return fmt.Errorf("look up owner %q: %w", owner, err)
		}
		if uid, err = strconv.Atoi(u.Uid); err != nil {
			return fmt.Errorf("owner %q has a non-numeric uid: %w", owner, err)
		}
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("look up group %q: %w", group, err)
		}
		var err2 error
		if gid, err2 = strconv.Atoi(g.Gid); err2 != nil {
			return fmt.Errorf("group %q has a non-numeric gid: %w", group, err2)
		}
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("set ownership of %s: %w", path, err)
	}
	return nil
}

// runReload executes the reload command with a timeout.
func runReload(t Target) error {
	timeout := t.ReloadTimeout
	if timeout <= 0 {
		timeout = DefaultReloadTimeout
	}
	cmd := exec.Command(t.ReloadCommand[0], t.ReloadCommand[1:]...) //nolint:gosec // argv from config, no shell
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %q: %w", t.ReloadCommand[0], err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%q failed: %w (%s)", strings.Join(t.ReloadCommand, " "),
				err, strings.TrimSpace(output.String()))
		}
		return nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("%q did not finish within %s", strings.Join(t.ReloadCommand, " "), timeout)
	}
}

// servedFingerprint asks the service what it is actually serving.
func servedFingerprint(t Target) (string, error) {
	timeout := t.VerifyTimeout
	if timeout <= 0 {
		timeout = DefaultVerifyTimeout
	}
	serverName := t.VerifyServerName
	if serverName == "" {
		if host, _, err := net.SplitHostPort(t.VerifyAddress); err == nil {
			serverName = host
		}
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout}, "tcp", t.VerifyAddress,
		&tls.Config{
			ServerName: serverName,
			// Not verifying the chain is right here and only here: the
			// question is "which certificate is this service serving", not
			// "do I trust it". A local check against a service that is
			// deliberately reachable only from this host.
			InsecureSkipVerify: true, //nolint:gosec // fingerprint comparison, not trust
		})
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", t.VerifyAddress, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("%s presented no certificate", t.VerifyAddress)
	}
	return fingerprintOfDER(certs[0].Raw), nil
}

func fingerprintOfPEM(chainPEM []byte) (string, error) {
	chain, err := certinfo.ParseChain(chainPEM)
	if err != nil {
		return "", fmt.Errorf("read the deployed certificate: %w", err)
	}
	return fingerprintOfDER(chain[0].Raw), nil
}

func fingerprintOfDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func short(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "…"
}

// Leaf exposes the deployed leaf certificate, for callers that want to log
// what they just installed.
func Leaf(chainPEM []byte) (*x509.Certificate, error) {
	chain, err := certinfo.ParseChain(chainPEM)
	if err != nil {
		return nil, err
	}
	return chain[0], nil
}
