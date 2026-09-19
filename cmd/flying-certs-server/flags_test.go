package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Flags written after the command name must be read.
//
// This is a regression test for a bug that appeared twice in this repository,
// once in each binary. Go's flag package stops parsing at the first non-flag
// argument, so `token -agent web1` left the flag unparsed and the command
// failed with "exactly one command expected" — while printing the usage block
// that says to write exactly that.
//
// It tests the real entry point rather than a helper, because the bug lived
// in the wiring between flag.Parse and the command switch, which is precisely
// what a helper would have skipped over.
func TestFlagsAfterTheCommandAreRead(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
acme:
  directory: staging
  email: admin@example.com
storage:
  account_dir: `+dir+`/account
  certificate_dir: `+dir+`/certs
dns:
  provider: rfc2136
certificates:
  - name: gateway
    domains: [gateway.example.com]
broker:
  state_dir: `+dir+`/state
agents:
  - name: web1
    certificates: [gateway]
    mode: issue
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
	}{
		{"token", []string{"-config", cfgPath, "token", "-agent", "web1"}},
		{"token with a lifetime", []string{"-config", cfgPath, "token", "-agent", "web1", "-token-lifetime", "10m"}},
		{"revoke", []string{"-config", cfgPath, "revoke", "-agent", "web1", "-reason", "testing"}},
		{"restore", []string{"-config", cfgPath, "restore", "-agent", "web1"}},
		{"backup", []string{"-config", cfgPath, "backup", "-out", filepath.Join(dir, "b.tar.gz")}},
		{"a command with no flags", []string{"-config", cfgPath, "agents"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := runWith(t, c.args)
			if err == nil {
				return
			}
			// Some of these legitimately fail on an empty state directory.
			// What must never happen is the parser refusing the shape of the
			// command line itself.
			for _, forbidden := range []string{
				"command is expected", "exactly one command", "unexpected argument",
				"flag provided but not defined", "-agent is required", "-out is required",
			} {
				if strings.Contains(err.Error(), forbidden) {
					t.Errorf("`%s` was not understood: %v", strings.Join(c.args, " "), err)
				}
			}
		})
	}
}

// An argument that really is stray is still refused, so the fix did not turn
// the parser into something that accepts anything.
func TestAStrayArgumentIsStillRefused(t *testing.T) {
	err := runWith(t, []string{"version", "extra"})
	if err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Errorf("a stray argument was accepted: %v", err)
	}
}

// runWith calls the real entry point with a fresh flag set.
func runWith(t *testing.T, args []string) error {
	t.Helper()
	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })

	os.Args = append([]string{"flying-certs-server"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(nopWriter{})
	return run()
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
