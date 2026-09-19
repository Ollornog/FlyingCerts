package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The same regression test as on the server side, for the same bug: `enrol
// -token X` must be read as a command with a flag, not as a command with two
// stray arguments. It was fixed in the server first and left here, which is
// why both binaries now have this test.
func TestFlagsAfterTheCommandAreRead(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
broker: https://127.0.0.1:1
identity_dir: `+dir+`/identity
certificates:
  - name: gateway-cert
    mode: issue
    domains: [gateway.example.com]
    cert_path: `+dir+`/tls.crt
    key_path: `+dir+`/tls.key
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := [][]string{
		{"-config", cfgPath, "enrol", "-token", "abc.def"},
		{"-config", cfgPath, "enrol", "-token", "abc.def", "-broker-ca", filepath.Join(dir, "ca.crt")},
		{"-config", cfgPath, "status"},
	}
	for _, args := range cases {
		err := runWith(t, args)
		if err == nil {
			continue
		}
		// Reaching the network and failing there is fine — that means the
		// command line was understood.
		for _, forbidden := range []string{
			"command is expected", "exactly one command", "unexpected argument",
			"flag provided but not defined",
		} {
			if strings.Contains(err.Error(), forbidden) {
				t.Errorf("`%s` was not understood: %v", strings.Join(args, " "), err)
			}
		}
	}
}

func runWith(t *testing.T, args []string) error {
	t.Helper()
	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })

	os.Args = append([]string{"flying-certs-agent"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(nopWriter{})
	return run()
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
