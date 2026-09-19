// Package pebbletest talks to Pebble, Let's Encrypt's test CA, from tests.
//
// It lives in its own package because more than one suite needs a real CA:
// the issuer's end-to-end run and the backup's restore-then-renew run. Copying
// the DNS-01 solver into each would mean two of them drifting apart, and a
// solver that quietly stopped matching Pebble would make both tests pass for
// the wrong reason.
//
// Start the CA with:
//
//	docker network create fc-pebble
//	docker run -d --name fc-challtestsrv --network fc-pebble -p 8055:8055 \
//	  ghcr.io/letsencrypt/pebble-challtestsrv@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b \
//	  -defaultIPv6 "" -defaultIPv4 127.0.0.1
//	docker run -d --name fc-pebble --network fc-pebble -p 14000:14000 -e PEBBLE_VA_NOSLEEP=1 \
//	  ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199 \
//	  -dnsserver fc-challtestsrv:8053
//
// The digests are the same ones the workflows pin, and they are pinned rather
// than `latest` for the usual reason plus a specific one: the first v0.1.0
// release run failed here on an ARI call that passes locally and in CI, with
// the only uncontrolled difference being which image the runner had pulled.
//
// Give each suite a domain of its own. The challenge server is shared, go test
// runs packages concurrently, and CleanUp deletes a TXT record by name — so two
// suites using one name delete each other's answer and the CA finds nothing.
// That is the collision the zone lock prevents inside a process (ADR-9); across
// two test binaries no lock reaches, so the names have to differ.
//
// Nothing here is imported by the program itself.
package pebbletest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge/dns01"
)

// DirectoryURL and ChalltestsrvAPI are where the containers above listen.
const (
	DirectoryURL    = "https://localhost:14000/dir"
	ChalltestsrvAPI = "http://localhost:8055"
)

// ProviderName is what the issuer records as the DNS provider in these tests.
const ProviderName = "pebble-challtestsrv"

// Provider solves DNS-01 by telling Pebble's companion DNS server which TXT
// record to answer with.
type Provider struct{}

// Present publishes the challenge record.
func (Provider) Present(ctx context.Context, domain, _, keyAuth string) error {
	// lego computes both the record name and its value. Recomputing either by
	// hand is how a solver ends up publishing something the CA will not accept.
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return post("/set-txt", map[string]string{"host": info.FQDN, "value": info.Value})
}

// CleanUp removes it again.
func (Provider) CleanUp(ctx context.Context, domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return post("/clear-txt", map[string]string{"host": info.FQDN})
}

func post(path string, body map[string]string) error {
	enc, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(ChalltestsrvAPI+path, "application/json", bytes.NewReader(enc))
	if err != nil {
		return fmt.Errorf("challtestsrv %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

// HTTPClient trusts Pebble's self-signed chain. Acceptable here and nowhere
// else: this talks to a CA that hands out deliberately worthless certificates.
func HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test CA
		},
	}
}

// Reachable reports whether the test CA is answering.
func Reachable() bool {
	resp, err := HTTPClient().Get(DirectoryURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Require skips the calling test when Pebble is absent — except on the CI
// runner, where it fails instead.
//
// A test that is always skipped is decoration, not a gate, and the place that
// would never notice is the one that is supposed to be the gate.
func Require(t *testing.T) {
	t.Helper()
	if Reachable() {
		return
	}
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Fatalf("Pebble is not reachable at %s, and this must not be skipped on the CI runner",
			DirectoryURL)
	}
	t.Skipf("Pebble not reachable at %s — see the package comment for how to start it", DirectoryURL)
}
