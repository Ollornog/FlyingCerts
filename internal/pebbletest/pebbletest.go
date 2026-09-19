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
	"strings"
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

// OrderIndexRace is the message Pebble returns when a renewal names a
// predecessor it has not finished indexing.
//
// It is a race inside the test server, not a client error and not something
// a real CA does. Pebble finalises an order in a goroutine and registers it
// in its by-serial index only afterwards (wfe/wfe.go):
//
//	go func() {
//	    wfe.ca.CompleteOrder(existingOrder)                  // certificate is fetchable
//	    err := wfe.db.AddOrderByIssuedSerial(existingOrder)  // only now findable
//	}()
//
// A client that collects the certificate and immediately renews it — naming
// it via ARI `replaces`, which is exactly what a correct client should do —
// can arrive between those two lines. Boulder has no such window, so nothing
// about this reaches production code.
const OrderIndexRace = "could not find order resulting in the given certificate serial number"

// IsOrderIndexRace reports whether an error is that race.
func IsOrderIndexRace(err error) bool {
	return err != nil && strings.Contains(err.Error(), OrderIndexRace)
}

// RetryPastOrderIndexRace runs fn, retrying only while Pebble is still
// indexing the predecessor order.
//
// Deliberately narrow: it matches one message from one test server and gives
// up quickly. A blanket retry would hide real failures, which is the whole
// objection to retrying in tests — this one waits out a known defect in the
// environment and lets everything else through untouched.
func RetryPastOrderIndexRace(t *testing.T, fn func() error) error {
	t.Helper()
	const attempts = 10
	var err error
	for i := range attempts {
		if err = fn(); !IsOrderIndexRace(err) {
			return err
		}
		t.Logf("Pebble has not indexed the predecessor order yet (attempt %d/%d); "+
			"this is the test server's race, not a failure of the code under test",
			i+1, attempts)
		time.Sleep(200 * time.Millisecond)
	}
	return err
}
