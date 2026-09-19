package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Ollornog/flying-certs/internal/certinfo"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/challenge/dns01"
)

// The end-to-end run against a real ACME CA.
//
// Every other test in this package checks one part. This one checks that the
// parts are wired together, which is where the bugs actually live: an account
// that loads, an issuer that obtains, a store that keeps — each fine on its
// own and still useless if the chain between them is wrong.
//
// It runs against Pebble, Let's Encrypt's test CA:
//
//	docker run -d --name fc-challtestsrv --network fc-pebble \
//	  -p 8055:8055 ghcr.io/letsencrypt/pebble-challtestsrv:latest \
//	  -defaultIPv6 "" -defaultIPv4 127.0.0.1
//	docker run -d --name fc-pebble --network fc-pebble \
//	  -p 14000:14000 -e PEBBLE_VA_NOSLEEP=1 \
//	  ghcr.io/letsencrypt/pebble:latest -dnsserver fc-challtestsrv:8053
//
// Without Pebble the test skips, so it never blocks anyone. In CI it must not
// skip — a test that is always skipped is decoration, not a gate.

const (
	pebbleDirectory = "https://localhost:14000/dir"
	challtestsrvAPI = "http://localhost:8055"
)

// challtestsrvProvider solves DNS-01 by telling Pebble's companion DNS server
// which TXT record to answer with.
type challtestsrvProvider struct{ t *testing.T }

func (p challtestsrvProvider) Present(ctx context.Context, domain, _, keyAuth string) error {
	// lego computes both the record name and its value; recomputing either by
	// hand is how a solver ends up publishing something the CA will not accept.
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return p.post("/set-txt", map[string]string{"host": info.FQDN, "value": info.Value})
}

func (p challtestsrvProvider) CleanUp(ctx context.Context, domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return p.post("/clear-txt", map[string]string{"host": info.FQDN})
}

func (p challtestsrvProvider) post(path string, body map[string]string) error {
	enc, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(challtestsrvAPI+path, "application/json", bytes.NewReader(enc))
	if err != nil {
		return fmt.Errorf("challtestsrv %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

// pebbleClient trusts Pebble's self-signed chain. Acceptable here and nowhere
// else: this talks to a CA that hands out deliberately worthless certificates.
func pebbleClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test CA
		},
	}
}

func pebbleReachable() bool {
	resp, err := pebbleClient().Get(pebbleDirectory)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func requirePebble(t *testing.T) {
	t.Helper()
	if pebbleReachable() {
		return
	}
	// On the GitHub runner a skip would hide a broken gate, so there it fails.
	// Locally (and inside ci-local, which has no Docker) skipping is fine.
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Fatalf("Pebble is not reachable at %s, and this must not be skipped on the CI runner", pebbleDirectory)
	}
	t.Skipf("Pebble not reachable at %s — see the comment at the top of this file", pebbleDirectory)
}

func TestEndToEndAgainstPebble(t *testing.T) {
	requirePebble(t)

	dir := t.TempDir()
	accounts, err := NewAccountStore(dir)
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	opts := ClientOptions{
		DirectoryURL: pebbleDirectory,
		HTTPClient:   pebbleClient(),
		UserAgent:    "flying-certs-test",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// --- 1. the account is created once and then reused -------------------
	acct, err := accounts.Register(ctx, opts, "admin@example.com", certcrypto.EC256)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if acct.GetRegistration().Location == "" {
		t.Fatal("the account carries no registration URL")
	}
	// The whole point of ADR-10: a second call must refuse rather than mint
	// another account.
	if _, err := accounts.Register(ctx, opts, "admin@example.com", certcrypto.EC256); err == nil {
		t.Error("a second Register succeeded — that is how you end up rate-limited")
	}
	loaded, err := accounts.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.GetRegistration().Location != acct.GetRegistration().Location {
		t.Error("the reloaded account is a different one")
	}

	// --- 2. obtain a certificate ------------------------------------------
	var logged bytes.Buffer
	issuer, err := NewIssuer(IssuerConfig{
		Accounts:    accounts,
		Client:      opts,
		DNSProvider: "pebble-challtestsrv",
		Provider:    challtestsrvProvider{t: t},
		// The record lives in Pebble's companion DNS server, which the local
		// resolver knows nothing about — the same shape as split-horizon DNS,
		// and exactly what this option exists for.
		DNS:     DNSOptions{SkipPropagationCheck: true},
		Secrets: []string{"PLACEHOLDER-provider-credential"},
		Log:     slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	const domain = "gateway.example.com"
	res, err := issuer.Obtain(ctx, Request{Domains: []string{domain}})
	if err != nil {
		t.Fatalf("Obtain: %v", err)
	}

	// --- 3. what came back is actually usable -----------------------------
	pair, err := certinfo.LoadPair(res.CertificatePEM, res.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("the CA's answer is not a usable pair: %v", err)
	}
	if got := pair.Leaf.DNSNames; len(got) != 1 || got[0] != domain {
		t.Errorf("DNSNames = %v, want [%s]", got, domain)
	}
	if certinfo.ExpiredAt(pair.Leaf, time.Now()) {
		t.Error("a freshly issued certificate is already expired")
	}
	if _, err := tls.X509KeyPair(res.CertificatePEM, res.PrivateKeyPEM); err != nil {
		t.Errorf("the pair does not load as a TLS certificate: %v", err)
	}

	// --- 4. renewal names its predecessor ---------------------------------
	// Without ReplacesCertID the rate-limit exemption in RFC 9773 §5 is lost
	// silently, and nobody notices until the limit bites.
	second, err := issuer.Obtain(ctx, Request{Domains: []string{domain}, Replaces: pair.Leaf})
	if err != nil {
		t.Fatalf("renewal with a replaces hint failed: %v", err)
	}
	newPair, err := certinfo.LoadPair(second.CertificatePEM, second.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("renewed pair unusable: %v", err)
	}
	if newPair.Leaf.SerialNumber.Cmp(pair.Leaf.SerialNumber) == 0 {
		t.Error("the renewal returned the same certificate")
	}

	// --- 5. nothing secret reached the log --------------------------------
	if strings.Contains(logged.String(), "PLACEHOLDER-provider-credential") {
		t.Error("a registered secret appeared in the log")
	}
}

// ARI against a CA that supports it. Pebble does, which makes this the only
// place the real path is exercised rather than a stand-in.
func TestRenewalInfoAgainstPebble(t *testing.T) {
	requirePebble(t)

	dir := t.TempDir()
	accounts, err := NewAccountStore(dir)
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	opts := ClientOptions{DirectoryURL: pebbleDirectory, HTTPClient: pebbleClient()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err := accounts.Register(ctx, opts, "admin@example.com", certcrypto.EC256); err != nil {
		t.Fatalf("Register: %v", err)
	}
	issuer, err := NewIssuer(IssuerConfig{
		Accounts:    accounts,
		Client:      opts,
		DNSProvider: "pebble-challtestsrv",
		Provider:    challtestsrvProvider{t: t},
		DNS:         DNSOptions{SkipPropagationCheck: true},
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	res, err := issuer.Obtain(ctx, Request{Domains: []string{"ari.example.com"}})
	if err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	pair, err := certinfo.LoadPair(res.CertificatePEM, res.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("LoadPair: %v", err)
	}

	info, err := issuer.RenewalInfo(ctx, pair.Leaf)
	if err != nil {
		t.Fatalf("RenewalInfo: %v", err)
	}
	decision := DecideRenewal(ctx,
		func(context.Context) (RenewalInfoFetcher, error) { return info, nil },
		pair.Leaf, time.Now(), time.Hour)
	if decision.Source != SourceARI {
		t.Errorf("Source = %q, want %q — the CA offers ARI, so it must be used",
			decision.Source, SourceARI)
	}
}
