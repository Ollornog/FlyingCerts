package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Ollornog/FlyingCerts/internal/certinfo"
	"github.com/Ollornog/FlyingCerts/internal/pebbletest"
	"github.com/go-acme/lego/v5/certcrypto"
)

// The end-to-end run against a real ACME CA.
//
// Every other test in this package checks one part. This one checks that the
// parts are wired together, which is where the bugs actually live: an account
// that loads, an issuer that obtains, a store that keeps — each fine on its
// own and still useless if the chain between them is wrong.
//
// The CA is Pebble; internal/pebbletest says how to start it and what happens
// when it is missing.

func TestEndToEndAgainstPebble(t *testing.T) {
	pebbletest.Require(t)

	dir := t.TempDir()
	accounts, err := NewAccountStore(dir)
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	opts := ClientOptions{
		DirectoryURL: pebbletest.DirectoryURL,
		HTTPClient:   pebbletest.HTTPClient(),
		UserAgent:    "FlyingCerts-test",
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
		DNSProvider: pebbletest.ProviderName,
		Provider:    pebbletest.Provider{},
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
	//
	// Wrapped because Pebble indexes a finished order in a goroutine and a
	// correct client can arrive before it has (see OrderIndexRace). The wrap
	// waits out that one message and nothing else — every other error still
	// fails the test on the first try.
	var second *Result
	err = pebbletest.RetryPastOrderIndexRace(t, func() error {
		var err error
		second, err = issuer.Obtain(ctx, Request{Domains: []string{domain}, Replaces: pair.Leaf})
		return err
	})
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
	pebbletest.Require(t)

	dir := t.TempDir()
	accounts, err := NewAccountStore(dir)
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	opts := ClientOptions{DirectoryURL: pebbletest.DirectoryURL, HTTPClient: pebbletest.HTTPClient()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err := accounts.Register(ctx, opts, "admin@example.com", certcrypto.EC256); err != nil {
		t.Fatalf("Register: %v", err)
	}
	issuer, err := NewIssuer(IssuerConfig{
		Accounts:    accounts,
		Client:      opts,
		DNSProvider: pebbletest.ProviderName,
		Provider:    pebbletest.Provider{},
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
