package acme

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The two universal escape hatches must always be present. Without them the
// curated list (ADR-14) would lock out anyone whose provider is missing, and
// the whole argument for curating falls apart.
func TestUniversalProvidersArePresent(t *testing.T) {
	got := SupportedProviders()
	for _, needed := range []string{"rfc2136", "acmedns"} {
		if !slices.Contains(got, needed) {
			t.Errorf("%q is missing — without it, an unlisted provider means a dead end. Have: %v",
				needed, got)
		}
	}
}

func TestSupportedProvidersIsSortedAndComplete(t *testing.T) {
	got := SupportedProviders()
	if len(got) != len(providers) {
		t.Errorf("SupportedProviders lists %d, the map has %d", len(got), len(providers))
	}
	if !slices.IsSorted(got) {
		t.Errorf("not sorted: %v — the list appears in error messages, so its order should be stable", got)
	}
}

// An unknown name must not just fail; it must say what to do next.
func TestUnknownProviderExplainsTheWayOut(t *testing.T) {
	_, err := newDNSProvider("some-registrar-we-never-heard-of")
	if err == nil {
		t.Fatal("an unknown provider was accepted")
	}
	msg := err.Error()
	for _, expected := range []string{"rfc2136", "acmedns", "rebuild"} {
		if !strings.Contains(msg, expected) {
			t.Errorf("the error does not mention %q, leaving the user stuck:\n%s", expected, msg)
		}
	}
}

// Construction must fail on an unknown provider, not the first renewal.
func TestIssuerRejectsUnknownProviderAtConstruction(t *testing.T) {
	store, err := NewAccountStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	_, err = NewIssuer(IssuerConfig{
		Accounts:    store,
		Client:      ClientOptions{DirectoryURL: "https://ca.example.com/directory"},
		DNSProvider: "not-compiled-in",
	})
	if err == nil {
		t.Fatal("an unknown provider was accepted at construction — it would fail at 4am instead")
	}
	if !strings.Contains(err.Error(), "not-compiled-in") {
		t.Errorf("the error does not name the provider: %v", err)
	}
}

func TestIssuerRequiresAccountStoreAndProvider(t *testing.T) {
	if _, err := NewIssuer(IssuerConfig{DNSProvider: "cloudflare"}); err == nil {
		t.Error("an Issuer without an account store was accepted")
	}
	store, _ := NewAccountStore(t.TempDir())
	if _, err := NewIssuer(IssuerConfig{Accounts: store}); err == nil {
		t.Error("an Issuer without a DNS provider was accepted")
	}
}

// A wildcard and its base name share one _acme-challenge record. If they were
// locked separately, two orders would overwrite each other's TXT value — the
// failure Cert Warden chased through issues #23 and #74.
func TestWildcardAndBaseShareOneChallengeTarget(t *testing.T) {
	cases := []struct {
		name    string
		domains []string
		want    string
	}{
		{"plain", []string{"host.example.com"}, "_acme-challenge.host.example.com"},
		{"wildcard", []string{"*.example.com"}, "_acme-challenge.example.com"},
		{"base", []string{"example.com"}, "_acme-challenge.example.com"},
		{"mixed case", []string{"HOST.Example.COM"}, "_acme-challenge.host.example.com"},
	}
	for _, c := range cases {
		if got := challengeTarget(c.domains); got != c.want {
			t.Errorf("%s: challengeTarget(%v) = %q, want %q", c.name, c.domains, got, c.want)
		}
	}

	if challengeTarget([]string{"*.example.com"}) != challengeTarget([]string{"example.com"}) {
		t.Error("a wildcard and its base name map to different locks — they share one record")
	}
}

// fakeProvider records what it was asked to publish, without touching DNS.
type fakeProvider struct{ presented []string }

// Note the context arguments: lego v5 added them to challenge.Provider, so a
// solver written against v4 does not satisfy the interface any more.
func (f *fakeProvider) Present(_ context.Context, domain, token, keyAuth string) error {
	f.presented = append(f.presented, domain)
	return nil
}

func (f *fakeProvider) CleanUp(_ context.Context, domain, token, keyAuth string) error {
	return nil
}

// An injected provider must bypass the compiled-in list entirely — that is
// what makes the whole path testable and lets someone embed a provider we do
// not ship.
func TestInjectedProviderBypassesTheList(t *testing.T) {
	store, err := NewAccountStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewAccountStore: %v", err)
	}
	iss, err := NewIssuer(IssuerConfig{
		Accounts:    store,
		Client:      ClientOptions{DirectoryURL: "https://ca.example.com/directory"},
		DNSProvider: "something-not-compiled-in",
		Provider:    &fakeProvider{},
	})
	if err != nil {
		t.Fatalf("an injected provider was rejected: %v", err)
	}
	if iss.Provider() != "something-not-compiled-in" {
		t.Errorf("Provider() = %q — the name stays as a label", iss.Provider())
	}
}

// Obtain must stop at the missing account rather than reach for the network.
func TestObtainWithoutAccountFailsClearly(t *testing.T) {
	store, _ := NewAccountStore(t.TempDir())
	iss, err := NewIssuer(IssuerConfig{
		Accounts:    store,
		Client:      ClientOptions{DirectoryURL: "https://ca.invalid/directory"},
		DNSProvider: "rfc2136",
		Provider:    &fakeProvider{},
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	_, err = iss.Obtain(context.Background(), Request{Domains: []string{"host.example.com"}})
	if err == nil {
		t.Fatal("Obtain succeeded without an account")
	}
	if !strings.Contains(err.Error(), "account") {
		t.Errorf("error should point at the missing account: %v", err)
	}
}

func TestObtainRejectsEmptyRequest(t *testing.T) {
	store, _ := NewAccountStore(t.TempDir())
	iss, _ := NewIssuer(IssuerConfig{
		Accounts:    store,
		Client:      ClientOptions{DirectoryURL: "https://ca.example.com/directory"},
		DNSProvider: "rfc2136",
	})
	if _, err := iss.Obtain(context.Background(), Request{}); err == nil {
		t.Error("a request without domains was accepted")
	}
}
