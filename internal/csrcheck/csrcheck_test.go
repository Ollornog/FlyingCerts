package csrcheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"strings"
	"testing"
)

func request(t *testing.T, cn string, dns []string, extras func(*x509.CertificateRequest)) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}
	if extras != nil {
		extras(tmpl)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return csr
}

func TestExactMatchIsAccepted(t *testing.T) {
	csr := request(t, "gateway.example.com", []string{"gateway.example.com"}, nil)
	if err := Verify(csr, []string{"gateway.example.com"}); err != nil {
		t.Errorf("an exact match was refused: %v", err)
	}
}

// The heart of it: an extra name is refused, not quietly dropped.
func TestExtraNameIsRefusedNotTrimmed(t *testing.T) {
	csr := request(t, "gateway.example.com",
		[]string{"gateway.example.com", "admin.example.com"}, nil)

	res := Check(csr, []string{"gateway.example.com"})
	if res.OK() {
		t.Fatal("a request with an extra name was accepted")
	}
	if len(res.Extra) != 1 || res.Extra[0] != "admin.example.com" {
		t.Errorf("Extra = %v, want the one name that is not permitted", res.Extra)
	}
	// The message has to name it, or the operator cannot act on it.
	if !strings.Contains(res.Error(), "admin.example.com") {
		t.Errorf("the error does not name the offending entry: %s", res.Error())
	}
}

// Subset is refused too, and that is the less obvious half. Allowing it turns
// one permission into several certificates in circulation.
func TestSubsetIsRefused(t *testing.T) {
	csr := request(t, "a.example.com", []string{"a.example.com"}, nil)
	res := Check(csr, []string{"a.example.com", "b.example.com"})
	if res.OK() {
		t.Fatal("a subset of the permitted names was accepted")
	}
	if len(res.Missing) != 1 || res.Missing[0] != "b.example.com" {
		t.Errorf("Missing = %v", res.Missing)
	}
}

// DNS does not care about case or a trailing dot, so neither may this — a
// check stricter than the thing it protects refuses identical requests.
func TestComparisonFollowsDNSRules(t *testing.T) {
	csr := request(t, "Gateway.Example.COM", []string{"Gateway.Example.COM."}, nil)
	if err := Verify(csr, []string{"gateway.example.com"}); err != nil {
		t.Errorf("a request differing only in case and trailing dot was refused: %v", err)
	}
}

// A common name outside the SANs must count, not be ignored: an ignored field
// is one someone will smuggle a name through.
func TestCommonNameOutsideSANsCounts(t *testing.T) {
	csr := request(t, "sneaky.example.com", []string{"gateway.example.com"}, nil)
	res := Check(csr, []string{"gateway.example.com"})
	if res.OK() {
		t.Fatal("a common name outside the permitted set was ignored")
	}
	if len(res.Extra) != 1 || res.Extra[0] != "sneaky.example.com" {
		t.Errorf("Extra = %v, want the common name", res.Extra)
	}
}

// Anything that is not a host name is refused outright.
func TestNonDNSIdentitiesAreRefused(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*x509.CertificateRequest)
		expect string
	}{
		{"ip", func(c *x509.CertificateRequest) {
			c.IPAddresses = []net.IP{net.ParseIP("198.51.100.1")}
		}, "198.51.100.1"},
		{"email", func(c *x509.CertificateRequest) {
			c.EmailAddresses = []string{"admin@example.com"}
		}, "admin@example.com"},
		{"uri", func(c *x509.CertificateRequest) {
			u, _ := url.Parse("spiffe://example.com/agent")
			c.URIs = []*url.URL{u}
		}, "spiffe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csr := request(t, "gateway.example.com", []string{"gateway.example.com"}, c.mutate)
			res := Check(csr, []string{"gateway.example.com"})
			if res.OK() {
				t.Fatalf("a request carrying an %s was accepted", c.name)
			}
			if !strings.Contains(res.Error(), c.expect) {
				t.Errorf("the error does not mention it: %s", res.Error())
			}
		})
	}
}

func TestWildcardIsMatchedLiterally(t *testing.T) {
	csr := request(t, "", []string{"*.internal.example.com"}, nil)
	if err := Verify(csr, []string{"*.internal.example.com"}); err != nil {
		t.Errorf("a permitted wildcard was refused: %v", err)
	}
	// A wildcard must not satisfy a permission for a concrete name.
	if err := Verify(csr, []string{"host.internal.example.com"}); err == nil {
		t.Error("a wildcard passed as a concrete name")
	}
	// And a concrete name must not satisfy a wildcard permission.
	concrete := request(t, "", []string{"host.internal.example.com"}, nil)
	if err := Verify(concrete, []string{"*.internal.example.com"}); err == nil {
		t.Error("a concrete name passed as a wildcard")
	}
}

func TestEmptyRequestIsRefusedWhenNamesArePermitted(t *testing.T) {
	csr := request(t, "", nil, nil)
	if err := Verify(csr, []string{"gateway.example.com"}); err == nil {
		t.Error("a request without names was accepted")
	}
}

func TestOrderDoesNotMatter(t *testing.T) {
	csr := request(t, "", []string{"b.example.com", "a.example.com"}, nil)
	if err := Verify(csr, []string{"a.example.com", "b.example.com"}); err != nil {
		t.Errorf("the same set in another order was refused: %v", err)
	}
}

func TestDuplicatesDoNotChangeTheOutcome(t *testing.T) {
	csr := request(t, "a.example.com", []string{"a.example.com", "a.example.com"}, nil)
	if err := Verify(csr, []string{"a.example.com"}); err != nil {
		t.Errorf("a repeated name was treated as an extra one: %v", err)
	}
}
