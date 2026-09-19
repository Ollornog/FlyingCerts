// Package csrcheck decides whether a certificate request asks for exactly what
// it is allowed to ask for.
//
// This is the check none of the comparable projects performs, and the reason
// this project exists. acme-manager verifies that a CSR matches the *request*
// that accompanies it — but what may be requested is unrestricted: any token
// with `create` can ask for any syntactically valid name. Cert Warden has no
// CSR path at all.
//
// Two rules, both deliberate:
//
// **Exact set equality, not subset.** step-ca compares token names and CSR
// names with reflect.DeepEqual (sign_options.go), and that is the right
// strictness. "Subset" sounds safer — surely asking for less is fine? — but it
// quietly turns one permission into many: a host allowed a.example.com and
// b.example.com could obtain a certificate for a. alone, for b. alone, and for
// both, which is three different certificates in circulation where the
// operator expected one. Worse, it makes the permission a maximum rather than
// a description, and nobody reads it that way.
//
// **Reject, never trim.** A request with an extra name is refused, not
// silently reduced to the permitted ones. Trimming means the caller asks for
// one certificate and receives a different one, discovers it at the TLS
// handshake, and has nothing in the logs explaining why.
package csrcheck

import (
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
)

// Result explains a refusal in terms an operator can act on.
type Result struct {
	// Missing are permitted names the request left out.
	Missing []string
	// Extra are names the request asks for and is not permitted.
	Extra []string
	// Other lists non-DNS identities found in the request.
	Other []string
}

// OK reports whether the request matched exactly.
func (r Result) OK() bool { return len(r.Missing) == 0 && len(r.Extra) == 0 && len(r.Other) == 0 }

// Error renders the mismatch, naming both sides. "Not permitted" without
// saying what was expected leaves the operator guessing.
func (r Result) Error() string {
	var parts []string
	if len(r.Extra) > 0 {
		parts = append(parts, "not permitted: "+strings.Join(r.Extra, ", "))
	}
	if len(r.Missing) > 0 {
		parts = append(parts, "missing: "+strings.Join(r.Missing, ", "))
	}
	if len(r.Other) > 0 {
		parts = append(parts, "unsupported identities: "+strings.Join(r.Other, ", "))
	}
	return strings.Join(parts, "; ")
}

// Check compares the names in csr against permitted.
//
// Comparison is case-insensitive and ignores a trailing dot, because DNS is —
// and a certificate for Example.COM is a certificate for example.com. The
// comparison must not be stricter than the thing it protects, or it refuses
// requests that are in fact identical.
func Check(csr *x509.CertificateRequest, permitted []string) Result {
	var res Result

	// Anything that is not a DNS name is refused outright. This tool issues
	// certificates for host names; an IP, an email or a URI in the request is
	// either a mistake or an attempt at something else.
	for _, ip := range csr.IPAddresses {
		res.Other = append(res.Other, "IP "+ip.String())
	}
	for _, email := range csr.EmailAddresses {
		res.Other = append(res.Other, "email "+email)
	}
	for _, uri := range csr.URIs {
		res.Other = append(res.Other, "URI "+uri.String())
	}

	want := normaliseSet(permitted)
	got := normaliseSet(csr.DNSNames)

	// The common name is a name too, historically. If it carries something
	// that is not among the SANs, it counts as an extra name rather than
	// being ignored — an ignored field is a field someone will smuggle
	// something through.
	if cn := normalise(csr.Subject.CommonName); cn != "" {
		if _, inSANs := got[cn]; !inSANs {
			got[cn] = struct{}{}
		}
	}

	for name := range want {
		if _, ok := got[name]; !ok {
			res.Missing = append(res.Missing, name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			res.Extra = append(res.Extra, name)
		}
	}
	sort.Strings(res.Missing)
	sort.Strings(res.Extra)
	sort.Strings(res.Other)
	return res
}

// Verify is Check as an error, for callers that only want yes or no.
func Verify(csr *x509.CertificateRequest, permitted []string) error {
	if res := Check(csr, permitted); !res.OK() {
		return fmt.Errorf("certificate request does not match what this agent is permitted (%s)", res.Error())
	}
	return nil
}

func normalise(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func normaliseSet(names []string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n := normalise(n); n != "" {
			out[n] = struct{}{}
		}
	}
	return out
}
