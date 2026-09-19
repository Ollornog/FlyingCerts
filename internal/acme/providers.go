package acme

import (
	"fmt"
	"sort"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/acmedns"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/providers/dns/desec"
	"github.com/go-acme/lego/v5/providers/dns/digitalocean"
	"github.com/go-acme/lego/v5/providers/dns/dnsupdate"
	"github.com/go-acme/lego/v5/providers/dns/hetzner"
	"github.com/go-acme/lego/v5/providers/dns/route53"
)

// providers are the DNS providers compiled into this binary.
//
// lego offers over 200. Importing them all is one line and costs 1546 built
// packages instead of 424 (measured with `go list -deps`), pulling in the SDKs
// of AWS, Azure, Google Cloud, Alibaba, Akamai, Tencent and others. For a program whose whole job is holding
// private keys, that supply chain works against the purpose.
//
// Nobody is locked out by this list, and that is what makes it defensible:
//
//   - rfc2136 speaks to any common authoritative DNS server (BIND, Knot,
//     PowerDNS) via dynamic update with a TSIG key. Note lego v5 renamed this
//     package to "dnsupdate"; the name kept here is the one people search for.
//   - acmedns is the delegation approach: a CNAME points challenge records at a
//     tiny service that can do nothing else. It needs no provider token at all,
//     which is the better security model anyway.
//
// To add one: import it above and add a line here. That is the whole change.
// It is deliberately a decision with a reason rather than a default, because a
// list that grows on "it does no harm" ends up back at 1546.
var providers = map[string]func() (challenge.Provider, error){
	"acmedns":      func() (challenge.Provider, error) { return acmedns.NewDNSProvider() },
	"cloudflare":   func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() },
	"desec":        func() (challenge.Provider, error) { return desec.NewDNSProvider() },
	"digitalocean": func() (challenge.Provider, error) { return digitalocean.NewDNSProvider() },
	"hetzner":      func() (challenge.Provider, error) { return hetzner.NewDNSProvider() },
	"rfc2136":      func() (challenge.Provider, error) { return dnsupdate.NewDNSProvider() },
	"route53":      func() (challenge.Provider, error) { return route53.NewDNSProvider() },
}

// SupportedProviders lists the compiled-in provider names, sorted.
func SupportedProviders() []string {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// newDNSProvider builds the named provider. Its credentials come from the
// environment, which is lego's convention and keeps them out of our config file.
//
// An unknown name fails with the list of what is available and a pointer to the
// two universal options, because "provider not found" without that is a dead end.
func newDNSProvider(name string) (challenge.Provider, error) {
	build, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf(
			"DNS provider %q is not compiled into this build; available: %v. "+
				"For a provider that is not listed, use rfc2136 (any standard DNS server) or "+
				"acmedns (CNAME delegation, needs no provider token), or add it to "+
				"internal/acme/providers.go and rebuild",
			name, SupportedProviders())
	}
	p, err := build()
	if err != nil {
		return nil, fmt.Errorf("configure DNS provider %q: %w", name, err)
	}
	return p, nil
}
