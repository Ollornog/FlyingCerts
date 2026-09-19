<p align="center"><img src="docs/flying-certs.png" alt="flying-certs" width="250" height="250"></p>

<h1 align="center">flying-certs</h1>

<p align="center"><b>English</b> · <a href="i18n/README.de.md">Deutsch</a></p>

<p align="right">
<a href="https://github.com/Ollornog/flying-certs/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/flying-certs/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-informational.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/go-1.27%2B-00ADD8.svg" alt="Go">
</p>

### Publicly trusted certificates for hosts the internet cannot reach.

**One exposed host does the ACME work, the others come and ask.** Your internal machines sit behind
NAT, on a mesh VPN, or on a network no CA will ever reach — and they still need certificates a
browser trusts, because your domain is HSTS-preloaded or your users carry phones you do not manage.

- **Don't want a DNS API token on twelve machines?** → you won't need one. Only the broker holds it.
- **Don't want the same private key on twelve machines either?** → then don't. In `issue` mode the key never leaves the host.
- **Want to know which host is about to run out?** → the broker knows, because it issued each one.
- **Already running your own ACME on every host?** → then you don't need this. Keep doing that.

> **A quick word on positioning:** flying-certs is **not a CA** and **not an ACME server**. It talks
> to a real ACME CA on behalf of hosts that cannot, and hands the result to the host that asked.
> So it is **no replacement** for step-ca or Vault PKI — those give you your *own* trust root.
> This one gets you certificates the *public* already trusts.

**How it fits together:**

```
        ACME / DNS-01
   CA ◀──────────────▶  broker (exposed)          agent (internal)
                        · obtains + renews        · asks for its certificate
                        · authorises each ask  ◀──  · writes it to disk
                        · records who/what/when     · reloads the service
                        · tracks expiry per host    · verifies the reload took effect
```

**What you get:**

- 🔐 **mTLS, no shared secret** — one single-use token to enrol, a certificate of its own from then on
- 📜 **Two delivery modes** — a certificate per host (recommended) or one shared certificate
- 🛡️ **Name authorisation** — a host gets certificates for *its* names, and no others
- 📋 **An audit trail worth something** — the identity comes from the client certificate, not from a header
- ⏰ **Expiry per host** — and a warning before a host locks itself out
- 🔁 **ARI-driven renewal** — the CA says when, with a sane fallback when it doesn't
- ✅ **Reload verification** — the agent checks what the service *actually serves*, not the exit code

---

## Installation

Binaries for Linux are attached to each [release](https://github.com/Ollornog/flying-certs/releases):

```bash
curl -fsSLO https://github.com/Ollornog/flying-certs/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS         # verify before you run it
```

Or build from source (Go 1.27+):

```bash
go build ./cmd/flying-certs-server
go build ./cmd/flying-certs-agent
```

## Quickstart

Write a configuration file (there is a commented example in
[`examples/config.yaml`](examples/config.yaml)), then:

```bash
export DNSUPDATE_NAMESERVER=ns.example.com:53      # your provider's credentials,
export DNSUPDATE_TSIG_SECRET=…                     # from the environment, not the file

flying-certs-server -config config.yaml register   # once: create the ACME account
flying-certs-server -config config.yaml obtain     # fetch what is not there yet
flying-certs-server -config config.yaml list       # see what you have
```

```
NAME               DOMAINS                   EXPIRES     REMAINING
gateway            gateway.example.com       2026-12-18  89 days left
internal-wildcard  *.internal.example.com    2026-12-18  89 days left
```

Then run `renew` from a timer. It asks the CA when it would prefer to be asked
(ARI) and otherwise renews after two thirds of the lifetime, so the same timer
works for 90-day and for 6-day certificates:

```bash
flying-certs-server -config config.yaml renew
```

Start against `directory: staging` — its certificates are worthless and its rate
limits forgiving, which is what you want while finding out whether your DNS
credentials work.

## How a host joins

No long-lived shared secret, and no login on the broker.

1. You issue a **bootstrap token** on the broker for a named host. Single-use, short-lived, and bound
   to that name and to the broker's own CA. It is *not* bound to the CSR: the agent generates its key
   only when it redeems the token, so there is nothing to bind to yet. ADR-6 records that correction
   rather than hiding it — a promise a protocol cannot keep is worse than one never made.
2. The agent redeems it **once** and receives its own client certificate.
3. From then on it authenticates by **mTLS** — nothing else is accepted.
4. It renews that certificate well before expiry, so it cannot lock itself out.

If it *does* expire, there is no automatic way back: an expired certificate cannot authenticate to
ask for its own replacement. That is deliberate, and the broker warns you long before it happens.

## Two delivery modes

Pick per host or per group. They are not equally good, and this says so.

**`issue` — a certificate of its own** *(recommended)*
The agent generates its key locally and sends only a CSR. **No private key ever travels.** The broker
checks every name in that CSR against what this host is allowed to have, then obtains the
certificate. Because it issues per host, "when does this host expire" has a real answer.

**`share` — a shared certificate**
The broker hands one certificate *and its private key* to every host authorised for it. Simpler, and
sometimes the only option — but the key travels, and every host holding it shares one fate. Expiry is
then a property of the certificate, not of the host.

## Running the broker

`obtain` and `renew` need nothing but a timer. Serving agents is a separate command:

```bash
flying-certs-server -config config.yaml serve              # the mTLS endpoint
flying-certs-server -config config.yaml token -agent web1  # one-time, prints the token
flying-certs-server -config config.yaml agents             # who is enrolled, and until when
flying-certs-server -config config.yaml check              # exits non-zero when something needs you
```

```
AGENT  MODE   LAST SEEN  IDENTITY     CERTIFICATES
web1   issue  2 h ago    27 days      1
gw     share  9 days     4 days left  2
```

`check` is the one meant for cron or a monitoring probe. It reports four situations and exits
non-zero for any of them, most urgent first:

| | |
|---|---|
| **never enrolled** | configured, but has never collected an identity |
| **silent** | has not been in touch for a week — its timer has probably stopped |
| **lockout soon** | its identity runs out before it can plausibly renew itself |
| **locked out** | its identity has expired; it now needs a new token by hand ([ADR-7](backlog/ADR-7-kein-weg-zurueck-nach-ablauf.md)) |

An agent you revoked on purpose is not reported as a problem.

```bash
flying-certs-server -config config.yaml revoke -agent web1 -reason "decommissioned"
flying-certs-server -config config.yaml restore -agent web1
```

A revocation takes effect on that agent's next request, not at the next restart.

## Backups

The ACME account key and the agent CA cannot be recreated. Lose the first and no renewal will ever
succeed again; lose the second and every agent is locked out with no way back.

```bash
flying-certs-server -config config.yaml backup -out /backup/broker-$(date +%F).tar.gz
flying-certs-server -config config.yaml backup-info -in /backup/broker-2026-09-20.tar.gz
flying-certs-server -config config.yaml restore-backup -in /backup/broker-2026-09-20.tar.gz
```

The archive holds private keys and says so. `-redact` leaves them out for a diagnosis copy — that
copy is marked **not restorable**, and `restore-backup` refuses it by name rather than failing
halfway through. `backup-info` answers "could I actually restore from this?" in a second and exits
non-zero when the answer is no, which is the check worth running on a schedule.

What makes this more than a `tar` wrapper is the test: it destroys the whole state, restores it,
reopens everything from disk, and then **renews against the CA and delivers to an agent that
enrolled before the disaster**. [ADR-16](backlog/ADR-16-sicherung.md) explains why — four separate
backup failures in a comparable project, every one of them a backup that had been checked only for
"the files came back".

## DNS providers

DNS-01 is the only challenge this tool uses, so it needs to write a TXT record. Compiled in:

`acmedns` · `cloudflare` · `desec` · `digitalocean` · `hetzner` · `rfc2136` · `route53`

That is seven out of lego's 200-plus, and the choice is deliberate: importing all of them costs
**1546 built packages instead of 424**, dragging in the SDKs of AWS, Azure, Google Cloud, Alibaba,
Akamai and others. For a program whose job is holding private keys, that supply chain works
against the purpose.

**Your provider is not listed? You are not stuck**, and that is what makes the short list
defensible:

- **`rfc2136`** speaks to any standard authoritative DNS server (BIND, Knot, PowerDNS) using
  dynamic update with a TSIG key — and a TSIG key can be scoped to a single record name.
- **`acmedns`** delegates challenge records by CNAME to a tiny service that can do nothing else.
  It needs **no provider token at all**, which is a better security model than handing out a
  full DNS API token in the first place.

Either of those beats a broad provider token. If you still want your own, add one import line in
`internal/acme/providers.go` and rebuild — see [ADR-14](backlog/ADR-14-dns-anbieter-auswahl.md)
for why this is a decision rather than a default.

## Tests & CI

```bash
scripts/check.sh            # the full gate: gofmt, vet, go test -race, hygiene, residue
scripts/check.sh --fast     # without the race detector (only when in a hurry)
```

The gate runs two things side by side, because the code is Go and the repository hygiene comes from a
shared Python base:

- **`go test -race ./...`** — the race detector belongs in the normal run, not a special one: the
  broker serves many agents at once and shares certificate state between them.
- **`tests/test_repo.py`** — guards the housekeeping: version in `internal/version` matches the
  changelog, no private infrastructure, no secrets, no key files, Actions pinned by commit SHA,
  `permissions:` on every workflow, German and English documents keeping the same shape.

**Before every push** — one gate, locally:

```bash
git config core.hooksPath .githooks   # once per clone: the pre-push hook runs the gate
scripts/check.sh
```

**GitHub Actions** runs the same gate **twice** on every push. A test that goes red on the second run
is broken, not the code — so the repeatability promise is demonstrated rather than claimed.

## Status

**Early, and honest about it.** The interfaces are not stable and there is no usable release yet.

All five milestones in [`backlog/`](backlog/) are done. The broker obtains and keeps certificates,
serves them over mTLS, tracks who collected what and when each identity runs out, warns before a
host locks itself out, and can be backed up and restored. Agents enrol with a one-time token,
collect over mTLS, and verify that their reload actually took effect.

**Proven end to end against a real CA.** Two runs against Pebble, Let's Encrypt's test CA, on every
CI run: the issuance path (account, DNS-01, renewal naming its predecessor, ARI) and the recovery
path (destroy everything, restore, renew, deliver). Both fail rather than skip when the test CA is
missing, because a test that quietly skips is decoration.

The design decisions were made **before** the code, by studying what comparable projects got wrong —
each one is recorded as an ADR in [`backlog/`](backlog/) naming the mistake it avoids. Where one
turned out to be wrong, the ADR says so instead of being quietly rewritten. If you disagree with
one, the reasoning is written down and can be argued with.

MIT license.

## Credits

Icon: <a href="https://www.flaticon.com/authors/slidicon" target="_blank" rel="noopener">Certificate icons created by Slidicon - Flaticon</a>
