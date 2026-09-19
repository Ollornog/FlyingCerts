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

Not yet — the interfaces are still moving. See [Status](#status).

## How a host joins

No long-lived shared secret, and no login on the broker.

1. You issue a **bootstrap token** on the broker for a named host. Single-use, short-lived, bound to
   that name *and* to the request it will be redeemed with.
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

What exists, all of it tested: atomic file writing with enforced permissions · certificate
inspection (pair validation, remaining lifetime, renewal timing) · the ACME account, which is loaded
and never silently replaced · the renewal decision, ARI first and a fraction of the lifetime as
fallback · serialisation of competing DNS-01 challenge records.

What does not exist yet: actually obtaining a certificate end to end, the mTLS API, and the agent.
Those are milestones **M-1** to **M-5** in [`backlog/`](backlog/).

The design decisions were made **before** the code, by studying what comparable projects got wrong —
each one is recorded as an ADR in [`backlog/`](backlog/) naming the mistake it avoids. If you
disagree with one, the reasoning is written down and can be argued with.

MIT license.

## Credits

Icon: <a href="https://www.flaticon.com/authors/slidicon" target="_blank" rel="noopener">Certificate icons created by Slidicon - Flaticon</a>
