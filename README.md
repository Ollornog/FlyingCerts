<p align="center"><img src="docs/flying-certs.png" alt="flying-certs" width="250" height="250"></p>

<h1 align="center">flying-certs</h1>

<p align="center"><b>English</b> · <a href="i18n/README.de.md">Deutsch</a></p>

<p align="right">
<a href="https://github.com/Ollornog/flying-certs/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/flying-certs/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-informational.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/go-1.27%2B-00ADD8.svg" alt="Go">
</p>

### Publicly trusted certificates for hosts that the internet cannot reach.

One host of yours is exposed and can talk to a CA. The rest are not — they sit on an internal
network, behind NAT, or on a mesh VPN. They still need certificates a browser trusts, because
your domain is in the HSTS preload list, or because your users carry phones you do not manage.

**flying-certs** puts a broker on the exposed host. It obtains certificates over ACME using a
DNS-01 challenge, and internal hosts **come and ask for theirs**. The broker knows who asked,
for what, and when — so it can also tell you which host is about to run out.

```
        ACME / DNS-01
   CA ◀──────────────▶  broker (exposed)          agent (internal)
                        · obtains + renews        · asks for its certificate
                        · authorises each ask  ◀──  · writes it to disk
                        · records who/what/when     · reloads the service
                        · tracks expiry per host    · verifies the reload took effect
```

## Why not just copy the files around

That is what most people do, and it works until it doesn't:

- **The private key travels.** One shared wildcard on a dozen hosts means one compromised host
  exposes every service under that name — and revoking it takes all of them down at once.
- **Nobody authorises the ask.** A file-copy job that is allowed to read a directory is allowed to
  read *all* of it. The filter usually lives on the client, which is the wrong side.
- **Nobody notices when it stops.** A copy job that silently does nothing looks exactly like a copy
  job with nothing to do — until a certificate expires in production.

flying-certs is the answer to those three, in that order.

## How a host joins

No long-lived shared secret, and no login on the broker.

1. You issue a **bootstrap token** on the broker for a named host. It is single-use and short-lived.
2. The agent redeems it **once** and receives its own client certificate.
3. From then on it authenticates with **mTLS** — nothing else is accepted. The broker knows every
   caller cryptographically, which is what makes the audit trail worth anything.
4. The agent renews its client certificate well before it expires, so it cannot lock itself out.

## Two delivery modes

Pick per host or per group. They are not equally good, and the docs say so.

**`issue` — a certificate of its own** *(recommended)*
The agent generates its key locally and sends only a CSR. **No private key ever travels.** The
broker obtains a certificate for that host from the CA and hands it back. Because the broker issues
per host, "when does this host expire" is a real question with a real answer.

**`share` — a shared certificate**
The broker hands out one certificate *and its private key* to every host authorised for it. Simpler,
and sometimes the only option — but the key travels, and every host holding it shares one fate.
Expiry is then a property of the certificate, not of the host.

## Status

Early. The interfaces are not stable yet. See [`backlog/`](backlog/) for what is planned and which
decisions have already been made, and [`CHANGELOG.md`](CHANGELOG.md) for what has shipped.

## What this is not

- **Not a CA.** It does not sign anything itself. It talks to a real ACME CA and passes the result on.
- **Not an ACME server.** Agents speak the flying-certs protocol, not ACME. Handing out someone
  else's certificate over ACME is not possible — ACME signs the CSR the client generated, and a leaf
  certificate cannot sign anything.
- **Not a replacement for letting each host do ACME itself.** If your hosts *can* reach a CA and hold
  their own DNS credentials safely, do that instead. This exists for when they cannot.

## Install

Binaries for Linux are attached to each [release](https://github.com/Ollornog/flying-certs/releases).
Verify what you downloaded:

```bash
sha256sum -c SHA256SUMS
```

## Documentation

- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Code of Conduct](CODE_OF_CONDUCT.md)
- [Backlog and decisions](backlog/)

## License

[MIT](LICENSE) — © 2026 ollornog
