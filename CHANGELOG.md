# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository scaffolding, bilingual community files and the shared test base.
- Backlog with milestones and the architecture decisions taken so far.
- Atomic file writing with enforced permissions, so a reader never sees a partial
  file nor one wider than intended.
- Certificate inspection: pair validation via the standard library, remaining
  lifetime as a duration, and renewal timing as a fraction of the lifetime.
- ACME account handling that loads an existing account and refuses to register a
  second one.
- Renewal decision driven by ARI where the CA offers it, falling back to the
  lifetime fraction where it does not.
- Serialisation of orders competing for the same DNS-01 challenge record.
- A logging redactor that removes known secrets from anything the ACME library
  writes, by value as well as by attribute name.
- Certificate issuance over DNS-01, with the ARI `replaces` hint so renewals are
  exempt from rate limits.
- A curated set of seven DNS providers, including `rfc2136` and `acmedns` so no
  provider is a dead end.
- A certificate store: chain, key and metadata per certificate, written
  atomically and never stored as a mismatched pair.
- Configuration with strict parsing — an unknown key is an error, not a default.
- `flying-certs-server` with `register`, `obtain`, `renew`, `list`, `providers`
  and `version`, plus a commented example configuration.
- An end-to-end test against Pebble, Let's Encrypt's test CA, covering account
  creation, issuance over DNS-01, renewal with the ARI `replaces` hint, and the
  guarantee that no credential reaches the log. It runs in CI, where it fails
  rather than skips if the test CA is missing.
- An internal CA that issues agent identities — separate from the public
  certificates in every respect, and never handed out (ADR-15).
- Single-use bootstrap tokens, made single-use by an atomic rename rather than
  a flag, so two simultaneous redemptions cannot both succeed. The guarantee
  survives a restart.
- An agent registry that answers "may this agent have this certificate?" by
  lookup, never by inference — the gap none of the comparable projects closes.
- The agent-facing API over mTLS: enrolment, certificate fetch honouring the
  delivery mode, identity renewal, and an append-only audit log.
- Rate limiting on enrolment, keyed on the remote address rather than on
  anything the caller can choose, with a bounded counter store.
- The `issue` mode: an agent sends a CSR and the broker obtains a certificate
  for it, so the private key never leaves the host. Every name in the request
  is checked against exactly what that agent is permitted — refused, never
  trimmed, and refused before the CA is contacted.
- `flying-certs-agent`: enrols once with a bootstrap token, then collects its
  certificates over mTLS and deploys them.
- Deployment that verifies itself: after the reload, the agent opens a TLS
  connection to the service and compares fingerprints. A reload that exits 0
  without rereading its files is caught instead of reported as success.
