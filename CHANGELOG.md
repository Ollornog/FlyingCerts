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
- Expiry tracking: the broker records when each agent's identity runs out, set
  at enrolment and at every identity renewal.
- `check`, which separates the four situations worth acting on — never enrolled,
  silent, lockout soon, locked out — orders them by urgency and exits non-zero,
  so it works as a cron or monitoring probe. An agent revoked on purpose is not
  reported as a problem.
- `serve`, `token`, `agents`, `revoke` and `restore` on the server command. The
  endpoint issues its own TLS certificate from the agent CA, prunes spent tokens
  and rate-limit counters hourly, and shuts down gracefully.
- Backup and restore (`backup`, `backup-info`, `restore-backup`): one archive of
  everything that cannot be recreated, storing logical areas rather than host
  paths so a restore can land elsewhere. A redacted copy for diagnosis is marked
  not restorable and refused by name. The scope is one list, and a test walks the
  configuration struct so no new state directory can fall out of it silently.
  The end-to-end test destroys the whole state, restores it, reopens everything
  from disk and then renews against the CA and delivers to an agent that enrolled
  before the disaster (ADR-16).
- `internal/pebbletest`, so the issuance and recovery suites share one DNS-01
  solver instead of two copies drifting apart.

- Configurable identity lifetimes, per agent and broker-wide, written the way
  they are spoken about: `1d`, `30d`, `1d12h` — or `unlimited`, which means the
  identity runs until the agent CA does. Unset, a duration and unlimited are
  three distinct states, so "not configured" can never be mistaken for
  "expires immediately" nor unlimited for "very long". A bare number is
  refused: it reads as days to the author and as nanoseconds to a parser.
- `agents` gained a LIFETIME column, and shows an unlimited identity as the
  date it really stops rather than claiming an expiry the format cannot hold.
- `check` separates findings that need action from ones merely worth knowing.
  An unlimited identity is reported every run and never fails it — a standing
  state that always exits non-zero teaches people to stop reading the output.

- **Device keys, the ordinary way a host joins.** The agent generates a key
  pair on first run and never sends the private half anywhere; you authorise
  the host by putting the fingerprint in the broker's `public_key`, the same
  arrangement as `authorized_keys`. With it a host can ask for an identity at
  any time — including after one has expired, which closes the one failure
  that previously needed somebody to log in (ADR-7, ADR-18).
- `keygen` and `fingerprint` on the agent; `enrol` without `-token` uses the
  device key. `run` now heals itself: a missing or expired identity is
  replaced silently on the next run.
- The identity may not reuse the device key, and the broker refuses a request
  that tries. Keeping them apart is what keeps the long-lived secret out of
  daily traffic.
- Bootstrap tokens remain, as the alternative for when nobody wants to fetch a
  fingerprint off the host first.

### Changed
- The TLS layer no longer verifies client certificates; this package does,
  per route. `VerifyClientCertIfGiven` cannot express a device key, which is
  deliberately not signed by our CA. What moved into our code is checked by
  `verify_test.go`: a self-signed certificate claiming an agent's name,
  another CA's certificate, an expired one, a server certificate from our own
  CA, and none at all — each refused.
- `unlimited` is no longer the answer to "I do not want a host to lock itself
  out"; a device key is, and it does not give up the self-limiting property.
  ADR-17 carries the correction, including the part that was overstated: an
  unlimited mTLS identity is still not an API key, because the secret never
  travels and the broker stores none.

### Fixed
- `public_key` never reached the registry: present in the configuration, the
  registry and the handlers, with the one line that copies it left out. Every
  unit test passed and the feature did nothing. Found by running it by hand,
  and now guarded by a test that walks `AgentSpec` and fails on any field
  that is not carried across.
- `tls.Certificate.Leaf` was set to the template rather than to the parsed
  certificate, so it carried no public key.
- `token -agent NAME` printed the usage block instead of issuing a token. Go's
  `flag` stops at the first non-flag argument, so everything after the command
  name was left unparsed. Command flags are now read from their own flag set
  after the command name — the way a person types it. `-force` moved with them.
  The same bug was in `flying-certs-agent` (`enrol -token …`) and is fixed
  there too; both entry points now have a regression test.
- An agent identity could outlive the CA that issued it. The check was against
  the CA's nominal lifetime rather than its actual expiry, so a CA years into
  service would still hand out certificates that stop working for no visible
  reason. Too long a lifetime is now refused rather than silently shortened.
- `SignAgent` returns the expiry it issued instead of leaving the caller to
  recompute it. Two places working out the same date from the same inputs is
  how they come to disagree — and for an unlimited identity the recomputation
  was wrong by a decade.

### Changed
- Renamed from `flying-certs` to **FlyingCerts**, matching how the other
  projects here are named. The Go module path moved with it
  (`github.com/Ollornog/FlyingCerts`) and GitHub redirects the old repository
  URL. What stayed lower-case: the commands (`flying-certs-server`,
  `flying-certs-agent`), the paths under `/etc` and `/var`, and the contact
  address — those are Unix conventions, not the project's name.
- The README no longer claims a bootstrap token is bound to the CSR it will be
  redeemed with. It cannot be: the agent generates its key only at redemption.
  ADR-6 records the correction.
