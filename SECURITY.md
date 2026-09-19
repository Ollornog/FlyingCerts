# Security Policy

<b>English</b> · <a href="i18n/SECURITY.de.md">Deutsch</a>
<br /><br />

## Reporting a vulnerability

Please report security problems **privately**, not as a public issue.

- Preferred: GitHub's [private vulnerability reporting](https://github.com/Ollornog/FlyingCerts/security/advisories/new)
- Alternatively by e-mail: flying-certs-github@ollornog.de

Please include what you did, what you expected and what happened instead, plus the version or
commit you tested. A minimal reproduction helps more than anything else.

## What you can expect

- **An acknowledgement within 14 days.** This project is maintained by one person in their spare
  time — that is the promise that can actually be kept, so it is the one being made.
- An assessment of whether the report is confirmed, and if so, a fix or a documented mitigation.
- Credit in the release notes, unless you prefer otherwise.

## Supported versions

While the project is below 1.0, only the latest release receives fixes.

## Scope

This project handles private keys and issues credentials. Reports about the following are
especially welcome:

- A client obtaining a certificate it is not authorised for.
- Bootstrap tokens being replayable, guessable, or valid for longer than intended.
- An agent being able to read or write anything on the broker beyond its own certificates.
- The audit trail being incomplete or forgeable.
<br /><br />
<p align="right"><img src="docs/flying-certs.png" alt="FlyingCerts" width="60" height="60"></p>
