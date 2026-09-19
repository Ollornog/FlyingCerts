# Contributing

<b>English</b> · <a href="i18n/CONTRIBUTING.de.md">Deutsch</a>
<br /><br />

Thanks for taking the time. This is a small project, so the rules are short.

## Before you write code

**Open an issue first** for anything beyond a typo or an obvious bug. This project makes security
trade-offs on purpose, and some of them look like mistakes until you know why. The reasoning lives
in [`backlog/`](backlog/) as decision records — please read the relevant one before proposing to
change what it decided.

## Workflow

- Work on a **feature branch**, not on `main`.
- Run the full suite before you push: `scripts/check.sh`. It must be green, and it must be green
  **twice in a row** — a test that fails on the second run is broken, not the code.
- Documentation and `CHANGELOG.md` travel in the **same commit** as the change they describe.
- Keep commits focused. One reason to change per commit.

## What the suite checks

Besides the Go tests, the suite enforces repository hygiene: required files, pinned GitHub Actions,
workflow permissions, changelog structure, and that the German and English documents keep the same
shape. If hygiene fails, fix the cause — do not work around the check.

## Security-relevant changes

Anything touching key handling, authentication, authorisation or the audit trail needs a test that
would have caught the problem it fixes. If you found a vulnerability, please follow
[SECURITY.md](SECURITY.md) instead of opening a pull request.

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
<br /><br />
<p align="right"><img src="docs/flying-certs.png" alt="flying-certs" width="60" height="60"></p>
