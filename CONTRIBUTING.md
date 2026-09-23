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
- Documentation-only changes take the fast path automatically — nothing to remember, but
  `scripts/check.sh --nur-hygiene` is the local equivalent if you want the same short loop.

## What the suite checks

Besides the Go tests, the suite enforces repository hygiene: required files, pinned GitHub Actions,
workflow permissions, changelog structure, and that the German and English documents keep the same
shape. If hygiene fails, fix the cause — do not work around the check.

## The documentation fast path

A change that touches **only** documentation does not need the Go toolchain or the test CA. The
CI leaves them out and runs hygiene instead — twice, because repeatability holds on every path:

```bash
scripts/check.sh --nur-hygiene      # ~0.3 s instead of ~50 s
```

`scripts/_nur_doku.sh` decides and names a reason for every boundary: `*.md` anywhere, `docs/`,
`i18n/`, `backlog/`, `LICENSE` count as documentation; everything else — including `go.mod`,
`examples/` and the workflows themselves — means the full suite.

Two things are deliberate. **Hygiene never gets skipped**: a service subdomain, a home directory
path or a customer name in a README is the same violation as one in code, so documentation may
take the short route *because* hygiene comes along, not because documentation is harmless. And
**when in doubt the full suite runs**: an empty diff, a missing base commit, a shallow clone, a
force push or a manual `workflow_dispatch` all resolve to "not only documentation".

The decision sits on **step** conditions inside the existing job, never on `paths-ignore`. A
workflow suppressed by a path filter never creates its check at all — it stays `Pending` and
blocks the pull request forever.

## Security-relevant changes

Anything touching key handling, authentication, authorisation or the audit trail needs a test that
would have caught the problem it fixes. If you found a vulnerability, please follow
[SECURITY.md](SECURITY.md) instead of opening a pull request.

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
<br /><br />
<p align="right"><img src="docs/FlyingCerts.png" alt="FlyingCerts" width="60" height="60"></p>
