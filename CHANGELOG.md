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
