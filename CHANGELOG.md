# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-19

First release. The header stage, extracted from the Sarv Inbox mail client,
where these rules run on real mail at ingest.

### Added

- **Verdict plumbing** (`/verdict`, zero dependencies) — `SPAM_THRESHOLD`,
  `SUSPICIOUS_THRESHOLD`, `spamVerdict`, `isSpamScore`, `parseSpamReasons`, and
  the `SpamReason` / `AuthStatus` types. Importable on its own so a renderer can
  read a stored score back without pulling in a scanner.
- **Sender identity** (`/identity`, `tldts` only) — `registrableDomain`,
  `domainOfAddress`, `domainsInText` and `assessSender`, which flags a friendly
  name claiming one brand while the address belongs to another eTLD+1.
- **Authentication results** — `extractAuthHeaderBlock` pulls the
  `Authentication-Results` / `ARC-Authentication-Results` / `Received-SPF`
  block out of a raw header dump, and `parseAuthenticationHeaders` reads the
  SPF/DKIM/DMARC verdicts out of it. Reads what your MTA decided; does not
  verify against DNS.
- **Origin IP** — `extractOriginIp` and friends, returning the public unicast
  address a message actually came from, preferring the SPF evaluator's own
  record over the `Received:` trace and rejecting private, loopback,
  link-local, CGNAT and reserved ranges.

### Security

- Both regular expressions carried over from the originating codebase were
  rewritten to be free of super-linear backtracking, and
  `regexp/no-super-linear-backtracking` is enforced as an **error** in this
  repository rather than a warning. This package's input is mail an attacker
  chose, parsed at ingest: a quadratic pattern against a large header block is
  not a slow scan, it is a mail flow that stops.
- The `Received:` `from` clause is walked token by token instead of matched,
  which cannot backtrack at all, and stops at `by` and `;` so that an address
  appearing in a timestamp or in the receiving side of a hop can never be
  reported as the origin.

[Unreleased]: https://github.com/Sarv/email-spam-scan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Sarv/email-spam-scan/releases/tag/v0.1.0
