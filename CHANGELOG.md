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
- **Header lookup** — `headerLookupFromText`, `headerValueFromText` and
  `headerValuesFromText`, which read a named header out of a raw block and
  unfold continuation lines, so callers with a header dump rather than a
  parsed envelope can feed the rules directly.
- **Bulk-mail headers** — `bulkHeaderSignals` and `hasBulkHeaderSignal` over
  `List-Id`, `List-Unsubscribe`, `Precedence`, `Auto-Submitted`, `Feedback-ID`
  and the common ESP trace headers, plus `BULK_HEADER_NAMES` so a fetch can ask
  for exactly what is read.
- **The header rule set** — `assessSpamSignals`, sixteen additive rules
  covering upstream spam verdicts, reported senders, authentication failure,
  display-name spoofing, IDN homographs, undeliverable and mismatched
  addresses, missing or malformed `Message-ID`, date skew, forged reply
  subjects, hidden recipients and bulk mail with no unsubscribe. Exports
  `SPAM_HEADER_NAMES`, `DATE_SKEW_SECONDS` and `isFreemailAddress`.
- **Deceptive links** (`/links`, `tldts` only) — `linkMismatches`,
  `assessLinks`, `linkDomainsAllMatch` and `assessPhishing`, finding anchors
  whose visible text names one registrable domain while the `href` goes to
  another. Thirty ESP and URL-shortener domains are skipped, because
  legitimate marketing mail routinely wraps links through them.
- **Security levels** (`/security`, `tldts` only) — `assessEmailSecurity`
  returning one of `verified | authenticated | unverified | caution | danger`
  with a per-check breakdown, plus `worstLevel`, `LEVEL_RANK`, `linkRuleKey`
  and `parseAuthStatus`. The human copy for each level is deliberately left to
  the caller: a library cannot know a product's voice or language.
- **RFC helpers** — `isValidMessageId` and `hasReplyPrefix`, with no schema
  library behind them.

### Security

- Every regular expression carried over from the originating codebase was
  rewritten to be free of super-linear backtracking — the authentication-header
  scanner, the `Received:` `from` clause, the generic header lookup and the
  reply-prefix matcher, four instances of the same shape — and
  `regexp/no-super-linear-backtracking` is enforced as an **error** in this
  repository rather than a warning. This package's input is mail an attacker
  chose, parsed at ingest: a quadratic pattern against a large header block is
  not a slow scan, it is a mail flow that stops.
- The `Received:` `from` clause is walked token by token instead of matched,
  which cannot backtrack at all, and stops at `by` and `;` so that an address
  appearing in a timestamp or in the receiving side of a hop can never be
  reported as the origin.
- Without a `DOMParser` — in Node, in a worker — every link check returns
  "found nothing" rather than throwing, with one deliberate exception:
  `linkDomainsAllMatch` returns **false**. Its claim is that every link stays
  on the sender's own domain, and that must not be asserted about HTML nobody
  was able to read.

[Unreleased]: https://github.com/Sarv/email-spam-scan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Sarv/email-spam-scan/releases/tag/v0.1.0
