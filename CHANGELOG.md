# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`scan(rawMessage)` and `scanMany`** (`/scan`, adds `postal-mime`) — raw RFC
  5322 bytes in, one JSON verdict out, with both stages included. Everything
  else in the package takes pieces a mail client already has; this is for the
  other half of the audience, who have a maildir, an archive or a gateway
  handing them bytes and would otherwise have to reimplement not just the MIME
  parsing but the decisions about what in a message to believe. `scanParsed`
  takes an already-parsed message, so a caller who needed the MIME for their own
  reasons does not pay to parse it twice.
- **`ScanOptions.authserv`** — the RFC 8601 authserv-id your own boundary MTA
  stamps into `Authentication-Results`. Given one, only that server's verdicts
  are believed. This matters more than it looks: `Authentication-Results` is
  plain text that any hop can write, including the sender, who can type
  `dmarc=pass` into their own message. Without an authserv-id, `scan` keeps only
  the **topmost** line of each authentication header and discards the rest, on
  the conventional assumption that your own MTA was the most recent hop — a
  forged verdict sits at the bottom of the trace, because every hop prepends.
  `trustedAuthHeaders` is exported so a caller can see which lines survived.
- **`ScanOptions.receivedAt`, and `receivedAt` / `receivedAtFromLine`**
  (`/headers`, still zero dependencies) — the delivery time the date-skew rule
  compares the sender's `Date:` against, read off the topmost `Received:` line.
  A raw `.eml` has no IMAP INTERNALDATE, so without this the skew rule could
  never fire on a scanned file and a message dated three years out would score
  the same as one dated correctly. Pass your own INTERNALDATE when you have one.
- **Bulk-stream guarantees.** `scanMany` yields results **in input order** even
  though the scans overlap — a bulk API whose output order depends on how long
  each message took is one nobody can write a stable test, or a resumable job,
  against. A message that cannot be read is reported as `{ error }`, never
  thrown: one bad message in a mailbox of fifty thousand must not end the run.
  The source is consumed lazily and at most `concurrency` messages are held at
  once, so it works on a mailbox larger than memory.
- **The body-content stage** (`/content`, `htmlparser2` + `tldts`) —
  `assessContentSignals` scores what the message says with seven new rules:
  `content-spam-vocabulary`, `content-shouting`, `content-hidden-text`,
  `link-display-mismatch`, `link-bare-ip`, `link-userinfo` and `link-punycode`.
  It scores the sender's **own** words: quoted history, the signature after a
  `-- ` delimiter, the mail client's footer and anything inside a `blockquote`
  or a client quote container are removed first. Otherwise the person who
  forwards a phish to their IT desk is scored as the phisher, and a long thread
  gets worse every time somebody hits reply. Where both a `text/plain` and a
  `text/html` part exist, only the HTML is scored — they say the same thing, and
  scoring both would double every hit for no reason but the MIME shape.
- **The stage cap.** The vocabulary and shouting rules are an interpretation of
  prose rather than a fact about it, so together they are worth 3 at the very
  most: enough to raise a suspicion for a human, never enough to reach
  `SPAM_THRESHOLD` and file a message. Word lists age badly, and one that can
  convict alone eventually eats somebody's ordinary mail. The hidden-text and
  link rules are facts about the bytes and accumulate uncapped. No single rule
  in the stage is worth more than 2 points.
- **Word lists as data, enrichable by pull request** — `src/data/spam-phrases.ts`
  groups phrases by the scam rather than by the word, which is what makes the
  cap meaningful: twelve pharmacy phrases are one pharmacy advert, not twelve
  pieces of evidence. Matching is on NFKC-normalised, lowercased text with
  zero-width and soft-hyphen characters stripped, on whole-word boundaries, so
  the fullwidth and invisible-character tricks match and `wonderful` does not.
- **Body extraction, exported** — `bodyContent`, `extractHtml` (visible text,
  quoted text, hidden text and every anchor with its label), `ownWords`,
  `matchSpamVocabulary`, `vocabularyPoints`, `normalizeForMatching`,
  `containsPhrase`, `collapseWhitespace` and `longestShoutRun`. A client that
  wants to explain why a rule fired needs to see exactly what the rule saw.
- **`assessmentOf` and `mergeAssessments`** (`/verdict`, still zero
  dependencies), plus `SpamAssessment`, which moved here from the header rules.
  Merging concatenates reasons and re-totals rather than OR-ing two booleans, so
  a header stage and a content stage that each fall short of the threshold can
  still add up to a filing. Two call sites each computing `isSpam` for
  themselves is how two parts of a product start disagreeing about one message.
- **Shared URL helpers** (`linkTarget`, `urlsInText`, `anchorMismatches`,
  `LINK_WRAPPER_DOMAINS`), extracted so the link stage and the content stage
  answer "where does this actually go?" with one implementation.
- **`FREEMAIL_DOMAINS`** is now exported — the corpus the freemail rules read.

### Changed

- **BREAKING (behavioural): the link checks now find links in Node.** They
  previously parsed HTML with the ambient `DOMParser`, so in Node they found
  nothing at all: the ingest-time scorer silently reported "no deceptive links"
  on every message it ever scored, while a renderer running the identical code
  on the identical message found them. HTML is now parsed with `htmlparser2`,
  so there is one implementation and one answer everywhere. If you scored mail
  server-side against 0.1.x, those verdicts were computed without the link
  rules and are worth re-running. `linkDomainsAllMatch` no longer has a
  "could not read the HTML" case; it now answers from what the HTML says.
- `postal-mime` is the MIME parser rather than `mailparser`: zero dependencies,
  dual CJS/ESM, no `engines` floor, and browser-safe. `mailparser` brings nine
  dependencies and declares `engines: node >=20`, which this package cannot
  inherit while claiming `>=18`.
- `htmlparser2` is pinned to `^10.1.0` deliberately. v11 and v12 are ESM-only
  and declare `engines: node >=20.19.0`; v10.1.0 is the last dual CJS/ESM line
  with no engines floor, and this package publishes CJS and claims `>=18`.

### Removed

- **The `free-email-domains` dependency, and with it an install-time network
  fetch.** Its `postinstall` script downloaded lists from a HubSpot CDN and two
  `raw.githubusercontent.com` URLs and rewrote its own `domains.js` with the
  result. The corpus is now vendored at `src/data/freemail-domains.ts` — 14,028
  lowercased, sorted, de-duplicated entries — under the upstream MIT licence,
  with tests that pin it populated, sorted, de-duplicated and free of anything
  that is not a bare hostname.
- `happy-dom` as a dev dependency. No test needs a DOM any more; the whole suite
  runs in the `node` environment.

### Security

- A dependency that fetches its own data at install time is a supply-chain hole
  that every consumer of this package would inherit: the content that ends up on
  disk depends on what three remote URLs served at install time, which nobody
  reviews, no lockfile pins, and a firewall or a 404 turns into a silently empty
  list. An empty freemail corpus does not fail — `has(domain)` simply answers
  false — so every freemail rule stops firing and nothing anywhere says so.
  Vendoring makes the corpus reviewable in a diff and identical on every install.

- **Header reading** (`/headers`, zero dependencies) — `headerLookupFromText`,
  `headerValueFromText`, `headerValuesFromText`, `bulkHeaderSignals`,
  `hasBulkHeaderSignal`, `BULK_HEADER_NAMES`, `extractAuthHeaderBlock` and
  `parseAuthenticationHeaders`, all of which were previously reachable only
  through the package root. Whether a sender declared itself bulk is a question
  a UI asks as often as a sync does, and both sides have to get the same answer;
  the root entry costs an address parser and a freemail corpus to import, which
  in a browser bundle is dead weight. A test pins this entry's dependency count
  at zero. Origin-IP extraction stays in the root entry — it reads headers too,
  but needs an IP parser.

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
