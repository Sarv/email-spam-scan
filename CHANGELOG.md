# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Brand marks** (`/brand`, `htmlparser2` + `tldts`) — `lookupBimi(domain,
  options)` resolves what a sender domain publishes about its own logo: the
  DMARC policy that gates it, the `default._bimi` record, the SVG itself, and
  the Verified Mark Certificate that turns a picture into a verified identity.
  `discoverFavicon(domain, options)` is the fallback mark for the domains that
  publish no BIMI at all. Both return a `data:` URI, so whatever renders the
  mark never talks to the domain.
- **A logo is shown only under an enforcing DMARC policy.** That is BIMI's
  whole premise — a spoofer must never get to wear the brand — so `p=none`, no
  DMARC record, or `pct` below 100 mean no logo whatever the BIMI record says.
  For a subdomain sender the organisational domain's `sp=` governs, because
  that is the policy that actually covers the mail.
- **The tick is a full certificate check, against pinned roots.** `status:
  'verified'` needs the chain to reach one of the `MVA_ROOTS` shipped in the
  package — the certificates themselves, by SHA-256 fingerprint, not an
  authority's name — with the BIMI extended key usage `1.3.6.1.5.5.7.3.31` on
  the leaf, a SubjectAltName covering the From domain, every certificate
  inside its validity dates, and the RFC 3709 logotype extension binding
  **this** logo by digest or by an embedded copy that matches byte for byte
  (SHA-1 included, because Apple's VMCs still use it). Anything short of that
  demotes to `'logo'` with the reason in `detail`: never a silent pass, and
  never taking the brand's logo away over a certificate problem.
- **The logo is checked before it is shown.** `checkBimiSvg` requires SVG Tiny
  PS and refuses script, event handlers, `foreignObject` and every external
  reference, at a 32 KB ceiling with a gzip bomb refused on its decompressed
  size. A logo is markup a stranger chose, rendered beside their name in a
  reader's mail.
- **`@peculiar/x509` and `asn1js` are optional peer dependencies**, reached
  through dynamic `import`s inside the loader that needs them, and pinned as
  such by the entry-point test. An install without them still gets the logo,
  the SVG check and the favicon; what it loses is the tick, and the detail
  names the package to add rather than blaming the brand's certificate.
- **The favicon is identified by its bytes, never by its `Content-Type`.** A
  200 that is really an HTML error page is the usual answer to a missing
  favicon, and it must never become somebody's avatar. Discovery follows what
  a browser does — the icons the homepage declares, best first, then
  `/favicon.ico` — and falls back to the organisational domain for the
  `notify.` and `mailer.` subdomains that serve no website. Fetching one
  discloses to that domain, once, that a client at this address looked it up,
  which is why a consumer should put it behind a setting.
- **`'none'` and `'error'` are different answers.** A DNS miss means the
  domain publishes nothing and is worth caching for a week; a resolver failure
  or an unreachable host is worth about a minute. Nothing here caches — the
  caller owns that, because the caller knows how long it wants to believe an
  answer — but conflating the two is how a brand's logo disappears for
  everyone after one bad afternoon on the network.
- **The entry runs in a browser.** DNS and HTTPS are injected (`query` and
  `fetch`, defaulting to `node:dns` and the platform `fetch`), and every byte
  operation goes through the web platform — `Uint8Array`, `crypto.subtle`,
  `DecompressionStream` — rather than `node:buffer` or `node:zlib`. The
  injected `DnsQuery` is the same contract `/reputation` takes, now a shared
  resolver rather than one per stage, so a caller with its own DoH client or
  cache passes it to both.
- **Reputation** (`/reputation`, `ipaddr.js` only) — `checkReputation(target,
  blocklists, options)` asks DNS blocklists what they have published about the
  address a message was delivered from and the domain it claims, and
  `assessReputation(result)` turns the answer into a scored assessment.
  Spamhaus ZEN, Spamhaus DBL and SpamCop are described and exported; `node:dns`
  is reached through a dynamic `import`, so the entry costs a browser bundle
  nothing but `ipaddr.js`.
- **No default list of blocklists, deliberately.** `blocklists` is a required
  argument. Every list has terms — free below some volume, a paid feed above
  it, and a permanent "over quota" answer once you pass it — and every lookup
  discloses to that operator a sender your user is receiving mail from. A
  package that queried zones by default would put you in breach of somebody's
  terms, and disclose your users' mail, without you having chosen either.
  `BLOCKLISTS` is a list to read and pick from, not one to inherit.
- **The return code is read as the answer.** A listing is scored by which code
  came back where the zone publishes a table (`127.0.0.2` SBL against
  `127.0.0.10` "should not be delivering mail directly" are not the same
  evidence), and two kinds of answer are never listings: `127.255.255.0/24`,
  which is the operator reporting a malformed query, an open resolver or an
  exceeded quota, and anything outside `127.0.0.0/8`, which is a wildcard or
  hijacked response. Both reach `errors`. Reading "an A record came back" as
  "listed" turns one misconfigured resolver into a filter that files every
  message as spam at once.
- **A failed lookup is never a clean result.** A timeout, a SERVFAIL or a
  target not worth querying leave `completed: false` with no hits, rather than
  `listed: false` presented as an all-clear; zones that did answer keep their
  hits, so one operator's outage never discards another's listing.
  `checkReputation` does not throw. Only public addresses are queried — the
  same gate `extractOriginIp` uses — so private and reserved ranges are skipped
  rather than published to an operator one query at a time.
- **Several lists agreeing counts once.** `assessReputation` charges the
  highest-scoring hit per kind of target rather than the sum, because the
  public lists mirror each other and ZEN is three lists in one zone; summing
  would make a score depend on how many zones a deployment configured. The
  address and the domain are separate facts, so those two do add up — as far
  as `REPUTATION_MAX_POINTS` (`SPAM_THRESHOLD + 1`), which is enough for a
  listed sender to be spam on this evidence alone and no more. The address is
  charged first and the domain takes what is left, so a truncated reason is
  always the weaker half; `assessReputation(result, { maxPoints: Infinity })`
  lifts the ceiling for a caller running its own points table.
- **The shield explains the sender's mark.** `assessEmailSecurity` accepts a
  `bimi` input — a `BimiLookup` from `/brand`, or the columns a caller cached
  from one — and adds a `brand` check saying who proved ownership of the
  domain and which Mark Verifying Authority vouched for them, or why no tick
  is being shown. It never moves the level: most legitimate senders publish no
  BIMI record, so scoring its absence would warn about most of the world's
  mail, and a certificate proves who owns a brand rather than that this
  message deserves trust. Reported as proof only under a DMARC pass, because
  without one the sentence is what a spoofer would like the reader to see.
  Omitting the input drops the row; passing `null` says "not looked up yet".
- **Reports from other recipients** —
  `assessReputation(result, { userReports })` scores the one signal a lookup
  cannot find: how many other people have already reported this sender's
  domain as spam. Three reports (`USER_REPORTS_MIN`, movable per call with
  `minUserReports`) are worth three points (`USER_REPORT_POINTS`) under the
  new `reputation-user-reported` id — one report is one opinion, and a
  crowd's opinion is evidence but not an operator's observation. Charged
  after the listings out of what is left of the same budget, so the crowd
  can never carry a message over the stage's ceiling by itself, and ignored
  entirely when the result carries no domain to name.
- **Stored reasons are read under their current ids.** `parseSpamReasons`
  maps the ids Sarv Inbox shipped before this package existed
  (`ip-blocklisted`, `domain-blocklisted`, `user-reported`) onto the
  namespaced ones, and `canonicalReasonId(id)` exposes the same mapping on
  its own. A verdict cached a year ago still renders against today's
  `SpamReasonId` union, and an id from a newer version passes through
  untouched rather than being dropped — a reader that shows less is better
  than one that shows a blank row for the message somebody is trying to open.
- **Bitmask zones** — `Barracuda` (`b.barracudacentral.org`, registration
  required before its mirror answers anything but NXDOMAIN), `SURBL`
  (`multi.surbl.org`) and `URIBL` (`multi.uribl.com`) join the catalogue. The
  two URI lists pack their categories into the last octet, so a domain that is
  both a phishing site and a malware host answers `127.0.0.24` — an address in
  no code table. A zone declares `bits` instead of `codes`, several records are
  ORed before they are read, and every category the mask sets is reported.
  Reading a bitmask as an exact code downgrades the worst listings there are;
  reading it as a boolean makes URIBL's grey list — bulk mail of dubious value
  — indistinguishable from a spam run.
- **A zone may publish its refusal inside `127.0.0.0/8`.** Both URI lists
  answer `127.0.0.1` to a query from a public resolver or from a querier over
  the free-use limit: a refusal in the shape of a listing, arriving for every
  domain at once. `Blocklist.refusals` names those codes so the error carries
  the operator's own words, and a refusal that arrives beside a real listing
  never discards the listing.
- **A category on every described code** (`spam`, `exploited`, `phishing`,
  `malware`, `botnet`, `policy`, `abused`, `grey`), reported on the hit, so a
  consumer can group listings across zones or apply its own points table
  without copying the catalogue back out of the package.
- **`checkReputationBatch(targets, blocklists, options)`** — many targets over
  one resolver, with `concurrency` queries in flight (default 8). A backlog
  scored after the fact is hundreds of addresses across several zones, and
  both obvious shapes are wrong: sequential is an hour of round-trips, and
  `Promise.all` over the lot opens a thousand simultaneous queries that c-ares
  will not serve and an operator reads as an attack. Results come back in the
  order the targets were given, and a batch with nothing worth asking about
  opens no socket at all.
- **`ScanOptions.reputation`** — an assessment from a lookup you ran yourself,
  folded into the message's score. The same arrangement as `options.auth` and
  for the same reason: the DNS happens outside `scan`, on your schedule and
  against zones you are entitled to query, and absent or `null` contributes
  nothing.
- **`reputation-ip-listed` and `reputation-domain-listed`** (`/verdict`) — two
  new reason ids, so a stored verdict that includes a blocklist hit still reads
  back with `parseSpamReasons`.
- **Real authentication** (`/verify`, no static dependencies) —
  `verifyAuthentication(message, options)` checks SPF, DKIM and DMARC against
  live DNS over the original unmodified bytes, instead of reading a verdict
  some other machine wrote into a header. It returns the same `AuthStatus` the
  header reader produces, plus every DKIM signature with its signing domain,
  selector, verbatim result word, comment and alignment, the SPF domain, the
  published DMARC policy, and whether the verification completed at all.
- **`mailauth` is an optional peer dependency, loaded on demand.** It is
  reached through a dynamic `import` inside the one function that uses it, so
  installing this package does not install a DNS library and no bundle carries
  one by accident; the entry-point test that walks the source import graph
  pins that. Without it installed, `verifyAuthentication` throws a message
  naming what to install and everything else in the package is unaffected.
- **`ScanOptions.auth`** — a verified verdict used in place of the one read
  from `Authentication-Results`. This is how DNS verification reaches the
  rules, and it is deliberately the long way round: `scan` and `scanParsed`
  still make no network calls at all, so the same message scores the same way
  in a test, in a bundle and on a machine with no resolver, and a run over
  fifty thousand messages does not quietly become fifty thousand DNS lookups.
  `null` or absent falls back to the headers, so a verification that timed out
  degrades to what the trusted headers said rather than to nothing.
- **A failed verification is never a failed verdict.** A timeout, a resolver
  error or an unreachable nameserver return `completed: false` and three
  `unknown`s, never `fail`. `auth-failed` is worth 3 points, and an outage on
  the verifier's side must not start scoring everybody's mail. `timeoutMs`
  defaults to 10 seconds and `resolver` accepts your own — a cache, a stub, a
  DoH client.
- **`unknownAuthStatus` and `rollUpAuthStatus`** (`/verdict`, still zero
  dependencies) — the "two of three passed" rollup, extracted so the header
  reader and the DNS verifier cannot drift into disagreeing about the same
  three component verdicts. The verifier maps `mailauth`'s `neutral` (body
  hash mismatch, no key, expired) and `policy` (a key below `minBitLength`) to
  `fail` for the same reason: those are the cases Gmail writes as `dkim=fail`
  in the header the other producer reads.
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
- **The attachment stage** (`/attachments`, **zero dependencies**) —
  `assessAttachmentSignals` scores what a file claims to be against what its
  bytes actually are, with seven new rules: `attachment-name-spoof`,
  `attachment-double-extension`, `attachment-executable`,
  `attachment-type-mismatch`, `attachment-macro`,
  `attachment-archive-executable` and `attachment-encrypted-archive`. The
  filename and the `Content-Type` are claims the sender wrote; the magic bytes
  are the only one of the three that cannot be made to say something other than
  what the reader's software will do, and the disagreement between them is the
  signal. `scan` runs the stage automatically on the bytes `postal-mime`
  decoded, so a caller gets it without changing anything.
- **Nothing is executed, unpacked or inflated.** An archive's central directory
  is read — names, declared sizes, the encrypted flag — and nothing else. That
  is a security decision, not an optimisation: a 42 KB zip bomb expands to
  several petabytes, and a scanner that inflates what it is handed needs a
  budget, a timeout and a recursion limit to survive being mailed one. It is
  also why the entry costs nothing: an inflater is the one dependency a scanner
  handed hostile archives should not carry. The directory walk is bounded at
  2,000 entries, and a listing that hit the bound says so rather than pretending
  it saw everything.
- **`inspectAttachment`, `sniffFileType`, `inspectFilename`, `listZipEntries`,
  `asBytes`** — the facts the rules scored, exported so a consumer can display
  them or score them differently. `asBytes` is the one place content is turned
  into a byte view, which is what keeps a Node `Buffer` — nearly always a window
  onto a larger shared pool — from being read from the start of the pool rather
  than the start of the file.
- **Attachment extension lists as data** — `src/data/attachment-extensions.ts`,
  with two executable lists rather than one. A `.js` file attached to an email
  is a dropper; a `.js` file inside a zip is `node_modules`. What counts inside
  an archive is the narrower set with no innocent reason to be zipped and
  mailed: Windows binaries, script-host formats, shortcuts and installers.
- **The stage is not an antivirus and does not claim to be.** No signature
  database, no emulation; a clean result means "nothing structurally
  deceptive", never "safe to open". No rule is worth more than 2 points and a
  bare executable attachment reaches neither threshold on its own — a developer
  mailing a build to a colleague sends the same bytes as a dropper. It is the
  combination that files a message.
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
- **The reply cut is its own entry** (`/quote`, no dependencies) —
  `stripQuotedTail(text)` returns everything above the quoted history with the
  signature left in place, `ownWords(text)` takes the signature and the client
  footer out as well, and `QUOTE_MARKERS` is the corpus both share. Two callers
  want opposite things from one cut: a scorer must not charge a sender for the
  phone number under their own name, and a contact miner is reading for exactly
  that number. They were two marker lists in two repositories, which is how a
  rule drifts invisibly — both copies go on returning a plausible string.

### Changed

- **`ownWords` recognises more of the quoted history**, having taken in the
  markers the other implementation carried: an attribution `html-to-text` has
  collapsed into the middle of a line (the shape most HTML mail arrives in),
  one that opens with the sender's name instead of "On", the French, German
  and Spanish forms, `Begin forwarded message:`, and an indented `>` prefix.
  In the other direction it no longer cuts at a bare `From:` line or at a
  five-character underscore rule, both of which occur in ordinary prose and in
  signatures — a false cut deletes the sender's own words, silently. Scores
  computed over long or non-English threads may go DOWN, which is the point:
  those points were being charged for words somebody else wrote.
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
