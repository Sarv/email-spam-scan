# email-spam-scan

[![npm version](https://img.shields.io/npm/v/@sarv-in/email-spam-scan.svg)](https://www.npmjs.com/package/@sarv-in/email-spam-scan)
[![npm downloads](https://img.shields.io/npm/dm/@sarv-in/email-spam-scan.svg)](https://www.npmjs.com/package/@sarv-in/email-spam-scan)
[![CI](https://github.com/Sarv/email-spam-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Sarv/email-spam-scan/actions/workflows/ci.yml)
[![coverage 100%](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/Sarv/email-spam-scan/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@sarv-in/email-spam-scan.svg)](./LICENSE)

Decide whether an email is spam, from the email itself.

**npm:** [`@sarv-in/email-spam-scan`](https://www.npmjs.com/package/@sarv-in/email-spam-scan) ·
**source:** [Sarv/email-spam-scan](https://github.com/Sarv/email-spam-scan) ·
**issues:** [report one](https://github.com/Sarv/email-spam-scan/issues) ·
**contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md)

You supply the headers — eventually the whole message — and it gives back a
score, a verdict, and a list of named reasons a human can read. No service to
call, no API key, no model to download. Every rule is a small pure function over
data you already have.

**Status: v0.1.x is the header stage, complete.** Sixteen header rules, the
sender-identity check, deceptive-link detection and the security-level decision
are all here, extracted from a mail client that runs them on real mail at
ingest. What is not here yet is the body-content stage, the attachment stage and
the streaming API — see [Roadmap](#roadmap). What ships today is listed under
[What it does today](#what-it-does-today), and nothing else is implied. This
package will not tell you it checked something it did not check.

## Contents

- [Install](#install)
- [Entry points](#entry-points)
- [Quick start](#quick-start)
- [What it does today](#what-it-does-today)
- [Scoring model](#scoring-model)
- [The header rules](#the-header-rules)
- [Security levels](#security-levels)
- [Reading a stored verdict back](#reading-a-stored-verdict-back)
- [Origin IP: which address actually sent this](#origin-ip-which-address-actually-sent-this)
- [Authentication results: read, not verified](#authentication-results-read-not-verified)
- [Roadmap](#roadmap)
- [API](#api)
- [Contributing](#contributing)
- [Licence](#licence)

## Install

```bash
npm install @sarv-in/email-spam-scan
# or
pnpm add @sarv-in/email-spam-scan
# or
yarn add @sarv-in/email-spam-scan
```

Node 18 or newer. TypeScript types ship with the package; ESM and CJS both work.

## Entry points

Five, so a browser bundle never has to carry what only a server needs.

| Import | Dependencies | Use it for |
| --- | --- | --- |
| `@sarv-in/email-spam-scan` | `tldts`, `ipaddr.js`, `email-addresses`, `free-email-domains` | Everything. The Node entry — header parsing and the scorer. |
| `@sarv-in/email-spam-scan/verdict` | **none** | Reading a stored score/reason back — in a renderer, a worker, anywhere. |
| `@sarv-in/email-spam-scan/identity` | `tldts` | The sender-spoof rule on its own. |
| `@sarv-in/email-spam-scan/links` | `tldts` | Deceptive-link detection. Needs a DOM; degrades to "found nothing" without one. |
| `@sarv-in/email-spam-scan/security` | `tldts` | The five-level decision, for the UI that renders it. |

The split exists because the common case in a mail client is displaying a
verdict that was computed at ingest, hours ago, on a server. That side needs
thresholds and a JSON parse, not a scanner.

The `links` and `security` entries parse HTML with the ambient `DOMParser`. In a
browser that is already there; in Node it is not, and every link check returns
"nothing found" rather than throwing. The one place that is load-bearing is
`linkDomainsAllMatch`, which returns **false** when there is HTML it could not
read: the claim it makes is "every link stays on the sender's own domain", and
that cannot be asserted about evidence nobody looked at.

## Quick start

```ts
import {
  extractAuthHeaderBlock,
  parseAuthenticationHeaders,
  extractOriginIp,
  assessSender,
  spamVerdict,
} from '@sarv-in/email-spam-scan';

const block = extractAuthHeaderBlock(rawHeaderText);
const auth = parseAuthenticationHeaders(block);
// { spf: 'pass', dkim: 'pass', dmarc: 'pass', overall: 'pass' }

const ip = extractOriginIp({ authHeaders: block, received: receivedLines });
// '185.199.108.1' — public unicast only, never a private or CGNAT hop

const reasons = assessSender('PayPal Support', 'billing@paypal.secure-login.ru');
// [{ severity: 'danger', text: 'The sender name mentions paypal.com …' }]

spamVerdict(6); // 'spam'
```

Or score the whole thing at once:

```ts
import { assessSpamSignals, headerLookupFromText } from '@sarv-in/email-spam-scan';

const { score, reasons, isSpam } = assessSpamSignals({
  fromName: 'PayPal Support',
  fromAddress: 'billing@paypal.secure-login.ru',
  subject: 'Re: your account',
  messageId: null,
  auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail', overall: 'fail' },
  headers: headerLookupFromText(rawHeaderText),
});

// score: 10, isSpam: true
// reasons: [
//   { id: 'auth-failed',        points: 3, detail: 'DMARC failed — …' },
//   { id: 'display-name-spoof', points: 3, detail: 'The sender name mentions paypal.com …' },
//   { id: 'missing-message-id', points: 2, detail: 'No Message-ID header — …' },
//   { id: 'fake-reply',         points: 2, detail: 'Looks like a reply, but …' },
// ]
```

## What it does today

**Sender identity** (`assessSender`) — the friendly name claims one brand while
the address belongs to another registrable domain. Compared at eTLD+1 via
`tldts`, so `mail.paypal.com` vs `paypal.com` does **not** fire, while
`paypal.com` vs `paypal.secure-login.ru` does.

**Authentication results** (`extractAuthHeaderBlock`, `parseAuthenticationHeaders`)
— reads the SPF/DKIM/DMARC verdicts your own MTA already wrote into
`Authentication-Results`, `ARC-Authentication-Results` and `Received-SPF`.

**Origin IP** (`extractOriginIp`) — the public address the message actually came
from, taken from the SPF evaluator's own record where possible and the
`Received:` trace otherwise. Private, loopback, link-local, CGNAT and reserved
ranges are rejected, so you get an address worth reputation-checking or nothing.

**The header scorer** (`assessSpamSignals`) — sixteen rules over the envelope,
the threading headers, the authentication verdict and the bulk-mail headers.
Listed in full under [The header rules](#the-header-rules).

**Deceptive links** (`linkMismatches`, `assessLinks`) — an anchor whose visible
text names one registrable domain while its `href` goes to another. Thirty ESP
and URL-shortener domains are skipped, because legitimate marketing mail wraps
its links through them and a banner that fires on every newsletter is a banner
nobody reads.

**The security level** (`assessEmailSecurity`) — combines all of the above into
one of five levels with a per-check breakdown, for the shield or banner a mail
client shows. The copy is deliberately yours: the library returns levels and
check ids, never English sentences for the user.

**Verdict plumbing** (`spamVerdict`, `isSpamScore`, `parseSpamReasons`) — the
thresholds and the stored-reason codec, with no dependencies at all.

## Scoring model

Additive, in the shape SpamAssassin made familiar: every rule that fires
contributes points and one human-readable sentence. Points are summed; the total
meets a threshold or it does not.

| Score | Verdict |
| --- | --- |
| `>= 5` (`SPAM_THRESHOLD`) | `spam` |
| `>= 3` (`SUSPICIOUS_THRESHOLD`) | `suspicious` |
| below that | `clean` |

No rule is a veto and no single rule can reach the spam threshold on evidence
that is merely suspicious. This matters more than the individual weights: a
false positive in a mail client is mail the recipient never learns existed, so a
rule that is right 95% of the time must not be able to file mail on its own.

Reasons are returned alongside the score precisely so a filing decision can be
explained to the person it affected.

## The header rules

Every rule `assessSpamSignals` can fire, with the weight it contributes. Only
the two 5-point rules can reach the spam threshold alone, and both are
categorical: something that saw more than the headers already decided, or the
recipient themselves said so.

| Reason id | Points | Fires when |
| --- | --- | --- |
| `upstream-spam` | 5 | `X-Spam-Flag: YES`, `X-Spam-Status: Yes`, or an Exchange SCL of 5 or more |
| `known-spammer` | 5 | The caller says the recipient reported this sender |
| `auth-failed` | 3 | DMARC failed — or, only when DMARC is unknown, SPF **and** DKIM both failed |
| `display-name-spoof` | 3 | The friendly name claims a domain the address does not belong to |
| `sender-invalid` | 2 | No sender address, or one RFC 5322 cannot parse |
| `reply-to-freemail` | 2 | Replies go to free webmail while the message claims a corporate domain |
| `missing-message-id` | 2 | No `Message-ID` — every real mail server adds one |
| `date-skew` | 2 | The `Date` header is more than 96 hours from when the server received it |
| `fake-reply` | 2 | A `Re:` subject with no `In-Reply-To` and no `References` |
| `sender-punycode` | 1 | The sender domain is punycode/IDN — a homograph risk, not proof |
| `reply-to-mismatch` | 1 | Replies go to a different registrable domain than the sender's |
| `malformed-message-id` | 1 | A `Message-ID` that is not `<local@domain>` |
| `missing-date` | 1 | No `Date` header |
| `no-recipient` | 1 | Neither `To` nor `Cc` names anyone |
| `bulk-no-unsubscribe` | 1 | Declared bulk mail offering no `List-Unsubscribe` |
| `precedence-junk` | 1 | `Precedence: junk` — the sender labelled it themselves |

The weights are chosen so the classic combinations cross the line while no
single benign anomaly does: a spoofed display name on a message that failed
DMARC is 3 + 3, a forged `Re:` from an unauthenticated sender is 2 + 3. A
forwarder that breaks DKIM, a cron job with no `Message-ID`, a home address in
`Reply-To` — each is one point or three, and each stays below 5 on its own.

`SPAM_HEADER_NAMES` and `BULK_HEADER_NAMES` are exported so your IMAP fetch can
ask for exactly the headers the rules read. A header a rule reads but the fetch
never asked for is a rule that silently never fires.

## Security levels

`assessEmailSecurity` returns one of five, ordered by `LEVEL_RANK`:

| Level | Means |
| --- | --- |
| `verified` | Authentication passed and every link stays on the sender's own domain |
| `authenticated` | Authentication passed; nothing else to say |
| `unverified` | The server recorded no authentication verdict — common, not alarming |
| `caution` | Something is off: a deceptive link, or a suspicious score |
| `danger` | DMARC failed, the display name is spoofed, or the score is over the spam threshold |

`worstLevel(a, b)` combines two, for a thread or a conversation view. The human
copy for each level is not in this package — a library cannot know your
product's voice, its language, or its reading age.

## Reading a stored verdict back

Score it once, store the number and the reasons, and read them back from
anywhere — including a browser — with no dependencies:

```ts
import { spamVerdict, parseSpamReasons } from '@sarv-in/email-spam-scan/verdict';

spamVerdict(row.spam_score);            // 'spam' | 'suspicious' | 'clean' | null
parseSpamReasons(row.spam_reasons);     // SpamReason[], [] if absent or corrupt
```

`spamVerdict` returns `null` — not `'clean'` — for `null`/`undefined`. A message
that was never scanned and a message that scored zero are different facts, and
collapsing them shows a green tick on mail nothing ever looked at.

## Origin IP: which address actually sent this

`Received:` headers are appended by each hop, and every hop below your own
boundary was written by someone you do not control. `extractOriginIp` therefore
prefers the address **your** SPF evaluator recorded (`client-ip=`,
`smtp.remote-ip=`, Microsoft's `sender IP is`) over anything in the trace, and
only walks the trace when the authentication headers name nothing.

Within a `Received:` line it reads the `from` clause only, stopping at `by` (the
receiving side, not the sender) and at `;` (the timestamp). It returns the first
**public unicast** address it finds, so a loopback content-filter hop or an
internal `10.x` relay is skipped rather than reported as the origin.

## Authentication results: read, not verified

This package **reads** the verdict your mail server already computed. It does
not perform SPF, DKIM or DMARC verification itself — that needs live DNS and the
original unmodified message, neither of which a header block contains.

The practical consequence: only trust these values for headers added **at or
above your own trust boundary**. Feed `parseAuthenticationHeaders` the output of
`extractAuthHeaderBlock`, never a whole raw header dump — otherwise a sender can
simply write `X-Anything: dmarc=pass` into a message and be believed.

Real verification, via `mailauth`-style DNS lookups, is on the roadmap as an
explicitly opt-in stage.

## Roadmap

Ordered, and open to contribution — see [CONTRIBUTING.md](./CONTRIBUTING.md).

1. **Body content stage.** Spam vocabulary and deceptive links, scored on the
   sender's own words rather than the quoted history. Word and domain lists live
   in this repo as data so they can be enriched by pull request.
2. **Attachment stage.** What is safely knowable without executing anything:
   dangerous and double extensions, archive contents, macro-bearing Office
   documents, MIME type that disagrees with the magic bytes.
3. **Streaming API.** `scan(rawMessage)` and a bulk stream, returning the JSON
   verdict per message.
4. **Real authentication.** Opt-in SPF/DKIM/DMARC verification against DNS.
5. **Reputation.** DNSBL and similar, in a separate package — it makes network
   calls, so it must never be something you get by accident.

## API

### Verdict — `@sarv-in/email-spam-scan/verdict`

- `SPAM_THRESHOLD: 5`, `SUSPICIOUS_THRESHOLD: 3`
- `spamVerdict(score): 'spam' | 'suspicious' | 'clean' | null`
- `isSpamScore(score): boolean`
- `parseSpamReasons(json): SpamReason[]` — never throws
- `type SpamReason`, `SpamReasonId`, `SpamVerdict`, `AuthStatus`

### Identity — `@sarv-in/email-spam-scan/identity`

- `registrableDomain(input): string | null` — eTLD+1
- `domainOfAddress(address): string | null`
- `domainsInText(text): string[]`
- `assessSender(name, address): PhishingReason[]`

### Links — `@sarv-in/email-spam-scan/links`

- `linkMismatches(html): LinkMismatch[]` — `{ shown, actual }`, de-duplicated, capped at three
- `assessLinks(html): PhishingReason[]` — the same, phrased for a human
- `linkDomainsAllMatch(html, senderDomain): boolean`
- `assessPhishing({ fromName, fromAddress, html }): PhishingAssessment`
- `LINK_WRAPPER_DOMAINS: Set<string>`

### Security — `@sarv-in/email-spam-scan/security`

- `assessEmailSecurity(input): SecurityAssessment`
- `worstLevel(a, b): SecurityLevel`
- `LEVEL_RANK`, `linkRuleKey(senderDomain, shown, actual)`, `parseAuthStatus(json)`
- `EMPTY_RULES`, `type LinkRuleSets`, `SecurityCheck`, `CheckStatus`

### Headers and rules — `@sarv-in/email-spam-scan`

- `extractAuthHeaderBlock(headers): string | null`
- `parseAuthenticationHeaders(block): AuthStatus`
- `extractOriginIp(sources): string | null`
- `originIpFromAuthHeaders(block)`, `originIpFromReceived(lines)`
- `normalizeIp(candidate)`, `isPublicIp(candidate)`
- `headerLookupFromText(headers): HeaderLookup`, `headerValueFromText`, `headerValuesFromText`
- `bulkHeaderSignals(get): BulkHeaderSignals`, `hasBulkHeaderSignal(get)`, `BULK_HEADER_NAMES`
- `assessSpamSignals(input): SpamAssessment`, `SPAM_HEADER_NAMES`, `DATE_SKEW_SECONDS`
- `isFreemailAddress(address)`, `isValidMessageId(id)`, `hasReplyPrefix(subject)`

## Contributing

Rules and word lists are the point of an open-source spam scanner — see
[CONTRIBUTING.md](./CONTRIBUTING.md). The short version: every rule arrives with
a fixture drawn from a real message, a cited source, and evidence that it adds
no false positive to the existing corpus. Coverage is enforced at 100% in CI,
because a spam rule with an untested branch silently files somebody's mail.

## Licence

MIT © Sarv. See [LICENSE](./LICENSE).
