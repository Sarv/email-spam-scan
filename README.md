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

**Status: v0.1.x is the header stage.** It is extracted from a mail client that
runs it on real mail at ingest, so what is here is in production use — but it is
not yet the whole scanner described in [Roadmap](#roadmap). What ships today is
listed under [What it does today](#what-it-does-today), and nothing else is
implied. This package will not tell you it checked something it did not check.

## Contents

- [Install](#install)
- [Entry points](#entry-points)
- [Quick start](#quick-start)
- [What it does today](#what-it-does-today)
- [Scoring model](#scoring-model)
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

Three, so a browser bundle never has to carry what only a server needs.

| Import | Dependencies | Use it for |
| --- | --- | --- |
| `@sarv-in/email-spam-scan` | `tldts`, `ipaddr.js` | Everything. The Node entry. |
| `@sarv-in/email-spam-scan/verdict` | **none** | Reading a stored score/reason back — in a renderer, a worker, anywhere. |
| `@sarv-in/email-spam-scan/identity` | `tldts` | The sender-spoof rule on its own. |

The split exists because the common case in a mail client is displaying a
verdict that was computed at ingest, hours ago, on a server. That side needs
thresholds and a JSON parse, not a scanner.

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

1. **Header rule set.** The full additive scorer: upstream spam verdicts,
   known-spammer lists, authentication failure, display-name spoofing, IDN
   homographs, `Reply-To` mismatch, missing/malformed `Message-ID`, date skew,
   forged reply subjects, bulk mail with no unsubscribe.
2. **Body content stage.** Spam vocabulary and deceptive links, scored on the
   sender's own words rather than the quoted history. Word and domain lists live
   in this repo as data so they can be enriched by pull request.
3. **Attachment stage.** What is safely knowable without executing anything:
   dangerous and double extensions, archive contents, macro-bearing Office
   documents, MIME type that disagrees with the magic bytes.
4. **Streaming API.** `scan(rawMessage)` and a bulk stream, returning the JSON
   verdict per message.
5. **Real authentication.** Opt-in SPF/DKIM/DMARC verification against DNS.
6. **Reputation.** DNSBL and similar, in a separate package — it makes network
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

### Headers — `@sarv-in/email-spam-scan`

- `extractAuthHeaderBlock(headers): string | null`
- `parseAuthenticationHeaders(block): AuthStatus`
- `extractOriginIp(sources): string | null`
- `originIpFromAuthHeaders(block)`, `originIpFromReceived(lines)`
- `normalizeIp(candidate)`, `isPublicIp(candidate)`

## Contributing

Rules and word lists are the point of an open-source spam scanner — see
[CONTRIBUTING.md](./CONTRIBUTING.md). The short version: every rule arrives with
a fixture drawn from a real message, a cited source, and evidence that it adds
no false positive to the existing corpus. Coverage is enforced at 100% in CI,
because a spam rule with an untested branch silently files somebody's mail.

## Licence

MIT © Sarv. See [LICENSE](./LICENSE).
