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

**Status: the header stage, the body-content stage, the attachment stage,
`scan(rawMessage)`, authentication verified against DNS, and blocklist
lookups.** Sixteen header rules, the sender-identity check, deceptive-link
detection, the security-level decision, seven body-content rules, seven
attachment rules and a scanner that takes raw RFC 5322 bytes are all here,
extracted from a mail client that runs them on real mail at ingest. The two
things that touch the network — [live SPF/DKIM/DMARC
verification](#verifying-authentication-yourself) and [blocklist
lookups](#reputation-asking-somebody-else) — are here too, each in its own
entry point you have to ask for by name. What
ships today is listed under [What it does today](#what-it-does-today), and
nothing else is implied. This package will not tell you it checked something it
did not check.

## Contents

- [Install](#install)
- [Entry points](#entry-points)
- [Quick start](#quick-start)
- [Scanning a whole message](#scanning-a-whole-message)
- [What it does today](#what-it-does-today)
- [Scoring model](#scoring-model)
- [The header rules](#the-header-rules)
- [The content rules](#the-content-rules)
- [The attachment rules](#the-attachment-rules)
- [Security levels](#security-levels)
- [Reading a stored verdict back](#reading-a-stored-verdict-back)
- [Origin IP: which address actually sent this](#origin-ip-which-address-actually-sent-this)
- [Authentication results: read, not verified](#authentication-results-read-not-verified)
- [Verifying authentication yourself](#verifying-authentication-yourself)
- [Reputation: asking somebody else](#reputation-asking-somebody-else)
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

Eleven, so a browser bundle never has to carry what only a server needs.

| Import | Dependencies | Use it for |
| --- | --- | --- |
| `@sarv-in/email-spam-scan` | `tldts`, `ipaddr.js`, `email-addresses`, `htmlparser2`, `postal-mime` | Everything. The Node entry — the scanner, all three stages, the header primitives. |
| `@sarv-in/email-spam-scan/verdict` | **none** | Reading a stored score/reason back — in a renderer, a worker, anywhere. |
| `@sarv-in/email-spam-scan/headers` | **none** | Reading raw header text: the lookup, and whether the sender declared itself bulk. |
| `@sarv-in/email-spam-scan/attachments` | **none** | The attachment stage: filenames, magic bytes, zip directories. Nothing is unpacked, so nothing is needed to unpack it. |
| `@sarv-in/email-spam-scan/identity` | `tldts` | The sender-spoof rule on its own. |
| `@sarv-in/email-spam-scan/links` | `tldts`, `htmlparser2` | Deceptive-link detection. |
| `@sarv-in/email-spam-scan/security` | `tldts`, `htmlparser2` | The five-level decision, for the UI that renders it. |
| `@sarv-in/email-spam-scan/content` | `tldts`, `htmlparser2` | The body-content stage: vocabulary, quote stripping, link structure. |
| `@sarv-in/email-spam-scan/scan` | all of the above + `postal-mime` | `scan(rawMessage)` and the bulk stream. The only entry that costs a MIME parser. |
| `@sarv-in/email-spam-scan/verify` | **none statically** — `mailauth`, an optional peer, is `import`ed on first use | Real SPF/DKIM/DMARC verification against DNS. One of the two entries that can make a network call. |
| `@sarv-in/email-spam-scan/reputation` | `ipaddr.js` — `node:dns` is `import`ed on first use | Blocklist lookups for a sending address or a domain. Node only, and it queries nothing you did not name. |

The split exists because the common case in a mail client is displaying a
verdict that was computed at ingest, hours ago, on a server. That side needs
thresholds and a JSON parse, not a scanner.

**Every entry answers the same question the same way in every environment.**
Until v0.2 the `links` and `security` entries parsed HTML with the ambient
`DOMParser`, which meant they found no links at all in Node — the ingest-time
scorer silently reported "no deceptive links" on every message it ever scored,
while the renderer running the identical code on the identical message found
them. HTML is now parsed with `htmlparser2`, so there is one implementation and
one answer. The entry-point dependency table above is pinned by a test that
walks the source import graph, so an accidental import cannot quietly add weight
to a browser bundle.

## Quick start

Hand it a message and it answers:

```ts
import { scan } from '@sarv-in/email-spam-scan/scan';

const result = await scan(await readFile('message.eml'), { authserv: 'mx.example.com' });

// {
//   assessed: true,
//   score: 10,
//   verdict: 'spam',
//   isSpam: true,
//   suspicious: true,
//   reasons: [ { id: 'auth-failed', points: 3, detail: 'DMARC failed — …' }, … ],
//   auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail', overall: 'fail' },
//   originIp: '185.199.108.1',
//   message: { messageId: null, subject: 'Re: your account', fromName: 'PayPal Support', … },
// }
```

Or use the pieces directly, when you already have them — which is the normal
case inside a mail client, where the IMAP fetch has handed you an envelope and a
header block and parsing the message again would be waste:

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

## Scanning a whole message

`scan(raw, options)` parses the message with
[`postal-mime`](https://www.npmjs.com/package/postal-mime), runs the header
stage, the content stage and the attachment stage over it, and returns one JSON
verdict — numbers,
strings and named reason ids, no classes and no functions, so you can store it
and read it back later with `spamVerdict` and `parseSpamReasons` alone. It takes
anything `postal-mime` takes: a string, a `Buffer`, a `Uint8Array`, a `Blob` or
a `ReadableStream`.

**Tell it your authserv-id.** This is the one security decision `scan` makes for
you, and it is worth understanding. `Authentication-Results` is plain text, and
every hop that handles a message can write one — including the sender, who can
simply type `Authentication-Results: dmarc=pass` into their own message before
sending it. RFC 8601 exists for this: your own boundary MTA stamps its
authserv-id (usually its hostname) at the start of the header it writes.

```ts
await scan(raw, { authserv: 'mx.example.com' }); // only that server is believed
```

Without one, `scan` keeps the **topmost** line of each authentication header and
discards the rest, on the conventional assumption that your own MTA was the most
recent hop — headers are prepended, so a forged verdict the sender wrote sits at
the bottom. That assumption is usually right and occasionally not: a forwarder
in front of you also prepends. `trustedAuthHeaders(headerLines, authserv?)` is
exported so you can see exactly which lines survived.

**Other options.** `receivedAt` (unix seconds) is the delivery time the
date-skew rule compares the sender's `Date:` against; it defaults to the
timestamp on the topmost `Received:` header, and you should pass your IMAP
INTERNALDATE instead when you have one, because you trust your own server's
clock more than a header. `auth` replaces the verdict read from the headers with one you verified
yourself — see
[Verifying authentication yourself](#verifying-authentication-yourself).
`reputation` folds in an assessment from a blocklist lookup you ran yourself —
see [Reputation: asking somebody else](#reputation-asking-somebody-else).
`knownSpammer: true` applies the categorical
5-point rule for a sender the recipient has reported. `ownMail: true` returns
`assessed: false` with a `null` verdict — not judged, which a UI must not render
as a green tick.

**Attachments are scored; their bytes are not handed back.**
`result.message.attachments` gives you each filename and MIME type, and the
`attachment-*` reasons say what the stage made of them — see
[The attachment rules](#the-attachment-rules). The content itself is left out
deliberately: it is the largest thing in a message, and a verdict you store
should stay small enough to store.

### The bulk stream

`scanMany` takes any iterable or async iterable and yields one result per
message:

```ts
import { scanMany } from '@sarv-in/email-spam-scan/scan';

for await (const { id, result, error } of scanMany(messages, { concurrency: 8 })) {
  if (error) log.warn(`${id} could not be read: ${error.message}`);
  else if (result.isSpam) await file(id, result);
}
```

Exactly one of `result` and `error` is set. A message that cannot be read is
**reported, never thrown**: in a run over a real mailbox, one bad message must
not end the run and lose the fifty thousand behind it.

Results come back **in input order** even though the scans overlap, because a
bulk API whose output order depends on how long each message happened to take is
one nobody can write a stable test — or a resumable job — against. The source is
consumed lazily and at most `concurrency` messages are held at once, so this
works on a mailbox larger than memory. Per-message `options` override the shared
ones.

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

**Real authentication** (`verifyAuthentication`) — SPF, DKIM and DMARC checked
against live DNS over the original message, rather than read out of a header
somebody else wrote. Its own entry point, its own optional dependency, and
never reached by accident. See
[Verifying authentication yourself](#verifying-authentication-yourself).

**Reputation** (`checkReputation`, `assessReputation`) — what other operators
have already published about the machine that delivered a message and the
domain it claims, asked over DNS. Its own entry point, no default list of zones,
and never reached by accident. See
[Reputation: asking somebody else](#reputation-asking-somebody-else).

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

**The body-content stage** (`assessContentSignals`) — seven rules over what the
message actually says, scored on the sender's **own** words: quoted history,
signature and the mail client's footer are removed first, so forwarding a phish
to your IT desk does not score you as the phisher and a long thread does not get
worse every time somebody hits reply. Listed in full under
[The content rules](#the-content-rules).

**Body extraction** (`bodyContent`, `extractHtml`, `ownWords`) — the same
extraction the rules saw, exported so you can show a preview or explain why a
rule fired. `extractHtml` returns the visible text, the quoted text, the text
the markup hid from the reader, and every anchor with its visible label.

**The attachment stage** (`assessAttachmentSignals`) — seven rules over what a
file claims to be against what its bytes actually are. Nothing is executed,
unpacked or inflated: a zip's own directory is read, never its contents. Listed
in full under [The attachment rules](#the-attachment-rules).

**Attachment primitives** (`inspectAttachment`, `sniffFileType`,
`inspectFilename`, `listZipEntries`) — the facts the rules scored, exported so
you can show them or score them differently. Zero dependencies, so a renderer
can use them too.

**The whole pipeline** (`scan`, `scanMany`) — raw RFC 5322 bytes in, one JSON
verdict out, all three stages included. See
[Scanning a whole message](#scanning-a-whole-message).

**Verdict plumbing** (`spamVerdict`, `isSpamScore`, `parseSpamReasons`,
`assessmentOf`, `mergeAssessments`) — the thresholds, the stored-reason codec,
and the seam that combines two stages into one verdict, with no dependencies at
all. Merging concatenates reasons and re-totals; it never ORs two booleans, so
two stages that each fall short can still add up to a filing.

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

## The content rules

`assessContentSignals({ subject, text, html })` scores what the sender wrote.
Everything they did not write is removed first: quoted history, the signature
after a `-- ` delimiter, the mail client's own footer, and anything inside a
`blockquote` or a client's quote container (`gmail_quote`, `moz-cite-prefix`,
`yahoo_quoted` and the rest). When both a `text/plain` and a `text/html` part
exist only the HTML is scored — they say the same thing, and scoring both would
double every hit for no reason but the MIME shape.

| Reason id | Points | Fires when |
| --- | --- | --- |
| `content-spam-vocabulary` | 1–2 | The sender's words match a scam vocabulary group. Once per group, capped at 2 overall |
| `content-hidden-text` | 2 | 120+ characters the message's own styling hides from the reader |
| `link-display-mismatch` | 2 each | A link's visible text names one registrable domain while its `href` goes to another. Up to three |
| `link-userinfo` | 2 | A link hides its destination behind `https://bank.example@evil.example/` |
| `link-bare-ip` | 2 | A link points straight at an IP address rather than a domain |
| `content-shouting` | 1 | Four or more consecutive words in capitals, or runs of `!!!` |
| `link-punycode` | 1 | A link goes to a punycode/IDN domain, which can imitate a familiar name |

**Two kinds of rule, and only one of them is capped.** The vocabulary and
shouting rules are an *interpretation* of prose; word lists age badly, and a
filter that can convict on vocabulary alone eventually eats somebody's ordinary
mail. Together they are worth 3 at the very most — enough to raise a suspicion
for a human to look at, never enough to reach `SPAM_THRESHOLD`. Matching every
group in the corpus **and** shouting the whole way through still cannot file a
message. The hidden-text and link rules are *facts about the bytes* — where a
link actually points, what the markup hid — and those accumulate without a cap,
because four of them at once is not a stronger opinion, it is four separate
deceptions. No single rule anywhere in the stage is worth more than 2 points.

**The word lists are data, in this repo, enrichable by pull request.**
`src/data/spam-phrases.ts` groups phrases by the scam rather than by the word,
which is what makes the cap meaningful: twelve pharmacy phrases are one pharmacy
advert, not twelve pieces of evidence. `src/data/freemail-domains.ts` is the
freemail corpus, vendored rather than installed: the upstream package fetches
its list over the network from a `postinstall` script and rewrites its own
source, which makes every install non-reproducible and can leave a consumer with
a silently empty list. See the 0.2.0 entry in [CHANGELOG.md](./CHANGELOG.md).

Matching is done on NFKC-normalised, lowercased text with zero-width and soft-
hyphen characters stripped, on whole-word boundaries. So `ＹＯＵ ＨＡＶＥ ＷＯＮ`
and `you ha<U+200B>ve won` both match, and `wonderful` does not.

## The attachment rules

`assessAttachmentSignals(attachments)` scores what a file claims to be against
what its bytes actually are. Three sources, and the value is in where they
disagree: the **name** is a claim the sender wrote that the reader's operating
system nonetheless acts on, the **MIME type** is a second claim the sender
wrote, and the **bytes** are the only one of the three that cannot be written
to say something other than what the software will do.

| Reason id | Points | Fires when |
| --- | --- | --- |
| `attachment-name-spoof` | 2 | The filename carries bidirectional override characters, so what is displayed is not what runs |
| `attachment-double-extension` | 2 | A document extension in front of an executable one — `invoice.pdf.exe` |
| `attachment-executable` | 2 | The file runs on a double click, by extension or by magic bytes |
| `attachment-type-mismatch` | 2 | The magic bytes contradict the extension, or the declared `Content-Type` |
| `attachment-macro` | 2 | A macro-enabled Office extension, or a zip that contains a VBA project whatever it is called |
| `attachment-archive-executable` | 2 | An archive contains a program — the container is there to get it past the envelope |
| `attachment-encrypted-archive` | 1 | An archive is password-protected, so nothing between here and the reader can look inside |

**Nothing is executed, unpacked or inflated.** An archive's central directory
is read — the names, the declared sizes, the encrypted flag — and that is all.
That is a security decision rather than an optimisation: a 42 KB zip bomb
expands to several petabytes, and every scanner that inflates what it is handed
needs a budget, a timeout and a recursion limit to survive being mailed one.
Reading the directory answers all four of the questions the rules ask and costs
a bounded walk. It is also why this entry has no dependencies — an inflater is
the one thing a scanner that is handed hostile archives should not carry.

**Each rule fires once per message.** Ten executables in one archive is one
decision the sender made, not ten. The reason names the first attachment that
triggered the rule and counts the others.

**This is not an antivirus, and a clean result does not mean safe to open.**
There is no signature database and no emulation here; what the stage can see is
structure. That is why no single rule is worth more than 2 points and why a
bare executable attachment reaches neither threshold on its own — a developer
mailing a build to a colleague sends the same bytes as a dropper, and the
difference is not visible from here. What is visible, and what the stage is
good at, is the combination that has no innocent version: a file whose name,
type and contents each say something different.

**It works without the bytes.** A caller that has only the MIME structure — a
client listing attachments before it has downloaded any — gets the name-based
rules and nothing else, rather than an error or a false clean.

**The extension lists are data, in this repo, enrichable by pull request.**
`src/data/attachment-extensions.ts` holds them, and note that there are two
executable lists rather than one. A `.js` file attached to an email is a
dropper; a `.js` file inside a zip is `node_modules`. What counts inside an
archive is the narrower set that has no innocent reason to be zipped up and
mailed — Windows binaries, script-host formats, shortcuts and installers.

## Security levels

`assessEmailSecurity` returns one of five, ordered by `LEVEL_RANK`:

| Level | Means |
| --- | --- |
| `verified` | Authentication passed and every link stays on the sender's own domain |
| `authenticated` | Authentication passed; nothing else to say |
| `unverified` | The server recorded no authentication verdict — common, not alarming |
| `caution` | Something is off: a deceptive link, or a suspicious score |
| `danger` | DMARC failed, the display name is spoofed, or the score is over the spam threshold |

`worstLevel(levels)` reduces several to the worst one, for a thread or a
conversation view — an empty list is `verified`, nothing to report. The human
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

`scan` makes this decision for you from the `authserv` option — see
[Scanning a whole message](#scanning-a-whole-message).

To establish the verdict yourself instead of reading somebody else's, see the
next section.

## Verifying authentication yourself

Everything above reads a verdict another machine wrote down. The `/verify`
entry computes one: SPF, DKIM and DMARC against live DNS, over the original
unmodified bytes.

```ts
import { verifyAuthentication } from '@sarv-in/email-spam-scan/verify';
import { scan } from '@sarv-in/email-spam-scan/scan';

const verified = await verifyAuthentication(raw, {
  ip: '198.51.100.7', // the address that connected — SPF is a question about it
  helo: 'mail.example.com',
  mailFrom: 'billing@example.com', // the envelope sender, not the `From:` header
});

// A verification that did not complete hands back nothing rather than a guess,
// and `null` tells `scan` to fall back to the trusted headers.
const result = await scan(raw, { auth: verified.completed ? verified.auth : null });
```

**It needs [`mailauth`](https://www.npmjs.com/package/mailauth), and it asks for
it at the last possible moment.** The package is declared as an **optional peer
dependency** and reached through a dynamic `import` inside the one function
that uses it. Install it and verification works; leave it out and every other
part of this package behaves exactly as it did, with only a call to
`verifyAuthentication` throwing — and throwing a message that says what to
install. Nothing else in the source imports it, statically or otherwise, which
is pinned by the same test that walks the import graph for every other entry.

**`scan` will not do this for you, and that is the design.** `scan` and
`scanParsed` make no network calls at all: the same message scores the same way
on a laptop with no resolver, in a test, and in a bundle, and nothing you run
over fifty thousand messages quietly turns into fifty thousand DNS lookups. You
choose when to verify, with your own timeout and your own concurrency, and hand
the answer back through `options.auth`.

**Three things have to come from your MTA, because the message does not carry
them.** `ip` is the address that connected, and SPF is a question about that
address and nothing else — without it, `spf` comes back `unknown` rather than
guessed. `helo` is what the client announced itself as. `mailFrom` is the
envelope sender from `MAIL FROM`, which is not the `From:` header and routinely
differs on forwarded and bulk mail. A `.eml` file on disk has none of the
three; a receiving server has all of them.

**What comes back:**

| Field | |
| --- | --- |
| `auth` | the same `AuthStatus` the header reader produces, so it drops straight into `scan` and `assessEmailSecurity` |
| `completed` | `false` when the verification itself failed — a DNS timeout, a resolver error. `auth` then asserts nothing |
| `spfDomain` | the domain SPF was evaluated for, or `null` when it never was |
| `signatures` | every DKIM signature: signing domain, selector, `mailauth`'s own verbatim result word, its comment, and whether it aligned with the `From:` domain |
| `dmarcPolicy` | the policy the domain published — `none`, `quarantine`, `reject` |
| `error` | why it did not complete, or `null` |

**A verification that failed is not a verdict of `fail`.** A timeout, an
unreachable resolver or a missing record all return `completed: false` and an
`auth` of three `unknown`s, never a failure the rules would score. The
distinction matters because `auth-failed` is a 3-point rule: an outage on your
side must not start scoring everybody's mail as spam. `timeoutMs` defaults to
10 seconds, and `resolver` lets you supply your own — a cache, a stub in tests,
a DoH client.

**Signatures keep `mailauth`'s vocabulary, the rollup does not.** Per signature
you get the exact word the library used (`pass`, `fail`, `neutral`, `policy`,
`temperror`) and its comment, because that is diagnostic detail you cannot
reconstruct. The rolled-up `auth.dkim` is coarser on purpose: `neutral` (body
hash mismatch, no key, expired) and `policy` (a key below `minBitLength`) both
become `fail`, so that a verified verdict and a Gmail header verdict describe
the same message the same way rather than disagreeing about a word.

## Reputation: asking somebody else

Every other rule in this package is a fact about the message in front of you.
This one is not: it asks operators who keep blocklists what they have already
observed about the machine that delivered it and the domain it claims. That is
the strongest single signal in spam filtering, and the only one that requires
telling a third party what you are looking at.

```ts
import {
  assessReputation,
  checkReputation,
  SPAMHAUS_ZEN,
  SPAMCOP,
} from '@sarv-in/email-spam-scan/reputation';
import { scan } from '@sarv-in/email-spam-scan/scan';

const result = await scan(raw);

const reputation = await checkReputation(
  { ip: result.originIp, domain: result.message.fromAddress?.split('@')[1] },
  [SPAMHAUS_ZEN, SPAMCOP], // required: there is no default list
);

// Re-score with what the operators said. `checkReputation` never throws, so a
// blocklist outage costs the message nothing.
const scored = await scan(raw, { reputation: assessReputation(reputation) });
```

**There is no default list of zones, and there never will be.** `blocklists` is
a required argument because every list has terms: Spamhaus is free for
low-volume use and requires a paid data feed above it, SpamCop has its own
conditions, and several lists return a permanent "you are over quota" answer
rather than a listing once you pass their threshold. A package that queried
them by default would put you in breach of somebody's terms without you ever
choosing to. `BLOCKLISTS` is exported as a starting point to read, not a
default to inherit — you pass what you have the right to query.

**And it tells the operator what you are scanning.** Every lookup is a DNS
query naming a sender your user is receiving mail from, and it goes to that
operator's resolvers, and it is visible to whatever resolver you route through.
That is a real disclosure, which is the other half of why this is opt-in, in
its own entry, and never invoked by `scan`.

**The return code is the answer, not the fact that there was one.** A blocklist
replies to `2.0.0.127.zen.spamhaus.org` with an `A` record inside `127.0.0.0/8`
and the last octets say what kind of listing it is — `127.0.0.2` is Spamhaus's
SBL, `127.0.0.10` is the policy list saying "this address should not be
delivering mail directly at all", which is a far weaker signal about a message
that arrived via a relay. This package reads the code, scores per code where
the zone publishes a table, and reports both under `hits[].codes` and
`hits[].meanings`.

Two answers are emphatically **not** listings, and both reach `errors` instead:

- **`127.255.255.0/24`.** That range is the operator complaining, not
  answering: malformed query, a query that arrived via a public resolver, or
  you are over their volume limit. Reading "an A record came back" as "listed"
  turns a misconfigured resolver into a filter that files **every** message as
  spam at once.
- **Anything outside `127.0.0.0/8`.** A wildcard DNS provider, a captive portal
  or a hijacked response answers with a real address. No blocklist publishes a
  listing there.

**A failed lookup is not a clean result.** A resolver timeout, a SERVFAIL, or
nothing worth querying all leave `completed: false` with no hits — never
`listed: false` presented as an all-clear. Zones that did answer are still in
`hits` and `checked`, so one operator's outage never discards another's
listing.

**Several lists agreeing counts once.** `assessReputation` charges the
**highest-scoring** hit per kind of target, not the sum. The public lists mirror
and feed each other, and ZEN is three lists in one zone — summing would make a
message's score depend on how many zones you happened to configure rather than
on the message. The address and the domain are separate facts about separate
things, so those two do add up.

**What comes back:**

| Field | |
| --- | --- |
| `listed` | whether any zone returned a listing |
| `hits` | one per listing: the zone, what was asked about, the codes, their meanings, the points, and the TXT explanation if you asked for it |
| `checked` | the zones that gave a usable answer, listed or not |
| `errors` | the zones that did not, and why |
| `completed` | `false` if any zone failed, or if there was nothing worth asking about |

`timeoutMs` (default 5 s), `servers` (your own resolvers rather than the
system's) and `includeText` (fetch each hit's `TXT` explanation, one extra
query per listing) are the options. `query` replaces the DNS layer outright,
which is how the tests run without a network.

**Only public addresses are ever queried.** `checkReputation` reuses the same
gate as `extractOriginIp`, so private, loopback, link-local, CGNAT and reserved
ranges are skipped rather than asked about — no operator has anything to say
about `10.0.0.4`, and asking would publish your network layout to them one
query at a time.

**Node only.** `node:dns/promises` is reached through a dynamic `import`, so
the entry costs a browser bundle `ipaddr.js` and nothing else — but calling
`checkReputation` without an injected `query` needs a Node resolver.

## Roadmap

Ordered, and open to contribution — see [CONTRIBUTING.md](./CONTRIBUTING.md).

1. ~~**Body content stage.**~~ **Done in 0.2.0** — spam vocabulary and link
   structure, scored on the sender's own words rather than the quoted history,
   with the word and domain lists in this repo as data. See
   [The content rules](#the-content-rules).
2. ~~**Attachment stage.**~~ **Done** — dangerous and double extensions,
   archive contents, macro-bearing Office documents, and a MIME type that
   disagrees with the magic bytes. Nothing is executed, unpacked or inflated.
   See [The attachment rules](#the-attachment-rules).
3. ~~**Streaming API.**~~ **Done** — `scan(rawMessage)` and `scanMany`,
   returning the JSON verdict per message. See
   [Scanning a whole message](#scanning-a-whole-message).
4. ~~**Real authentication.**~~ **Done** — opt-in SPF/DKIM/DMARC verification
   against live DNS via `mailauth`, in its own entry point with its own
   optional dependency, handed back to `scan` through `options.auth`. See
   [Verifying authentication yourself](#verifying-authentication-yourself).
5. ~~**Reputation.**~~ **Done** — DNSBL lookups for the sending address and the
   sender domain, in their own entry point with no default list of zones, handed
   back to `scan` through `options.reputation`. See
   [Reputation: asking somebody else](#reputation-asking-somebody-else).

## API

### Verdict — `@sarv-in/email-spam-scan/verdict`

- `SPAM_THRESHOLD: 5`, `SUSPICIOUS_THRESHOLD: 3`
- `spamVerdict(score): 'spam' | 'suspicious' | 'clean' | null`
- `isSpamScore(score): boolean`
- `parseSpamReasons(json): SpamReason[]` — never throws
- `assessmentOf(reasons): SpamAssessment` — sums and applies both thresholds
- `mergeAssessments(...parts): SpamAssessment` — combines stages; `null` parts are skipped
- `unknownAuthStatus(): AuthStatus`, `rollUpAuthStatus(components)` — the one rollup both the header reader and the DNS verifier use
- `type SpamReason`, `SpamReasonId`, `SpamVerdict`, `SpamAssessment`, `AuthStatus`

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

### Scan — `@sarv-in/email-spam-scan/scan`

- `scan(raw, options?): Promise<ScanResult>` — the whole pipeline over one message
- `scanParsed(email, options?): ScanResult` — the same, over an already-parsed message
- `scanMany(source, options?): AsyncGenerator<BulkScanResult>` — in input order
- `trustedAuthHeaders(headerLines, authserv?): string` — which verdicts survived
- `type ScanOptions`, `ScanResult`, `ScannedMessage`, `RawMessage`, `BulkScanInput`, `BulkScanOptions`, `BulkScanResult`

### Verify — `@sarv-in/email-spam-scan/verify`

Needs the optional peer `mailauth`; nothing else in the package does.

- `verifyAuthentication(message, options?): Promise<AuthVerification>` — SPF, DKIM and DMARC against DNS
- `authVerificationFrom(result): AuthVerification` — the mapping alone, over a `mailauth` result you already have
- `type VerifyOptions`, `AuthVerification`, `VerifiedSignature`, `VerifyInput`, `DnsResolver`

### Reputation — `@sarv-in/email-spam-scan/reputation`

Node only; `node:dns` is imported on first use. No zone is ever queried unless
you name it.

- `checkReputation(target, blocklists, options?): Promise<ReputationResult>` — the lookups; never throws
- `assessReputation(result): SpamAssessment` — the result scored, for `scan`'s `options.reputation`
- `SPAMHAUS_ZEN`, `SPAMHAUS_DBL`, `SPAMCOP`, `BLOCKLISTS` — described zones to choose from, not a default
- `reverseIpLabel(ip)`, `normalizeQueryDomain(domain)`, `blocklistQueryName(target, blocklist)` — the query names, on their own
- `readBlocklistCodes(blocklist, codes): CodeReading` — what a set of return codes means
- `type Blocklist`, `BlocklistCode`, `BlocklistKind`, `BlocklistHit`, `CodeReading`, `DnsQuery`, `ReputationOptions`, `ReputationResult`, `ReputationTarget`, `ReputationLookupError`

### Content — `@sarv-in/email-spam-scan/content`

- `assessContentSignals(input): SpamAssessment` — the whole stage
- `bodyContent(input): BodyContent` — `{ words, anchors, hiddenText }`, what the rules saw
- `extractHtml(html): HtmlExtract` — `{ text, quotedText, hiddenText, anchors }`
- `ownWords(text): string` — plain-text body with quotes, signature and footer removed
- `matchSpamVocabulary(text, groups?): VocabularyHit[]`, `vocabularyPoints(hits)`
- `normalizeForMatching(text)`, `containsPhrase(haystack, phrase)`, `collapseWhitespace(text)`
- `longestShoutRun(text): number`
- `SPAM_PHRASE_GROUPS`, `VOCABULARY_CAP`

### Attachments — `@sarv-in/email-spam-scan/attachments`

Zero dependencies: nothing here unpacks anything, so there is nothing to unpack
it with.

- `assessAttachmentSignals(attachments): SpamAssessment` — the whole stage
- `inspectAttachment(input): AttachmentFacts` — the facts one file yields, unscored
- `inspectFilename(name): FilenameFacts`, `extensionsOf(name)`, `stripBidiControls(name)`
- `sniffFileType(content): SniffedType | null` — the family the first bytes belong to
- `isExecutableType(type)`, `expectedTypesForExtension(ext)`, `expectedTypesForMimeType(type)`
- `listZipEntries(content): ZipListing | null` — the central directory, never the contents
- `asBytes(content): Uint8Array | null` — one correct view over every parser's shape
- `EXECUTABLE_EXTENSIONS`, `ARCHIVE_EXECUTABLE_EXTENSIONS`, `ARCHIVE_EXTENSIONS`, `MACRO_ENABLED_EXTENSIONS`, `DECOY_EXTENSIONS`

### Security — `@sarv-in/email-spam-scan/security`

- `assessEmailSecurity(input): SecurityAssessment`
- `worstLevel(levels): SecurityLevel`
- `LEVEL_RANK`, `linkRuleKey(senderDomain, shown, actual)`, `parseAuthStatus(json)`
- `EMPTY_RULES`, `type LinkRuleSets`, `SecurityCheck`, `CheckStatus`

### Header reading — `@sarv-in/email-spam-scan/headers`

Zero dependencies, so a browser bundle can ask these questions without importing
the scanner.

- `headerLookupFromText(headers): HeaderLookup`, `headerValueFromText`, `headerValuesFromText`
- `bulkHeaderSignals(get): BulkHeaderSignals`, `hasBulkHeaderSignal(get)`, `BULK_HEADER_NAMES`
- `extractAuthHeaderBlock(headers): string | null`
- `parseAuthenticationHeaders(block): AuthStatus`
- `receivedAt(lines): number | null`, `receivedAtFromLine(line)` — delivery time from the trace

### Rules and scoring — `@sarv-in/email-spam-scan`

- `extractOriginIp(sources): string | null` — reads headers, but needs an IP parser
- `originIpFromAuthHeaders(block)`, `originIpFromReceived(lines)`
- `normalizeIp(candidate)`, `isPublicIp(candidate)`
- `assessSpamSignals(input): SpamAssessment`, `SPAM_HEADER_NAMES`, `DATE_SKEW_SECONDS`
- `isFreemailAddress(address)`, `isValidMessageId(id)`, `hasReplyPrefix(subject)`
- `FREEMAIL_DOMAINS` — the vendored corpus, sorted and lowercased
- `linkTarget(href): LinkTarget | null`, `urlsInText(text)`, `anchorMismatches(anchors)`

## Contributing

Rules and word lists are the point of an open-source spam scanner — see
[CONTRIBUTING.md](./CONTRIBUTING.md). The short version: every rule arrives with
a fixture drawn from a real message, a cited source, and evidence that it adds
no false positive to the existing corpus. Coverage is enforced at 100% in CI,
because a spam rule with an untested branch silently files somebody's mail.

## Licence

MIT © Sarv. See [LICENSE](./LICENSE).
