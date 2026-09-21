# Contributing to mailguard

Thanks for helping. Rules and lists are the whole point of an open-source spam
scanner: the people who see a new campaign first are the people running mail
servers, not us.

## Contents

- [The bar for a new rule](#the-bar-for-a-new-rule)
- [The bar for a word or domain list entry](#the-bar-for-a-word-or-domain-list-entry)
- [Getting set up](#getting-set-up)
- [The map](#the-map)
- [Scoring: how to pick a weight](#scoring-how-to-pick-a-weight)
- [Regular expressions](#regular-expressions)
- [Tests](#tests)
- [Code style](#code-style)
- [Commits and pull requests](#commits-and-pull-requests)
- [Releasing](#releasing)
- [Reporting a bug](#reporting-a-bug)
- [Reporting a security issue](#reporting-a-security-issue)

## The bar for a new rule

A spam rule is not like other code. When it is wrong, the damage is invisible:
the recipient is never told the mail existed. So a rule arrives with four
things, and a pull request without them will be asked for them.

1. **A fixture from a real message.** Headers, redacted of anything personal,
   in `test/fixtures/`. Invented examples prove the code runs, not that the rule
   catches anything.
2. **A cited source.** An RFC, a vendor doc, a public write-up, a CVE, a
   postmaster advisory. "I have seen this a lot" is a reason to open an issue,
   not to merge a rule.
3. **Evidence it adds no false positive.** Run the suite: the ham fixtures are
   ordinary legitimate mail, including the awkward kinds — mailing lists,
   automated notifications, forwarded mail, marketing from real companies,
   long Outlook threads. If your rule fires on any of them, it is not ready.
4. **A weight, argued.** See [Scoring](#scoring-how-to-pick-a-weight).

Rules whose real-world signal is "this looks a bit unusual" are exactly the ones
that seem free and are not. Legitimate mail is far stranger than people expect.

## The bar for a word or domain list entry

Lists live in the repo as data so they can be enriched by pull request, which
also means a bad entry is a bad entry for everyone.

- **A word must be spam-specific, not topic-specific.** "invoice", "password",
  "urgent" and "payment" appear in enormous volumes of legitimate business mail.
  A word earns its place by being rare in ham, not by being common in spam.
- **Say where it came from** in the pull request. A campaign you received, a
  public corpus, a vendor advisory.
- **Domain entries need the registrable domain** (eTLD+1), not a full URL.
- **Never add a domain because one sender abused it.** Shorteners, ESPs and
  file-sharing hosts carry both spam and ordinary mail; blocking the carrier
  punishes everyone who uses it. Those belong in the wrapper list, not the
  block list.
- Entries stay alphabetically sorted, one per line, so diffs stay readable and
  two contributors do not silently conflict.

## Getting set up

```bash
git clone https://github.com/Sarv/mailguard.git
cd mailguard
pnpm install
pnpm verify      # lint + type-check + test with coverage + build
```

Individual steps: `pnpm lint`, `pnpm type-check`, `pnpm test`,
`pnpm test:coverage`, `pnpm build`, `pnpm format`.

`pnpm verify` is what CI runs. If it is green locally it will be green there,
on Linux, macOS and Windows across Node 20, 22 and 24.

## The map

```
src/
  verdict.ts          thresholds, SpamReason, AuthStatus — ZERO dependencies
  identity.ts         registrable domains, sender-name spoofing — tldts only
  headers/
    auth-results.ts   extract and read Authentication-Results
    origin-ip.ts      the public address the message came from
  index.ts            the Node barrel
test/                 one file per source module
```

### Why three entry points

`verdict.ts` must stay dependency-free and `identity.ts` must stay on `tldts`
alone, because both are imported into browser bundles. Adding an import to
either is a breaking change for those consumers even though the types do not
move. If you need something heavier, it belongs under `headers/` or a new
directory, not in those two files.

## Scoring: how to pick a weight

The model is additive — every rule that fires contributes points and one
sentence. `>= 5` is spam, `>= 3` is suspicious.

- **5** — conclusive on its own. An upstream spam verdict; a sender on a known
  spammer list. Reserve it. Anything worth 5 points can file mail alone.
- **3** — strong, but demands a corroborating signal to reach spam. DMARC
  failure; a display name impersonating another domain.
- **2** — a real tell that is individually explicable. A missing `Message-ID`;
  a large date skew; a `Reply-To` pointing at free mail.
- **1** — weak. Only meaningful in company. Punycode in the sender; bulk mail
  with no unsubscribe header.

If you cannot say which of those four your rule is, the rule is not understood
well enough to merge yet. Two weak signals should not add up to a filing
decision by accident, so prefer to under-weight a new rule: raising a weight
later is easy, and apologising for deleted mail is not.

## Regular expressions

Prefer a maintained library to a pattern. Where a pattern is genuinely the right
tool, it must be free of super-linear backtracking —
`regexp/no-super-linear-backtracking` is an **error** here, not a warning, and
CI will reject the pull request.

This is stricter than most repositories on purpose. Everything here parses input
an attacker chose, at ingest, on the path mail travels. A pattern that is
quadratic in the length of a header is not a slow scan; it is a mail server that
stops accepting mail. Two rewrites in the initial release exist for exactly this
reason — see the comments in `origin-ip.ts` and `auth-results.ts`.

Where a loop and a `split` say the same thing as a pattern, write the loop. It
cannot backtrack, and the next person can read it.

## Tests

Coverage is enforced at **100%** — statements, branches, functions and lines —
and CI fails below it. That is not a badge; it is the only thing standing
between a rule with an untested branch and somebody's mail disappearing.

- Tests live in `test/`, one file per source module, run with Vitest.
- **Name the regression.** Each test or block carries a one-line comment saying
  what breaks if it fails. A test whose purpose is not stated gets deleted by
  someone later, and the protection goes with it.
- **Cover the failure paths**, not just the happy one: absent headers, a
  malformed value, an empty string, a value that is technically valid and
  useless.
- **Never delete, skip or loosen a test to get to green.** A pre-existing test
  that now fails is a decision — either the behaviour genuinely changed and the
  test is updated *and the change said out loud in the commit message*, or
  something broke and the code is fixed.
- **Do not assert a bug into permanence.** If current behaviour looks wrong,
  raise it rather than pinning it. Where a known gap must be recorded, say so in
  the test name, as `auth-results.test.ts` does for the authserv-id limitation,
  so the next person can tell a deliberate limitation from an accident.

## Code style

Prettier and ESLint decide; `pnpm format` applies them. Beyond that:

- Pure functions over mutated state; small enough to unit test alone.
- Relative imports carry the `.js` extension — the package is ESM-first.
- `import type` for types, always.
- No `any`. No `console`.
- Comments explain **why**, especially why a rule is weighted as it is or why an
  obvious-looking simplification is wrong. The code already says what it does.

## Commits and pull requests

Conventional commits, single line:
`<type>(<scope>): <subject>` — `feat`, `fix`, `docs`, `style`, `refactor`,
`test`, `chore`. Present-tense imperative: "add", not "added".

```
feat(rules): flag a Reply-To on a different registrable domain
fix(origin-ip): stop reading the timestamp section of a Received line
docs(readme): say plainly that SPF is read, not verified
```

Keep a pull request to one logical change, and say in the description what mail
it catches and what mail you checked it does **not** catch.

## Releasing

Maintainers only. Version, tag, push the tag: the publish workflow releases to
npm via GitHub OIDC trusted publishing, so there is no token to leak. Update
`CHANGELOG.md` in the same change as the version bump.

## Reporting a bug

Open an issue with the smallest header block that reproduces it, redacted.
A false positive — legitimate mail this scored as spam — is the most valuable
bug report this project can receive. Please include what the mail actually was.

## Reporting a security issue

Do not open a public issue for a vulnerability in this package (a
denial-of-service pattern, a rule that can be trivially evaded by construction).
Email security@sarv.com instead.
