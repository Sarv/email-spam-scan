/**
 * The sender's own words, out of a plain-text body that may carry a whole
 * thread below them.
 *
 * WHY THIS MATTERS TO A SCORE. Content rules charge points for what the sender
 * wrote. Score the quoted history too and a thread gets worse every time
 * somebody replies to it, the person who forwards a phish to IT for review is
 * scored as the phisher, and a one-line "thanks" under four screens of a
 * marketing blast inherits every keyword in the blast. The rule that matters
 * is not which words appeared in the file — it is which words this sender
 * chose.
 *
 * WHY IT IS HAND-WRITTEN. `email-reply-parser` (the JavaScript port of
 * GitHub's) is the mature library for this job and was the first choice. It is
 * ESM-only and declares `engines: node >= 22`, and this package publishes a
 * CommonJS build and supports Node 18 — a `require()` of it throws
 * `ERR_REQUIRE_ESM` on every Node below 22, in the consumer's process, at run
 * time. Taking it would mean either breaking that promise or bundling somebody
 * else's code into ours. What is left is small and specified: RFC 3676 §4.3
 * gives the signature delimiter, RFC 3676 §4.5 gives the `>` quote prefix, and
 * the attribution lines below are the handful of literal strings that the
 * clients in actual use emit. It stays here, pure and covered, rather than
 * growing: anything more ambitious about reconstructing a thread belongs in a
 * library, and this is not one.
 */

/**
 * The last line of the attribution above quoted history: anything ending in
 * `wrote:`.
 *
 * Deliberately not `on .* wrote:` on one line, because the date between them
 * wraps — Gmail emits "On Tue, 3 Mar 2026 at 09:14, Alice <a@b.com>" and
 * "wrote:" as two separate lines, and matching only the joined form leaves the
 * whole quoted thread in the sender's own words.
 */
const ATTRIBUTION_END = /\bwrote:\s*$/i;

/**
 * The FIRST line of that attribution, when it wrapped: "On <a date>, ...".
 * Recognised only so it can be removed along with the `wrote:` line it belongs
 * to — never on its own, where "On 3 July we shipped 40 units" is an ordinary
 * sentence. Requiring a digit keeps it to something with a date in it.
 */
const ATTRIBUTION_START = /^\s*on\b.+\d/i;

/**
 * Lines that begin the quoted history. Everything from the first match on is
 * somebody else's writing.
 *
 * Each is anchored and requires the shape the client actually emits, because a
 * false match here DELETES the sender's own words from the scan — silently,
 * and in the direction that loses signal.
 *
 *   `On <date> <someone> wrote:`     Gmail, Apple Mail, Thunderbird, most others
 *   `<someone> wrote:`               the same attribution wrapped onto one line
 *   `-----Original Message-----`     Outlook, and every client that copied it
 *   `________________________`       Outlook's horizontal rule above the history
 *   `From: …`                        the header block Outlook writes instead
 *   `> …`                            the RFC 3676 quote prefix itself
 *   `Sent from my …`                 not history, but not prose either
 */
const QUOTE_START_PATTERNS: readonly RegExp[] = [
  ATTRIBUTION_END,
  /^\s*-{2,}\s*original message\s*-{2,}\s*$/i,
  /^\s*-{2,}\s*forwarded message\s*-{2,}\s*$/i,
  /^\s*_{5,}\s*$/,
  /^\s*from:\s+\S/i,
  /^\s*>/,
];

/**
 * RFC 3676 §4.3: a line of exactly `-- ` (two hyphens, one space) separates the
 * signature from the body. Accepted without the trailing space too, because
 * most clients and most mail-transfer paths strip it.
 */
const SIGNATURE_DELIMITER = /^-- ?$/;

/**
 * `Sent from my iPhone` and its cousins — a client's footer, not the sender's
 * words. Kept to the literal openings the clients actually emit rather than a
 * general "sent from …", which would cut a body at an ordinary sentence.
 */
const MOBILE_FOOTER =
  /^\s*(?:sent from my |sent from mail for |sent from outlook|get outlook for )/i;

/**
 * Strip the quoted history and the signature, leaving what this sender typed.
 *
 * Returns the whole input unchanged when nothing matches, and an empty string
 * when the sender typed nothing at all — a bare forward with no comment. An
 * empty result is a real answer, not a failure: it means the content rules have
 * no words of this sender's to judge, and they must then charge nothing rather
 * than fall back to judging the thread.
 *
 * KNOWN LIMITATION: the attribution pattern cuts at any line ending in
 * `wrote:`, so a body whose own prose ends a line that way ("here is what the
 * auditor wrote:") loses everything below it. This is the heuristic every
 * reply parser uses, and the failure is in the safe direction — the scan sees
 * FEWER of the sender's words and therefore charges fewer points, never more.
 * Narrowing it needs the date formats of every locale, which is the reason
 * this job belongs in a library and the reason the library was not usable.
 */
export function ownWords(body: string | null | undefined): string {
  if (!body) return '';
  const kept: string[] = [];
  for (const line of body.split(/\r?\n/)) {
    if (SIGNATURE_DELIMITER.test(line) || MOBILE_FOOTER.test(line)) break;
    if (QUOTE_START_PATTERNS.some((pattern) => pattern.test(line))) {
      // A wrapped attribution left its opening line above the one that
      // matched. Take it too, or the sender is credited with the date and
      // address of the person they are replying to.
      for (let last = kept[kept.length - 1]; last !== undefined && ATTRIBUTION_START.test(last);) {
        kept.pop();
        last = kept[kept.length - 1];
      }
      break;
    }
    kept.push(line);
  }
  return kept.join('\n').trim();
}
