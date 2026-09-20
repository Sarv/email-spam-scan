/**
 * Where somebody else's email begins — and, above it, the words this sender
 * actually typed.
 *
 * WHY THIS MATTERS TO A SCORE. Content rules charge points for what the sender
 * wrote. Score the quoted history too and a thread gets worse every time
 * somebody replies to it, the person who forwards a phish to IT for review is
 * scored as the phisher, and a one-line "thanks" under four screens of a
 * marketing blast inherits every keyword in the blast. The rule that matters
 * is not which words appeared in the file — it is which words this sender
 * chose.
 *
 * TWO CUTS, ONE CORPUS. The markers below answer one question, and two callers
 * ask it for opposite reasons:
 *
 *   * {@link stripQuotedTail} — everything above the quoted history, SIGNATURE
 *     INCLUDED. Contact mining wants precisely that: the sign-off is the part
 *     worth reading, and the only thing that must go is the sign-off belonging
 *     to the person being replied to.
 *   * {@link ownWords} — the same cut, then the signature and the client footer
 *     removed as well, because a scorer must not charge a sender for the phone
 *     number under their own name or for "Sent from my iPhone".
 *
 * They were two implementations in two repositories until they were folded
 * together here, which is the failure this module exists to prevent: a second
 * copy of a marker list drifts, and the drift is invisible — both copies go on
 * returning a plausible string.
 *
 * WHY IT IS HAND-WRITTEN. `email-reply-parser` (the JavaScript port of
 * GitHub's) is the mature library for this job and was the first choice. It is
 * ESM-only and declares `engines: node >= 22`, and this package publishes a
 * CommonJS build and supports Node 20 — a `require()` of it throws
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
 * Everything that opens quoted or forwarded history. The cut is at the FIRST
 * one that matches, so each pattern must match at the true beginning of the
 * quoted block — not in the middle of it, and never in the sender's own prose:
 * a false match here DELETES the sender's words, silently, and in the
 * direction that loses signal.
 *
 * Several are deliberately not anchored to the end of a line. These patterns
 * run on `html-to-text` output as well as on `text/plain`, and that converter
 * routinely collapses a whole reply chain onto a single line — a marker that
 * assumes it sits alone on one misses the longest threads, which are exactly
 * the ones carrying the most of somebody else's words.
 *
 * None carries the `g` flag, so `exec` here is stateless and the array is safe
 * to share between callers and to export.
 */
export const QUOTE_MARKERS: readonly RegExp[] = [
  // "On <date>, <name> <addr> wrote:" — Gmail, Apple Mail, Thunderbird and
  // most of the rest. The span reaches across newlines because the attribution
  // wraps (Gmail puts a bare "wrote:" on the next line), and it is bounded and
  // lazy so it cannot backtrack pathologically over a long body.
  /^On\b[\s\S]{1,300}?\bwrote:/m,
  // The same attribution when it is NOT at the start of a line, which is what
  // `html-to-text` leaves behind: "... review this today. On Wed, Jul 29, 2026
  // at 12:05 PM, Bindu <b@x.com> wrote: ...". A weekday or a digit after "On"
  // is what keeps ordinary prose ("he wrote:") out.
  /\bOn\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|\d)[\s\S]{1,300}?\bwrote:/i,
  // An attribution that does not open with "On" — "Alice Smith
  // <alice@example.com> wrote:" — including the wrapped form where "wrote:"
  // sits alone on the line below. An address or a date somewhere on the line
  // is required, and that requirement is the whole guard: without it this also
  // matches "here is what the auditor wrote:" and throws away everything the
  // sender typed under it. Both halves are bounded, as above.
  /^[^\n]{0,200}[@\d][^\n]{0,200}\s*wrote:\s*$/m,
  // The same line in the languages the clients localise it into.
  /^Le\s.+\sa\s[ée]crit\s*:\s*$/m,
  /^Am\s.+\sschrieb\s.+:\s*$/m,
  /^El\s.+\sescribi[óo]:\s*$/m,
  // Outlook's separators, and every client that copied them.
  /^\s*-{2,}\s*original message\s*-{2,}\s*$/im,
  /^\s*-{2,}\s*forwarded message\s*-{2,}/im,
  /^\s*begin forwarded message:\s*$/im,
  // Outlook's horizontal rule above the history. Long by design: Outlook draws
  // about thirty characters, whereas a rule somebody typed above their OWN
  // sign-off is shorter — and cutting at that one would throw away the
  // signature this text was stripped to find.
  /^_{20,}\s*$/m,
  // The header block Outlook writes where other clients write an attribution.
  // The second header line is required: a lone "From:" also opens ordinary
  // prose and a ticket system's quoted metadata.
  /^From:[^\n]+\n\s*(?:To|Sent|Date|Subject|Cc):/im,
  // RFC 3676 §4.5, the quote prefix itself. Leading whitespace is allowed — a
  // client that indents the quote has still quoted.
  /^\s*>/m,
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
 * Everything above the quoted history: this sender's own message, signature
 * and all.
 *
 * Returns the whole input when nothing matches, and an empty string when the
 * quoted history starts at the top — a bare forward the sender added nothing
 * to. That empty string is a real answer, not a failure: it means there is
 * nothing here that this sender wrote.
 *
 * KNOWN LIMITATION: an attribution is recognised by shape, so a line of the
 * sender's own prose that carries a date or an address and ends in `wrote:`
 * cuts the message there. This is the heuristic every reply parser uses, and
 * the failure is in the safe direction — less of the sender's text, never
 * somebody else's counted as theirs.
 */
export function stripQuotedTail(text: string | null | undefined): string {
  if (!text) return '';
  let earliest = text.length;
  for (const marker of QUOTE_MARKERS) {
    const match = marker.exec(text);
    if (match && match.index < earliest) earliest = match.index;
  }
  return text.slice(0, earliest).trimEnd();
}

/**
 * Strip the quoted history AND the signature, leaving what this sender typed.
 *
 * The signature goes because this is the text a SCORE is computed over, and a
 * sign-off is a sender's job title and phone number, not their argument — a
 * rule that charges points for either would charge every mail from anyone with
 * a long footer.
 *
 * Returns an empty string when the sender typed nothing at all. The content
 * rules must then charge nothing rather than fall back to judging the thread.
 */
export function ownWords(body: string | null | undefined): string {
  const own = stripQuotedTail(body);
  if (!own) return '';
  const kept: string[] = [];
  for (const line of own.split(/\r?\n/)) {
    if (SIGNATURE_DELIMITER.test(line) || MOBILE_FOOTER.test(line)) break;
    kept.push(line);
  }
  return kept.join('\n').trim();
}
