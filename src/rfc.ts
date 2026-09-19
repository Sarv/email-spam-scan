/**
 * Two small RFC 5322 predicates the header rules need.
 *
 * Both are deliberately hand-written rather than delegated. `email-addresses`
 * is used for address parsing, where the grammar is genuinely hard; these two
 * are a bracket check and a prefix check, and pulling a schema validator in for
 * them would cost a dependency for a line of work.
 */

/**
 * RFC 5322 `msg-id`, checked structurally: angle-addr brackets with an `@`
 * between two non-empty halves.
 *
 * Written as string operations rather than `/^<.+@.+>$/` because this runs on
 * every message at ingest and the input is chosen by the sender. It is also
 * more honest about what it checks: the full grammar allows quoted strings and
 * domain literals, and this does not attempt them — it catches the absent
 * bracket and the missing domain, which is what forged and hand-rolled
 * Message-IDs actually get wrong.
 */
export function isValidMessageId(messageId: string): boolean {
  if (!messageId.startsWith('<') || !messageId.endsWith('>')) return false;
  const inner = messageId.slice(1, -1);
  const at = inner.indexOf('@');
  // Both halves must be non-empty, and neither may contain a bracket of its own.
  if (at <= 0 || at === inner.length - 1) return false;
  return !inner.includes('<') && !inner.includes('>');
}

/**
 * Reply and forward prefixes across common locales, each optionally carrying a
 * count like `Re[2]:` / `Re(2):`. Multi-letter only (never a bare `R:`/`I:`,
 * which are too easily part of a real subject), and always anchored to a colon,
 * so this cannot over-strip.
 *
 *   en: re, fwd - de: aw, wg - nordic: sv - nl: antw, doorst - fr: rep, tr
 *   es: rv - it: rif - pt: enc
 *
 * Deliberately NOT `ref`/`res`/`vs` — those are ordinary subject words as often
 * as reply markers.
 */
// The counter group carries its own leading whitespace, rather than sitting
// between two independent `\s*`. Written the other way the two could exchange
// the same spaces whenever no counter is present, which is polynomial
// backtracking on a Subject line the sender writes. Both groups are
// non-capturing: nothing reads what they matched, only whether they did.
const REPLY_PREFIX_RE =
  /^\s*(?:re|fwd?|aw|wg|sv|rv|tr|rif|enc|antw|antwort|doorst|rép)(?:\s*(?:\[\d+\]|\(\d+\)))?\s*:/i;

/** Does this subject begin with a reply or forward prefix? */
export function hasReplyPrefix(subject: string | null | undefined): boolean {
  if (!subject) return false;
  return REPLY_PREFIX_RE.test(subject);
}
