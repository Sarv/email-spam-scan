/**
 * When the receiving system actually took delivery, read off the `Received:`
 * trace.
 *
 * IMAP hands a client an INTERNALDATE — the server's own record of when the
 * message arrived — and the date-skew rule needs it: a `Date:` header is
 * whatever the sender wrote, and only something outside the message can say
 * whether that was a lie. A raw `.eml` file on disk has no INTERNALDATE, so
 * without this the rule can never fire on a scanned file, and a message dated
 * three years in the future scores the same as one dated correctly.
 *
 * The topmost `Received:` line is the last hop to run, which is the receiving
 * side — the one machine in the trace the reader has any reason to believe.
 * Lines below it were written by hops nobody here controls, so they are not
 * consulted: a sender who wants to defeat the skew rule can write whatever they
 * like into the ones they added.
 *
 * Zero dependencies, so this stays in the `/headers` entry with the rest of
 * the raw-header primitives.
 */

/** A trailing `(comment)` the RFC allows after the timestamp; `Date` chokes on some of them. */
const TRAILING_COMMENT = /\s*\([^()]*\)\s*$/;

/**
 * The delivery time from one `Received:` header value, as unix SECONDS.
 *
 * The timestamp follows the LAST semicolon in the line — the `from`/`by`
 * clauses before it may contain semicolons of their own inside comments, so
 * splitting on the first one reads a hostname as a date.
 */
export function receivedAtFromLine(line: string | null | undefined): number | null {
  if (!line) return null;
  const semicolon = line.lastIndexOf(';');
  if (semicolon === -1) return null;
  const stamp = line
    .slice(semicolon + 1)
    .replace(TRAILING_COMMENT, '')
    .trim();
  if (!stamp) return null;
  const ms = new Date(stamp).getTime();
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/**
 * The delivery time from a message's `Received:` headers, as unix SECONDS.
 *
 * `lines` must be in the order they appear in the message — headers are
 * PREPENDED by each hop, so the first element is the most recent hop. The first
 * line that carries a parseable timestamp wins; a hop that wrote a malformed
 * one costs its own line, not the answer.
 */
export function receivedAt(lines: readonly string[] | null | undefined): number | null {
  for (const line of lines ?? []) {
    const seconds = receivedAtFromLine(line);
    if (seconds !== null) return seconds;
  }
  return null;
}
