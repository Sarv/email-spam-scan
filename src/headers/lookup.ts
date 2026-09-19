/**
 * Reading one header out of a raw block.
 *
 * Every rule in this package takes a {@link HeaderLookup} rather than a string,
 * so a caller that already holds parsed headers (an IMAP client that unfolded
 * them out of a Buffer, a `mailparser` result, a `Map`) runs exactly the same
 * rules as one holding a raw block. Nothing here parses MIME: the whole point
 * of the header stage is that it works before a body exists.
 */

/** Reads one header's unfolded value, or null/undefined when it is absent. */
export type HeaderLookup = (name: string) => string | null | undefined;

/**
 * EVERY value of one header out of a raw header block, unfolded, in the order
 * they appear (newest hop first for trace headers such as `Received`).
 *
 * Anchored at the start of the block or after a newline, but WITHOUT the `m`
 * flag: with `m`, `$` matches every physical line-end, so the lazy capture stops
 * at the first line and a folded multi-line value (a To/Cc list wrapped across
 * lines, a long `List-Unsubscribe`) is truncated to its first entry. Without
 * `m`, the capture runs until the next UNFOLDED newline — a `\n` not followed by
 * whitespace, i.e. the next header — and the continuation lines are joined here.
 * The terminator is a LOOKAHEAD so the newline stays available as the next
 * occurrence's anchor: two adjacent `Received:` lines must both be found.
 *
 * There is deliberately no `[^\S\r\n]*` between the colon and the capture.
 * It reads as "skip the space after the colon", but the capture accepts those
 * same spaces, so the two can exchange them — polynomial backtracking on a
 * header block the sender wrote. The `.trim()` below removes the space anyway,
 * and had to be there regardless for the folded case.
 */
export function headerValuesFromText(headers: string, name: string): string[] {
  if (!headers) return [];
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?:^|\\r?\\n)${escaped}:([\\s\\S]*?)(?=\\r?\\n(?!\\s)|$)`, 'gi');
  const values: string[] = [];
  for (const match of headers.matchAll(re)) {
    const value = (match[1] as string).replace(/\r?\n\s+/g, ' ').trim();
    if (value) values.push(value);
  }
  return values;
}

/** The FIRST value of one header out of a raw header block, unfolded — see {@link headerValuesFromText}. */
export function headerValueFromText(headers: string, name: string): string | null {
  return headerValuesFromText(headers, name)[0] ?? null;
}

/** A {@link HeaderLookup} over a raw header block. */
export function headerLookupFromText(headers: string | null | undefined): HeaderLookup {
  const text = headers || '';
  return (name) => headerValueFromText(text, name);
}
