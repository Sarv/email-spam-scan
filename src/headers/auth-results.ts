import type { AuthStatus } from '../verdict.js';

/**
 * Pull the mail-authentication headers out of a raw header block.
 *
 * `Authentication-Results` (RFC 8601) is where the RECEIVING server records
 * its SPF / DKIM / DMARC verdicts; `ARC-Authentication-Results` carries them
 * across forwarders, and `Received-SPF` is the older SPF-only form. Together
 * they are the only evidence of authentication a client ever sees without
 * doing the DNS work itself.
 *
 * Every occurrence is kept, not just the first: a message that crossed several
 * hops has one line per hop, and the parser downstream treats the whole block
 * as one text. Folded continuation lines are unfolded into one line each.
 *
 * Note what this is NOT: it is not verification. It is a report of what some
 * other machine concluded, and it is only worth what that machine is worth —
 * trustworthy for the hop that your own server wrote, decorative for the ones
 * a forwarder passed along. Actually verifying SPF/DKIM/DMARC needs the
 * network and the original message; that is a separate, opt-in stage.
 *
 * @returns the matching headers as `name: value` lines, or undefined when the
 *   block has none — so a caller stores NULL ("no verdict recorded") rather
 *   than an empty string that would later parse as a verdict of "unknown".
 */
export function extractAuthHeaderBlock(
  rawHeaders: string | Buffer | undefined | null,
): string | undefined {
  if (!rawHeaders) return undefined;
  const text = typeof rawHeaders === 'string' ? rawHeaders : rawHeaders.toString('utf8');
  // Header name anchored at the start of the block or after a newline; value
  // runs until the next UNFOLDED newline (one not followed by whitespace).
  //
  // No `[ \t]*` before the value group, deliberately. It reads as "skip the
  // space after the colon", but the value group accepts those same spaces, so
  // the two can exchange them — polynomial backtracking on a header block an
  // attacker writes. The leading space is removed by the `.trim()` below,
  // which had to happen anyway for the folded case.
  const pattern =
    /(?:^|\r?\n)((?:arc-)?authentication-results|received-spf):([\s\S]*?)(?=\r?\n(?![ \t])|$)/gi;
  const lines: string[] = [];
  for (const match of text.matchAll(pattern)) {
    // Group 2 is not optional in the pattern, so a match always carries it;
    // the index type is `| undefined` only because of `noUncheckedIndexedAccess`.
    const value = (match[2] as string).replace(/\r?\n[ \t]+/g, ' ').trim();
    if (value) lines.push(`${match[1]}: ${value}`);
  }
  return lines.length ? lines.join('\n') : undefined;
}

/**
 * The extracted block into the three verdicts a consumer stores.
 *
 * FEED THIS ONLY the output of {@link extractAuthHeaderBlock}, never a raw
 * header block. The matching is substring-based, so against raw headers a
 * sender could plant `X-Whatever: dmarc=pass` and be believed; against the
 * extracted block, only headers that a receiving MTA is supposed to have
 * written are in scope. The types make that hard to get wrong by accident —
 * but it is the reason the two functions are in one file.
 *
 * KNOWN LIMITATION, recorded rather than hidden: this reads the FIRST verdict
 * of each kind it finds anywhere in the block, not the one belonging to the
 * most trustworthy `authserv-id`. On a message that crossed a forwarder, an
 * upstream hop's `dkim=pass` therefore outranks your own server's `dkim=fail`.
 * RFC 8601 defines the structure needed to do this properly (authserv-id,
 * per-method result, ptype.property) and a real parser for it is the tracked
 * next step; this is the behaviour being carried over unchanged from Sarv
 * Inbox so that the extraction can be proven at parity first.
 */
export function parseAuthenticationHeaders(block: string | null | undefined): AuthStatus {
  const result: AuthStatus = { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown', overall: 'none' };
  if (!block) return result;

  const headers = block.toLowerCase();

  // Order matters: `spf=softfail` contains no `spf=fail`, but checking the
  // shorter values first would still be a trap worth not setting.
  if (headers.includes('spf=pass')) result.spf = 'pass';
  else if (headers.includes('spf=fail')) result.spf = 'fail';
  else if (headers.includes('spf=softfail')) result.spf = 'softfail';
  else if (headers.includes('spf=neutral')) result.spf = 'neutral';
  else if (headers.includes('spf=none')) result.spf = 'none';

  if (headers.includes('dkim=pass')) result.dkim = 'pass';
  else if (headers.includes('dkim=fail')) result.dkim = 'fail';
  else if (headers.includes('dkim=none')) result.dkim = 'none';

  if (headers.includes('dmarc=pass')) result.dmarc = 'pass';
  else if (headers.includes('dmarc=fail')) result.dmarc = 'fail';
  else if (headers.includes('dmarc=none')) result.dmarc = 'none';

  const components = [result.spf, result.dkim, result.dmarc];
  const passed = components.filter((value) => value === 'pass').length;
  const failed = components.filter((value) => value === 'fail').length;

  if (failed > 0) result.overall = 'fail';
  else if (passed >= 2) result.overall = 'pass';
  else if (passed >= 1) result.overall = 'partial';

  return result;
}
