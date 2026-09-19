/**
 * The IP address that handed this message to the recipient's mail system —
 * the one input every reputation check (DNS blocklists, reverse DNS) needs.
 *
 * Recorded at scan time even when no reputation stage is enabled, because it
 * cannot be recovered later: by the time anyone wants to ask a blocklist about
 * a message, the headers it came from may be long gone.
 *
 * Two sources, in order of trust:
 *
 *   1. The receiving server's own SPF evaluation. `Received-SPF` carries the
 *      address it checked as `client-ip=`; `Authentication-Results` repeats it
 *      in the SPF comment ("sender IP is x", "designates x as permitted
 *      sender") or as `smtp.remote-ip=` (RFC 8601 iprev). This is
 *      authoritative: it IS the connecting client as the server saw it.
 *      Headers are prepended hop by hop, so the first match top-down is the
 *      verdict OUR server wrote, not one a forwarder carried along in an ARC
 *      header.
 *   2. The `Received:` trace, top down. The first hop written with a `from`
 *      clause naming a PUBLIC address is the last external handoff. This is
 *      the fallback for servers that record no SPF result at all. It is a
 *      heuristic — a provider whose internal relays use public addresses will
 *      name one of those first — which is why the SPF sources win when present.
 *
 * Private, loopback, link-local, carrier-NAT and IPv4-mapped-private addresses
 * are never returned: they are the receiving side's own plumbing, and a
 * blocklist has nothing to say about them.
 *
 * `ipaddr.js` owns the address grammar and the range classification; the code
 * here only finds candidate tokens and asks it.
 */
import ipaddr from 'ipaddr.js';

const IPV4_SHAPE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * A candidate token as a canonical address string, or null when it is not an
 * IP address at all. Strips the `[...]` and `IPv6:` decoration Received lines
 * use, and folds an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) to its IPv4.
 */
export function normalizeIp(candidate: string | null | undefined): string | null {
  if (!candidate) return null;
  const token = candidate
    .trim()
    .replace(/^\[|\]$/g, '')
    .replace(/^ipv6:/i, '');
  if (!token) return null;
  // Validity is checked BEFORE parsing, so the parsers below cannot throw.
  if (IPV4_SHAPE.test(token)) {
    // Strict dotted-quad only: ipaddr.js also accepts octal, hex and short
    // forms, none of which a mail server writes into a header — and all of
    // which are a way to smuggle a different address past a reader's eye.
    return ipaddr.IPv4.isValidFourPartDecimal(token) ? ipaddr.IPv4.parse(token).toString() : null;
  }
  if (token.includes(':') && ipaddr.IPv6.isValid(token)) {
    return ipaddr.process(token).toString();
  }
  return null;
}

/** True for a routable public unicast address (v4 or v6). */
export function isPublicIp(candidate: string | null | undefined): boolean {
  const ip = normalizeIp(candidate);
  return ip !== null && ipaddr.process(ip).range() === 'unicast';
}

/** Where an SPF evaluator writes the address it checked. Order = preference. */
const AUTH_IP_PATTERNS: readonly RegExp[] = [
  /\bclient-ip=([^;\s()]+)/gi,
  /\bsender ip is ([^;\s()]+)/gi,
  /\bdesignates ([^;\s()]+) as permitted sender/gi,
  /\bsmtp\.remote-ip=([^;\s()]+)/gi,
];

/** The connecting client's address from the authentication header block. */
export function originIpFromAuthHeaders(block: string | null | undefined): string | null {
  if (!block) return null;
  for (const pattern of AUTH_IP_PATTERNS) {
    for (const match of block.matchAll(pattern)) {
      // Group 1 is not optional in the pattern, so a match always carries it. The
      // index type is `| undefined` only because `noUncheckedIndexedAccess` is on,
      // and a `?? ''` fallback here would be an unreachable branch that the 100%
      // coverage gate could never be satisfied for honestly.
      const ip = normalizeIp(match[1] as string);
      if (ip && isPublicIp(ip)) return ip;
    }
  }
  return null;
}

/**
 * The last external hop from the `Received:` lines, top-down (the order the
 * header block lists them — newest first). Only the `from` clause of each line
 * is read: the `by` clause names the receiving side, whose address is not the
 * one being judged.
 */
export function originIpFromReceived(
  received: readonly string[] | null | undefined,
): string | null {
  if (!received?.length) return null;
  for (const raw of received) {
    // Whitespace is collapsed first, so the clause can be walked token by
    // token rather than matched. The regex this replaces —
    // `/^from\s+(.*?)(?:\s+by\s+|\s*;|$)/i` — had three quantifiers that
    // could exchange the same spaces with each other, which is polynomial
    // backtracking on a `Received:` line, i.e. on text the sender writes. A
    // split and a loop cannot backtrack at all, and say the same thing more
    // plainly.
    const tokens = raw.replace(/\s+/g, ' ').trim().split(' ');
    if (tokens[0]?.toLowerCase() !== 'from') continue;
    for (const token of tokens.slice(1)) {
      // `by` hands over to the RECEIVING side, whose address is not the one
      // being judged; `;` ends the clause and starts the timestamp.
      if (token.toLowerCase() === 'by') break;
      const beforeSemicolon = token.split(';')[0] as string;
      for (const piece of beforeSemicolon.split(/[()[\]]+/)) {
        const ip = normalizeIp(piece);
        if (ip && isPublicIp(ip)) return ip;
      }
      if (token.includes(';')) break;
    }
  }
  return null;
}

export interface OriginIpSources {
  /** The {@link extractAuthHeaderBlock} output for this message, if any. */
  authHeaders?: string | null;
  /** Every `Received:` value, unfolded, in header order (newest first). */
  received?: readonly string[] | null;
}

/** The one address to record, or null when no source names a public one. */
export function extractOriginIp(sources: OriginIpSources): string | null {
  return originIpFromAuthHeaders(sources.authHeaders) ?? originIpFromReceived(sources.received);
}
