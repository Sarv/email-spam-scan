/**
 * Deceptive links — an anchor whose visible text names one domain while the
 * href goes somewhere else entirely.
 *
 * Domain comparison is on the registrable domain (eTLD+1), so
 * `mail.paypal.com` vs `paypal.com` is NOT flagged while `paypal.com` vs
 * `paypal.secure-login.ru` is.
 *
 * HTML is read with `htmlparser2` rather than the ambient `DOMParser`. Until
 * v0.2 this module used the browser's parser and returned "found nothing"
 * wherever there was not one — which meant a scan running in Node, where mail
 * is actually scored, silently reported that a phishing body contained no
 * deceptive links. The verdict depended on which process happened to compute
 * it, and the two never met to disagree out loud. One parser that works
 * everywhere is the only version of this check that can be trusted.
 */
import { extractHtml } from './content/html-text.js';
import { assessSender, type PhishingReason } from './identity.js';
import {
  anchorMismatches,
  linkTarget,
  shownDomains,
  LINK_WRAPPER_DOMAINS,
  type LinkMismatch,
} from './urls.js';

export type { LinkMismatch };
export { LINK_WRAPPER_DOMAINS };

export type PhishingLevel = 'none' | 'caution' | 'danger';

export interface PhishingAssessment {
  level: PhishingLevel;
  reasons: PhishingReason[];
}

/**
 * Every anchor whose visible text names one registrable domain while its href
 * goes to another — the structured form, so callers can act on the PAIR (trust
 * it, block it, list it) rather than only render a sentence about it.
 * De-duplicated, and capped at three.
 *
 * Quoted history is included. This function answers "what is in this document"
 * for a reader looking at it, and a deceptive link is worth pointing at
 * wherever in the thread it sits. The body-content SCORER takes the narrower
 * view — see `bodyContent` — because charging the forwarder points for the
 * phish they forwarded is a different mistake.
 */
export function linkMismatches(html: string | null | undefined): LinkMismatch[] {
  return anchorMismatches(extractHtml(html).anchors);
}

/** {@link linkMismatches}, phrased for a human. */
export function assessLinks(html: string | null | undefined): PhishingReason[] {
  return linkMismatches(html).map(({ shown, actual }) => ({
    severity: 'caution' as const,
    text: `A link that appears to go to ${shown} actually points to ${actual}.`,
  }));
}

/** One link that leaves the sender's domain, as {@link summarizeLinkDomains} found it. */
export interface OffDomainLink {
  /** Where it goes: the registrable domain, or the bare host for an IP or an unknown suffix. */
  actual: string;
  /** The domains its visible text names instead, if any — the pair a trust rule is keyed by. */
  shown: string[];
}

/** What the sender's own links do, for a caller that must SAY so. */
export interface LinkDomainSummary {
  /** Unquoted http(s) links the sender wrote. Zero means there was nothing to check. */
  linkCount: number;
  /** Those that leave the sender's domain, one entry per link, in document order. */
  offDomain: OffDomainLink[];
}

/**
 * Where the sender's own links actually go.
 *
 * The counted form of {@link linkDomainsAllMatch}, and the reason it exists:
 * a boolean can decide a level but cannot explain it. A reader shown "every
 * link stays on the sender's domain" on one message and a lesser verdict on
 * the next, with an identical list of ticks under both, learns only that the
 * badge is arbitrary. The difference is in here — how many links there were,
 * and which ones left — and a caller that renders it turns two mystery badges
 * into one sentence.
 *
 * ZERO LINKS IS NOT THE SAME FACT AS "every link stayed home", even though
 * both permit the top level. {@link linkCount} keeps them apart so the words
 * shown to a reader can too: a message with nothing to check has not passed a
 * check, and telling them it did is the kind of small lie that makes the
 * honest badges worthless.
 *
 * Quoted history is excluded — see {@link linkDomainsAllMatch} for why.
 */
export function summarizeLinkDomains(
  html: string | null | undefined,
  senderDomain: string | null,
): LinkDomainSummary {
  const offDomain: OffDomainLink[] = [];
  let linkCount = 0;
  for (const anchor of extractHtml(html).anchors) {
    if (anchor.quoted) continue;
    const target = linkTarget(anchor.href);
    // Non-http(s) hrefs — `mailto:`, `#top`, `cid:` — are not places to be
    // sent, so they cannot point away from home.
    if (!target) continue;
    linkCount += 1;
    if (target.domain && target.domain === senderDomain) continue;
    const actual = target.domain ?? target.host;
    offDomain.push({ actual, shown: shownDomains(anchor, actual) });
  }
  return { linkCount, offDomain };
}

/**
 * True when every http(s) link the sender WROTE resolves to their own
 * registrable domain. Absence of links counts as true — nothing points away.
 *
 * QUOTED HISTORY IS NOT THE SENDER'S. A reply carries the mail it answers,
 * and that mail is somebody else's: its links, its footer, its logo. Counting
 * them means the second message in every conversation and all after it fail a
 * test the first one passed, for links their sender neither wrote nor is
 * shown — clients collapse the quote. The claim this function backs is "every
 * link in THIS message is the sender's own", and the quoted thread was never
 * part of that claim.
 *
 * The deceptive-link check deliberately keeps the wide view: a link whose text
 * names one domain and whose href goes to another is worth pointing at
 * wherever in a thread it sits, because a forged quoted chain is a real
 * phishing technique. See {@link linkMismatches}.
 *
 * Returns false when the sender's domain is unknown: the claim being made is
 * "everything here stays home", and there is no home to compare against.
 *
 * @param isVetted asked about each link that leaves the domain, and true
 *   forgives it. A caller holding the user's trust rules passes one: a reader
 *   who has said "this sender's links through this host are fine" has answered
 *   the very question being asked, and re-asking it on every message makes the
 *   rule look ignored. Omitted, no link is forgiven.
 */
export function linkDomainsAllMatch(
  html: string | null | undefined,
  senderDomain: string | null,
  isVetted?: (link: OffDomainLink) => boolean,
): boolean {
  if (!html) return true;
  if (!senderDomain) return false;
  return summarizeLinkDomains(html, senderDomain).offDomain.every(
    (link) => isVetted?.(link) === true,
  );
}

/**
 * Combine the sender-identity and link signals into one assessment. `level` is
 * the highest severity present, and `reasons` lists each concrete tell.
 */
export function assessPhishing(input: {
  fromName?: string | null;
  fromAddress?: string | null;
  html?: string | null;
}): PhishingAssessment {
  const reasons = [...assessSender(input.fromName, input.fromAddress), ...assessLinks(input.html)];
  const level: PhishingLevel = reasons.some((r) => r.severity === 'danger')
    ? 'danger'
    : reasons.length > 0
      ? 'caution'
      : 'none';
  return { level, reasons };
}
