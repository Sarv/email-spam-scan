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
import { anchorMismatches, linkTarget, LINK_WRAPPER_DOMAINS, type LinkMismatch } from './urls.js';

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

/**
 * True when every http(s) link in the body resolves to the sender's own
 * registrable domain. Absence of links counts as true — nothing points away.
 *
 * Returns false when the sender's domain is unknown: the claim being made is
 * "everything here stays home", and there is no home to compare against.
 */
export function linkDomainsAllMatch(
  html: string | null | undefined,
  senderDomain: string | null,
): boolean {
  if (!html) return true;
  if (!senderDomain) return false;
  for (const anchor of extractHtml(html).anchors) {
    const target = linkTarget(anchor.href);
    // Non-http(s) hrefs — `mailto:`, `#top`, `cid:` — are not places to be
    // sent, so they cannot point away from home.
    if (target && target.domain !== senderDomain) return false;
  }
  return true;
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
