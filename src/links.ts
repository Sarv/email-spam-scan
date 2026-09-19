/**
 * Deceptive links — an anchor whose visible text names one domain while the
 * href goes somewhere else entirely.
 *
 * Needs a DOM parser, so this is the one module in the package that is not
 * pure computation over strings. It uses the global `DOMParser`: present in a
 * browser and in Electron's renderer, absent in plain Node unless a caller
 * supplies one (`happy-dom`, `jsdom`, or Node's own `--experimental` builds).
 * When it is absent, every function here degrades to "found nothing" rather
 * than throwing — a scanner that cannot inspect links must not claim links are
 * bad, and must not take the whole scan down either.
 *
 * Domain comparison is on the registrable domain (eTLD+1), so
 * `mail.paypal.com` vs `paypal.com` is NOT flagged while `paypal.com` vs
 * `paypal.secure-login.ru` is.
 */
import { assessSender, domainsInText, registrableDomain, type PhishingReason } from './identity.js';

export type PhishingLevel = 'none' | 'caution' | 'danger';

export interface PhishingAssessment {
  level: PhishingLevel;
  reasons: PhishingReason[];
}

/** One deceptive link: the domain the text shows vs the domain the href goes to. */
export interface LinkMismatch {
  shown: string;
  actual: string;
}

/**
 * Common ESP / link-tracker / URL-shortener registrable domains. Legitimate
 * marketing mail routinely wraps links through these, so a "text says
 * brand.com, href is <esp>" mismatch there is expected, not deceptive — skip
 * them to keep the signal meaningful, because a warning that fires on ordinary
 * newsletters is a warning people learn to click past.
 *
 * Contributions: add a host that exists to COUNT a click and redirect. Do not
 * add a host merely because one sender abused it — these carry ordinary mail
 * too, and blocking the carrier punishes everyone who uses it.
 */
export const LINK_WRAPPER_DOMAINS: ReadonlySet<string> = new Set<string>([
  'amazonses.com',
  'bit.ly',
  'cmail19.com',
  'cmail20.com',
  'createsend.com',
  'doubleclick.net',
  'exct.net',
  'goo.gl',
  'google.com',
  'hs-sending.com',
  'hubs.ly',
  'hubspot.com',
  'hubspotlinks.com',
  'list-manage.com',
  'lnkd.in',
  'mailchimp.com',
  'mailgun.org',
  'mandrillapp.com',
  'marketo.com',
  'ow.ly',
  'pardot.com',
  'rs6.net',
  'safelinks.protection.outlook.com',
  'salesforce.com',
  'sendgrid.net',
  'sendible.com',
  'sparkpostmail.com',
  't.co',
  'tinyurl.com',
]);

/** Parse HTML with the ambient DOMParser, or null when there is none / it fails. */
function parseHtml(html: string | null | undefined): Document | null {
  if (!html || typeof DOMParser === 'undefined') return null;
  try {
    return new DOMParser().parseFromString(html, 'text/html');
  } catch {
    return null;
  }
}

/**
 * The `href` of an anchor that the `a[href]` selector matched. The cast is
 * honest where the `|| ''` it replaces was not: the selector already required
 * the attribute, so the fallback was a branch no message could reach, and a
 * coverage gate cannot be met by a test that cannot be written.
 */
function hrefOf(anchor: Element): string {
  return anchor.getAttribute('href') as string;
}

/** The registrable domain an href resolves to, or null when it is not http(s). */
function hrefDomain(href: string): string | null {
  if (!/^https?:\/\//i.test(href)) return null;
  try {
    return registrableDomain(new URL(href).hostname);
  } catch {
    return null;
  }
}

/**
 * Every anchor whose visible text names one registrable domain while its href
 * goes to another — the structured form, so callers can act on the PAIR (trust
 * it, block it, list it) rather than only render a sentence about it.
 * De-duplicated, and capped at three: the fourth example of the same trick
 * persuades nobody who was not already persuaded by the first.
 */
export function linkMismatches(html: string | null | undefined): LinkMismatch[] {
  const doc = parseHtml(html);
  if (!doc) return [];
  const seen = new Set<string>();
  const out: LinkMismatch[] = [];
  for (const anchor of Array.from(doc.querySelectorAll('a[href]'))) {
    if (out.length >= 3) break;
    const actual = hrefDomain(hrefOf(anchor));
    if (!actual || LINK_WRAPPER_DOMAINS.has(actual)) continue;
    for (const shown of domainsInText(anchor.textContent)) {
      if (shown === actual || LINK_WRAPPER_DOMAINS.has(shown)) continue;
      const key = `${shown}->${actual}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ shown, actual });
      break;
    }
  }
  return out;
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
 * Returns false when there is HTML with links but no parser to read it: the
 * claim being made is "everything here stays home", and that cannot be
 * asserted on evidence nobody looked at.
 */
export function linkDomainsAllMatch(
  html: string | null | undefined,
  senderDomain: string | null,
): boolean {
  if (!html) return true;
  if (!senderDomain) return false;
  const doc = parseHtml(html);
  if (!doc) return false;
  for (const anchor of Array.from(doc.querySelectorAll('a[href]'))) {
    const href = hrefOf(anchor);
    if (!/^https?:\/\//i.test(href)) continue;
    const domain = hrefDomain(href);
    if (domain !== senderDomain) return false;
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
