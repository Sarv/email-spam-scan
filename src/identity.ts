/**
 * Who the message claims to be from, judged from the From header alone.
 *
 * `support@paypal.com` as the friendly name on a message that actually came
 * from attacker@evil.ru is the oldest phishing tell there is, and it needs
 * nothing but the envelope — no body, no network, no DNS. That makes it the
 * one high-signal check available at the moment a message arrives, before a
 * body has been downloaded, which is why it lives in its own entry point
 * rather than inside the scanner.
 *
 * Two very different callers want the same answer and must never disagree
 * about it: the ingest-time scorer, and the UI drawing a shield on a message
 * someone is reading months later. Two copies of a security rule drift, in
 * exactly the direction nobody notices — the one where the warning quietly
 * stops firing.
 *
 * Browser-safe by construction: the only import is `tldts`, which is pure.
 * Available as `@sarv-in/email-spam-scan/identity` so a renderer can take this
 * rule without the scanner behind it.
 *
 * Domain comparison is done on the registrable domain (eTLD+1), so
 * `mail.paypal.com` vs `paypal.com` is NOT flagged, while `paypal.com` vs
 * `paypal.secure-login.ru` is.
 */
import { getDomain } from 'tldts';

export interface PhishingReason {
  /** 'danger' is a categorical tell; 'caution' is suggestive on its own. */
  severity: 'danger' | 'caution';
  text: string;
}

/**
 * Registrable domain (eTLD+1), lowercased — e.g. `a.b.paypal.co.uk` →
 * `paypal.co.uk`. Null for anything that is not a resolvable public domain
 * (bare words, IPs, empty). `allowPrivateDomains: false` keeps a host like
 * `someone.github.io` collapsing to its true registrable owner.
 */
export function registrableDomain(input: string | null | undefined): string | null {
  if (!input) return null;
  const host = input.trim().toLowerCase();
  if (!host) return null;
  return getDomain(host, { allowPrivateDomains: false }) || null;
}

/** Registrable domain of an email address (the part after the last `@`). */
export function domainOfAddress(address: string | null | undefined): string | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  if (at < 0) return null;
  return registrableDomain(address.slice(at + 1));
}

/**
 * Registrable domains referenced inside a free-text display name.
 *
 * Tokenised on separators and handed to `tldts` to adjudicate — no pattern
 * tries to recognise a domain itself. A token like `Advik` yields null and is
 * ignored; `paypal.com` or `security@paypal.com` yields `paypal.com`. The
 * dot requirement stops `tldts` resolving a bare word against its no-dot
 * fallbacks and inventing a brand out of somebody's surname.
 */
export function domainsInText(text: string | null | undefined): string[] {
  if (!text) return [];
  const found = new Set<string>();
  for (const rawToken of text.split(/[\s<>(),;:"'|]+/)) {
    const token = rawToken.trim();
    if (!token) continue;
    // If the token is (or contains) an email address, keep the host side.
    const candidate = token.includes('@') ? token.slice(token.lastIndexOf('@') + 1) : token;
    if (!candidate.includes('.')) continue;
    const domain = registrableDomain(candidate);
    if (domain) found.add(domain);
  }
  return [...found];
}

/**
 * Assess the sender identity from the always-available From name + address.
 *
 * DANGER when the display name references a different registrable domain than
 * the one the mail was sent from (the classic display-name spoof); CAUTION
 * when the sender domain is punycode/IDN, which can be a homograph of a real
 * brand and can equally be somebody's perfectly ordinary non-Latin domain —
 * which is why it is a caution and not a verdict.
 */
export function assessSender(
  fromName: string | null | undefined,
  fromAddress: string | null | undefined,
): PhishingReason[] {
  const reasons: PhishingReason[] = [];
  const senderDomain = domainOfAddress(fromAddress);
  if (!senderDomain) return reasons;

  const nameDomains = domainsInText(fromName).filter((domain) => domain !== senderDomain);
  if (nameDomains.length > 0) {
    reasons.push({
      severity: 'danger',
      text: `The sender name mentions ${nameDomains.join(', ')}, but this email was actually sent from ${senderDomain}.`,
    });
  }

  if (senderDomain.includes('xn--')) {
    reasons.push({
      severity: 'caution',
      text: `The sender domain "${senderDomain}" uses punycode, which can be used to imitate a well-known brand.`,
    });
  }

  return reasons;
}
