/**
 * The two DNS records the brand stage reads: BIMI and DMARC.
 *
 * Both are `k=v; k=v` TXT records, and both are parsed here rather than where
 * they are used, because a record is a value — a string in, a small object
 * out — and a value is the easiest thing in this package to test exhaustively
 * against the forms that actually appear in the wild.
 */

/** Split a `k=v; k=v` record into lower-cased keys. Values keep their case. */
function tagValues(txt: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of txt.split(';')) {
    const equals = part.indexOf('=');
    if (equals < 0) continue;
    const key = part.slice(0, equals).trim().toLowerCase();
    if (key !== '') out.set(key, part.slice(equals + 1).trim());
  }
  return out;
}

/**
 * An `https` URL, or null.
 *
 * BIMI's logo and evidence are fetched by the receiver, so `http` is not a
 * lesser grade of the same thing — it is a logo an attacker on the path gets
 * to choose. The scheme check is the whole of the trust decision here.
 */
function httpsUrlOrNull(value: string | undefined): string | null {
  if (value === undefined || value === '') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.toString() : null;
  } catch {
    return null;
  }
}

export interface BimiRecord {
  /** `l=` — https URL of the SVG logo; null when the tag is absent. */
  logoUrl: string | null;
  /** `a=` — https URL of the evidence (PEM chain); null when absent. */
  evidenceUrl: string | null;
  /** `l=` present but empty: the domain explicitly declines to show a logo. */
  declined: boolean;
}

/** Parse one TXT record as BIMI. Null when it is not a BIMI1 record at all. */
export function parseBimiRecord(txt: string): BimiRecord | null {
  const tags = tagValues(txt);
  if ((tags.get('v') ?? '').toUpperCase() !== 'BIMI1') return null;
  // `l=` present and empty is the explicit decline; absent is simply no logo.
  const logo = tags.get('l');
  const declined = logo === '';
  return {
    logoUrl: declined ? null : httpsUrlOrNull(logo),
    evidenceUrl: httpsUrlOrNull(tags.get('a')),
    declined,
  };
}

export type DmarcPolicyValue = 'none' | 'quarantine' | 'reject';

export interface DmarcRecord {
  policy: DmarcPolicyValue | null;
  subdomainPolicy: DmarcPolicyValue | null;
  /** `pct=`, defaulting to 100 as the spec does. */
  pct: number;
}

function policyValue(value: string | undefined): DmarcPolicyValue | null {
  const policy = (value ?? '').toLowerCase();
  return policy === 'none' || policy === 'quarantine' || policy === 'reject' ? policy : null;
}

/** Parse one TXT record as DMARC. Null when it is not a DMARC1 record. */
export function parseDmarcRecord(txt: string): DmarcRecord | null {
  const tags = tagValues(txt);
  if ((tags.get('v') ?? '').toUpperCase() !== 'DMARC1') return null;
  const pct = Number.parseInt(tags.get('pct') ?? '100', 10);
  return {
    policy: policyValue(tags.get('p')),
    subdomainPolicy: policyValue(tags.get('sp')),
    pct: Number.isFinite(pct) ? pct : 100,
  };
}

/**
 * Does this DMARC policy let a receiver display BIMI? The spec requires an
 * enforcing policy — quarantine or reject — applied to ALL mail (`pct=100`).
 * For a subdomain the `sp=` policy governs when it is present.
 *
 * This is the rule that makes a logo mean anything: under `p=none` a spoofer's
 * message is delivered too, and it would wear the brand beside the real one.
 */
export function dmarcEnforcesBimi(record: DmarcRecord | null, forSubdomain: boolean): boolean {
  if (record === null) return false;
  const effective =
    forSubdomain && record.subdomainPolicy !== null ? record.subdomainPolicy : record.policy;
  return (effective === 'quarantine' || effective === 'reject') && record.pct >= 100;
}
