/**
 * BIMI — Brand Indicators for Message Identification: the logo a domain
 * publishes for its mail, and the certificate that turns that logo into a
 * verified identity.
 *
 * A domain publishes `default._bimi.<domain>` TXT: `v=BIMI1; l=<svg>; a=<pem>`.
 * `l=` points at an SVG Tiny PS logo; `a=` (optional) at a certificate chain
 * from a Mark Verifying Authority that has checked the trademark and the
 * domain. The two are different claims, and this module keeps them apart:
 *
 *   - the LOGO alone is what the domain says about itself. It is shown only
 *     for a domain under an enforcing DMARC policy, because that is the whole
 *     premise of BIMI — a spoofer must never get to wear the brand — and
 *
 *   - the CERTIFICATE is a third party vouching for it, and it is what earns
 *     the tick. See `vmc.ts` for everything that has to hold first.
 *
 * DNS and HTTPS are both injected, so the entire policy is testable with a
 * fixture resolver and a fixture fetch, and nothing here caches: the caller
 * owns the cache, because the caller knows how long it wants to believe an
 * answer and this module does not.
 */
import { reasonFrom } from '../cause.js';
import { nodeDnsQuery, type DnsQuery, type DnsResolverOptions } from '../dns.js';
import { registrableDomain } from '../identity.js';

import { bytesToBase64, decodeUtf8 } from './bytes.js';
import { defaultFetch, fetchBounded, type FetchLike } from './fetch.js';
import type { MarkVerifyingAuthorityRoot } from './mva-roots.js';
import {
  dmarcEnforcesBimi,
  parseBimiRecord,
  parseDmarcRecord,
  type BimiRecord,
  type DmarcPolicyValue,
  type DmarcRecord,
} from './records.js';
import { BIMI_LOGO_MAX_BYTES, checkBimiSvg } from './svg.js';
import { validateVmc, type VmcResult } from './vmc.js';

/** The BIMI selector every receiver checks first. */
export const BIMI_SELECTOR = 'default';
/** A VMC chain is a few KB of PEM; generous, but bounded. */
export const BIMI_EVIDENCE_MAX_BYTES = 64 * 1024;

export type BimiStatus = 'verified' | 'logo' | 'declined' | 'none' | 'invalid' | 'error';

export interface BimiLookup {
  status: BimiStatus;
  /** The logo as a `data:image/svg+xml;base64,...` URI, for 'verified' and 'logo'. */
  logo: string | null;
  organization: string | null;
  issuer: string | null;
  /** Unix seconds; the certificate's notAfter. */
  certificateExpires: number | null;
  dmarcPolicy: DmarcPolicyValue | null;
  /** Which domain's record was used — the From domain or its organisational domain. */
  recordDomain: string | null;
  /** Why, in one sentence. Always set. */
  detail: string;
}

export interface BimiOptions extends DnsResolverOptions {
  /** Your own lookup, in place of `node:dns`. */
  query?: DnsQuery;
  /** Your own fetch, in place of the platform's. */
  fetch?: FetchLike;
  /** "Now" for the certificate's validity dates. */
  now?: () => Date;
  /** Trust anchors; defaults to the pinned Mark Verifying Authorities. */
  roots?: readonly MarkVerifyingAuthorityRoot[];
}

function emptyLookup(over: Partial<BimiLookup>): BimiLookup {
  return {
    status: 'none',
    logo: null,
    organization: null,
    issuer: null,
    certificateExpires: null,
    dmarcPolicy: null,
    recordDomain: null,
    detail: '',
    ...over,
  };
}

/**
 * The first record at `name` that parses as `kind`.
 *
 * `lenient` swallows a resolver failure. A SERVFAIL or a timeout on a
 * SUBDOMAIN's names is ordinary — `_dmarc.mailer.example.com` is often not a
 * zone at all — and must not end the lookup, because the organisational
 * domain still has the answer. The same failure at the organisational domain
 * is a real error and is allowed to throw.
 */
async function firstRecord<T>(
  query: DnsQuery,
  name: string,
  parse: (txt: string) => T | null,
  lenient: boolean,
): Promise<T | null> {
  let records: string[];
  try {
    records = await query(name, 'TXT');
  } catch (cause) {
    if (lenient) return null;
    throw cause;
  }
  for (const txt of records) {
    const parsed = parse(txt);
    if (parsed !== null) return parsed;
  }
  return null;
}

interface DmarcStanding {
  record: DmarcRecord | null;
  /** The policy was read at the organisational domain, so `sp=` governs. */
  forSubdomain: boolean;
}

async function dmarcFor(
  query: DnsQuery,
  domain: string,
  organizationalDomain: string,
): Promise<DmarcStanding> {
  const own = await firstRecord(
    query,
    `_dmarc.${domain}`,
    parseDmarcRecord,
    organizationalDomain !== domain,
  );
  if (own !== null || organizationalDomain === domain) return { record: own, forSubdomain: false };
  const parent = await firstRecord(
    query,
    `_dmarc.${organizationalDomain}`,
    parseDmarcRecord,
    false,
  );
  return { record: parent, forSubdomain: true };
}

async function bimiRecordFor(
  query: DnsQuery,
  domain: string,
  organizationalDomain: string,
): Promise<{ record: BimiRecord; recordDomain: string } | null> {
  const candidates =
    organizationalDomain !== domain ? [domain, organizationalDomain] : [organizationalDomain];
  for (const candidate of candidates) {
    const record = await firstRecord(
      query,
      `${BIMI_SELECTOR}._bimi.${candidate}`,
      parseBimiRecord,
      candidate !== organizationalDomain,
    );
    if (record !== null) return { record, recordDomain: candidate };
  }
  return null;
}

/**
 * Resolve a From domain's BIMI standing.
 *
 * A DNS miss is an ANSWER ('none'); a network failure is 'error'. The
 * difference decides what a caller may cache — "this domain publishes no
 * logo" is worth remembering for a week, "the resolver was unreachable" for
 * about a minute — and getting it wrong is how a brand's logo disappears for
 * everyone after one bad afternoon on the network.
 */
export async function lookupBimi(
  fromDomain: string,
  options: BimiOptions = {},
): Promise<BimiLookup> {
  const domain = fromDomain.trim().toLowerCase();
  if (domain === '') return emptyLookup({ detail: 'No sender domain' });
  const organizationalDomain = registrableDomain(domain) ?? domain;

  try {
    const query = options.query ?? (await nodeDnsQuery(options));
    const fetch = options.fetch ?? defaultFetch();

    // DMARC first: BIMI is only ever shown under an enforcing policy, so a
    // domain that has not committed to one is not asked for a logo at all.
    const dmarc = await dmarcFor(query, domain, organizationalDomain);
    const dmarcPolicy =
      dmarc.record === null
        ? null
        : ((dmarc.forSubdomain ? dmarc.record.subdomainPolicy : null) ?? dmarc.record.policy);

    const found = await bimiRecordFor(query, domain, organizationalDomain);
    if (found === null) {
      return emptyLookup({ dmarcPolicy, detail: 'The domain publishes no BIMI record' });
    }
    const { record, recordDomain } = found;
    if (record.declined) {
      return emptyLookup({
        status: 'declined',
        dmarcPolicy,
        recordDomain,
        detail: 'The domain declines to show a logo',
      });
    }
    if (record.logoUrl === null) {
      return emptyLookup({
        status: 'invalid',
        dmarcPolicy,
        recordDomain,
        detail: 'The BIMI record has no https logo URL',
      });
    }
    if (!dmarcEnforcesBimi(dmarc.record, dmarc.forSubdomain)) {
      return emptyLookup({
        status: 'invalid',
        dmarcPolicy,
        recordDomain,
        detail: `BIMI requires an enforcing DMARC policy; ${
          dmarcPolicy !== null ? `the domain's is p=${dmarcPolicy}` : 'the domain publishes none'
        }`,
      });
    }

    const fetched = await fetchBounded(fetch, record.logoUrl, BIMI_LOGO_MAX_BYTES);
    if (fetched === null) {
      return emptyLookup({
        status: 'invalid',
        dmarcPolicy,
        recordDomain,
        detail: `The logo could not be downloaded, or is larger than ${BIMI_LOGO_MAX_BYTES / 1024} KB`,
      });
    }
    const svg = checkBimiSvg(fetched.bytes);
    if (!svg.ok) {
      return emptyLookup({
        status: 'invalid',
        dmarcPolicy,
        recordDomain,
        detail: `The logo was rejected: ${svg.reason}`,
      });
    }
    const logo = `data:image/svg+xml;base64,${bytesToBase64(fetched.bytes)}`;

    if (record.evidenceUrl === null) {
      return emptyLookup({
        status: 'logo',
        logo,
        dmarcPolicy,
        recordDomain,
        detail: 'The domain publishes a logo but no Verified Mark Certificate',
      });
    }
    const evidence = await fetchBounded(fetch, record.evidenceUrl, BIMI_EVIDENCE_MAX_BYTES);
    if (evidence === null) {
      return emptyLookup({
        status: 'logo',
        logo,
        dmarcPolicy,
        recordDomain,
        detail: 'The certificate could not be downloaded',
      });
    }

    const vmc = await verifyCertificate(evidence.bytes, domain, fetched.bytes, options);
    if (typeof vmc === 'string') {
      return emptyLookup({
        status: 'logo',
        logo,
        dmarcPolicy,
        recordDomain,
        detail: `Certificate not verified: ${vmc}`,
      });
    }
    return emptyLookup({
      status: vmc.status === 'verified' ? 'verified' : 'logo',
      logo,
      dmarcPolicy,
      recordDomain,
      organization: vmc.organization,
      issuer: vmc.issuer,
      certificateExpires: vmc.notAfter,
      detail: vmc.status === 'verified' ? vmc.detail : `Certificate not verified: ${vmc.detail}`,
    });
  } catch (cause) {
    return emptyLookup({
      status: 'error',
      detail: `Lookup failed: ${reasonFrom(cause)}`,
    });
  }
}

/**
 * Validate the certificate, or say — as a string — why it could not even be
 * attempted.
 *
 * `@peculiar/x509` is an OPTIONAL peer dependency, so an install that only
 * wanted the logo has no certificate tooling at all. That is a setup fact,
 * not a network failure and not a bad certificate: the domain still gets its
 * logo, and the missing tick is explained by a sentence naming what to
 * install rather than by an accusation against the brand.
 */
async function verifyCertificate(
  pem: Uint8Array,
  domain: string,
  logo: Uint8Array,
  options: BimiOptions,
): Promise<VmcResult | string> {
  try {
    return await validateVmc(decodeUtf8(pem), domain, logo, {
      roots: options.roots,
      now: options.now?.(),
    });
  } catch (cause) {
    return reasonFrom(cause);
  }
}
