/**
 * The Verified Mark Certificate — the part of BIMI that earns a tick.
 *
 * A published logo is what a domain says about itself. A VMC is a third party
 * saying it: a Mark Verifying Authority has checked the trademark registration
 * and the domain, and issued an X.509 certificate that binds the two to a
 * specific picture. Every one of those clauses has to hold before anything is
 * displayed as verified, because a tick that can be earned by less is a tick
 * anyone can mint.
 *
 * So this module answers one question — may this logo, for this domain, be
 * shown as verified? — and every way of answering "no" names its cause, since
 * a shield that reads "logo published, certificate not verified: expired on
 * 2025-04-01" is worth having and a silently missing tick is not.
 */
import { registrableDomain } from '../identity.js';

import { bytesEqual, bytesToHex, sha1Hex, sha256Hex } from './bytes.js';
import { decodeLogoDataUri, extractLogotypeEvidence } from './logotype.js';
import { MVA_ROOTS, type MarkVerifyingAuthorityRoot } from './mva-roots.js';
import {
  loadX509,
  type Certificate,
  type ExtendedKeyUsage,
  type SubjectAlternativeName,
} from './peers.js';

/** id-kp-BrandIndicatorforMessageIdentification (RFC 9495). */
export const BIMI_EKU_OID = '1.3.6.1.5.5.7.3.31';
/** id-pe-logotype (RFC 3709 / RFC 6170). */
export const LOGOTYPE_EXTENSION_OID = '1.3.6.1.5.5.7.1.12';

export type VmcStatus =
  | 'verified'
  | 'unparseable'
  | 'not-vmc'
  | 'expired'
  | 'not-yet-valid'
  | 'broken-chain'
  | 'untrusted-root'
  | 'domain-mismatch'
  | 'logo-mismatch';

export interface VmcResult {
  status: VmcStatus;
  /** Subject O — the brand owner the authority verified. */
  organization: string | null;
  /** Issuer CN — which authority's CA signed it. */
  issuer: string | null;
  /** Issuer O. */
  issuerOrganization: string | null;
  /** Unix seconds. */
  notAfter: number | null;
  detail: string;
}

/** `AB:CD:...` upper-case, the form `openssl` prints and {@link MVA_ROOTS} records. */
export function fingerprintHex(der: ArrayBuffer | Uint8Array): string {
  const bytes = der instanceof Uint8Array ? der : new Uint8Array(der);
  return (bytesToHex(bytes).toUpperCase().match(/../g) ?? []).join(':');
}

function firstField(
  certificate: Certificate,
  which: 'subject' | 'issuer',
  field: string,
): string | null {
  const name = which === 'subject' ? certificate.subjectName : certificate.issuerName;
  return name.getField(field)[0] ?? null;
}

/** How a certificate is named in a message: its CN, or the whole DN if it has none. */
function label(certificate: Certificate): string {
  return firstField(certificate, 'subject', 'CN') ?? certificate.subject;
}

/** The SAN dNSNames a VMC lists, lower-cased. */
export async function vmcDomains(certificate: Certificate): Promise<string[]> {
  const { SubjectAlternativeNameExtension } = await loadX509();
  const san = certificate.getExtension(
    SubjectAlternativeNameExtension,
  ) as SubjectAlternativeName | null;
  if (san === null) return [];
  return san.names.items
    .filter((name) => name.type === 'dns')
    .map((name) => name.value.toLowerCase());
}

export interface ValidateVmcOptions {
  /** Trust anchors; defaults to the pinned authorities. Tests pass their own. */
  roots?: readonly MarkVerifyingAuthorityRoot[];
  /** "Now" for the validity checks; defaults to the wall clock. */
  now?: Date;
}

function normalizeFingerprint(value: string): string {
  return value.replace(/:/g, '').toUpperCase();
}

/**
 * Validate a VMC chain for a domain and a logo.
 *
 * Throws only if the optional peer dependencies are missing — every other
 * failure is a {@link VmcResult} with a status and a sentence.
 */
export async function validateVmc(
  pem: string,
  domain: string,
  logo: Uint8Array,
  options: ValidateVmcOptions = {},
): Promise<VmcResult> {
  const x509 = await loadX509();
  const now = options.now ?? new Date();
  const roots = options.roots ?? MVA_ROOTS;
  const fail = (status: VmcStatus, detail: string, leaf?: Certificate): VmcResult => ({
    status,
    organization: leaf ? firstField(leaf, 'subject', 'O') : null,
    issuer: leaf ? firstField(leaf, 'issuer', 'CN') : null,
    issuerOrganization: leaf ? firstField(leaf, 'issuer', 'O') : null,
    notAfter: leaf ? Math.floor(leaf.notAfter.getTime() / 1000) : null,
    detail,
  });

  let certificates: Certificate[];
  try {
    certificates = x509.PemConverter.decode(pem).map((der) => new x509.X509Certificate(der));
  } catch (cause) {
    return fail(
      'unparseable',
      `The certificate file could not be parsed: ${(cause as Error).message}`,
    );
  }
  const first = certificates[0];
  if (first === undefined)
    return fail('unparseable', 'The certificate file contains no certificate');

  // The leaf is the one nobody else in the file was signed by.
  const issuers = new Set(certificates.map((certificate) => certificate.issuer));
  const leaf = certificates.find((certificate) => !issuers.has(certificate.subject)) ?? first;

  const eku = leaf.getExtension(x509.ExtendedKeyUsageExtension) as ExtendedKeyUsage | null;
  if (eku === null || !eku.usages.includes(BIMI_EKU_OID)) {
    return fail(
      'not-vmc',
      'The certificate is not a Verified Mark Certificate (no BIMI key usage)',
      leaf,
    );
  }
  if (now < leaf.notBefore) {
    return fail(
      'not-yet-valid',
      `The certificate is not valid until ${leaf.notBefore.toISOString().slice(0, 10)}`,
      leaf,
    );
  }
  if (now > leaf.notAfter) {
    return fail(
      'expired',
      `The certificate expired on ${leaf.notAfter.toISOString().slice(0, 10)}`,
      leaf,
    );
  }

  // Chain to a PINNED root. The builder verifies every signature on the way;
  // what it cannot know is which self-signed certificate deserves trust — and
  // VMCs do not chain to the web PKI, so the browser's answer is no help.
  let rootCertificates: Certificate[];
  try {
    rootCertificates = roots.map((root) => new x509.X509Certificate(root.pem));
  } catch (cause) {
    return fail(
      'untrusted-root',
      `Pinned root could not be loaded: ${(cause as Error).message}`,
      leaf,
    );
  }
  const builder = new x509.X509ChainBuilder({
    certificates: [
      ...certificates.filter((certificate) => certificate !== leaf),
      ...rootCertificates,
    ],
  });
  let chain: readonly Certificate[];
  try {
    chain = await builder.build(leaf);
  } catch (cause) {
    return fail(
      'broken-chain',
      `The certificate chain could not be built: ${(cause as Error).message}`,
      leaf,
    );
  }
  // `build` always returns the certificate it was handed, so the chain is
  // never empty — `reduce` says so to the type checker without leaving a
  // fallback branch behind that no test could ever reach.
  const top = chain.reduce((_deeper, certificate) => certificate, leaf);
  if (!(await top.isSelfSigned())) {
    return fail('broken-chain', `The chain stops at "${label(top)}" without reaching a root`, leaf);
  }
  const thumbprint = normalizeFingerprint(fingerprintHex(await top.getThumbprint('SHA-256')));
  const pinned = roots.find((root) => normalizeFingerprint(root.sha256) === thumbprint);
  if (pinned === undefined) {
    return fail(
      'untrusted-root',
      `The chain ends at "${label(top)}", which is not a recognised Mark Verifying Authority`,
      leaf,
    );
  }
  for (const issued of chain.slice(1)) {
    if (now < issued.notBefore || now > issued.notAfter) {
      return fail(
        'expired',
        `An issuing certificate ("${label(issued)}") is outside its validity period`,
        leaf,
      );
    }
  }

  // The domain. A VMC names the domains it covers; the From domain — or its
  // organisational domain, since BIMI records fall back to it — must be one.
  const wanted = domain.toLowerCase();
  const organizationalDomain = registrableDomain(wanted) ?? wanted;
  const names = await vmcDomains(leaf);
  const covered = names.some(
    (name) => name === wanted || name === organizationalDomain || wanted.endsWith(`.${name}`),
  );
  if (!covered) {
    return fail(
      'domain-mismatch',
      names.length > 0
        ? `The certificate covers ${names.join(', ')}, not ${wanted}`
        : 'The certificate names no domain',
      leaf,
    );
  }

  // The logo. The certificate binds a specific SVG by digest (and usually
  // embeds it); the file the domain serves has to be that one, or the tick
  // would vouch for a picture the authority never saw.
  const logotype = leaf.getExtension(LOGOTYPE_EXTENSION_OID);
  if (logotype === null)
    return fail('not-vmc', 'The certificate carries no logotype extension', leaf);
  const evidence = await extractLogotypeEvidence(logotype.value);
  const bound =
    evidence.sha256.includes(await sha256Hex(logo)) ||
    evidence.sha1.includes(await sha1Hex(logo)) ||
    (await embedsLogo(evidence.dataUris, logo));
  if (!bound) {
    return fail(
      'logo-mismatch',
      'The logo the domain serves is not the one the certificate was issued for',
      leaf,
    );
  }

  const organization = firstField(leaf, 'subject', 'O');
  return {
    status: 'verified',
    organization,
    issuer: firstField(leaf, 'issuer', 'CN'),
    issuerOrganization: firstField(leaf, 'issuer', 'O') ?? pinned.organization,
    notAfter: Math.floor(leaf.notAfter.getTime() / 1000),
    detail: `${organization ?? 'The brand'} proved ownership of ${wanted} to ${pinned.organization}`,
  };
}

/** Does one of the certificate's embedded logos have exactly these bytes? */
async function embedsLogo(dataUris: readonly string[], logo: Uint8Array): Promise<boolean> {
  for (const uri of dataUris) {
    const embedded = await decodeLogoDataUri(uri);
    if (embedded !== null && bytesEqual(embedded, logo)) return true;
  }
  return false;
}
