/**
 * Certificates for the BIMI tests.
 *
 * A Verified Mark Certificate cannot be faked into existence with a string:
 * the code under test parses X.509, builds a chain, verifies signatures and
 * reads two extensions, so the tests have to mint real certificates. They are
 * generated here, once per test file, with the same library the check itself
 * loads — which means the happy path is proved against the real thing and
 * every refusal is proved against a certificate that differs in exactly one
 * way from it.
 *
 * Everything is web-platform, as the code under test is: `crypto.subtle` for
 * keys and digests, `CompressionStream` for the gzipped logo a real VMC
 * embeds. No `node:crypto`, no `node:zlib`, no `Buffer`.
 */
import 'reflect-metadata'; // @peculiar/x509 resolves its extensions through decorator metadata

import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  Extension,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  type X509Certificate,
  X509CertificateGenerator,
} from '@peculiar/x509';
import * as asn1js from 'asn1js';

import type { MarkVerifyingAuthorityRoot } from '../src/brand/mva-roots.js';
import type { Certificate } from '../src/brand/peers.js';
import { BIMI_EKU_OID, LOGOTYPE_EXTENSION_OID, fingerprintHex } from '../src/brand/vmc.js';

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/** A valid Tiny PS logo — the picture every certificate here is issued for. */
export const SVG = utf8(
  '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" version="1.2" ' +
    'baseProfile="tiny-ps" viewBox="0 0 10 10"><title>Example</title>' +
    '<circle cx="5" cy="5" r="4" fill="#0a0"/></svg>',
);

/** A different valid logo — the one a domain must not be able to substitute. */
export const OTHER_SVG = utf8(
  '<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps"><title>Other</title></svg>',
);

export const digestOf = async (
  algorithm: 'SHA-256' | 'SHA-1',
  bytes: Uint8Array,
): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest(algorithm, new Uint8Array(bytes)));

export const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

/** Base64 of a small fixture — spelled out here so no code under test builds it. */
export const base64Of = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));

export async function gzipOf(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([new Uint8Array(bytes)])
    .stream()
    .pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** id-sha256, the algorithm a VMC normally binds its logo with. */
export const SHA256_OID = '2.16.840.1.101.3.4.2.1';
/** id-sha1, which RFC 3709's examples use and Apple's real VMC still does. */
export const SHA1_OID = '1.3.14.3.2.26';

export interface LogotypeOptions {
  /** The digest bytes to bind; null publishes no hash at all. */
  hash?: Uint8Array | null;
  /** false: no embedded copy of the logo. */
  embed?: boolean;
  /** Override the embedded `data:` URI. */
  dataUri?: string;
  hashOid?: string;
  /** Carry NULL parameters in the AlgorithmIdentifier, as real ones do. */
  nullParams?: boolean;
  /** An AlgorithmIdentifier with no OID inside it at all. */
  emptyAlgorithm?: boolean;
}

/** An RFC 3709 logotype extension value binding `svg` — the shape MVAs issue. */
export async function logotypeDer(
  svg: Uint8Array,
  options: LogotypeOptions = {},
): Promise<ArrayBuffer> {
  const hash = options.hash === undefined ? await digestOf('SHA-256', svg) : options.hash;
  const algorithmParts: asn1js.BaseBlock[] =
    options.emptyAlgorithm === true
      ? []
      : [new asn1js.ObjectIdentifier({ value: options.hashOid ?? SHA256_OID })];
  if (options.nullParams === true) algorithmParts.push(new asn1js.Null());
  const hashes =
    hash === null
      ? []
      : [
          new asn1js.Sequence({
            value: [
              new asn1js.Sequence({ value: algorithmParts }),
              new asn1js.OctetString({ valueHex: toArrayBuffer(hash) }),
            ],
          }),
        ];
  const uris =
    options.embed === false
      ? []
      : [
          new asn1js.IA5String({
            value: options.dataUri ?? `data:image/svg+xml;base64,${base64Of(await gzipOf(svg))}`,
          }),
        ];
  const details = new asn1js.Sequence({
    value: [
      new asn1js.IA5String({ value: 'image/svg+xml' }),
      new asn1js.Sequence({ value: hashes }),
      new asn1js.Sequence({ value: uris }),
    ],
  });
  const logotypeData = new asn1js.Sequence({
    value: [new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [details] })] })],
  });
  const direct = new asn1js.Constructed({
    idBlock: { tagClass: 3, tagNumber: 0 },
    value: [logotypeData],
  });
  const subjectLogo = new asn1js.Constructed({
    idBlock: { tagClass: 3, tagNumber: 2 },
    value: [direct],
  });
  return new asn1js.Sequence({ value: [subjectLogo] }).toBER();
}

const KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGNING_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' };

/** Fixed "now", so a certificate's dates mean the same thing every run. */
export const NOW = new Date('2026-06-01T00:00:00Z');
export const past = (days: number): Date => new Date(NOW.getTime() - days * 86_400_000);
export const future = (days: number): Date => new Date(NOW.getTime() + days * 86_400_000);

export interface Authority {
  cert: X509Certificate;
  keys: CryptoKeyPair;
}

export interface CaOptions {
  notBefore?: Date;
  notAfter?: Date;
  issuer?: Authority;
}

/** A self-signed CA — a Mark Verifying Authority's root, or a look-alike. */
export async function makeRoot(name: string, options: CaOptions = {}): Promise<Authority> {
  const keys = await crypto.subtle.generateKey(KEY_ALGORITHM, true, ['sign', 'verify']);
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name,
    notBefore: options.notBefore ?? past(365),
    notAfter: options.notAfter ?? future(3650),
    signingAlgorithm: SIGNING_ALGORITHM,
    keys,
    extensions: [
      new BasicConstraintsExtension(true, 1, true),
      await SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });
  return { cert, keys };
}

/** A CA signed by another CA — the issuing tier a real VMC chain has. */
export async function makeIntermediate(
  name: string,
  issuer: Authority,
  options: CaOptions = {},
): Promise<Authority> {
  const keys = await crypto.subtle.generateKey(KEY_ALGORITHM, true, ['sign', 'verify']);
  const cert = await X509CertificateGenerator.create({
    serialNumber: '03',
    subject: name,
    issuer: issuer.cert.subject,
    notBefore: options.notBefore ?? past(200),
    notAfter: options.notAfter ?? future(1000),
    signingAlgorithm: SIGNING_ALGORITHM,
    publicKey: keys.publicKey,
    signingKey: issuer.keys.privateKey,
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      await SubjectKeyIdentifierExtension.create(keys.publicKey),
      await AuthorityKeyIdentifierExtension.create(issuer.keys.publicKey),
    ],
  });
  return { cert, keys };
}

/**
 * Two authorities that each issued the other, with no self-signed copy of
 * either — a chain the builder walks into a loop instead of finishing.
 *
 * Cross-signing between CAs is ordinary; a published PEM that carries only
 * the cross-signed pair and not the root is the shape that produces this.
 */
export async function makeCrossSignedLoop(): Promise<Authority[]> {
  const alphaKeys = await crypto.subtle.generateKey(KEY_ALGORITHM, true, ['sign', 'verify']);
  const betaKeys = await crypto.subtle.generateKey(KEY_ALGORITHM, true, ['sign', 'verify']);
  const cross = async (
    subject: string,
    issuer: string,
    keys: CryptoKeyPair,
    signingKeys: CryptoKeyPair,
  ): Promise<Authority> => ({
    keys,
    cert: await X509CertificateGenerator.create({
      serialNumber: '04',
      subject,
      issuer,
      notBefore: past(200),
      notAfter: future(1000),
      signingAlgorithm: SIGNING_ALGORITHM,
      publicKey: keys.publicKey,
      signingKey: signingKeys.privateKey,
      extensions: [
        new BasicConstraintsExtension(true, 1, true),
        await SubjectKeyIdentifierExtension.create(keys.publicKey),
        await AuthorityKeyIdentifierExtension.create(signingKeys.publicKey),
      ],
    }),
  });
  return [
    await cross('CN=Alpha Cross CA', 'CN=Beta Cross CA', alphaKeys, betaKeys),
    await cross('CN=Beta Cross CA', 'CN=Alpha Cross CA', betaKeys, alphaKeys),
  ];
}

export interface LeafOptions {
  domains?: string[];
  /** false: no SubjectAltName extension at all. */
  san?: boolean;
  notBefore?: Date;
  notAfter?: Date;
  /** false: no BIMI extended key usage, so it is not a VMC. */
  eku?: boolean;
  /** null: no logotype extension, so nothing binds a logo. */
  logotype?: ArrayBuffer | null;
  issuer?: Authority;
  /** null: a subject DN carrying no organisation. */
  organization?: string | null;
}

/** An end-entity certificate: a VMC unless an option takes something away. */
export async function makeLeaf(options: LeafOptions = {}): Promise<X509Certificate> {
  const issuer = options.issuer ?? (await testPki()).root;
  const keys = await crypto.subtle.generateKey(KEY_ALGORITHM, true, ['sign', 'verify']);
  const extensions: Extension[] = [
    await AuthorityKeyIdentifierExtension.create(issuer.keys.publicKey),
  ];
  if (options.san !== false) {
    extensions.push(
      new SubjectAlternativeNameExtension(
        (options.domains ?? ['example.com']).map((domain) => ({
          type: 'dns' as const,
          value: domain,
        })),
      ),
    );
  }
  if (options.eku !== false) extensions.push(new ExtendedKeyUsageExtension([BIMI_EKU_OID]));
  if (options.logotype !== null) {
    extensions.push(
      new Extension(LOGOTYPE_EXTENSION_OID, false, options.logotype ?? (await logotypeDer(SVG))),
    );
  }
  const organization = options.organization === undefined ? 'Example Inc' : options.organization;
  return X509CertificateGenerator.create({
    serialNumber: '02',
    subject: organization === null ? 'CN=Example Brand' : `CN=Example Brand, O=${organization}`,
    issuer: issuer.cert.subject,
    notBefore: options.notBefore ?? past(30),
    notAfter: options.notAfter ?? future(365),
    signingAlgorithm: SIGNING_ALGORITHM,
    publicKey: keys.publicKey,
    signingKey: issuer.keys.privateKey,
    extensions,
  });
}

/** The PEM file a domain publishes at its `a=` URL. */
export const pemOf = (...certificates: X509Certificate[]): string =>
  certificates.map((certificate) => certificate.toString('pem')).join('\n');

export interface Pki {
  /** The pinned authority these tests trust. */
  root: Authority;
  rootDescriptor: MarkVerifyingAuthorityRoot;
  /** A perfectly valid root that nobody pinned. */
  otherRoot: Authority;
}

let cached: Pki | undefined;

/** The test authorities, built once per test file. */
export async function testPki(): Promise<Pki> {
  if (cached === undefined) {
    const root = await makeRoot('CN=Test Verified Mark Root, O=Test MVA');
    cached = {
      root,
      rootDescriptor: {
        name: 'Test Verified Mark Root',
        organization: 'Test MVA',
        source: 'generated by the test suite',
        sha256: fingerprintHex(await root.cert.getThumbprint('SHA-256')),
        pem: root.cert.toString('pem'),
      },
      otherRoot: await makeRoot('CN=Someone Else Root, O=Not An MVA'),
    };
  }
  return cached;
}

/** A pinned-root descriptor for any authority these tests mint. */
export async function descriptorFor(
  authority: Authority,
  organization = 'Test MVA',
): Promise<MarkVerifyingAuthorityRoot> {
  return {
    name: authority.cert.subject,
    organization,
    source: 'generated by the test suite',
    sha256: fingerprintHex(await authority.cert.getThumbprint('SHA-256')),
    pem: authority.cert.toString('pem'),
  };
}

/**
 * `@peculiar/x509`'s certificate as the structural type this package declares.
 *
 * The package deliberately does not import the library's types (see
 * `peers.ts`), and the library's `getExtension` overloads do not line up with
 * the one-signature shape declared here. The runtime object is the real
 * thing; only the compiler needs telling.
 */
export const asCertificate = (certificate: X509Certificate): Certificate =>
  certificate as unknown as Certificate;
