/**
 * The optional peer dependencies the VMC check needs, and the structural
 * types this package describes them with.
 *
 * WHY OPTIONAL. Verifying a Verified Mark Certificate means parsing X.509,
 * building a chain and verifying signatures — `@peculiar/x509` and `asn1js`,
 * a few hundred kilobytes that every other entry in this package would
 * otherwise carry to do nothing. So they are peer dependencies, declared
 * optional and reached through a dynamic `import`, exactly as `mailauth` is
 * in `/verify`: a consumer who only wants a domain's logo (or only its
 * favicon) installs nothing extra, and a consumer who wants the tick gets a
 * clear setup error rather than a missing module.
 *
 * WHY STRUCTURAL TYPES. `import type { X509Certificate } from '@peculiar/x509'`
 * would be a compile-time dependency on a package that, by design, may not be
 * installed — every consumer's `tsc` would then fail on a type it cannot
 * resolve. The shapes below describe only the parts this package touches, so
 * the types stand on their own and the runtime objects are the real thing.
 */

import { reasonFrom } from '../cause.js';

/** A distinguished name, as `@peculiar/x509` exposes it. */
export interface X509Name {
  getField(field: string): string[];
}

export interface CertificateExtension {
  value: ArrayBuffer;
}

export interface ExtendedKeyUsage extends CertificateExtension {
  usages: readonly string[];
}

export interface SubjectAlternativeName extends CertificateExtension {
  names: { items: readonly { type: string; value: string }[] };
}

/** An extension class, used as the token `getExtension` selects by type. */
export type ExtensionClass = abstract new (...args: never[]) => CertificateExtension;

export interface Certificate {
  /** The subject DN as one string, for messages and for chain matching. */
  subject: string;
  issuer: string;
  subjectName: X509Name;
  issuerName: X509Name;
  notBefore: Date;
  notAfter: Date;
  getExtension(type: string | ExtensionClass): CertificateExtension | null;
  getThumbprint(algorithm: string): Promise<ArrayBuffer>;
  isSelfSigned(): Promise<boolean>;
}

export interface ChainBuilder {
  build(certificate: Certificate): Promise<readonly Certificate[]>;
}

export interface X509Module {
  PemConverter: { decode(pem: string): ArrayBuffer[] };
  X509Certificate: new (raw: string | ArrayBuffer | Uint8Array) => Certificate;
  X509ChainBuilder: new (params: { certificates: Certificate[] }) => ChainBuilder;
  ExtendedKeyUsageExtension: ExtensionClass;
  SubjectAlternativeNameExtension: ExtensionClass;
}

/** One ASN.1 block, described by its tag rather than by `asn1js`'s classes. */
export interface Asn1Node {
  idBlock: { tagClass: number; tagNumber: number };
  valueBlock: { value?: unknown; valueHexView: Uint8Array; toString(): string };
}

export interface Asn1Module {
  fromBER(input: ArrayBuffer | Uint8Array): { offset: number; result: Asn1Node };
}

function missing(name: string, cause: unknown): Error {
  return new Error(
    `Verifying a BIMI certificate needs the optional peer dependency '${name}', which is not ` +
      `installed. Add it (npm install ${name}) to enable Verified Mark Certificate checks; ` +
      'the logo lookup, the SVG check and the favicon lookup all work without it. ' +
      `(${reasonFrom(cause)})`,
  );
}

let cachedX509: X509Module | undefined;
let cachedAsn1: Asn1Module | undefined;

export async function loadX509(): Promise<X509Module> {
  if (cachedX509 !== undefined) return cachedX509;
  try {
    // `@peculiar/x509` resolves its extension classes through a DI container
    // that reads decorator metadata, so the polyfill has to be loaded first —
    // without it `getExtension(SubjectAlternativeNameExtension)` finds nothing
    // and a perfectly good certificate looks like it names no domain.
    await import('reflect-metadata');
    cachedX509 = (await import('@peculiar/x509')) as unknown as X509Module;
  } catch (cause) {
    throw missing('@peculiar/x509', cause);
  }
  return cachedX509;
}

export async function loadAsn1(): Promise<Asn1Module> {
  if (cachedAsn1 !== undefined) return cachedAsn1;
  try {
    cachedAsn1 = (await import('asn1js')) as unknown as Asn1Module;
  } catch (cause) {
    throw missing('asn1js', cause);
  }
  return cachedAsn1;
}
