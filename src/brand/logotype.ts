/**
 * The RFC 3709 logotype extension — the part of a VMC that says WHICH logo
 * the certificate was issued for.
 *
 * Without this, a certificate would only prove that some brand owns some
 * domain, and any logo at all could be displayed beside it. With it, the
 * picture a receiver renders is the picture the Mark Verifying Authority
 * looked at: the extension carries the logo's digest, and usually the logo
 * itself, gzipped into a `data:` URI.
 */
import { base64ToBytes, encodeUtf8, gunzip, isGzip } from './bytes.js';
import { loadAsn1, type Asn1Node } from './peers.js';
import { BIMI_LOGO_MAX_BYTES } from './svg.js';

/** id-sha256. */
const SHA256_OID = '2.16.840.1.101.3.4.2.1';
/** id-sha1 — RFC 3709's original algorithm, and what Apple's VMC still uses. */
const SHA1_OID = '1.3.14.3.2.26';

const UNIVERSAL_CLASS = 1;
const TAG_OCTET_STRING = 4;
const TAG_OBJECT_IDENTIFIER = 6;
const TAG_UTF8_STRING = 12;
const TAG_SEQUENCE = 16;
const TAG_PRINTABLE_STRING = 19;
const TAG_IA5_STRING = 22;

function isNode(value: unknown): value is Asn1Node {
  return (
    typeof value === 'object' &&
    value !== null &&
    'idBlock' in value &&
    'valueBlock' in value &&
    typeof (value as Asn1Node).idBlock?.tagNumber === 'number'
  );
}

function isTag(node: Asn1Node, tagNumber: number): boolean {
  return node.idBlock.tagClass === UNIVERSAL_CLASS && node.idBlock.tagNumber === tagNumber;
}

/**
 * A block's child blocks.
 *
 * An OBJECT IDENTIFIER also keeps a `value` array — its arcs — whose entries
 * are plain records, not blocks. Descending into those is the crash the first
 * real VMC (Apple's) produced, so an OID is a leaf here by decree as well as
 * by the `isNode` filter.
 */
function children(node: Asn1Node): Asn1Node[] {
  if (isTag(node, TAG_OBJECT_IDENTIFIER)) return [];
  const value = node.valueBlock.value;
  return Array.isArray(value) ? value.filter(isNode) : [];
}

function hex(node: Asn1Node): string {
  let out = '';
  for (const byte of node.valueBlock.valueHexView) out += byte.toString(16).padStart(2, '0');
  return out;
}

export interface LogotypeEvidence {
  /** SHA-256 digests found in the extension, lower-case hex. */
  sha256: string[];
  /** SHA-1 digests, lower-case hex. */
  sha1: string[];
  /** `data:` URIs found in the extension (the embedded logo, usually gzipped). */
  dataUris: string[];
}

/**
 * Pull the pieces that bind a logo out of a logotype extension value, walking
 * the ASN.1 GENERICALLY: every `SEQUENCE { AlgorithmIdentifier, OCTET STRING }`
 * whose algorithm is SHA-256 or SHA-1 is a digest, and every string that
 * starts `data:` is an embedded logo.
 *
 * Generic on purpose. The exact nesting differs between `direct` and
 * `indirect` LogotypeInfo and between authorities, and a schema written
 * against one issuer's certificates fails another's silently — which would
 * show as "this brand's logo does not match its certificate" for a brand that
 * did everything right.
 */
export async function extractLogotypeEvidence(
  extensionValue: ArrayBuffer | Uint8Array,
): Promise<LogotypeEvidence> {
  const out: LogotypeEvidence = { sha256: [], sha1: [], dataUris: [] };
  const asn1 = await loadAsn1();
  const parsed = asn1.fromBER(extensionValue);
  if (parsed.offset === -1) return out;

  const walk = (node: Asn1Node): void => {
    if (
      isTag(node, TAG_IA5_STRING) ||
      isTag(node, TAG_UTF8_STRING) ||
      isTag(node, TAG_PRINTABLE_STRING)
    ) {
      const text = node.valueBlock.value;
      if (typeof text === 'string' && text.toLowerCase().startsWith('data:')) {
        out.dataUris.push(text);
      }
      return;
    }
    const kids = children(node);
    // HashAlgAndValue ::= SEQUENCE { hashAlg AlgorithmIdentifier, hashValue OCTET STRING }
    const [algorithm, value, ...rest] = kids;
    if (
      isTag(node, TAG_SEQUENCE) &&
      rest.length === 0 &&
      algorithm !== undefined &&
      value !== undefined &&
      isTag(algorithm, TAG_SEQUENCE) &&
      isTag(value, TAG_OCTET_STRING)
    ) {
      const oid = children(algorithm)[0];
      const name =
        oid !== undefined && isTag(oid, TAG_OBJECT_IDENTIFIER) ? oid.valueBlock.toString() : null;
      if (name === SHA256_OID || name === SHA1_OID) {
        (name === SHA256_OID ? out.sha256 : out.sha1).push(hex(value));
        return;
      }
    }
    for (const kid of kids) walk(kid);
  };
  walk(parsed.result);
  return out;
}

/**
 * The bytes a `data:` URI carries, gunzipped when it is gzip.
 *
 * The decompression bound is four times the logo ceiling rather than the
 * ceiling itself: this is a comparison, not a download. Refusing a logo here
 * for being verbose would report "the logo does not match its certificate",
 * which is the accusation this stage must never make by accident.
 */
export async function decodeLogoDataUri(uri: string): Promise<Uint8Array | null> {
  const comma = uri.indexOf(',');
  if (comma < 0) return null;
  const meta = uri.slice('data:'.length, comma).toLowerCase();
  const payload = uri.slice(comma + 1);

  let bytes: Uint8Array | null;
  if (meta.includes(';base64')) {
    bytes = base64ToBytes(payload);
  } else {
    try {
      bytes = encodeUtf8(decodeURIComponent(payload));
    } catch {
      return null;
    }
  }
  if (bytes === null) return null;
  return isGzip(bytes) ? gunzip(bytes, BIMI_LOGO_MAX_BYTES * 4) : bytes;
}
