/**
 * The byte-level primitives the brand stage needs, written against the web
 * platform rather than `node:buffer`, `node:crypto` and `node:zlib`.
 *
 * WHY NOT NODE'S. A logo and a certificate are bytes, and hashing, base64 and
 * gzip are the three things one has to do to them. Reaching for `Buffer`,
 * `createHash` and `gunzipSync` would be shorter — and would make `/brand`
 * the first entry in this package that a browser or a worker cannot import at
 * all. `crypto.subtle`, `atob`/`btoa` and `DecompressionStream` are in every
 * runtime this package supports, so the whole stage stays portable and a
 * renderer can render the shield it is told about.
 *
 * The cost is that two of these are async where Node's are synchronous, which
 * is why {@link sha256Hex} and {@link gunzip} return promises. Everything
 * above them was already async — they are waiting on DNS and HTTPS.
 */

/** The digests the logotype extension binds a logo with. */
export type DigestAlgorithm = 'SHA-256' | 'SHA-1';

function subtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle as SubtleCrypto | undefined;
  if (subtle === undefined) {
    throw new Error(
      'The brand stage needs the Web Crypto API (globalThis.crypto.subtle), which this ' +
        'runtime does not expose. It is present by default in browsers and in Node 19 and ' +
        'later; on Node 18, start the process with --experimental-global-webcrypto.',
    );
  }
  return subtle;
}

/** Lower-case hex, the form a certificate's digests are compared in. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/** The digest of some bytes, lower-case hex. */
export async function digestHex(algorithm: DigestAlgorithm, bytes: Uint8Array): Promise<string> {
  // A fresh view: `BufferSource` excludes the shared-memory backing a plain
  // `Uint8Array` is allowed to have, and the copy is a logo, not a mailbox.
  const digest = await subtleCrypto().digest(algorithm, new Uint8Array(bytes));
  return bytesToHex(new Uint8Array(digest));
}

export const sha256Hex = (bytes: Uint8Array): Promise<string> => digestHex('SHA-256', bytes);
export const sha1Hex = (bytes: Uint8Array): Promise<string> => digestHex('SHA-1', bytes);

/**
 * Base64, in chunks. `String.fromCharCode(...bytes)` over a 64 KB logo is a
 * spread of 65 000 arguments, which overflows the call stack on some engines
 * and works on others — the worst kind of bug to ship in a library.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  const CHUNK = 0x2000;
  let binary = '';
  for (let index = 0; index < bytes.length; index += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(index, index + CHUNK));
  }
  return btoa(binary);
}

/** Decode base64. Null — never a throw — when the input is not base64. */
export function base64ToBytes(base64: string): Uint8Array | null {
  let binary: string;
  try {
    binary = atob(base64.replace(/\s+/g, ''));
  } catch {
    return null;
  }
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) out[index] = binary.charCodeAt(index);
  return out;
}

export function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function encodeUtf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return left.every((byte, index) => byte === right[index]);
}

/** The two-byte gzip magic. A VMC embeds its logo compressed. */
export function isGzip(bytes: Uint8Array): boolean {
  return bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
}

/**
 * Gunzip, with the output BOUNDED.
 *
 * The bound is the point: the bytes come from a certificate fetched over the
 * network, and a few hundred bytes of gzip can expand to gigabytes. Streaming
 * rather than one-shot is what makes the cap enforceable — the read stops at
 * the first chunk that crosses it, instead of after the whole bomb has been
 * allocated.
 *
 * Null when the input is not valid gzip, when it expands past `maxBytes`, or
 * when the runtime has no `DecompressionStream` — three different ways of
 * having no logo, all of which mean the same thing to the caller.
 */
export async function gunzip(bytes: Uint8Array, maxBytes: number): Promise<Uint8Array | null> {
  if (typeof DecompressionStream === 'undefined') return null;
  try {
    const decompressed = new Blob([new Uint8Array(bytes)])
      .stream()
      .pipeThrough(new DecompressionStream('gzip'));
    const reader = decompressed.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  } catch {
    return null;
  }
}
