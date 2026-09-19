/**
 * The one place attachment content is turned into bytes to look at.
 *
 * A caller hands in whatever their MIME parser gave them — `postal-mime`
 * returns an `ArrayBuffer`, Node's `mailparser` a `Buffer`, a browser's
 * `File.arrayBuffer()` another `ArrayBuffer`, a test a plain `Uint8Array`.
 * Every rule in this stage needs the same view over all of them, and a view
 * built the wrong way is a whole class of silent bug: `new Uint8Array(buf)`
 * on a `Buffer` copies the wrong window, because a Node `Buffer` is usually a
 * slice of a larger shared pool and its `byteOffset` is not zero.
 *
 * So this is shared rather than repeated in `magic.ts` and `zip.ts`: get it
 * right once, and the zip parser and the signature table can never disagree
 * about where the file starts.
 */

/** Content in any of the shapes a MIME parser hands back. */
export type AttachmentContent = ArrayBuffer | ArrayBufferView;

/**
 * A byte view over attachment content; `null` when there is nothing to read.
 *
 * Empty content reads as `null` rather than an empty array: every caller
 * treats "no bytes" and "zero bytes" the same way — skip the rules that need
 * content — and collapsing them here keeps that decision out of each rule.
 */
export function asBytes(content: AttachmentContent | null | undefined): Uint8Array | null {
  if (!content) return null;
  const bytes = ArrayBuffer.isView(content)
    ? new Uint8Array(content.buffer, content.byteOffset, content.byteLength)
    : new Uint8Array(content);
  return bytes.byteLength > 0 ? bytes : null;
}

/** Whether `bytes` carries `signature` at `offset`. */
export function hasSignature(bytes: Uint8Array, signature: readonly number[], offset = 0): boolean {
  return signature.every((byte, index) => bytes[offset + index] === byte);
}
