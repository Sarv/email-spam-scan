import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  base64ToBytes,
  bytesEqual,
  bytesToBase64,
  bytesToHex,
  decodeUtf8,
  digestHex,
  encodeUtf8,
  gunzip,
  isGzip,
  sha1Hex,
  sha256Hex,
} from '../src/brand/bytes.js';
import { BIMI_LOGO_MAX_BYTES } from '../src/brand/svg.js';

import { gzipOf, SVG, utf8 } from './vmc-fixture.js';

/**
 * The web-platform byte primitives the brand stage is built on.
 *
 * What this protects: these replace `Buffer`, `node:crypto` and `node:zlib`
 * so that `/brand` can run in a browser or a worker. Each one is a place
 * where a wrong answer is silent — a digest that disagrees with the
 * certificate reads as "this brand substituted its logo", and a gunzip
 * without a bound is a memory-exhaustion bug reachable from a stranger's
 * certificate.
 */
afterEach(() => {
  vi.unstubAllGlobals();
});

describe('hex and digests', () => {
  it('pads every byte to two hex digits', () => {
    expect(bytesToHex(new Uint8Array([0x00, 0x0f, 0xab, 0xff]))).toBe('000fabff');
    expect(bytesToHex(new Uint8Array(0))).toBe('');
  });

  it('computes the SHA-256 and SHA-1 of the same bytes', async () => {
    // Known-answer, so a broken digest cannot agree with itself and pass.
    expect(await sha256Hex(utf8('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(await sha1Hex(utf8('abc'))).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
    expect(await digestHex('SHA-256', new Uint8Array(0))).toHaveLength(64);
  });

  // A runtime with no Web Crypto is a setup mistake, and it must say so.
  // Silently reporting "the logo does not match" would blame the brand for
  // the reader's own Node flags.
  it('names the missing Web Crypto API rather than failing quietly', async () => {
    vi.stubGlobal('crypto', undefined);
    await expect(sha256Hex(utf8('abc'))).rejects.toThrow(/Web Crypto API/);
  });
});

describe('base64 and text', () => {
  it('round-trips bytes through base64', () => {
    expect(bytesToBase64(utf8('hello'))).toBe('aGVsbG8=');
    expect(base64ToBytes('aGVsbG8=')).toEqual(utf8('hello'));
    expect(decodeUtf8(encodeUtf8('héllo'))).toBe('héllo');
  });

  // Regression: `String.fromCharCode(...bytes)` over a 64 KB logo is a spread
  // of 65 000 arguments, which overflows the call stack on some engines and
  // works on others. The chunked loop is the whole point of the function.
  it('encodes a logo-sized buffer without a stack overflow', () => {
    const big = new Uint8Array(BIMI_LOGO_MAX_BYTES);
    for (let index = 0; index < big.length; index += 1) big[index] = index % 251;
    const base64 = bytesToBase64(big);
    expect(base64).toHaveLength(Math.ceil(big.length / 3) * 4);
    expect(base64ToBytes(base64)).toEqual(big);
  });

  it('answers null for input that is not base64, and tolerates whitespace', () => {
    expect(base64ToBytes('!!!!')).toBeNull();
    expect(base64ToBytes('aGVs\nbG8=')).toEqual(utf8('hello'));
  });
});

describe('comparison and gzip', () => {
  it('compares bytes by length and content', () => {
    expect(bytesEqual(utf8('abc'), utf8('abc'))).toBe(true);
    expect(bytesEqual(utf8('abc'), utf8('abcd'))).toBe(false);
    expect(bytesEqual(utf8('abc'), utf8('abd'))).toBe(false);
  });

  it('recognises the gzip magic', () => {
    expect(isGzip(new Uint8Array([0x1f, 0x8b, 0x08]))).toBe(true);
    expect(isGzip(utf8('<svg'))).toBe(false);
    expect(isGzip(new Uint8Array([0x1f]))).toBe(false);
  });

  it('decompresses an embedded logo', async () => {
    expect(await gunzip(await gzipOf(SVG), BIMI_LOGO_MAX_BYTES)).toEqual(SVG);
  });

  // THE reason the bound exists: a few hundred bytes of gzip from a stranger's
  // certificate can expand to gigabytes. The read has to stop at the cap, not
  // after the whole bomb has been allocated.
  it('refuses a payload that expands past the cap', async () => {
    const bomb = await gzipOf(new Uint8Array(512 * 1024));
    expect(bomb.length).toBeLessThan(4_096);
    expect(await gunzip(bomb, BIMI_LOGO_MAX_BYTES)).toBeNull();
  });

  it('answers null for corrupt gzip and for a runtime with no DecompressionStream', async () => {
    const corrupt = new Uint8Array([0x1f, 0x8b, ...utf8('not gzip at all')]);
    expect(await gunzip(corrupt, BIMI_LOGO_MAX_BYTES)).toBeNull();
    vi.stubGlobal('DecompressionStream', undefined);
    expect(await gunzip(await gzipOf(SVG), BIMI_LOGO_MAX_BYTES)).toBeNull();
  });
});
