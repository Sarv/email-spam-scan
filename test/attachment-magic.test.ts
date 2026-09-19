import { describe, expect, it } from 'vitest';

import { asBytes, hasSignature } from '../src/attachments/bytes.js';
import {
  expectedTypesForExtension,
  expectedTypesForMimeType,
  isExecutableType,
  sniffFileType,
  type SniffedType,
} from '../src/attachments/magic.js';

/** A file starting with these bytes, padded so it is plausibly a file. */
function fileStartingWith(...prefix: number[]): Uint8Array {
  const bytes = new Uint8Array(64);
  bytes.set(prefix);
  return bytes;
}

const text = (value: string): Uint8Array => new TextEncoder().encode(value);

describe('asBytes', () => {
  it('reads an ArrayBuffer, a typed array and a DataView alike', () => {
    const buffer = new Uint8Array([1, 2, 3]).buffer;
    expect(asBytes(buffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(asBytes(new Uint8Array([1, 2, 3]))).toEqual(new Uint8Array([1, 2, 3]));
    expect(asBytes(new DataView(buffer))).toEqual(new Uint8Array([1, 2, 3]));
  });

  // THE regression this helper exists for. A Node `Buffer` is nearly always a
  // window onto a larger shared pool, so `new Uint8Array(buffer.buffer)` reads
  // from the start of the POOL — other messages' bytes — rather than from the
  // start of this file. Every sniff and every zip offset would be wrong, and
  // wrong in a way that changes with unrelated allocations.
  it('honours a view that does not start at the beginning of its buffer', () => {
    const pool = new Uint8Array([0xff, 0xff, 0x25, 0x50, 0x44, 0x46, 0x2d]);
    const view = pool.subarray(2);
    expect(asBytes(view)).toEqual(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]));
    expect(sniffFileType(view)).toBe('pdf');
  });

  // Regression: "no bytes" and "zero bytes" must be the same value, or every
  // rule that skips content has to test for both and one of them will forget.
  it('reads absent and empty content as nothing to look at', () => {
    expect(asBytes(null)).toBeNull();
    expect(asBytes(undefined)).toBeNull();
    expect(asBytes(new Uint8Array(0))).toBeNull();
    expect(asBytes(new ArrayBuffer(0))).toBeNull();
  });
});

describe('hasSignature', () => {
  it('matches at the start and at an offset', () => {
    const bytes = new Uint8Array([0x00, 0x4d, 0x5a]);
    expect(hasSignature(bytes, [0x4d, 0x5a], 1)).toBe(true);
    expect(hasSignature(bytes, [0x4d, 0x5a])).toBe(false);
  });

  // Regression: reading past the end must be a miss, not an exception and not
  // a match against `undefined === undefined`.
  it('does not match a signature longer than the content', () => {
    expect(hasSignature(new Uint8Array([0x4d]), [0x4d, 0x5a])).toBe(false);
  });
});

describe('sniffFileType', () => {
  const cases: ReadonlyArray<readonly [SniffedType, Uint8Array]> = [
    ['zip', fileStartingWith(0x50, 0x4b, 0x03, 0x04)],
    ['zip', fileStartingWith(0x50, 0x4b, 0x05, 0x06)],
    ['zip', fileStartingWith(0x50, 0x4b, 0x07, 0x08)],
    ['ole', fileStartingWith(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)],
    ['pdf', text('%PDF-1.7\n')],
    ['rtf', text('{\\rtf1\\ansi')],
    ['gzip', fileStartingWith(0x1f, 0x8b, 0x08)],
    ['bzip2', text('BZh9')],
    ['xz', fileStartingWith(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)],
    ['7z', fileStartingWith(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c)],
    ['rar', text('Rar!\x1a\x07')],
    ['cab', text('MSCF')],
    ['elf', fileStartingWith(0x7f, 0x45, 0x4c, 0x46)],
    ['mach-o', fileStartingWith(0xfe, 0xed, 0xfa, 0xce)],
    ['mach-o', fileStartingWith(0xfe, 0xed, 0xfa, 0xcf)],
    ['mach-o', fileStartingWith(0xce, 0xfa, 0xed, 0xfe)],
    ['mach-o', fileStartingWith(0xcf, 0xfa, 0xed, 0xfe)],
    ['class', fileStartingWith(0xca, 0xfe, 0xba, 0xbe)],
    ['png', fileStartingWith(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)],
    ['jpeg', fileStartingWith(0xff, 0xd8, 0xff, 0xe0)],
    ['gif', text('GIF89a')],
    ['script', text('#!/bin/sh\necho hi\n')],
    ['windows-pe', fileStartingWith(0x4d, 0x5a, 0x90, 0x00)],
  ];

  // Every row of the table, because the table IS the module: a typo in one
  // signature silently removes one family from the mismatch rule, and the
  // only symptom is a deception that stops being caught.
  for (const [type, bytes] of cases) {
    it(`names ${type} from its first bytes`, () => {
      expect(sniffFileType(bytes)).toBe(type);
    });
  }

  // Regression: an unrecognised prefix must be "no opinion", never a guess.
  // Plain text, CSV and half the formats in the world have no magic number,
  // and a scanner that finds those suspicious is one that flags everything.
  it('has no opinion about content with no signature, or no content', () => {
    expect(sniffFileType(text('Dear Ankur,\n\nPlease find the numbers attached.\n'))).toBeNull();
    expect(sniffFileType(new Uint8Array(0))).toBeNull();
    expect(sniffFileType(null)).toBeNull();
    expect(sniffFileType(undefined)).toBeNull();
  });
});

describe('isExecutableType', () => {
  it('names the families an operating system runs', () => {
    for (const runs of ['class', 'elf', 'mach-o', 'script', 'windows-pe'] as const) {
      expect(isExecutableType(runs)).toBe(true);
    }
  });

  // Regression: a zip is not an executable even though a `.jar` runs — the
  // container says nothing, and treating it as a program would score every
  // `.docx` in the world.
  it('does not treat a container or a document as a program', () => {
    for (const inert of ['zip', 'ole', 'pdf', 'png', '7z'] as const) {
      expect(isExecutableType(inert)).toBe(false);
    }
    expect(isExecutableType(null)).toBe(false);
  });
});

describe('expectedTypesForExtension', () => {
  it('knows what the common extensions should look like', () => {
    expect(expectedTypesForExtension('pdf')).toEqual(['pdf']);
    expect(expectedTypesForExtension('exe')).toEqual(['windows-pe']);
    expect(expectedTypesForExtension('docx')).toEqual(['zip', 'ole']);
  });

  // Regression: an extension with no unambiguous signature must produce NO
  // expectation. If `.txt` ever gained one, every plain-text attachment whose
  // bytes happen to start with something recognisable becomes a mismatch.
  it('expects nothing of an extension that has no signature, or of none', () => {
    for (const noSignature of ['txt', 'csv', 'svg', 'eml']) {
      expect(expectedTypesForExtension(noSignature)).toEqual([]);
    }
    expect(expectedTypesForExtension(null)).toEqual([]);
    expect(expectedTypesForExtension('')).toEqual([]);
  });
});

describe('expectedTypesForMimeType', () => {
  it('reads the type and ignores its parameters, in any case', () => {
    expect(expectedTypesForMimeType('application/pdf')).toEqual(['pdf']);
    expect(expectedTypesForMimeType('Application/PDF; name="invoice.pdf"')).toEqual(['pdf']);
    expect(expectedTypesForMimeType('  image/png  ')).toEqual(['png']);
  });

  // Regression, and the most load-bearing one in this module.
  // `application/octet-stream` is what a sender writes when they are NOT
  // claiming anything — a great deal of ordinary mail, from clients that
  // never guess a type. Reading "no claim" as a false claim would fire the
  // mismatch rule across the whole corpus.
  it('treats the types that claim nothing as claiming nothing', () => {
    for (const noClaim of [
      'application/octet-stream',
      'text/plain; charset=utf-8',
      'text/html',
      'application/unknown',
    ]) {
      expect(expectedTypesForMimeType(noClaim)).toEqual([]);
    }
    expect(expectedTypesForMimeType(null)).toEqual([]);
    expect(expectedTypesForMimeType(undefined)).toEqual([]);
    expect(expectedTypesForMimeType('')).toEqual([]);
  });
});
