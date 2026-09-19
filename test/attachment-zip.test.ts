import { describe, expect, it } from 'vitest';

import { sniffFileType } from '../src/attachments/magic.js';
import { listZipEntries } from '../src/attachments/zip.js';

import { buildZip } from './zip-fixture.js';

describe('listZipEntries', () => {
  // The baseline: the fixture builds a real archive, so if this fails either
  // the parser or the fixture has stopped agreeing with the format, and the
  // sniff assertion says which.
  it('lists the members of a real archive', () => {
    const zip = buildZip([{ name: 'invoice.pdf' }, { name: 'notes.txt', content: 'hello' }]);

    expect(sniffFileType(zip)).toBe('zip');
    expect(listZipEntries(zip)).toEqual({
      truncated: false,
      entries: [
        {
          name: 'invoice.pdf',
          directory: false,
          encrypted: false,
          compressedSize: 11,
          uncompressedSize: 11,
        },
        {
          name: 'notes.txt',
          directory: false,
          encrypted: false,
          compressedSize: 5,
          uncompressedSize: 5,
        },
      ],
    });
  });

  // Regression: a directory record has no content and must not be mistaken
  // for a member. `payload/` is not a program even when `payload` is.
  it('marks directory records as directories', () => {
    const listing = listZipEntries(
      buildZip([{ name: 'docs/', content: '' }, { name: 'docs/a.txt' }]),
    );

    expect(listing?.entries.map((entry) => entry.directory)).toEqual([true, false]);
  });

  // Regression: the encrypted flag is the whole basis of one rule, and it
  // lives in the general-purpose bit field rather than anywhere obvious.
  it('reports which members are password-protected', () => {
    const listing = listZipEntries(
      buildZip([{ name: 'open.txt' }, { name: 'sealed.doc', encrypted: true }]),
    );

    expect(listing?.entries.map((entry) => entry.encrypted)).toEqual([false, true]);
  });

  // Regression: a 32-bit size field saturated at 0xFFFFFFFF is not a 4 GB
  // file, it is a pointer to a ZIP64 record this parser does not read.
  // Reporting the sentinel as a size would be a fabricated 4 GB attachment.
  it('reports a ZIP64 size as unknown rather than as four gigabytes', () => {
    const listing = listZipEntries(buildZip([{ name: 'huge.bin', zip64Sizes: true }]));

    expect(listing?.entries[0]).toMatchObject({
      compressedSize: null,
      uncompressedSize: null,
    });
  });

  // Regression: the EOCD may be followed by up to 64 KB of comment, so a
  // parser that only looks at the last 22 bytes fails on every archive some
  // tools produce — silently, by returning null and disabling the rules.
  it('finds the directory behind an archive comment', () => {
    const listing = listZipEntries(buildZip([{ name: 'a.txt' }], { commentLength: 300 }));

    expect(listing?.entries.map((entry) => entry.name)).toEqual(['a.txt']);
  });

  // Regression: a directory that claims more members than it holds is
  // malformed in exactly the way a hostile one would be. It must yield what
  // is really there plus `truncated`, never an exception and never a loop.
  it('stops where a lying directory actually ends and says so', () => {
    const listing = listZipEntries(buildZip([{ name: 'a.txt' }], { declaredEntryCount: 40 }));

    expect(listing).toEqual({
      truncated: true,
      entries: [
        {
          name: 'a.txt',
          directory: false,
          encrypted: false,
          compressedSize: 5,
          uncompressedSize: 5,
        },
      ],
    });
  });

  // Regression: the entry count is attacker-controlled and the walk is linear
  // in it, so the bound is what stops a 64 KB attachment costing 65,535
  // iterations of header reads on every message that arrives. The entries
  // read are still real; the rules charge on what they saw.
  it('stops after its bound on an archive with more members than it will read', () => {
    const many = Array.from({ length: 2_001 }, (_unused, index) => ({ name: `f${index}.txt` }));
    const listing = listZipEntries(buildZip(many));

    expect(listing?.truncated).toBe(true);
    expect(listing?.entries).toHaveLength(2_000);
  });

  // Regression: `null` means "no opinion", and every caller reads it that
  // way. Anything that is not a readable zip must reach that answer rather
  // than throwing inside a scanner that runs on every inbound message.
  it('has no opinion about content that is not a readable archive', () => {
    expect(listZipEntries(null)).toBeNull();
    expect(listZipEntries(undefined)).toBeNull();
    expect(listZipEntries(new Uint8Array(0))).toBeNull();
    // Shorter than the smallest possible EOCD record.
    expect(listZipEntries(new Uint8Array(10))).toBeNull();
    // Long enough, but with no EOCD signature anywhere in it.
    expect(listZipEntries(new Uint8Array(200))).toBeNull();
  });

  // Regression: an EOCD whose offset points outside the file is the cheapest
  // malformed archive there is, and the read that follows it is the one that
  // would go out of bounds.
  it('survives a directory offset that points past the end of the file', () => {
    const zip = buildZip([{ name: 'a.txt' }]);
    const view = new DataView(zip.buffer);
    const eocd = zip.byteLength - 22;
    view.setUint32(eocd + 16, 0xfffffff0, true);

    expect(listZipEntries(zip)).toEqual({ truncated: true, entries: [] });
  });
});
