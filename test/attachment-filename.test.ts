import { describe, expect, it } from 'vitest';

import { extensionsOf, inspectFilename, stripBidiControls } from '../src/attachments/filename.js';

/**
 * The right-to-left override, by code point rather than as a literal.
 *
 * Writing the character into this file would reorder this file — the same
 * trojan-source problem the rule exists to catch — and would make the test
 * unreadable in every editor that renders it. `String.fromCodePoint` keeps
 * the test honest about what it is testing and the source readable.
 */
const RLO = String.fromCodePoint(0x202e);
const LRI = String.fromCodePoint(0x2066);

describe('stripBidiControls', () => {
  // If this stops removing overrides, the name the rules read is the name the
  // ATTACKER drew rather than the one the operating system runs.
  it('removes the characters that reorder how a name is displayed', () => {
    expect(stripBidiControls(`invoice${RLO}fdp.exe`)).toBe('invoicefdp.exe');
    expect(stripBidiControls(`${LRI}report.pdf`)).toBe('report.pdf');
  });

  it('leaves an ordinary name exactly as it was', () => {
    expect(stripBidiControls('quarterly report (final).pdf')).toBe('quarterly report (final).pdf');
  });

  // Arabic and Hebrew filenames are ordinary mail. Only the control
  // characters go; the letters they were reordering must survive untouched.
  it('keeps non-Latin letters and only drops the controls', () => {
    expect(stripBidiControls(`فاتورة${RLO}.pdf`)).toBe('فاتورة.pdf');
  });
});

describe('extensionsOf', () => {
  it('reads the trailing extension tokens in written order', () => {
    expect(extensionsOf('archive.tar.gz')).toEqual(['tar', 'gz']);
    expect(extensionsOf('report.PDF')).toEqual(['pdf']);
  });

  // A name with no extension must not borrow one from its stem, or every
  // rule downstream is reading a claim nobody made.
  it('finds none in a name with no dot, and none in a dotfile', () => {
    expect(extensionsOf('README')).toEqual([]);
    expect(extensionsOf('.bashrc')).toEqual([]);
  });

  // The regression this guards: treating every dot-separated fragment as an
  // extension reports a double extension on somebody's meeting notes.
  it('ignores fragments that are not extension-shaped', () => {
    expect(extensionsOf('minutes.2026-03-04.notes from the call.pdf')).toEqual([
      '2026-03-04',
      'pdf',
    ]);
    expect(extensionsOf('v1.0.final.docx')).toEqual(['0', 'final', 'docx']);
  });

  // Zip entries arrive as paths. Reading the extension off the wrong segment
  // would let `run.exe/notes.txt` pass as a text file.
  it('reads the last path segment, on either separator', () => {
    expect(extensionsOf('docs/invoice.pdf.exe')).toEqual(['pdf', 'exe']);
    expect(extensionsOf('docs\\invoice.pdf.exe')).toEqual(['pdf', 'exe']);
    expect(extensionsOf('some.dir/README')).toEqual([]);
  });

  it('strips the display-reordering characters before reading extensions', () => {
    expect(extensionsOf(`cv${RLO}fdp.exe`)).toEqual(['exe']);
  });

  it('drops a trailing dot, which claims nothing', () => {
    expect(extensionsOf('report.')).toEqual([]);
  });
});

describe('inspectFilename', () => {
  it('reports the extension that decides what a double click does', () => {
    expect(inspectFilename('invoice.pdf.exe')).toEqual({
      name: 'invoice.pdf.exe',
      extension: 'exe',
      extensions: ['pdf', 'exe'],
      reordered: false,
    });
  });

  // The flag is what the name-spoof rule fires on; losing it loses the rule.
  it('flags a name that reorders itself, and reports the real one', () => {
    expect(inspectFilename(`cv${RLO}fdp.exe`)).toEqual({
      name: 'cvfdp.exe',
      extension: 'exe',
      extensions: ['exe'],
      reordered: true,
    });
  });

  // An inline image or a calendar part often has no name. That is ordinary
  // mail, not a signal, and must not throw or invent an extension.
  it('treats an absent name as no name rather than an error', () => {
    for (const absent of [null, undefined, '']) {
      expect(inspectFilename(absent)).toEqual({
        name: '',
        extension: null,
        extensions: [],
        reordered: false,
      });
    }
  });
});
