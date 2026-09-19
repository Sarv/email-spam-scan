import { describe, expect, it } from 'vitest';

import {
  ARCHIVE_EXECUTABLE_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  DECOY_EXTENSIONS,
  EXECUTABLE_EXTENSIONS,
  MACRO_ENABLED_EXTENSIONS,
} from '../src/data/attachment-extensions.js';

const LISTS = {
  EXECUTABLE_EXTENSIONS,
  ARCHIVE_EXECUTABLE_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  MACRO_ENABLED_EXTENSIONS,
  DECOY_EXTENSIONS,
} as const;

/**
 * The lists are data, so the review of a change to them is a diff — and a
 * diff only reviews well while the file stays in the shape the header
 * promises. These tests are what a pull request adding an extension runs
 * into.
 */
describe('the attachment extension lists', () => {
  for (const [name, list] of Object.entries(LISTS)) {
    // Regression: lookups go through a Set built from these arrays and are
    // done against a lowercased, dot-stripped token. An entry written `.EXE`
    // can never match anything — it is dead weight that reads like cover.
    it(`${name} holds lowercase, dot-free tokens only`, () => {
      const malformed = list.filter((extension) => !/^[a-z0-9][a-z0-9_-]*$/.test(extension));
      expect(malformed).toEqual([]);
    });

    // Regression: a duplicate is invisible to `Set` but hides a bad merge,
    // and an unsorted list makes every future diff unreadable — which is how
    // an extension gets added twice or dropped by accident.
    it(`${name} is sorted and deduplicated`, () => {
      expect(new Set(list).size).toBe(list.length);
      expect([...list]).toEqual([...list].sort());
    });
  }

  // Regression: the archive list is meant to be a SUBSET — the members of the
  // executable list that have no innocent reason to be zipped and mailed. If
  // something appears only in the archive list, a file scores inside a zip
  // that would not score as an attachment, which is backwards.
  it('scores nothing inside an archive that it would not score outside one', () => {
    const outside = new Set(EXECUTABLE_EXTENSIONS);
    expect(ARCHIVE_EXECUTABLE_EXTENSIONS.filter((extension) => !outside.has(extension))).toEqual(
      [],
    );
  });

  // Regression: the whole point of the second list is that it is narrower.
  // If a refactor ever makes them equal, every zipped project directory with
  // a `.js` or a `.sh` in it starts scoring, and nobody would see why.
  it('keeps the inside-an-archive set strictly narrower than the outside one', () => {
    expect(ARCHIVE_EXECUTABLE_EXTENSIONS.length).toBeLessThan(EXECUTABLE_EXTENSIONS.length);
    for (const ordinaryInAProject of ['js', 'py', 'sh', 'pl', 'dll']) {
      expect(EXECUTABLE_EXTENSIONS).toContain(ordinaryInAProject);
      expect(ARCHIVE_EXECUTABLE_EXTENSIONS).not.toContain(ordinaryInAProject);
    }
  });

  // Regression: `.bin` was in the executable list once. Every Word document
  // with an embedded OLE object carries `oleObject1.bin`, so every one of
  // them fired the archive-executable rule. The lesson generalises — an
  // extension earns a place only if a double click RUNS it.
  it('excludes the extensions that are ordinary freight inside an Office file', () => {
    for (const notAProgram of ['bin', 'xml', 'rels', 'png', 'dat']) {
      expect(EXECUTABLE_EXTENSIONS).not.toContain(notAProgram);
      expect(ARCHIVE_EXECUTABLE_EXTENSIONS).not.toContain(notAProgram);
    }
  });

  // Regression: the ones the rules exist for. Losing any of these silently
  // stops the executable rule firing on the formats it was written for.
  it('covers the formats a double click runs', () => {
    for (const runs of ['exe', 'scr', 'vbs', 'js', 'lnk', 'hta', 'jar', 'settingcontent-ms']) {
      expect(EXECUTABLE_EXTENSIONS).toContain(runs);
    }
  });

  // Regression: a `.jar` is a zip, but the Java runtime runs it. Filing it as
  // an archive rather than an executable loses the only rule that catches it.
  it('treats a .jar as a program rather than a container', () => {
    expect(EXECUTABLE_EXTENSIONS).toContain('jar');
    expect(ARCHIVE_EXTENSIONS).not.toContain('jar');
  });

  // Regression: the legacy binary Office formats CAN carry macros and almost
  // never do. Adding them scores every document a law firm has sent since
  // 1997; `rules.ts` looks for the VBA project in the bytes instead.
  it('leaves the legacy Office formats out of the macro list', () => {
    for (const legacy of ['doc', 'xls', 'ppt']) {
      expect(MACRO_ENABLED_EXTENSIONS).not.toContain(legacy);
    }
    for (const declaresMacros of ['docm', 'xlsm', 'pptm']) {
      expect(MACRO_ENABLED_EXTENSIONS).toContain(declaresMacros);
    }
  });

  // Regression: a decoy is a name a reader trusts. If something that runs
  // ever lands in this list, `invoice.exe.exe` reads as a double extension
  // and the sentence the rule writes stops making sense.
  it('keeps everything that runs out of the decoy list', () => {
    const runs = new Set(EXECUTABLE_EXTENSIONS);
    expect(DECOY_EXTENSIONS.filter((extension) => runs.has(extension))).toEqual([]);
  });
});
