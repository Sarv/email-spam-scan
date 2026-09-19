import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * What each entry point COSTS a consumer, in third-party packages.
 *
 * This is the contract the README's entry-point table publishes, and it is the
 * one thing about this package that breaks silently. A browser consumer picks
 * a narrow entry precisely so a Node-only or CommonJS dependency never reaches
 * its bundle; the day one does, nothing here fails — the library still builds,
 * its own tests still pass, and the consumer's bundler still produces a file.
 * The failure surfaces as a blank window in someone else's app.
 *
 * It has already happened once, in the first consumer: an app re-exported the
 * bulk-header primitives from the MAIN entry into a module its renderer
 * imported, which dragged `free-email-domains` — a CommonJS array with no
 * default export — into a Vite dev server that served it unconverted. White
 * screen, and a stack trace naming a file nobody had touched.
 *
 * So: walk each entry's import graph over the SOURCE, collect every bare
 * specifier, and pin the set. Adding a dependency to an entry is then a
 * deliberate edit to this table, in the same commit, where a reviewer sees it.
 */
const EXPECTED: Record<string, readonly string[]> = {
  'src/verdict.ts': [],
  'src/headers/index.ts': [],
  // The attachment stage reads magic bytes, filenames and a zip's own
  // directory, and does all three without a package — see the note in
  // `attachments/zip.ts` on why an inflater is the one thing a scanner that
  // is handed hostile archives must not carry.
  'src/attachments/index.ts': [],
  // Nothing. `verify` reaches `mailauth` through a DYNAMIC import and declares
  // it as an optional peer dependency, so a consumer who never verifies pays
  // nothing for the entry existing — and a consumer who does gets a clear
  // error rather than a missing module. The assertion below is what keeps that
  // true, because the walk above cannot see a dynamic import.
  'src/verify.ts': [],
  'src/identity.ts': ['tldts'],
  'src/links.ts': ['htmlparser2', 'tldts'],
  'src/security.ts': ['htmlparser2', 'tldts'],
  'src/content/index.ts': ['htmlparser2', 'tldts'],
  // The one entry that costs a MIME parser. Everything above must stay free of
  // it: a renderer showing a shield on an already-scored message has no raw
  // bytes to parse and no business carrying a parser for them.
  'src/scan.ts': ['email-addresses', 'htmlparser2', 'ipaddr.js', 'postal-mime', 'tldts'],
  'src/index.ts': ['email-addresses', 'htmlparser2', 'ipaddr.js', 'postal-mime', 'tldts'],
};

const SRC_ROOT = resolve(__dirname, '..');

/**
 * Bare specifiers reachable from `entry`, following relative imports only.
 *
 * Type-only imports are dropped: `import type` is erased at build time and
 * costs a consumer nothing, so counting it would fail the test for a
 * dependency that never reaches the bundle.
 */
function externalDeps(entry: string): string[] {
  const seen = new Set<string>();
  const external = new Set<string>();
  const queue = [resolve(SRC_ROOT, entry)];

  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);

    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(/^(?:import|export)\s+([^;]*?)\bfrom\s+'([^']+)'/gm)) {
      // Both groups are mandatory in the pattern, so a match always fills
      // them; the defaults are only here to satisfy `noUncheckedIndexedAccess`.
      // An empty specifier could never be a relative path, so it would land in
      // `external` and fail the expectation loudly rather than pass silently.
      const [, clause = '', specifier = ''] = match;
      if (specifier.startsWith('.')) {
        // tsup resolves the `.js` an ESM-correct TypeScript source must write.
        queue.push(join(dirname(file), specifier.replace(/\.js$/, '.ts')));
      } else if (!/^\s*type\s/.test(clause)) {
        external.add(specifier);
      }
    }
  }
  return [...external].sort();
}

describe('entry-point dependency cost', () => {
  for (const [entry, expected] of Object.entries(EXPECTED)) {
    // If this fails, an entry point gained (or lost) a dependency. Update the
    // table AND the README's entry-point table — a consumer chose this entry
    // because of what it said.
    it(`${entry} costs exactly ${expected.length > 0 ? expected.join(', ') : 'nothing'}`, () => {
      expect(externalDeps(entry)).toEqual([...expected]);
    });
  }

  // The zero-dependency entries are the load-bearing ones: they are what a
  // browser or a worker imports. Stated separately so the reason survives a
  // future edit to the table above.
  it('keeps /verdict, /headers and /attachments free of any third-party package', () => {
    expect(externalDeps('src/verdict.ts')).toEqual([]);
    expect(externalDeps('src/headers/index.ts')).toEqual([]);
    expect(externalDeps('src/attachments/index.ts')).toEqual([]);
  });

  // Regression, and the one this file's static walk CANNOT catch: a dynamic
  // import is invisible to it, so a refactor that "tidied" the loader into a
  // normal top-level import would pass every test above while quietly putting
  // `mailauth` and its dependency tree into the main entry — and into every
  // bundle that imports this package at all.
  it('reaches mailauth only through a dynamic import, never a static one', () => {
    const source = readFileSync(resolve(SRC_ROOT, 'src/verify.ts'), 'utf8');
    expect(source).toContain("await import('mailauth')");
    expect(source).not.toMatch(/^(?:import|export)\s[^;]*\bfrom\s+'mailauth'/m);
  });

  // The barrel must reach everything the narrow entries do, or a Node consumer
  // who follows the README and imports only the main entry loses a name.
  it('re-exports every narrow entry from the main entry', () => {
    const barrel = readFileSync(resolve(SRC_ROOT, 'src/index.ts'), 'utf8');
    for (const path of [
      './attachments/index.js',
      './content/index.js',
      './headers/index.js',
      './identity.js',
      './links.js',
      './scan.js',
      './security.js',
      './urls.js',
      './verdict.js',
      './verify.js',
    ]) {
      expect(barrel).toContain(`from '${path}'`);
    }
  });
});
