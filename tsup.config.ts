import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    // Separate entries so a consumer who only needs to READ a stored verdict,
    // or only needs the sender-identity rule, never pulls the scanner (and
    // eventually its MIME parser and corpora) into their bundle.
    //
    // This is not hypothetical tidiness: the first consumer is an Electron
    // renderer that shows a shield on an already-scored message. Importing the
    // full entry there would drag a Node-only MIME parser into a browser
    // bundle and blank the window — the exact failure that forced the
    // deep-import aliases these entries replace.
    //
    // `verdict` is zero-dependency by contract; `identity` costs `tldts` only.
    verdict: 'src/verdict.ts',
    identity: 'src/identity.ts',
    // `links` and `security` are the renderer's pair: the DOM-dependent link
    // checks, and the level decision that a shield or a banner displays.
    // Neither drags in the address parser or the freemail corpus that the
    // header rules need.
    links: 'src/links.ts',
    security: 'src/security.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
});
