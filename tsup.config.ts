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
    // `headers` is the other zero-dependency entry: reading raw header text,
    // with no rules attached. A consumer that only needs to know whether a
    // message declared itself bulk must not have to import the scanner — the
    // header rules cost an address parser and a freemail corpus.
    headers: 'src/headers/index.ts',
    // `links` and `security` are the renderer's pair: the DOM-dependent link
    // checks, and the level decision that a shield or a banner displays.
    // Neither drags in the address parser or the freemail corpus that the
    // header rules need.
    links: 'src/links.ts',
    security: 'src/security.ts',
    // `content` is the body stage: the sender's own words and the links in
    // them. It costs an HTML parser and `tldts`, and deliberately not the
    // address parser or the freemail corpus the header rules need — a consumer
    // that has a body to score should not inherit the header stage to do it.
    content: 'src/content/index.ts',
    // `scan` is the whole pipeline over a raw RFC 5322 message. It is the one
    // entry that costs a MIME parser, which is precisely why it is its own:
    // the renderer entries above must never inherit it.
    scan: 'src/scan.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
});
