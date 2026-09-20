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
    // `attachments` is the third zero-dependency entry, and the one a client
    // is most likely to want alone: a signature table, a filename reader and
    // a zip-directory walk, none of which needs a package. A renderer
    // deciding whether to warn on a paperclip gets the scanner's own answer
    // without the scanner.
    attachments: 'src/attachments/index.ts',
    // `links` and `security` are the renderer's pair: the link checks, and
    // the level decision that a shield or a banner displays.
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
    // `verify` is the only entry that can reach the network, and the only one
    // whose dependency is optional: `mailauth` is a peer dependency loaded
    // through a dynamic import, so nothing here — and nothing that imports the
    // scanner — carries it unless a consumer installs it and calls in.
    verify: 'src/verify.ts',
    // `reputation` is the other entry that can reach the network, and the only
    // Node-only one: its default resolver comes from `node:dns`, loaded — like
    // `mailauth` above — through a dynamic import, so nothing resolves it
    // until a lookup actually happens and no browser bundle trips over it.
    reputation: 'src/reputation.ts',
    // `brand` is the sender's mark: the BIMI logo a domain publishes, the
    // certificate that verifies it, and the favicon that stands in when there
    // is neither. It reaches the network like the two above, and like them it
    // does so through injected DNS and fetch — so it is the one networked
    // entry a browser can also import. Its certificate tooling
    // (`@peculiar/x509`, `asn1js`) is optional and dynamically imported, for
    // the same reason `mailauth` is.
    brand: 'src/brand/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
});
