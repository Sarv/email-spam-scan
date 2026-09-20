import 'reflect-metadata'; // before the fixture reaches @peculiar/x509: its DI container needs the polyfill
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { lookupBimi } from '../src/brand/bimi.js';
import type { FetchLike } from '../src/brand/fetch.js';
import { BIMI_LOGO_MAX_BYTES } from '../src/brand/svg.js';
import type { DnsQuery } from '../src/dns.js';

import { fakeFetch, toArrayBuffer, type Route } from './fetch-fixture.js';
import { NOW, SVG, base64Of, makeLeaf, pemOf, testPki, type Pki } from './vmc-fixture.js';

/**
 * The BIMI lookup, end to end: DNS, then policy, then the logo, then the
 * certificate.
 *
 * What this protects: BIMI's whole premise is that a spoofer never gets to
 * wear the brand. Every rule below is the difference between a logo that
 * means something and a picture any domain can put next to its name — the
 * DMARC gate, the SVG profile, the pinned Mark Verifying Authority — and the
 * none/error distinction is what stops one bad afternoon on the network from
 * being cached as "this brand has no logo".
 */
const LOGO = 'https://brand.example/logo.svg';
const VMC = 'https://brand.example/vmc.pem';
const SVG_DATA_URI = `data:image/svg+xml;base64,${base64Of(SVG)}`;

/** A resolver where a name that is absent simply has no records, as `nodeDnsQuery` reports it. */
const fakeDns =
  (records: Record<string, string[]>, asked: string[] = []): DnsQuery =>
  (name) => {
    asked.push(name);
    return Promise.resolve(records[name] ?? []);
  };

let pki: Pki;
beforeAll(async () => {
  pki = await testPki();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
  vi.doUnmock('@peculiar/x509');
  vi.doUnmock('node:dns/promises');
});

const withDeps = (records: Record<string, string[]>, routes: Record<string, Route> = {}) => ({
  query: fakeDns(records),
  fetch: fakeFetch(routes),
  now: () => NOW,
  roots: [pki.rootDescriptor],
});

const enforcing = { '_dmarc.brand.example': ['v=DMARC1; p=reject'] };
const svgRoute = { [LOGO]: { body: SVG, type: 'image/svg+xml' } };

describe('lookupBimi', () => {
  // A DNS miss is an ANSWER worth caching for a week; an error is not.
  it('is "none" for a domain that publishes no record', async () => {
    const found = await lookupBimi('plain.example', withDeps({}));
    expect(found).toMatchObject({
      status: 'none',
      logo: null,
      detail: 'The domain publishes no BIMI record',
    });
  });

  it('is "declined" when the domain publishes an empty l=', async () => {
    const found = await lookupBimi(
      'brand.example',
      withDeps({ ...enforcing, 'default._bimi.brand.example': ['v=BIMI1; l=;'] }),
    );
    expect(found).toMatchObject({
      status: 'declined',
      detail: 'The domain declines to show a logo',
    });
  });

  // THE premise, end to end: no enforcing DMARC, no logo - whatever the record says.
  it('refuses to show a logo under p=none or with no DMARC at all', async () => {
    const record = { 'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`] };
    const weak = await lookupBimi(
      'brand.example',
      withDeps({ '_dmarc.brand.example': ['v=DMARC1; p=none'], ...record }, svgRoute),
    );
    expect(weak).toMatchObject({ status: 'invalid', logo: null, dmarcPolicy: 'none' });
    expect(weak.detail).toContain("the domain's is p=none");

    const silent = await lookupBimi('brand.example', withDeps(record, svgRoute));
    expect(silent.status).toBe('invalid');
    expect(silent.detail).toContain('the domain publishes none');
  });

  it('returns the logo as a data URI when the record carries no certificate', async () => {
    const found = await lookupBimi(
      'brand.example',
      withDeps(
        {
          '_dmarc.brand.example': ['v=DMARC1; p=quarantine'],
          'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`],
        },
        svgRoute,
      ),
    );
    expect(found).toMatchObject({
      status: 'logo',
      logo: SVG_DATA_URI,
      dmarcPolicy: 'quarantine',
      recordDomain: 'brand.example',
      detail: 'The domain publishes a logo but no Verified Mark Certificate',
    });
  });

  // The whole feature: a record, an enforcing policy, a Tiny PS logo, and a
  // certificate that chains to a pinned Mark Verifying Authority.
  it('is "verified" with the organisation and the issuer when the certificate checks out', async () => {
    const leaf = await makeLeaf({ domains: ['brand.example'] });
    const found = await lookupBimi(
      'brand.example',
      withDeps(
        { ...enforcing, 'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}; a=${VMC}`] },
        {
          ...svgRoute,
          [VMC]: { body: pemOf(leaf, pki.root.cert), type: 'application/x-pem-file' },
        },
      ),
    );
    expect(found).toMatchObject({
      status: 'verified',
      logo: SVG_DATA_URI,
      organization: 'Example Inc',
      issuer: 'Test Verified Mark Root',
    });
    expect(found.certificateExpires).toBeGreaterThan(NOW.getTime() / 1000);
  });

  // A bad certificate demotes to "logo" with the reason - never to "verified",
  // and never to nothing: the logo still stands on its own, DMARC-gated.
  it('falls back to "logo" and says why when the certificate does not verify', async () => {
    const leaf = await makeLeaf({ domains: ['other.example'] });
    const records = {
      ...enforcing,
      'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}; a=${VMC}`],
    };

    const mismatch = await lookupBimi(
      'brand.example',
      withDeps(records, { ...svgRoute, [VMC]: { body: pemOf(leaf, pki.root.cert) } }),
    );
    expect(mismatch.status).toBe('logo');
    expect(mismatch.logo).not.toBeNull();
    expect(mismatch.detail).toMatch(/Certificate not verified: .*other\.example/);

    const missing = await lookupBimi('brand.example', withDeps(records, svgRoute));
    expect(missing).toMatchObject({
      status: 'logo',
      detail: 'The certificate could not be downloaded',
    });
  });

  it('rejects a logo that fails the SVG check or is too large to fetch', async () => {
    const records = { ...enforcing, 'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`] };
    const scripted = await lookupBimi(
      'brand.example',
      withDeps(records, {
        [LOGO]: { body: '<svg><script>x</script></svg>', type: 'image/svg+xml' },
      }),
    );
    expect(scripted.status).toBe('invalid');
    expect(scripted.detail).toContain('script');

    const huge = await lookupBimi(
      'brand.example',
      withDeps(records, {
        [LOGO]: { body: SVG, type: 'image/svg+xml', length: BIMI_LOGO_MAX_BYTES + 1 },
      }),
    );
    expect(huge.status).toBe('invalid');
    expect(huge.detail).toContain('could not be downloaded');
  });

  // A server that under-declares its length must not get past the cap either:
  // the ceiling is on the bytes, not on the sender's honesty.
  it('rejects a logo whose body exceeds the cap however it was declared', async () => {
    const found = await lookupBimi(
      'brand.example',
      withDeps(
        { ...enforcing, 'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`] },
        {
          [LOGO]: {
            body: new Uint8Array(BIMI_LOGO_MAX_BYTES + 1).fill(0x20),
            type: 'image/svg+xml',
            length: 100,
          },
        },
      ),
    );
    expect(found.status).toBe('invalid');
  });

  it('rejects a record whose logo URL is not https', async () => {
    const found = await lookupBimi(
      'brand.example',
      withDeps({
        ...enforcing,
        'default._bimi.brand.example': ['v=BIMI1; l=http://brand.example/logo.svg'],
      }),
    );
    expect(found).toMatchObject({
      status: 'invalid',
      detail: 'The BIMI record has no https logo URL',
    });
  });
});

describe('a subdomain sender', () => {
  // Mail from news./mailer./notify.: BIMI falls back to the organisational
  // domain's record, and the organisation's `sp=` governs the subdomain.
  it('falls back to the organisational domain, where sp= governs', async () => {
    const found = await lookupBimi(
      'news.brand.example',
      withDeps(
        {
          '_dmarc.brand.example': ['v=DMARC1; p=reject; sp=quarantine'],
          'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`],
        },
        svgRoute,
      ),
    );
    expect(found).toMatchObject({
      status: 'logo',
      recordDomain: 'brand.example',
      dmarcPolicy: 'quarantine',
    });

    const spNone = await lookupBimi(
      'news.brand.example',
      withDeps(
        {
          '_dmarc.brand.example': ['v=DMARC1; p=reject; sp=none'],
          'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`],
        },
        svgRoute,
      ),
    );
    expect(spNone.status).toBe('invalid');
  });

  // No sp= at all: the organisation's own p= is what the subdomain inherits.
  it('inherits p= when the organisational record declares no sp=', async () => {
    const found = await lookupBimi(
      'news.brand.example',
      withDeps({ ...enforcing, 'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`] }, svgRoute),
    );
    expect(found).toMatchObject({
      status: 'logo',
      dmarcPolicy: 'reject',
      recordDomain: 'brand.example',
    });
  });

  it('uses the subdomain’s own records when it publishes them', async () => {
    const found = await lookupBimi(
      'news.brand.example',
      withDeps(
        {
          // A non-DMARC TXT at the same name must not shadow the real one.
          '_dmarc.news.brand.example': ['v=spf1 -all', 'v=DMARC1; p=quarantine'],
          'default._bimi.news.brand.example': [`v=BIMI1; l=${LOGO}`],
        },
        svgRoute,
      ),
    );
    expect(found).toMatchObject({
      status: 'logo',
      dmarcPolicy: 'quarantine',
      recordDomain: 'news.brand.example',
    });
  });

  // `_dmarc.mailer.brand.example` often is not a zone at all and the resolver
  // says SERVFAIL. The organisational domain still answers - use it.
  it('falls through to the organisational domain when the subdomain’s names fail to resolve', async () => {
    const answer = fakeDns({ ...enforcing, 'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`] });
    const query: DnsQuery = (name, type) =>
      name.endsWith('.mailer.brand.example')
        ? Promise.reject(new Error('ESERVFAIL'))
        : answer(name, type);
    const found = await lookupBimi('mailer.brand.example', {
      query,
      fetch: fakeFetch(svgRoute),
      now: () => NOW,
    });
    expect(found).toMatchObject({
      status: 'logo',
      recordDomain: 'brand.example',
      dmarcPolicy: 'reject',
    });
  });
});

describe('failures the caller must not cache as "none"', () => {
  // Cached for a week, a resolver blip would hide a real brand's logo.
  it('is "error" when the resolver fails, for a subdomain and for the domain itself', async () => {
    const query: DnsQuery = (name) => Promise.reject(new Error(`ESERVFAIL ${name}`));
    for (const domain of ['mailer.brand.example', 'brand.example']) {
      const found = await lookupBimi(domain, { query, fetch: fakeFetch({}), now: () => NOW });
      expect(found).toMatchObject({ status: 'error', logo: null });
      expect(found.detail).toContain('Lookup failed: ESERVFAIL');
    }
  });

  it('is "error" when the logo host cannot be reached', async () => {
    const found = await lookupBimi(
      'brand.example',
      withDeps(
        { ...enforcing, 'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}`] },
        {
          [LOGO]: { throws: true },
        },
      ),
    );
    expect(found).toMatchObject({ status: 'error', detail: 'Lookup failed: ECONNRESET' });
  });

  // A rejected promise can carry anything; the detail still has to read as a
  // sentence rather than as "[object Object]" or an empty string.
  it('describes a rejection that is not an Error', async () => {
    const query: DnsQuery = () => Promise.reject('the resolver went away');
    const found = await lookupBimi('brand.example', {
      query,
      fetch: fakeFetch({}),
      now: () => NOW,
    });
    expect(found).toMatchObject({
      status: 'error',
      detail: 'Lookup failed: the resolver went away',
    });
  });

  it('is "none" for an empty domain', async () => {
    expect(await lookupBimi('   ', withDeps({}))).toMatchObject({
      status: 'none',
      detail: 'No sender domain',
    });
  });

  // A name with no registrable domain (a bare host, an intranet name) is
  // still looked up as itself rather than skipped.
  it('looks up a name that has no organisational domain as itself', async () => {
    const asked: string[] = [];
    const found = await lookupBimi('localhost', {
      query: fakeDns({}, asked),
      fetch: fakeFetch({}),
      now: () => NOW,
    });
    expect(found.status).toBe('none');
    expect(asked).toEqual(['_dmarc.localhost', 'default._bimi.localhost']);
  });
});

describe('what the options default to', () => {
  it('resolves with node:dns and fetches with the platform fetch when given neither', async () => {
    const records: Record<string, string[][]> = {
      '_dmarc.brand.example': [['v=DMARC1; ', 'p=reject']],
      'default._bimi.brand.example': [[`v=BIMI1; l=${LOGO}`]],
    };
    vi.doMock('node:dns/promises', () => ({
      Resolver: class {
        resolveTxt(name: string): Promise<string[][]> {
          const record = records[name];
          if (record === undefined) {
            return Promise.reject(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }));
          }
          return Promise.resolve(record);
        }
        resolve4(): Promise<string[]> {
          return Promise.resolve([]);
        }
        setServers(): void {}
      },
    }));
    vi.stubGlobal('fetch', ((url: string) =>
      Promise.resolve({
        ok: url === LOGO,
        status: url === LOGO ? 200 : 404,
        url,
        headers: {
          get: (name: string): string | null => (name === 'content-type' ? 'image/svg+xml' : null),
        },
        arrayBuffer: () => Promise.resolve(toArrayBuffer(SVG)),
      })) satisfies FetchLike);

    const { lookupBimi: freshLookup } = await import('../src/brand/bimi.js');
    expect(await freshLookup('brand.example', { now: () => NOW })).toMatchObject({
      status: 'logo',
      logo: SVG_DATA_URI,
    });
  });

  // The certificate tooling is an OPTIONAL peer: an install that only wanted
  // the logo still gets the logo, and the missing tick is explained by a
  // sentence naming what to install rather than by an accusation.
  it('keeps the logo and names the peer when the certificate tooling is not installed', async () => {
    const pem = pemOf(await makeLeaf({ domains: ['brand.example'] }), pki.root.cert);
    vi.doMock('@peculiar/x509', () => {
      throw new Error("Cannot find package '@peculiar/x509'");
    });

    const { lookupBimi: freshLookup } = await import('../src/brand/bimi.js');
    const found = await freshLookup('brand.example', {
      query: fakeDns({
        ...enforcing,
        'default._bimi.brand.example': [`v=BIMI1; l=${LOGO}; a=${VMC}`],
      }),
      fetch: fakeFetch({ ...svgRoute, [VMC]: { body: pem } }),
      now: () => NOW,
      roots: [pki.rootDescriptor],
    });
    expect(found).toMatchObject({ status: 'logo', logo: SVG_DATA_URI });
    expect(found.detail).toContain("optional peer dependency '@peculiar/x509'");
  });
});

// Guard the fixture's own assumption: the `.example` names these tests use
// must split into subdomain and organisational domain the way the scenarios
// above assume, or every fallback test is quietly testing nothing.
describe('the test domains', () => {
  it('treats news.brand.example as a subdomain of brand.example', async () => {
    const asked: string[] = [];
    await lookupBimi('news.brand.example', {
      query: fakeDns({}, asked),
      fetch: fakeFetch({}),
      now: () => NOW,
    });
    expect(asked).toEqual([
      '_dmarc.news.brand.example',
      '_dmarc.brand.example',
      'default._bimi.news.brand.example',
      'default._bimi.brand.example',
    ]);
  });
});
