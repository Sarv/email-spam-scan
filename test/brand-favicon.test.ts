import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  FAVICON_MAX_BYTES,
  discoverFavicon,
  extractIconLinks,
  faviconHosts,
  rankIconCandidates,
  sniffImageType,
} from '../src/brand/favicon.js';

import { fakeFetch } from './fetch-fixture.js';
import { base64Of, utf8 } from './vmc-fixture.js';

/**
 * Domain favicons as the fallback sender mark.
 *
 * What this protects: a mark is trusted at a glance. A "favicon" that is
 * really a 200 HTML error page becomes a broken tile on every message from
 * that domain, and a favicon fetched per message rather than per domain is a
 * tracking pixel we built ourselves. The discovery order and the
 * byte-sniffing are what keep both from happening.
 */
const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);
const filled = (length: number, value: number): Uint8Array => new Uint8Array(length).fill(value);
const join = (...parts: Uint8Array[]): Uint8Array => {
  const total = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    total.set(part, offset);
    offset += part.length;
  }
  return total;
};

const PNG = join(bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a), filled(16, 1));
const ICO = join(bytes(0x00, 0x00, 0x01, 0x00, 0x01, 0x00), filled(16, 2));
const HTML_404 = '<!doctype html><html><body>Not found</body></html>';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('extractIconLinks', () => {
  it('collects icon links from the head, resolving relative URLs and <base>', () => {
    const html = `<html><head>
      <base href="https://cdn.shop.example/assets/">
      <link rel="icon" href="fav.png" sizes="32x32" type="image/png">
      <LINK REL="Shortcut Icon" HREF="/favicon.ico">
      <link rel="apple-touch-icon" href="https://shop.example/apple.png">
      <link rel="stylesheet" href="style.css">
    </head><body><link rel="icon" href="body-icon.png"></body></html>`;
    const icons = extractIconLinks(html, 'https://shop.example/');
    expect(icons.map((icon) => icon.href)).toEqual([
      'https://cdn.shop.example/assets/fav.png',
      'https://cdn.shop.example/favicon.ico',
      'https://shop.example/apple.png',
    ]);
    expect(icons[0]).toMatchObject({ sizes: '32x32', type: 'image/png', rel: 'icon' });
  });

  // A `javascript:` or `data:` href in a <link rel=icon> is not an icon we
  // will ever fetch; letting one through would put an attacker-chosen URL in
  // front of whatever renders the mark.
  it('ignores non-web schemes, empty and malformed hrefs', () => {
    const html =
      '<head><link rel="icon" href="data:image/png;base64,AAAA">' +
      '<link rel="icon" href="javascript:alert(1)">' +
      '<link rel="icon" href="">' +
      '<link rel="icon" href="http://[">' +
      '<link href="/no-rel.png">' +
      '<link rel="icon"></head>';
    expect(extractIconLinks(html, 'https://x.example/')).toEqual([]);
  });

  // A page with no </head> at all still has a head: <body> ends it. Scanning
  // on would let a link anywhere in the document name the brand's mark.
  it('ends the head at <body> when no </head> closes it', () => {
    const icons = extractIconLinks(
      '<link rel="icon" href="/i.png"><body><link rel="icon" href="/late.png">',
      'https://x.example/',
    );
    expect(icons.map((icon) => icon.href)).toEqual(['https://x.example/i.png']);
  });

  it('keeps the page URL when <base href> is malformed, and ignores links after <body>', () => {
    const icons = extractIconLinks(
      '<head><base href="http://["><link rel="icon" href="/i.png"></head><body><link rel="icon" href="/late.png"></body>',
      'https://x.example/',
    );
    expect(icons.map((icon) => icon.href)).toEqual(['https://x.example/i.png']);
  });

  // </head> and <body> each end the head; a page with neither must not have
  // its whole body scanned for links.
  it('stops at </head> even when no <body> tag follows', () => {
    const icons = extractIconLinks(
      '<head><link rel="icon" href="/i.png"></head><link rel="icon" href="/after.png">',
      'https://x.example/',
    );
    expect(icons.map((icon) => icon.href)).toEqual(['https://x.example/i.png']);
  });
});

describe('rankIconCandidates', () => {
  it('prefers a scalable SVG, then the largest raster, treating apple-touch-icon as 180px', () => {
    const ranked = rankIconCandidates([
      { href: 'a', rel: 'icon', sizes: '16x16', type: null },
      { href: 'b', rel: 'apple-touch-icon', sizes: null, type: null },
      { href: 'c', rel: 'icon', sizes: '32x32 64x64', type: null },
      { href: 'd', rel: 'icon', sizes: null, type: 'image/svg+xml' },
      { href: 'e', rel: 'icon', sizes: 'any', type: null },
    ]);
    expect(ranked.map((candidate) => candidate.href)).toEqual(['d', 'e', 'b', 'c', 'a']);
  });

  it('ranks an unsized plain icon and unparseable sizes lowest', () => {
    const ranked = rankIconCandidates([
      { href: 'a', rel: 'icon', sizes: null, type: null },
      { href: 'b', rel: 'icon', sizes: 'foo', type: null },
      { href: 'c', rel: 'icon', sizes: '48x48', type: null },
    ]);
    expect(ranked[0]?.href).toBe('c');
  });
});

describe('sniffImageType', () => {
  it('recognises PNG, ICO and SVG bytes and refuses HTML', () => {
    expect(sniffImageType(PNG)).toBe('image/png');
    expect(sniffImageType(ICO)).toBe('image/x-icon');
    expect(
      sniffImageType(utf8('<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"/>')),
    ).toBe('image/svg+xml');
    expect(sniffImageType(utf8(HTML_404))).toBeNull();
    expect(sniffImageType(new Uint8Array(0))).toBeNull();
    // Long enough to index, wrong in the last byte: the signature must match
    // whole, not merely be the right length.
    expect(sniffImageType(join(utf8('GIF9'), filled(8, 0)))).toBeNull();
  });

  it('sniffs JPEG, GIF and WebP too', () => {
    expect(sniffImageType(join(bytes(0xff, 0xd8, 0xff), filled(8, 0)))).toBe('image/jpeg');
    expect(sniffImageType(join(utf8('GIF89a'), filled(8, 0)))).toBe('image/gif');
    expect(sniffImageType(join(utf8('RIFF'), filled(4, 0), utf8('WEBP'), filled(8, 0)))).toBe(
      'image/webp',
    );
  });
});

describe('discoverFavicon', () => {
  it('uses the best icon the homepage declares, and stops there', async () => {
    const calls: string[] = [];
    const found = await discoverFavicon('shop.example', {
      fetch: fakeFetch(
        {
          'https://shop.example/': {
            body: '<head><link rel="icon" href="/i16.png" sizes="16x16"><link rel="apple-touch-icon" href="/touch.png"></head>',
            type: 'text/html; charset=utf-8',
          },
          'https://shop.example/touch.png': { body: PNG, type: 'image/png' },
          'https://shop.example/i16.png': { body: PNG, type: 'image/png' },
        },
        calls,
      ),
    });
    expect(found).toMatchObject({ status: 'found', source: 'declared' });
    expect(found.dataUri).toBe(`data:image/png;base64,${base64Of(PNG)}`);
    // Best first, and it stopped there - one icon fetch, not all of them.
    expect(calls).toEqual(['https://shop.example/', 'https://shop.example/touch.png']);
  });

  it('falls back to /favicon.ico when the page declares nothing usable', async () => {
    const found = await discoverFavicon('shop.example', {
      fetch: fakeFetch({
        'https://shop.example/': { body: '<head><title>x</title></head>', type: 'text/html' },
        'https://shop.example/favicon.ico': { body: ICO, type: 'image/vnd.microsoft.icon' },
      }),
    });
    expect(found).toMatchObject({
      status: 'found',
      source: 'root',
      detail: 'shop.example/favicon.ico',
    });
    expect(found.dataUri).toContain('data:image/x-icon;base64,');
  });

  // THE trap: a server that answers every unknown path with a 200 HTML page.
  // Trusting the Content-Type or the status would put that page in the mark.
  it('refuses a 200 that is not an image, then tries www.', async () => {
    const found = await discoverFavicon('shop.example', {
      fetch: fakeFetch({
        'https://shop.example/favicon.ico': { body: HTML_404, type: 'image/x-icon' },
        'https://www.shop.example/favicon.ico': { body: PNG, type: 'text/plain' }, // wrong type, real bytes
      }),
    });
    expect(found).toMatchObject({
      status: 'found',
      source: 'root',
      detail: 'www.shop.example/favicon.ico',
    });
  });

  it('skips an icon too large to cache and does not retry www. for a www. domain', async () => {
    const calls: string[] = [];
    const found = await discoverFavicon('www.shop.example', {
      fetch: fakeFetch(
        {
          'https://www.shop.example/': {
            body: '<head><link rel="icon" href="/big.png"></head>',
            type: 'text/html',
          },
          'https://www.shop.example/big.png': {
            body: PNG,
            type: 'image/png',
            length: FAVICON_MAX_BYTES + 1,
          },
        },
        calls,
      ),
    });
    expect(found.status).toBe('none');
    expect(calls.filter((url) => url.startsWith('https://www.www.'))).toEqual([]);
  });

  // 'none' is worth caching for a week and 'error' for a minute; conflating
  // them either pins a transient outage or re-asks a silent domain forever.
  it('is "none" when nothing exists and "error" when the domain cannot be reached', async () => {
    expect((await discoverFavicon('shop.example', { fetch: fakeFetch({}) })).status).toBe('none');
    const unreachable = await discoverFavicon('shop.example', {
      fetch: fakeFetch({
        'https://shop.example/': { throws: true },
        'https://shop.example/favicon.ico': { throws: true },
        'https://www.shop.example/': { throws: true },
        'https://www.shop.example/favicon.ico': { throws: true },
      }),
    });
    expect(unreachable).toMatchObject({
      status: 'error',
      detail: 'The domain could not be reached',
    });
    expect(await discoverFavicon('  ', { fetch: fakeFetch({}) })).toMatchObject({
      status: 'none',
      detail: 'No domain',
    });
  });

  it('resolves declared icons against the final URL after a redirect', async () => {
    const found = await discoverFavicon('shop.example', {
      fetch: fakeFetch({
        'https://shop.example/': {
          body: '<head><link rel="icon" href="icon.png"></head>',
          type: 'text/html',
          url: 'https://www.shop.example/home/',
        },
        'https://www.shop.example/home/icon.png': { body: PNG, type: 'image/png' },
      }),
    });
    expect(found.status).toBe('found');
  });

  it('skips a homepage that is not HTML or is declared too large, and an icon with an empty body', async () => {
    const found = await discoverFavicon('shop.example', {
      fetch: fakeFetch({
        'https://shop.example/': { body: 'not html', type: 'application/json' },
        'https://shop.example/favicon.ico': { body: '' },
        'https://www.shop.example/': {
          body: '<head><link rel="icon" href="/i.png"></head>',
          type: 'text/html',
          length: 10_000_000,
        },
        'https://www.shop.example/favicon.ico': { body: ICO, type: 'image/x-icon' },
      }),
    });
    expect(found).toMatchObject({
      status: 'found',
      source: 'root',
      detail: 'www.shop.example/favicon.ico',
    });
  });

  it('records a declared icon that cannot be fetched and still reaches the root icon', async () => {
    const found = await discoverFavicon('shop.example', {
      fetch: fakeFetch({
        'https://shop.example/': {
          body: '<head><link rel="icon" href="/i.png"></head>',
          type: 'text/html',
        },
        'https://shop.example/i.png': { throws: true },
        'https://shop.example/favicon.ico': { body: PNG, type: 'image/png' },
      }),
    });
    expect(found).toMatchObject({ status: 'found', source: 'root' });

    // ...and when the root is missing too, the thrown fetch makes it an error, not "none".
    const errored = await discoverFavicon('shop.example', {
      fetch: fakeFetch({
        'https://shop.example/': {
          body: '<head><link rel="icon" href="/i.png"></head>',
          type: 'text/html',
        },
        'https://shop.example/i.png': { throws: true },
      }),
    });
    expect(errored.status).toBe('error');
  });

  it('treats a homepage response without a content type as undeclared', async () => {
    const found = await discoverFavicon('shop.example', {
      fetch: fakeFetch({
        'https://shop.example/': { body: '<head><link rel="icon" href="/i.png"></head>' },
        'https://shop.example/i.png': { body: PNG, type: 'image/png' },
      }),
    });
    expect(found.status).toBe('none');
  });

  // The whole point of the injected fetch is that the platform's is only a
  // default: a caller who passes nothing still gets the platform one.
  it('uses the platform fetch when none is given', async () => {
    const platform = vi.fn(() =>
      Promise.resolve({
        ok: false,
        status: 404,
        url: '',
        headers: { get: (): string | null => null },
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      }),
    );
    vi.stubGlobal('fetch', platform);
    expect((await discoverFavicon('shop.example')).status).toBe('none');
    expect(platform).toHaveBeenCalled();
  });
});

describe('the organisational-domain fallback', () => {
  // Mail comes from notify. / email. / mailer. subdomains that serve no site;
  // the brand's icon lives on the organisational domain.
  it('lists the domain, its www, then the organisational domain and its www - deduplicated', () => {
    expect(faviconHosts('notify.cloudflare.example')).toEqual([
      'notify.cloudflare.example',
      'www.notify.cloudflare.example',
      'cloudflare.example',
      'www.cloudflare.example',
    ]);
    expect(faviconHosts('shop.example')).toEqual(['shop.example', 'www.shop.example']);
    expect(faviconHosts('www.shop.example')).toEqual(['www.shop.example', 'shop.example']);
    expect(faviconHosts('')).toEqual([]);
    // Nothing registrable at all: the host itself is still worth asking.
    expect(faviconHosts('localhost')).toEqual(['localhost', 'www.localhost']);
  });

  it('finds the organisational domain’s icon when the sending subdomain has no website', async () => {
    const found = await discoverFavicon('notify.cloudflare.example', {
      fetch: fakeFetch({
        'https://notify.cloudflare.example/': { throws: true },
        'https://notify.cloudflare.example/favicon.ico': { throws: true },
        'https://www.notify.cloudflare.example/': { throws: true },
        'https://www.notify.cloudflare.example/favicon.ico': { throws: true },
        'https://cloudflare.example/': {
          body: '<head><link rel="icon" href="/brand.png"></head>',
          type: 'text/html',
        },
        'https://cloudflare.example/brand.png': { body: PNG, type: 'image/png' },
      }),
    });
    expect(found).toMatchObject({
      status: 'found',
      source: 'declared',
      detail: 'Declared by cloudflare.example (icon)',
    });
  });
});
