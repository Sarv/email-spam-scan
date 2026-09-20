import { afterEach, describe, expect, it, vi } from 'vitest';

import { defaultFetch, fetchBounded, type FetchResponse } from '../src/brand/fetch.js';

import { fakeFetch, toArrayBuffer } from './fetch-fixture.js';
import { utf8 } from './vmc-fixture.js';

/**
 * The bounded HTTPS boundary both brand lookups share.
 *
 * What this protects: every byte here comes from a domain the reader has not
 * chosen to visit. A download without a ceiling is a memory-exhaustion bug
 * reachable by anyone who can put a URL in a DNS record, and a non-2xx that
 * throws instead of answering null would turn one missing icon into a failed
 * lookup for the whole domain.
 */
afterEach(() => {
  vi.unstubAllGlobals();
});

describe('fetchBounded', () => {
  it('returns the bytes, the lower-cased type and the final URL', async () => {
    const fetched = await fetchBounded(
      fakeFetch({
        'https://x.example/a': {
          body: 'hello',
          type: 'Text/HTML; charset=UTF-8',
          url: 'https://x.example/b',
        },
      }),
      'https://x.example/a',
      1_000,
    );
    expect(fetched).toEqual({
      bytes: utf8('hello'),
      contentType: 'text/html; charset=utf-8',
      url: 'https://x.example/b',
    });
  });

  it('answers null for a non-2xx, and reports no type as an empty one', async () => {
    const routes = {
      'https://x.example/a': { status: 500 },
      'https://x.example/b': { body: 'hi' },
    };
    expect(await fetchBounded(fakeFetch(routes), 'https://x.example/a', 1_000)).toBeNull();
    expect((await fetchBounded(fakeFetch(routes), 'https://x.example/b', 1_000))?.contentType).toBe(
      '',
    );
  });

  // A server that admits the size up front saves downloading the body at all,
  // and a body that runs long after under-declaring itself is still refused —
  // otherwise the ceiling is only as real as the sender's honesty.
  it('refuses a declared or an actual oversize', async () => {
    const declared = fakeFetch({ 'https://x.example/big': { body: 'hi', length: 10_000 } });
    expect(await fetchBounded(declared, 'https://x.example/big', 1_000)).toBeNull();
    expect(
      await fetchBounded(declared, 'https://x.example/big', 1_000, { truncate: true }),
    ).toBeNull();

    const understated = fakeFetch({ 'https://x.example/big': { body: 'hello world', length: 2 } });
    expect(await fetchBounded(understated, 'https://x.example/big', 5)).toBeNull();
    expect(
      (await fetchBounded(understated, 'https://x.example/big', 5, { truncate: true }))?.bytes,
    ).toEqual(utf8('hello'));
  });

  // net.fetch, a cache, a proxy: an implementation need only answer what the
  // interface asks for. A missing content-length or final URL is normal, and
  // must not read as a zero-length body or an empty URL to resolve against.
  it('accepts a response that declares neither a length nor a final URL', async () => {
    const minimal = (): Promise<FetchResponse> =>
      Promise.resolve({
        ok: true,
        status: 200,
        headers: { get: (): string | null => null },
        arrayBuffer: () => Promise.resolve(toArrayBuffer(utf8('hi'))),
      });
    expect(await fetchBounded(minimal, 'https://x.example/a', 1_000)).toEqual({
      bytes: utf8('hi'),
      contentType: '',
      url: 'https://x.example/a',
    });
  });
});

describe('defaultFetch', () => {
  it('hands back the platform fetch', () => {
    expect(defaultFetch()).toBe(globalThis.fetch);
  });

  // A runtime with no fetch is a setup fact, and it must name the option that
  // fixes it rather than fail somewhere deep in a lookup.
  it('names the option to pass when the runtime has none', () => {
    vi.stubGlobal('fetch', undefined);
    expect(() => defaultFetch()).toThrow(/options\.fetch/);
  });
});
