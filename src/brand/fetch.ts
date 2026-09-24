/**
 * The HTTPS boundary the brand stage shares.
 *
 * Both lookups here — the BIMI logo and the favicon — fetch a file from a
 * domain the reader has not chosen to visit, so both go through one injected
 * `fetch`: a caller can hand in a proxy, an Electron `net.fetch`, a cache, or
 * a fixture in a test that must never open a socket.
 *
 * Every download is BOUNDED. A remote file whose size the caller does not
 * control is a memory-exhaustion bug waiting for the first server that
 * answers a logo request with a DVD image.
 */

export interface FetchResponse {
  ok: boolean;
  status: number;
  /** The final URL after redirects, when the implementation reports one. */
  url?: string;
  headers: { get(name: string): string | null };
  arrayBuffer(): Promise<ArrayBuffer>;
}

/** The subset of WHATWG `fetch` these lookups use — `net.fetch` satisfies it. */
export type FetchLike = (url: string) => Promise<FetchResponse>;

/** The platform `fetch`, or a clear error naming what to inject instead. */
export function defaultFetch(): FetchLike {
  const platform = globalThis.fetch as FetchLike | undefined;
  if (platform === undefined) {
    throw new Error(
      'The brand lookups need a fetch implementation. This runtime has no global fetch ' +
        '(Node 18 and later, and every browser, do) — pass one as options.fetch.',
    );
  }
  return platform;
}

export interface FetchedBytes {
  bytes: Uint8Array;
  /** Lower-cased, parameters and all. */
  contentType: string;
  /** The final URL, for resolving relative links against. */
  url: string;
}

export interface FetchBoundedOptions {
  /**
   * Keep the first `maxBytes` of a body that runs long, instead of refusing
   * it. Right for an HTML page, where the icons are declared in the `<head>`;
   * wrong for a logo, where a truncated file is a corrupt one.
   *
   * A server that DECLARES an oversized body is still refused either way —
   * there is no reason to download a page that has already said it is too big.
   */
  truncate?: boolean;
}

/**
 * Fetch at most `maxBytes`. Null — never a throw — for a non-2xx answer or a
 * body that is too big; the caller's next candidate is the interesting part,
 * not this one's excuse. Network failures still throw, because those are
 * about the caller's own connection rather than about the domain.
 */
export async function fetchBounded(
  fetch: FetchLike,
  url: string,
  maxBytes: number,
  options: FetchBoundedOptions = {},
): Promise<FetchedBytes | null> {
  const response = await fetch(url);
  if (!response.ok) return null;
  const bytes = await readBounded(response, maxBytes, options);
  if (bytes === null) return null;
  return {
    bytes,
    contentType: (response.headers.get('content-type') ?? '').toLowerCase(),
    url: response.url ?? url,
  };
}

/**
 * The body of a response the caller has already judged by status, at most
 * `maxBytes` of it — or null when it is bigger than that. The half of
 * {@link fetchBounded} that a caller who needs the STATUS (a 404 that means
 * "no such domain" against a 429 that means "asked too often") uses on its own.
 */
export async function readBounded(
  response: FetchResponse,
  maxBytes: number,
  options: FetchBoundedOptions = {},
): Promise<Uint8Array | null> {
  const declared = Number.parseInt(response.headers.get('content-length') ?? '', 10);
  // A server that admits the size up front saves downloading the body at all.
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  const body = new Uint8Array(await response.arrayBuffer());
  if (body.length > maxBytes && options.truncate !== true) return null;
  return options.truncate === true ? body.subarray(0, maxBytes) : body;
}
