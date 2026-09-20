/**
 * A fetch that answers from a table.
 *
 * Both brand lookups take their HTTPS boundary as an argument precisely so a
 * test can hand them this and never open a socket. It is shared by the BIMI
 * and favicon suites because the shape they need is identical: a route table,
 * a record of what was asked (the ORDER of the requests is half of what the
 * favicon discovery promises), and the ability to make one route fail.
 */
import type { FetchLike, FetchResponse } from '../src/brand/fetch.js';

export interface Route {
  status?: number;
  body?: Uint8Array | string;
  /** Content-Type to report, whatever the bytes actually are. */
  type?: string;
  /** Content-Length to declare, whatever the body's length actually is. */
  length?: number;
  /** Fail the way an unreachable host does. */
  throws?: boolean;
  /** The final URL to report, as a redirect would. */
  url?: string;
}

export const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

export function fakeFetch(routes: Record<string, Route>, calls: string[] = []): FetchLike {
  return (url: string): Promise<FetchResponse> => {
    calls.push(url);
    const route = routes[url];
    if (route === undefined) {
      return Promise.resolve({
        ok: false,
        status: 404,
        url,
        headers: { get: () => null },
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
      });
    }
    if (route.throws === true) return Promise.reject(new Error('ECONNRESET'));
    const body =
      typeof route.body === 'string'
        ? new TextEncoder().encode(route.body)
        : (route.body ?? new Uint8Array(0));
    const status = route.status ?? 200;
    return Promise.resolve({
      ok: status < 400,
      status,
      url: route.url ?? url,
      headers: {
        get: (name: string): string | null => {
          const header = name.toLowerCase();
          if (header === 'content-type') return route.type ?? null;
          if (header === 'content-length') return String(route.length ?? body.length);
          return null;
        },
      },
      arrayBuffer: () => Promise.resolve(toArrayBuffer(body)),
    });
  };
}
