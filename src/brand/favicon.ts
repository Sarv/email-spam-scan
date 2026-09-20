/**
 * A domain's favicon — the fallback mark when a sender publishes no BIMI logo.
 *
 * Fetched ONCE per domain and returned as a `data:` URI, so the code that
 * renders it never talks to the domain. That the fetch happens at all is a
 * disclosure: it tells the domain that some client at this address looked it
 * up, once. Far less than the per-message tracking pixel that remote images
 * are, but not nothing — which is why a consumer should put it behind a
 * setting rather than call it for every sender that appears.
 *
 * Discovery order mirrors what a browser does: the icons the homepage
 * declares (`<link rel="icon">`, `apple-touch-icon`, ...), best first, then
 * `/favicon.ico`.
 */
import { Parser } from 'htmlparser2';

import { registrableDomain } from '../identity.js';

import { bytesToBase64, decodeUtf8 } from './bytes.js';
import { defaultFetch, fetchBounded, type FetchLike } from './fetch.js';

export const FAVICON_MAX_BYTES = 64 * 1024;
export const HOMEPAGE_MAX_BYTES = 256 * 1024;
/** Declared icons tried before falling back to `/favicon.ico`. */
const MAX_DECLARED_ICONS = 3;

const ICON_RELS = new Set(['icon', 'apple-touch-icon', 'apple-touch-icon-precomposed']);

export interface IconCandidate {
  /** Absolute URL. */
  href: string;
  rel: string;
  sizes: string | null;
  type: string | null;
}

function attribute(attribs: Record<string, string>, name: string): string | null {
  const value = attribs[name]?.toLowerCase().trim();
  return value === undefined || value === '' ? null : value;
}

/**
 * The icons a page declares in its `<head>`, resolved to absolute URLs and
 * honouring `<base href>`.
 *
 * Parsed with a real HTML parser: attribute order, quoting and case all vary
 * in the wild, and a regex over `<link ...>` gets every one of them wrong
 * somewhere.
 */
export function extractIconLinks(html: string, pageUrl: string): IconCandidate[] {
  const found: IconCandidate[] = [];
  let base = pageUrl;
  let inHead = true;
  const parser = new Parser(
    {
      onopentag(name, attribs) {
        if (!inHead) return;
        const tag = name.toLowerCase();
        if (tag === 'body') {
          inHead = false;
          return;
        }
        if (tag === 'base' && attribs.href !== undefined) {
          try {
            base = new URL(attribs.href, pageUrl).toString();
          } catch {
            // Keep the page URL: a malformed <base> is not a reason to stop.
          }
          return;
        }
        if (tag !== 'link') return;
        const rel = (attribs.rel ?? '').toLowerCase().trim();
        if (!rel.split(/\s+/).some((token) => ICON_RELS.has(token))) return;
        const declared = attribs.href;
        if (declared === undefined || declared === '') return;
        let href: string;
        try {
          const resolved = new URL(declared, base);
          if (resolved.protocol !== 'https:' && resolved.protocol !== 'http:') return;
          href = resolved.toString();
        } catch {
          return;
        }
        found.push({
          href,
          rel,
          sizes: attribute(attribs, 'sizes'),
          type: attribute(attribs, 'type'),
        });
      },
      onclosetag(name) {
        if (name.toLowerCase() === 'head') inHead = false;
      },
    },
    { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true },
  );
  parser.write(html);
  parser.end();
  return found;
}

/** The largest declared pixel size, or 0 when unknown (`any` counts as scalable). */
function sizeRank(candidate: IconCandidate): number {
  if (candidate.type === 'image/svg+xml') return 10_000;
  if (candidate.sizes === null) return candidate.rel.includes('apple-touch-icon') ? 180 : 0;
  if (candidate.sizes === 'any') return 9_999;
  return (
    candidate.sizes
      .split(/\s+/)
      // `32x32` parses as 32: parseInt reads the leading digits and stops.
      .map((size) => Number.parseInt(size, 10))
      .filter((pixels) => Number.isFinite(pixels))
      .reduce((best, pixels) => Math.max(best, pixels), 0)
  );
}

/**
 * Best first: a scalable SVG, then the largest raster, with apple-touch-icons
 * (180px by convention) ahead of an unsized `rel=icon` (typically 16px). An
 * avatar is drawn at 40-48px, so "largest" is the right default.
 */
export function rankIconCandidates(candidates: readonly IconCandidate[]): IconCandidate[] {
  return [...candidates].sort((left, right) => sizeRank(right) - sizeRank(left));
}

/** Do these bytes start with this ASCII text? */
function startsWith(bytes: Uint8Array, text: string, offset = 0): boolean {
  if (bytes.length < offset + text.length) return false;
  return [...text].every((character, index) => bytes[offset + index] === character.charCodeAt(0));
}

const SVG_PROLOGUE = /^\s*(?:<\?xml[^>]*>\s*)?(?:<!--[\s\S]*?-->\s*)*<svg[\s>]/i;

const IMAGE_MAGIC: { type: string; matches: (bytes: Uint8Array) => boolean }[] = [
  { type: 'image/png', matches: (bytes) => startsWith(bytes, '\x89PNG') },
  {
    type: 'image/x-icon',
    matches: (bytes) =>
      bytes.length > 4 &&
      bytes[0] === 0x00 &&
      bytes[1] === 0x00 &&
      bytes[2] === 0x01 &&
      bytes[3] === 0x00,
  },
  {
    type: 'image/jpeg',
    matches: (bytes) =>
      bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff,
  },
  { type: 'image/gif', matches: (bytes) => startsWith(bytes, 'GIF8') },
  {
    type: 'image/webp',
    matches: (bytes) => startsWith(bytes, 'RIFF') && startsWith(bytes, 'WEBP', 8),
  },
  {
    type: 'image/svg+xml',
    matches: (bytes) => SVG_PROLOGUE.test(decodeUtf8(bytes.subarray(0, 512))),
  },
];

/**
 * The image type the BYTES say they are.
 *
 * A server that answers a missing favicon with a 200 and an HTML page is
 * common, and that page must never become somebody's avatar; a wrong or
 * missing `Content-Type` must not lose a real icon either. Only the file's
 * own signature settles it.
 */
export function sniffImageType(bytes: Uint8Array): string | null {
  return IMAGE_MAGIC.find((candidate) => candidate.matches(bytes))?.type ?? null;
}

export type FaviconStatus = 'found' | 'none' | 'error';

export interface FaviconResult {
  status: FaviconStatus;
  /** `data:<type>;base64,...` when found. */
  dataUri: string | null;
  /** Where it came from. */
  source: 'declared' | 'root' | null;
  detail: string;
}

export interface FaviconOptions {
  /** Your own fetch, in place of the platform's. */
  fetch?: FetchLike;
}

async function fetchIcon(fetch: FetchLike, url: string): Promise<string | null> {
  const fetched = await fetchBounded(fetch, url, FAVICON_MAX_BYTES);
  if (fetched === null || fetched.bytes.length === 0) return null;
  const type = sniffImageType(fetched.bytes);
  if (type === null) return null;
  return `data:${type};base64,${bytesToBase64(fetched.bytes)}`;
}

/**
 * The hosts worth asking for a domain's favicon, in order: the domain itself,
 * its `www.`, then — because mail so often comes from `notify.`, `email.` and
 * `mailer.` subdomains that serve no website at all — the organisational
 * domain and its `www.`. Deduplicated, so `www.example.com` is asked once.
 */
export function faviconHosts(domain: string): string[] {
  const host = domain.trim().toLowerCase();
  if (host === '') return [];
  const organizationalDomain = registrableDomain(host);
  const candidates = [host, `www.${host}`];
  if (organizationalDomain !== null && organizationalDomain !== host) {
    candidates.push(organizationalDomain, `www.${organizationalDomain}`);
  }
  const hosts: string[] = [];
  for (const candidate of candidates) {
    const deduped = candidate.startsWith('www.www.') ? candidate.slice(4) : candidate;
    if (!hosts.includes(deduped)) hosts.push(deduped);
  }
  return hosts;
}

/**
 * Find a domain's favicon: on each host from {@link faviconHosts}, the
 * homepage's declared icons (best first, a few at most), then `/favicon.ico`.
 * At most a handful of requests per domain, ever.
 *
 * A domain that could not be reached is 'error' rather than 'none', for the
 * same reason the BIMI lookup makes that distinction: one is worth caching
 * for a week and the other for a minute.
 */
export async function discoverFavicon(
  domain: string,
  options: FaviconOptions = {},
): Promise<FaviconResult> {
  const host = domain.trim().toLowerCase();
  if (host === '') return { status: 'none', dataUri: null, source: null, detail: 'No domain' };
  const fetch = options.fetch ?? defaultFetch();
  let unreachable = false;

  for (const candidate of faviconHosts(host)) {
    const pageUrl = `https://${candidate}/`;

    // 1. What the homepage declares.
    try {
      const page = await fetchBounded(fetch, pageUrl, HOMEPAGE_MAX_BYTES, { truncate: true });
      if (page !== null && page.contentType.includes('text/html')) {
        const declared = rankIconCandidates(
          extractIconLinks(decodeUtf8(page.bytes), page.url),
        ).slice(0, MAX_DECLARED_ICONS);
        for (const icon of declared) {
          try {
            const dataUri = await fetchIcon(fetch, icon.href);
            if (dataUri !== null) {
              return {
                status: 'found',
                dataUri,
                source: 'declared',
                detail: `Declared by ${candidate} (${icon.rel})`,
              };
            }
          } catch {
            unreachable = true;
          }
        }
      }
    } catch {
      unreachable = true;
    }

    // 2. The conventional location.
    try {
      const dataUri = await fetchIcon(fetch, `${pageUrl}favicon.ico`);
      if (dataUri !== null) {
        return {
          status: 'found',
          dataUri,
          source: 'root',
          detail: `${candidate}/favicon.ico`,
        };
      }
    } catch {
      unreachable = true;
    }
  }

  return unreachable
    ? { status: 'error', dataUri: null, source: null, detail: 'The domain could not be reached' }
    : { status: 'none', dataUri: null, source: null, detail: 'The domain publishes no favicon' };
}
