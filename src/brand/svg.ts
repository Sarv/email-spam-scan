/**
 * Is a published BIMI logo safe to render?
 *
 * The logo is shown as an `<img>` from a `data:` URI, where a browser runs no
 * script and loads no external resource, so this is defence in depth rather
 * than the only line. It still refuses anything a logo has no business
 * containing: script and animation elements, embedded documents, event
 * handlers, and any reference that leaves the file — the last of which is the
 * one that matters even in an `<img>`, because a logo that fetches something
 * is a tracking pixel wearing a brand.
 *
 * Parsed as XML rather than pattern-matched. A tag split across an entity, an
 * attribute quoted oddly, a comment in the middle of a name: every one of
 * those defeats a regex, and an SVG that a checker and a renderer disagree
 * about is exactly the file an attacker is looking for.
 */
import { Parser } from 'htmlparser2';

import { decodeUtf8 } from './bytes.js';

/**
 * Logo size ceiling. The BIMI spec says a logo SHOULD stay under 32 KB, but
 * real ones do not always (Cloudflare's is 44 KB) and receivers show them;
 * 64 KB keeps a cache bounded without refusing brands that are merely verbose.
 */
export const BIMI_LOGO_MAX_BYTES = 64 * 1024;

export interface SvgCheck {
  ok: boolean;
  /** Why it was rejected; null when ok. */
  reason: string | null;
  /** Declares `baseProfile="tiny-ps"`, the profile BIMI requires. */
  tinyPs: boolean;
}

const FORBIDDEN_SVG_TAGS = new Set([
  'script',
  'foreignobject',
  'iframe',
  'embed',
  'object',
  'audio',
  'video',
  'animate',
  'set',
  'animatemotion',
  'animatetransform',
]);

const EXTERNAL_IN_STYLE = /url\s*\(|@import|expression\s*\(/i;
const EXTERNAL_IN_TEXT = /url\s*\(['"\s]*(?:https?:|\/\/)|@import/i;

/** The reason an attribute disqualifies a logo, or null when it is harmless. */
function attributeProblem(attribute: string, rawValue: string): string | null {
  const name = attribute.toLowerCase();
  const value = rawValue.trim();
  if (name.startsWith('on')) return `event handler attribute ${attribute}`;
  if ((name === 'href' || name === 'xlink:href' || name === 'src') && value !== '') {
    // A fragment points inside this same file, which is how an SVG references
    // its own gradients and clip paths. Anything else leaves it.
    if (!value.startsWith('#')) return `external reference in ${attribute}`;
  }
  if (name === 'style' && EXTERNAL_IN_STYLE.test(value)) return 'external reference in style';
  return null;
}

/** Check a published logo. `tinyPs` is reported, not enforced — see the note in `bimi.ts`. */
export function checkBimiSvg(bytes: Uint8Array): SvgCheck {
  if (bytes.length === 0) return { ok: false, reason: 'empty file', tinyPs: false };
  if (bytes.length > BIMI_LOGO_MAX_BYTES) {
    return { ok: false, reason: `larger than ${BIMI_LOGO_MAX_BYTES / 1024} KB`, tinyPs: false };
  }

  let root: string | null = null;
  let tinyPs = false;
  let reason: string | null = null;
  const parser = new Parser(
    {
      onopentag(name, attribs) {
        if (reason !== null) return;
        const tag = name.toLowerCase();
        if (root === null) {
          root = tag;
          if (tag !== 'svg') {
            reason = 'not an SVG document';
            return;
          }
          // xmlMode keeps attribute case, and the spec spells it `baseProfile`.
          const profile = attribs.baseProfile ?? attribs.baseprofile ?? '';
          if (profile.toLowerCase() === 'tiny-ps') tinyPs = true;
        }
        if (FORBIDDEN_SVG_TAGS.has(tag)) {
          reason = `contains <${tag}>`;
          return;
        }
        for (const [attribute, value] of Object.entries(attribs)) {
          const problem = attributeProblem(attribute, value);
          if (problem !== null) {
            reason = problem;
            return;
          }
        }
      },
      ontext(data) {
        // A <style> element's body is text, and `@import` in one reaches the
        // network from inside a file that otherwise looks inert.
        if (reason === null && EXTERNAL_IN_TEXT.test(data)) {
          reason = 'external reference in stylesheet';
        }
      },
    },
    { xmlMode: true, decodeEntities: true },
  );
  parser.write(decodeUtf8(bytes));
  parser.end();

  // No `onerror`: htmlparser2 reports one only when the parser is misused
  // (written to after `end()`), never for malformed markup. A file that is
  // not XML at all simply yields no root element, which is what this checks.
  if (reason === null && root === null) reason = 'not an SVG document';
  return { ok: reason === null, reason, tinyPs };
}
