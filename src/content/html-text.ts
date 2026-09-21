/**
 * What a reader actually SEES in an HTML mail, plus what the markup hid from
 * them — extracted with a real HTML parser, in one pass, with no DOM.
 *
 * WHY A PARSER AND NOT THE BROWSER'S. The previous version of the link checks
 * used the ambient `DOMParser`, which exists in a renderer and does not exist
 * in Node. That made the verdict depend on WHERE the scan ran: the same
 * message scored one way at ingest, in a main process with no DOM, and another
 * way in the window that displayed it. For a security signal that is worse
 * than having no signal, because the disagreement is invisible — the ingest
 * side simply reported "no deceptive links" about a body it never read.
 * `htmlparser2` is pure JavaScript with no platform assumptions, so one
 * implementation now answers identically in both places.
 *
 * WHY NOT A REGEX. Mail HTML is the worst HTML there is: unclosed tags,
 * `<a>` inside `<a>`, attributes in single quotes or none, entity-encoded
 * angle brackets, comments in the middle of a tag. Every one of those is a way
 * to show the reader one link and a scanner another, which is exactly the
 * attack this module exists to catch. A tolerant parser that resolves them the
 * way a mail client would is the only honest reader.
 *
 * `htmlparser2` is pinned to v10 deliberately: it is the last line that ships a
 * real CommonJS build, and this package publishes CJS for consumers on Node 18.
 */
import { Parser } from 'htmlparser2';

/** One `<a href>` as the reader meets it: what it says, and where it goes. */
export interface HtmlAnchor {
  /** The `href` attribute verbatim, not resolved and not normalised. */
  href: string;
  /** The anchor's visible text, whitespace-collapsed. */
  text: string;
  /** True when the anchor sits inside quoted history rather than the sender's own words. */
  quoted: boolean;
}

/**
 * One place in the document a click can GO, whatever element offers it.
 *
 * Wider than {@link HtmlAnchor} on purpose, and answering a different
 * question. An anchor is read for the pair a reader sees — the words and the
 * destination — so the deceptive-link check needs exactly the elements that
 * have visible words. "Where could this message send me" has no such limit:
 * an image map's `<area>` is a click target with no text at all, and a
 * `<form action>` is where a credential-harvesting page posts what the reader
 * typed, which is the most consequential destination in a phishing mail and
 * the one that is never an anchor.
 */
export interface HtmlLink {
  /** The attribute verbatim, not resolved and not normalised. */
  href: string;
  /** True when it sits inside quoted history rather than the sender's own words. */
  quoted: boolean;
  /** The element that offered it. */
  from: 'a' | 'area' | 'form';
}

export interface HtmlExtract {
  /** The sender's own visible words: quoted history and invisible text removed. */
  text: string;
  /** The visible words of the quoted history alone. */
  quotedText: string;
  /**
   * Text present in the markup that the reader cannot see. Spam hides keywords
   * and whole innocuous paragraphs this way to pull a statistical filter's
   * score down; a human reading the message never encounters a word of it.
   */
  hiddenText: string;
  /** Every `<a href>` in the document, each flagged with whether it was quoted. */
  anchors: HtmlAnchor[];
  /** Every navigable destination, in document order — see {@link HtmlLink}. */
  links: HtmlLink[];
}

/**
 * The attribute that makes each element a destination.
 *
 * Deliberately short. `<iframe src>`, `<img src>` and `<link href>` are
 * fetched by the client, not navigated to by the reader, and counting them
 * would put every tracking pixel's host into the answer — which on ordinary
 * marketing mail is most of the hosts there are.
 */
const NAVIGABLE_ATTRIBUTE: ReadonlyMap<string, string> = new Map([
  ['a', 'href'],
  ['area', 'href'],
  ['form', 'action'],
]);

/**
 * Tags whose CONTENT is not prose: code, styling and metadata the reader never
 * reads as words. Their text is dropped entirely rather than counted as hidden
 * — a stylesheet is not a spammer concealing a paragraph, and counting it as
 * one would fire the hidden-text rule on every HTML newsletter ever sent.
 */
const NON_PROSE_TAGS: ReadonlySet<string> = new Set([
  'script',
  'style',
  'head',
  'title',
  'noscript',
  'template',
]);

/**
 * Tags that end a line of text, so that `<p>a</p><p>b</p>` reads as two words
 * and not as `ab`. Without this, adjacent block elements silently weld two
 * words into a third that matches nothing — or, worse, into one that does.
 */
const BLOCK_TAGS: ReadonlySet<string> = new Set([
  'address',
  'article',
  'aside',
  'blockquote',
  'br',
  'dd',
  'div',
  'dl',
  'dt',
  'fieldset',
  'figcaption',
  'figure',
  'footer',
  'form',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'header',
  'hr',
  'li',
  'main',
  'nav',
  'ol',
  'p',
  'pre',
  'section',
  'table',
  'td',
  'th',
  'tr',
  'ul',
]);

/**
 * Class and id fragments that mail clients put on the container holding the
 * message being replied to or forwarded.
 *
 * `blockquote` covers the standards-compliant case; these cover the clients
 * that wrap the history in a plain `div` instead. Matched as a lowercase
 * substring of the class or id, because clients add their own prefixes
 * (`x_gmail_quote` after an Exchange round-trip, `m_123gmail_quote` on a
 * Gmail-rendered forward).
 *
 * Contributions welcome: the correct test for adding one is that the client
 * uses it for the QUOTED PORTION specifically, not for the message body.
 */
const QUOTE_CONTAINER_MARKERS: readonly string[] = [
  'gmail_quote',
  'gmail_extra',
  'yahoo_quoted',
  'moz-cite-prefix',
  'divrplyfwdmsg',
  'olk_src_body_section',
  'zmail_extra',
  'appendonsend',
  'protonmail_quote',
];

/**
 * Inline-style declarations that take an element out of the reader's sight.
 *
 * Matched on the style attribute with the whitespace removed, so
 * `display : none` and `display:none` are the same thing — mail that hides
 * text is mail that is already trying not to be read literally.
 */
const HIDDEN_STYLE_MARKERS: readonly string[] = [
  'display:none',
  'visibility:hidden',
  'opacity:0',
  'font-size:0',
  'max-height:0',
];

interface Frame {
  /** Inside a `<script>`/`<style>`/`<head>` subtree — text is not prose at all. */
  nonProse: boolean;
  /** Inside quoted history. */
  quoted: boolean;
  /** Inside something the reader cannot see. */
  hidden: boolean;
  /** The anchor this tag opened, if it opened one. */
  anchor: { href: string; parts: string[] } | null;
}

/** Does this element's own markup say the reader cannot see it? */
function isHiddenElement(attribs: Record<string, string>): boolean {
  if (attribs['hidden'] !== undefined) return true;
  const style = (attribs['style'] ?? '').toLowerCase().replace(/\s+/g, '');
  return HIDDEN_STYLE_MARKERS.some((marker) => style.includes(marker));
}

/** Does this element's markup say it holds the message being replied to? */
function isQuoteContainer(name: string, attribs: Record<string, string>): boolean {
  if (name === 'blockquote') return true;
  const marker = `${attribs['class'] ?? ''} ${attribs['id'] ?? ''}`.toLowerCase();
  return QUOTE_CONTAINER_MARKERS.some((candidate) => marker.includes(candidate));
}

/** Collapse runs of whitespace to single spaces and trim. */
export function collapseWhitespace(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/**
 * Read an HTML body once and return everything the content rules need from it.
 *
 * A single pass rather than four, because each of the four answers depends on
 * the same nesting: an anchor is quoted because an ancestor was a blockquote,
 * a paragraph is hidden because an ancestor had `display:none`. Walking the
 * tree once with an explicit stack is both cheaper and the only way those four
 * answers cannot disagree with each other.
 *
 * `htmlparser2` is tolerant by contract — every byte sequence is a document to
 * it, malformed markup included — so there is no parse failure to handle here
 * and no `catch` pretending there might be.
 */
export function extractHtml(html: string | null | undefined): HtmlExtract {
  const empty: HtmlExtract = { text: '', quotedText: '', hiddenText: '', anchors: [], links: [] };
  if (!html) return empty;

  const own: string[] = [];
  const quoted: string[] = [];
  const hidden: string[] = [];
  const anchors: HtmlAnchor[] = [];
  const links: HtmlLink[] = [];
  const stack: Frame[] = [];
  const top = (): Frame | undefined => stack[stack.length - 1];

  const parser = new Parser(
    {
      onopentag(name, attribs) {
        const parent = top();
        const frame: Frame = {
          nonProse: parent?.nonProse === true || NON_PROSE_TAGS.has(name),
          quoted: parent?.quoted === true || isQuoteContainer(name, attribs),
          hidden: parent?.hidden === true || isHiddenElement(attribs),
          anchor: null,
        };
        const href = name === 'a' ? attribs['href'] : undefined;
        if (href !== undefined) frame.anchor = { href, parts: [] };
        // Collected on OPEN, unlike anchors, which wait for their closing tag
        // to have gathered their text: `links` is in document order, and a
        // `<form>` that is never closed still names where it would post.
        const navigable = NAVIGABLE_ATTRIBUTE.get(name);
        const target = navigable === undefined ? undefined : attribs[navigable];
        if (target !== undefined && target !== '') {
          links.push({ href: target, quoted: frame.quoted, from: name as HtmlLink['from'] });
        }
        stack.push(frame);
        if (BLOCK_TAGS.has(name)) (frame.quoted ? quoted : own).push('\n');
      },
      ontext(text) {
        const frame = top();
        if (frame?.nonProse === true) return;
        // Every open anchor collects the text, not just the innermost one, so
        // that `<a href><span>paypal.com</span></a>` reports the label the
        // reader sees rather than an empty one.
        for (const open of stack) if (open.anchor) open.anchor.parts.push(text);
        if (frame?.hidden === true) hidden.push(text);
        else (frame?.quoted === true ? quoted : own).push(text);
      },
      onclosetag(name) {
        const frame = stack.pop();
        if (frame?.anchor) {
          anchors.push({
            href: frame.anchor.href,
            text: collapseWhitespace(frame.anchor.parts.join('')),
            quoted: frame.quoted,
          });
        }
        if (BLOCK_TAGS.has(name)) (frame?.quoted === true ? quoted : own).push('\n');
      },
    },
    { decodeEntities: true },
  );
  parser.write(html);
  parser.end();

  return {
    text: collapseWhitespace(own.join('')),
    quotedText: collapseWhitespace(quoted.join('')),
    hiddenText: collapseWhitespace(hidden.join('')),
    anchors,
    links,
  };
}
