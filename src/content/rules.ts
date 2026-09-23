/**
 * The body-content stage: what the message SAYS, once you have removed
 * everything the sender did not write.
 *
 * This runs after the header stage and adds to it. It never replaces it, and
 * it deliberately charges less: headers are facts a mail system recorded, and
 * body content is an interpretation of somebody's prose.
 *
 * Two different kinds of rule live here, and only one of them is capped.
 *
 * INTERPRETIVE rules — the vocabulary corpus and shouting — are a guess about
 * what prose means. Word lists age badly, and a filter that can convict on
 * vocabulary alone eventually eats somebody's ordinary mail. Together they are
 * worth `VOCABULARY_CAP + 1` = 3 at the very most: enough to raise a suspicion
 * for a human to look at, never enough to reach `SPAM_THRESHOLD` and file the
 * message. Matching every group in the corpus AND shouting the whole way
 * through still cannot put mail in the spam folder by itself. They finish a
 * case the headers started; they cannot open one.
 *
 * STRUCTURAL rules — hidden text, and the four link checks — are facts about
 * the bytes, not readings of them: where a link actually points, and what the
 * markup hid from the reader. Those accumulate without a cap, because several
 * of them at once is not a stronger opinion, it is several separate deceptions,
 * and a message carrying all of them is spam whatever its headers said.
 *
 * No single rule anywhere in the file can reach `SPAM_THRESHOLD` on its own,
 * so none of them is a veto. The heaviest is the deceptive link whose text
 * names the READER'S OWN domain — 4 points — because a link dressed as the
 * reader's organisation that goes somewhere else has no honest version;
 * everything else is worth 2 or less.
 *
 * WHAT IT SCORES. The sender's own words: quoted history, signature and the
 * client's footer removed first (`quote.ts` for plain text, the blockquote and
 * quote-container handling in `html-text.ts` for HTML). Score the whole file
 * instead and the person who forwards a phish to their IT desk is scored as
 * the phisher, and a long thread gets worse every time somebody replies to it.
 *
 * WHAT IT DOES NOT DO. No network, no DNS, no reputation, no model. Every
 * answer is a pure function of the bytes handed in, which is what makes a
 * score reproducible months later when somebody asks why their mail was filed.
 */
import { brandOwningDomain, registrableDomain } from '../identity.js';
import {
  anchorMismatches,
  linkTarget,
  urlsInText,
  type AnchorLike,
  type LinkTarget,
} from '../urls.js';
import {
  assessmentOf,
  type SpamAssessment,
  type SpamReason,
  type SpamReasonId,
} from '../verdict.js';

import { extractHtml, type HtmlAnchor } from './html-text.js';
import { ownWords } from './quote.js';
import { matchSpamVocabulary, vocabularyPoints } from './vocabulary.js';

export interface ContentSignalInput {
  /** The Subject line. Scored with the body — it is the sender's words too. */
  subject?: string | null;
  /** The `text/plain` body, as received. Quoted history is removed here. */
  text?: string | null;
  /** The `text/html` body, as received. */
  html?: string | null;
  /**
   * Domains the READER belongs to: the To and Cc addresses, and the mailbox
   * owner's own. A deceptive link whose visible text names one of these is
   * dressed as the reader's own organisation — "Sarv.com Engagement Letter"
   * pointing at kuaiyudh.top — which is worth twice what an anonymous
   * mismatch is. Hosts or addresses are accepted; each is reduced to its
   * registrable domain, and anything unresolvable is ignored.
   */
  recipientDomains?: readonly (string | null | undefined)[];
}

/**
 * The sender's own words and links, pulled out of whichever body parts exist.
 *
 * Exported because it is useful on its own — a client that wants to show a
 * preview, or to explain WHY a rule fired, needs the same extraction the rules
 * saw — and because it is the seam the streaming API will reuse when it starts
 * handing whole MIME messages in.
 */
export interface BodyContent {
  /** Subject and body text the sender wrote, normalised to one string. */
  words: string;
  /** Links in the sender's own words; quoted history excluded. */
  anchors: AnchorLike[];
  /** Text the markup hid from the reader. */
  hiddenText: string;
}

/** Prefer the HTML body's own words; fall back to the plain-text part. */
export function bodyContent(input: ContentSignalInput): BodyContent {
  const html = extractHtml(input.html);
  const plain = ownWords(input.text);
  const subject = (input.subject ?? '').trim();

  // Both parts of a multipart/alternative say the same thing, so scoring both
  // would double every hit. HTML wins when it has words, because that is the
  // part the reader was shown.
  const body = html.text || plain;
  const textAnchors: AnchorLike[] = urlsInText(plain).map((href) => ({ href, text: '' }));
  const ownAnchors: AnchorLike[] = html.anchors
    .filter((anchor: HtmlAnchor) => !anchor.quoted)
    .map(({ href, text }) => ({ href, text }));

  return {
    words: [subject, body].filter(Boolean).join('\n'),
    anchors: html.text ? ownAnchors : [...ownAnchors, ...textAnchors],
    hiddenText: html.hiddenText,
  };
}

/**
 * Hidden text this long is concealment rather than a stray styled element.
 *
 * Mail HTML is full of legitimately invisible scraps — a one-pixel tracking
 * image's alt text, a preheader a client hides after using it, a hidden table
 * cell holding a layout hack. Those are a handful of characters. Hiding a
 * paragraph to drag a statistical filter's score down takes a paragraph.
 */
const HIDDEN_TEXT_MIN_CHARS = 120;

/** Four consecutive shouted words is a sales pitch; two is an acronym. */
const SHOUTED_WORDS_MIN_RUN = 4;

/** A word that counts as shouted: three or more letters, all upper case. */
function isShoutedWord(word: string): boolean {
  const letters = word.replace(/\P{L}/gu, '');
  return (
    letters.length >= 3 && letters === letters.toUpperCase() && letters !== letters.toLowerCase()
  );
}

/**
 * The longest run of consecutive shouted words.
 *
 * A run rather than a ratio, because a ratio fires on short messages: a
 * two-word subject that happens to be an acronym is 100% shouted. `letters !==
 * letters.toLowerCase()` keeps scripts without case — Chinese, Arabic, Hebrew —
 * from counting as shouted, which they would under an `=== toUpperCase()` test
 * alone, and which would charge points for every message written in them.
 */
export function longestShoutRun(text: string): number {
  let longest = 0;
  let current = 0;
  for (const word of text.split(/\s+/)) {
    current = isShoutedWord(word) ? current + 1 : 0;
    if (current > longest) longest = current;
  }
  return longest;
}

/** Three or more exclamation marks in a row. */
const EXCLAMATION_RUN = /!{3,}/;

/**
 * Score one message's body content. Pure; no network, no DOM, no ambient state.
 *
 * Returns an assessment in the same shape every stage uses, so a caller merges
 * it with the header stage through `mergeAssessments` rather than adding
 * numbers by hand.
 */
export function assessContentSignals(input: ContentSignalInput): SpamAssessment {
  const reasons: SpamReason[] = [];
  const add = (id: SpamReasonId, points: number, detail: string): void => {
    reasons.push({ id, points, detail });
  };
  const content = bodyContent(input);

  // 1. Vocabulary. Capped below the suspicious threshold — see VOCABULARY_CAP.
  const hits = matchSpamVocabulary(content.words);
  const points = vocabularyPoints(hits);
  if (points > 0) {
    add(
      'content-spam-vocabulary',
      points,
      `The message uses ${hits.map((hit) => hit.label).join(', and ')}`,
    );
  }

  // 2. Shouting. One point, and only ever one: it is a tell about the writer,
  //    not about the message, and plenty of honest small businesses shout.
  const shouted = longestShoutRun(content.words);
  if (shouted >= SHOUTED_WORDS_MIN_RUN) {
    add('content-shouting', 1, `${shouted} words in a row in capitals`);
  } else if (EXCLAMATION_RUN.test(content.words)) {
    add('content-shouting', 1, 'Runs of exclamation marks');
  }

  // 3. Text the reader cannot see. There is no honest reason to hide a
  //    paragraph in a message; the only thing it can change is what a filter
  //    that reads the markup thinks the message is about.
  if (content.hiddenText.length >= HIDDEN_TEXT_MIN_CHARS) {
    add(
      'content-hidden-text',
      2,
      `${content.hiddenText.length} characters of text are hidden from the reader by the message's own styling`,
    );
  }

  // 4. Links. Structural facts about where a link goes. Three weights for
  //    the one deception, by whose name the text borrowed: the reader's own
  //    domain (4 — "Sarv.com Engagement Letter" going to kuaiyudh.top has no
  //    honest version), a protected brand's (3 — the same lie the sender
  //    rule charges 3 for, told in the body instead), and anyone else's (2).
  //    Even the heaviest stays below `SPAM_THRESHOLD`: a vendor's newsletter
  //    that wraps a link to the reader's own site through a tracking host
  //    not on the wrapper list must not be filed on that alone.
  const readers = new Set(
    (input.recipientDomains ?? [])
      .map((domain) =>
        registrableDomain(
          domain?.includes('@') ? domain.slice(domain.lastIndexOf('@') + 1) : domain,
        ),
      )
      .filter((domain): domain is string => domain !== null),
  );
  for (const { shown, actual } of anchorMismatches(content.anchors)) {
    if (readers.has(shown)) {
      add(
        'link-display-mismatch',
        4,
        `A link dressed as your own domain ${shown} actually points to ${actual}`,
      );
      continue;
    }
    const brand = brandOwningDomain(shown);
    if (brand) {
      add(
        'link-display-mismatch',
        3,
        `A link that appears to go to ${brand.name} (${shown}) actually points to ${actual}`,
      );
      continue;
    }
    add(
      'link-display-mismatch',
      2,
      `A link that appears to go to ${shown} actually points to ${actual}`,
    );
  }

  const targets = content.anchors
    .map((anchor) => linkTarget(anchor.href))
    .filter((target): target is LinkTarget => target !== null);

  // Each of the three below fires once per message, not once per link: twenty
  // links to the same IP is one decision the sender made.
  const userinfo = targets.find((target) => target.hasUserinfo);
  if (userinfo) {
    add(
      'link-userinfo',
      2,
      `A link hides its real destination behind a username — it reads as one site but goes to ${userinfo.host}`,
    );
  }

  const bareIp = targets.find((target) => target.isIp);
  if (bareIp) {
    add(
      'link-bare-ip',
      2,
      `A link points straight at an IP address (${bareIp.host}) rather than a domain`,
    );
  }

  const punycode = targets.find((target) => target.isPunycode);
  if (punycode) {
    add(
      'link-punycode',
      1,
      `A link goes to the punycode domain ${punycode.host}, which can imitate a familiar name`,
    );
  }

  return assessmentOf(reasons);
}
