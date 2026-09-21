/**
 * The body-content entry point: `@sarv-in/mailguard/content`.
 *
 * Costs `htmlparser2` and `tldts`, and nothing else — no address parser, no
 * freemail corpus. A consumer that has a body and wants it scored takes this;
 * a consumer that only reads a stored verdict still takes `/verdict` and pays
 * nothing.
 */
export {
  assessContentSignals,
  bodyContent,
  longestShoutRun,
  type BodyContent,
  type ContentSignalInput,
} from './rules.js';
export { collapseWhitespace, extractHtml, type HtmlAnchor, type HtmlExtract } from './html-text.js';
export { ownWords, stripQuotedTail, QUOTE_MARKERS } from './quote.js';
export {
  containsPhrase,
  matchSpamVocabulary,
  normalizeForMatching,
  vocabularyPoints,
  type VocabularyHit,
} from './vocabulary.js';
export { SPAM_PHRASE_GROUPS, VOCABULARY_CAP, type SpamPhraseGroup } from '../data/spam-phrases.js';
