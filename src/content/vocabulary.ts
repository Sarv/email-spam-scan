/**
 * Matching the spam vocabulary against a body.
 *
 * The matcher itself — case folding, NFKC, invisible-character stripping and
 * the whole-word test — lives in `../text.ts`, because the protected brand
 * names in `../identity.ts` are matched the same way and the two must never
 * disagree about what "the same word" means. This file is what the content
 * stage adds on top: once per GROUP, and a cap.
 */
import { SPAM_PHRASE_GROUPS, VOCABULARY_CAP, type SpamPhraseGroup } from '../data/spam-phrases.js';
import { containsPhrase, normalizeForMatching } from '../text.js';

export { containsPhrase, normalizeForMatching };

/** One group that matched, and the first phrase of it that did. */
export interface VocabularyHit {
  id: string;
  label: string;
  weight: number;
  /** The phrase that fired, for a reason line and for debugging a false positive. */
  phrase: string;
}

/**
 * Every vocabulary group present in the text, each reported once.
 *
 * Once per GROUP, not once per phrase: a pharmacy advert naming twelve drugs is
 * one pharmacy advert. Counting each phrase would make the score a function of
 * how wordy the spam was, which is a property of the spammer's prose and not of
 * how dangerous the message is.
 */
export function matchSpamVocabulary(
  text: string | null | undefined,
  groups: readonly SpamPhraseGroup[] = SPAM_PHRASE_GROUPS,
): VocabularyHit[] {
  const haystack = normalizeForMatching(text);
  if (!haystack) return [];
  const hits: VocabularyHit[] = [];
  for (const group of groups) {
    const phrase = group.phrases.find((candidate) => containsPhrase(haystack, candidate));
    if (phrase !== undefined) {
      hits.push({ id: group.id, label: group.label, weight: group.weight, phrase });
    }
  }
  return hits;
}

/**
 * What the matched groups are worth, capped.
 *
 * The cap is the safety property of the whole vocabulary stage: see
 * {@link VOCABULARY_CAP}. Vocabulary adds to a suspicion other rules raised; it
 * is never allowed to raise one by itself.
 */
export function vocabularyPoints(hits: readonly VocabularyHit[]): number {
  return Math.min(
    VOCABULARY_CAP,
    hits.reduce((sum, hit) => sum + hit.weight, 0),
  );
}
