import { describe, expect, it } from 'vitest';

import {
  containsPhrase,
  matchSpamVocabulary,
  normalizeForMatching,
  vocabularyPoints,
} from '../src/content/vocabulary.js';
import { SPAM_PHRASE_GROUPS, VOCABULARY_CAP } from '../src/data/spam-phrases.js';

describe('normalizeForMatching', () => {
  it('folds case and collapses whitespace', () => {
    expect(normalizeForMatching('  You   HAVE\n WON ')).toBe('you have won');
    expect(normalizeForMatching(null)).toBe('');
    expect(normalizeForMatching('')).toBe('');
    expect(normalizeForMatching('   ')).toBe('');
  });

  // Regression: fullwidth and mathematical alphabets render as ordinary
  // letters. Without NFKC the corpus matches none of them, and a spammer gets
  // the whole vocabulary stage for free by changing a font.
  it('folds the Unicode encodings of the same letters (NFKC)', () => {
    expect(normalizeForMatching('ＹＯＵ ＨＡＶＥ ＷＯＮ')).toBe('you have won');
  });

  // Regression: a zero-width space between two letters is invisible on screen
  // and fatal to a string comparison. Removing them is the only reason the
  // corpus survives contact with real spam.
  it('removes the invisible characters inserted to break matching', () => {
    expect(normalizeForMatching('you ha​ve w­on﻿')).toBe('you have won');
  });
});

describe('containsPhrase', () => {
  // Regression: `won` inside `wonderful` must not fire the prize-scam group.
  // Substring matching on a word corpus is how a filter eats ordinary mail.
  it('matches whole words only', () => {
    expect(containsPhrase('you have won a prize', 'you have won')).toBe(true);
    expect(containsPhrase('what a wonderful day', 'you have won')).toBe(false);
    expect(containsPhrase('congratulations, you have won!', 'you have won')).toBe(true);
    expect(containsPhrase('reyou have wonx', 'you have won')).toBe(false);
  });

  // Regression: the first occurrence may fail the boundary test while a later
  // one passes. Returning false on the first near-miss loses the real hit.
  it('keeps looking after a hit that failed the boundary test', () => {
    expect(containsPhrase('wonx and then you have won', 'you have won')).toBe(true);
    expect(containsPhrase('ayou have wonb, ayou have wonb', 'you have won')).toBe(false);
  });

  it('is false for an empty phrase and for a phrase that is not there', () => {
    expect(containsPhrase('anything', '')).toBe(false);
    expect(containsPhrase('anything', 'nothing here')).toBe(false);
  });

  // Regression: scripts without word characters at the boundary — a phrase at
  // the very start or the very end of the text — must still match.
  it('matches at the start and the end of the text', () => {
    expect(containsPhrase('you have won', 'you have won')).toBe(true);
  });
});

describe('matchSpamVocabulary', () => {
  // Regression: twelve pharmacy words are one pharmacy advert. Counting each
  // phrase makes the score a function of how wordy the spammer was.
  it('reports each group once, however many of its phrases matched', () => {
    const hits = matchSpamVocabulary(
      'no prescription needed, no prescription required, cheap meds, male enhancement',
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.id).toBe('unlicensed-pharmacy');
    expect(hits[0]?.phrase).toBe('no prescription needed');
  });

  it('reports every distinct group that matched', () => {
    const ids = matchSpamVocabulary(
      'urgent action required: verify your password, you have won',
    ).map((hit) => hit.id);
    expect(ids).toEqual(['credential-phishing', 'prize-lottery', 'pressure']);
  });

  it('finds nothing in ordinary prose, and nothing in nothing', () => {
    expect(
      matchSpamVocabulary('Please find the Q3 invoice attached. Payment is due Friday.'),
    ).toEqual([]);
    expect(matchSpamVocabulary('')).toEqual([]);
    expect(matchSpamVocabulary(null)).toEqual([]);
  });

  it('can be given a different corpus, which is what makes the data file data', () => {
    const hits = matchSpamVocabulary('the moon is made of cheese', [
      { id: 'test', label: 'test language', weight: 1, phrases: ['made of cheese'] },
    ]);
    expect(hits).toEqual([
      { id: 'test', label: 'test language', weight: 1, phrase: 'made of cheese' },
    ]);
  });
});

describe('vocabularyPoints', () => {
  // Regression: THE safety property of the whole vocabulary stage. Word lists
  // age badly and a filter that can convict on vocabulary alone eventually
  // eats somebody's ordinary mail. The cap sits below SUSPICIOUS_THRESHOLD, so
  // matching every group in the file still cannot raise a suspicion by itself.
  it('is capped below the suspicious threshold no matter how much matched', () => {
    const everything = SPAM_PHRASE_GROUPS.map((group) => ({
      id: group.id,
      label: group.label,
      weight: group.weight,
      phrase: group.phrases[0] as string,
    }));
    expect(everything.reduce((sum, hit) => sum + hit.weight, 0)).toBeGreaterThan(VOCABULARY_CAP);
    expect(vocabularyPoints(everything)).toBe(VOCABULARY_CAP);
  });

  it('is zero when nothing matched, and the plain sum below the cap', () => {
    expect(vocabularyPoints([])).toBe(0);
    expect(vocabularyPoints([{ id: 'a', label: 'a', weight: 1, phrase: 'x' }])).toBe(1);
  });
});

describe('the corpus itself', () => {
  // Regression: a phrase written with a capital, a double space or a trailing
  // space can never match, because matching happens against normalised text.
  // It would sit in the file looking like protection and provide none.
  it('is written in the normalised form it is matched against', () => {
    for (const group of SPAM_PHRASE_GROUPS) {
      for (const phrase of group.phrases) {
        expect(phrase, `${group.id}: ${JSON.stringify(phrase)}`).toBe(normalizeForMatching(phrase));
      }
    }
  });

  // Regression: two groups charging for the same phrase would double-score it.
  it('has no duplicate phrases and no duplicate group ids', () => {
    const phrases = SPAM_PHRASE_GROUPS.flatMap((group) => group.phrases);
    expect(new Set(phrases).size).toBe(phrases.length);
    const ids = SPAM_PHRASE_GROUPS.map((group) => group.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  // Regression: a single word is where this kind of list goes wrong —
  // "winner" is in sports newsletters, "you have been selected as a winner" is
  // not. Phrases, not words.
  it('contains no single-word entries', () => {
    for (const group of SPAM_PHRASE_GROUPS) {
      for (const phrase of group.phrases) {
        expect(phrase.split(' ').length, `${group.id}: ${phrase}`).toBeGreaterThan(1);
      }
    }
  });
});
