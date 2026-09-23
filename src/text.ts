/**
 * Matching prose against a phrase list, without being defeated by the three
 * tricks every spammer already uses.
 *
 * 1. CASE. `VIAGRA`, `Viagra` and `vIaGrA` are one word. Case-folded.
 * 2. LOOKALIKE CODEPOINTS. Unicode has several encodings of the same letter —
 *    fullwidth `ｖｉａｇｒａ`, the mathematical alphabets, the compatibility
 *    ligatures. NFKC folds them onto the plain letters, which is precisely
 *    what that normalisation form is for.
 * 3. INVISIBLE SEPARATORS. A zero-width space between two letters is invisible
 *    to the reader and fatal to a naive `indexOf`; `v<U+200B>iagra` reads as
 *    `viagra` on screen and matches nothing in a string comparison. They are
 *    removed before matching, along with the soft hyphen, which renders as
 *    nothing unless the line happens to wrap there.
 *
 * What is deliberately NOT attempted is leetspeak and homoglyph folding —
 * `v1agra`, `раypal` with a Cyrillic а. Collapsing those means deciding that
 * `1` is an `i` and `а` is an `a` in every language at once, which breaks
 * ordinary words in other scripts and turns a corpus into a source of false
 * positives. Homograph domains are caught where they can be caught honestly,
 * by comparing the punycode host in `urls.ts` and `identity.ts`.
 *
 * Matching itself is `indexOf` plus a boundary test, not a regular expression.
 * The phrases come from data files that contributors edit; compiling
 * attacker-adjacent data into a pattern is how a corpus entry becomes a
 * catastrophic-backtracking bug on somebody else's mail server.
 *
 * ZERO IMPORTS. Two lists are matched this way — the spam vocabulary in the
 * content stage and the protected brand names in the identity rule — and the
 * identity rule ships to browsers on `tldts` alone. Sharing the matcher from
 * here keeps the two lists agreeing about what "the same word" means without
 * the identity entry inheriting the vocabulary corpus to get it.
 */

/** Characters that render as nothing and exist here only to break matching. */
const INVISIBLE_CHARS = /[\u00ad\u200b-\u200d\u2060\ufeff]/g;

/**
 * Fold text down to the form the lists are written in: NFKC, lowercase, no
 * invisible characters, single spaces.
 */
export function normalizeForMatching(text: string | null | undefined): string {
  if (!text) return '';
  return text
    .normalize('NFKC')
    .toLowerCase()
    .replace(INVISIBLE_CHARS, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Letters and digits in any script — the characters a word may be made of. */
const WORD_CHAR = /[\p{L}\p{N}]/u;

/**
 * Does `phrase` occur in `haystack` as whole words?
 *
 * The boundary test is on the characters either side of the hit rather than on
 * `\b`, so that a phrase ending in punctuation or a currency symbol behaves,
 * and so that `won` inside `wonderful` cannot fire the prize-scam group.
 */
export function containsPhrase(haystack: string, phrase: string): boolean {
  if (!phrase) return false;
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(phrase, from);
    if (at < 0) return false;
    const before = at === 0 ? '' : haystack.charAt(at - 1);
    const after = haystack.charAt(at + phrase.length);
    if (!WORD_CHAR.test(before) && !WORD_CHAR.test(after)) return true;
    from = at + 1;
  }
}
