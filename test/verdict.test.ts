import { describe, expect, it } from 'vitest';

import {
  isSpamScore,
  parseSpamReasons,
  spamVerdict,
  SPAM_THRESHOLD,
  SUSPICIOUS_THRESHOLD,
  type SpamReason,
} from '../src/verdict.js';

/**
 * The stored verdict: where the line is, and reading reasons back.
 *
 * What this protects: this module is the ONLY thing a reader (a shield, a
 * report, another service) needs in order to agree with the scanner about
 * what a number means. If the reader and the scanner ever disagree about the
 * threshold, a message is filed as spam and displayed as clean, which is the
 * one outcome worse than either verdict on its own — the user is told the
 * mail is fine and never sees it again.
 */
describe('spamVerdict', () => {
  // Boundaries are inclusive on purpose. A message scoring exactly the
  // threshold IS spam; an off-by-one here silently widens the inbox by one
  // whole rule's worth of mail.
  it('is inclusive at both thresholds', () => {
    expect(spamVerdict(SPAM_THRESHOLD)).toBe('spam');
    expect(spamVerdict(SPAM_THRESHOLD - 0.01)).toBe('suspicious');
    expect(spamVerdict(SUSPICIOUS_THRESHOLD)).toBe('suspicious');
    expect(spamVerdict(SUSPICIOUS_THRESHOLD - 0.01)).toBe('clean');
  });

  it('reads clean for zero and for a negative score', () => {
    expect(spamVerdict(0)).toBe('clean');
    expect(spamVerdict(-3)).toBe('clean');
  });

  // Regression: "never scored" must not read as "scored clean". A message
  // synced before the scanner existed has no verdict, and showing it a green
  // shield claims a check that never ran.
  it('is null — not "clean" — when the message was never scored', () => {
    expect(spamVerdict(null)).toBeNull();
    expect(spamVerdict(undefined)).toBeNull();
    expect(spamVerdict(Number.NaN)).toBeNull();
    expect(spamVerdict(Number.POSITIVE_INFINITY)).toBeNull();
    expect(spamVerdict('5' as unknown as number)).toBeNull();
  });
});

describe('isSpamScore', () => {
  it('is true only at or above the spam threshold', () => {
    expect(isSpamScore(SPAM_THRESHOLD)).toBe(true);
    expect(isSpamScore(SPAM_THRESHOLD + 10)).toBe(true);
    expect(isSpamScore(SUSPICIOUS_THRESHOLD)).toBe(false);
    expect(isSpamScore(null)).toBe(false);
  });
});

describe('parseSpamReasons', () => {
  const reason: SpamReason = { id: 'auth-failed', points: 3, detail: 'DMARC failed' };

  it('round-trips what the scanner wrote', () => {
    expect(parseSpamReasons(JSON.stringify([reason]))).toEqual([reason]);
  });

  // Every one of these is a real stored value: a NULL column, a column written
  // before the feature existed, a truncated write. None may throw — the row
  // that fails to parse is the message the user is trying to open.
  it('reads anything unusable as "no reasons", never a throw', () => {
    expect(parseSpamReasons(null)).toEqual([]);
    expect(parseSpamReasons(undefined)).toEqual([]);
    expect(parseSpamReasons('')).toEqual([]);
    expect(parseSpamReasons('not json')).toEqual([]);
    expect(parseSpamReasons('{"id":"auth-failed"}')).toEqual([]);
    expect(parseSpamReasons('null')).toEqual([]);
    expect(parseSpamReasons('42')).toEqual([]);
  });

  // Partial survival, deliberately: one bad element in an array of five should
  // cost the reader that one line, not the whole explanation.
  it('keeps the good elements of a partly-bad array', () => {
    const json = JSON.stringify([
      reason,
      null,
      'nonsense',
      { id: 'missing-date' },
      { id: 'date-skew', points: '2', detail: 'x' },
      { id: 'fake-reply', points: 2, detail: 42 },
    ]);
    expect(parseSpamReasons(json)).toEqual([reason]);
  });
});
