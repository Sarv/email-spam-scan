import { describe, expect, it } from 'vitest';

import { ownWords } from '../src/content/quote.js';

describe('ownWords', () => {
  it('returns nothing for no body', () => {
    expect(ownWords(null)).toBe('');
    expect(ownWords(undefined)).toBe('');
    expect(ownWords('')).toBe('');
  });

  it('returns the whole body when there is nothing quoted', () => {
    expect(ownWords('Hello,\n\nHere is the report.\n')).toBe('Hello,\n\nHere is the report.');
  });

  // Regression: the attribution line Gmail, Apple Mail and Thunderbird write.
  // Keep it and every reply in a thread inherits the thread's vocabulary.
  it('cuts at the attribution line above the quoted history', () => {
    expect(
      ownWords(
        'Sounds good.\n\nOn Tue, 3 Mar 2026 at 09:14, Alice <a@b.com> wrote:\n> you have won a prize',
      ),
    ).toBe('Sounds good.');
  });

  // Gmail wraps a long attribution onto a second line ending in `wrote:`,
  // which is why the pattern does not require `On ... wrote:` on one line.
  it('cuts at a wrapped attribution whose last line is just "wrote:"', () => {
    expect(
      ownWords(
        'Sounds good.\n\nOn Tue, 3 Mar 2026 at 09:14, Alice Extremely Long Name <alice@example.com>\nwrote:\n> hi',
      ),
    ).toBe('Sounds good.');
  });

  it('cuts at the Outlook separators', () => {
    expect(ownWords('My reply\n\n-----Original Message-----\nFrom: Bob')).toBe('My reply');
    expect(ownWords('My reply\n\n---------- Forwarded message ---------\nFrom: Bob')).toBe(
      'My reply',
    );
    expect(ownWords('My reply\n\n________________________________\nFrom: Bob')).toBe('My reply');
    expect(ownWords('My reply\n\nFrom: Bob Smith\nSent: Tuesday')).toBe('My reply');
  });

  // RFC 3676 §4.5: the quote prefix itself, with or without the attribution.
  it('cuts at the first quoted line', () => {
    expect(ownWords('My reply\n> you have won\n>> and again')).toBe('My reply');
    expect(ownWords('  > indented quote')).toBe('');
  });

  // RFC 3676 §4.3. Accepted without the trailing space too, because clients
  // and transfer paths strip it.
  it('cuts at the signature delimiter', () => {
    expect(ownWords('My reply\n-- \nBob Smith\nCEO, guaranteed returns ltd')).toBe('My reply');
    expect(ownWords('My reply\n--\nBob Smith')).toBe('My reply');
  });

  // Regression: a client footer is the client's words, not the sender's.
  it('cuts at the mobile and client footers', () => {
    expect(ownWords('ok\n\nSent from my iPhone')).toBe('ok');
    expect(ownWords('ok\n\nGet Outlook for iOS')).toBe('ok');
    expect(ownWords('ok\n\nSent from Mail for Windows')).toBe('ok');
    expect(ownWords('ok\n\nSent from Outlook')).toBe('ok');
  });

  // Regression: the footer pattern must not eat ordinary prose. "Sent from
  // the warehouse this morning" is a sentence, not a signature.
  it('does not cut an ordinary sentence that happens to start with "Sent from"', () => {
    expect(ownWords('Sent from the warehouse this morning, all ten pallets.')).toBe(
      'Sent from the warehouse this morning, all ten pallets.',
    );
  });

  // Regression: an empty result is a real answer. A bare forward with no
  // comment gives the content rules nothing of this sender's to judge, and
  // they must then charge nothing rather than score the thread.
  it('returns empty for a bare forward the sender added nothing to', () => {
    expect(ownWords('---------- Forwarded message ---------\nYou have won a prize')).toBe('');
  });
});
