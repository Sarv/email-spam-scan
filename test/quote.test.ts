import { describe, expect, it } from 'vitest';

import { ownWords, stripQuotedTail } from '../src/content/quote.js';

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

  // Regression: `html-to-text` collapses a whole reply chain onto ONE line, so
  // an attribution that is only recognised at a line start misses every mail
  // that reached the scanner as HTML — which is most of them.
  it('cuts at an attribution collapsed into the middle of a line', () => {
    expect(
      ownWords(
        'Please review this today. On Wed, Jul 29, 2026 at 12:05 PM, Bindu <b@x.com> wrote: you have won',
      ),
    ).toBe('Please review this today.');
  });
});

describe('stripQuotedTail', () => {
  it('returns nothing for no text', () => {
    expect(stripQuotedTail(null)).toBe('');
    expect(stripQuotedTail(undefined)).toBe('');
    expect(stripQuotedTail('')).toBe('');
  });

  // Regression, and the whole reason there are two functions: contact mining
  // reads the sign-off. Strip it here — as `ownWords` deliberately does — and
  // the phone number the miner exists to find goes with it.
  it('keeps the signature that ownWords removes', () => {
    const body = 'Thanks!\n--\nBob Smith\n+91 99887 76655\n\nOn Tue, X wrote:\n> theirs';
    expect(stripQuotedTail(body)).toBe('Thanks!\n--\nBob Smith\n+91 99887 76655');
    expect(ownWords(body)).toBe('Thanks!');
  });

  // Regression: an attribution need not open with "On" — Outlook and several
  // mobile clients write the name first. Miss it and the quoted sender's
  // signature is mined as if the forwarder had written it.
  it('cuts at an attribution that does not open with "On"', () => {
    expect(stripQuotedTail('Mine.\n\nAlice Smith <alice@example.com> wrote:\n> theirs')).toBe(
      'Mine.',
    );
  });

  // Regression: recognising ANY line that ends in `wrote:` deletes the rest of
  // a message over an ordinary sentence. A date or an address on the line is
  // what tells an attribution from prose.
  it('does not cut at prose that happens to end in "wrote:"', () => {
    const body = 'Here is what the auditor wrote:\nthe controls are adequate.';
    expect(stripQuotedTail(body)).toBe(body);
  });

  // Regression: the header block Outlook writes instead of an attribution.
  it('cuts at the Outlook header block, and not at a lone "From:" line', () => {
    expect(stripQuotedTail('Mine.\n\nFrom: Bob Smith\nSent: Tuesday\nTheirs.')).toBe('Mine.');
    expect(stripQuotedTail('From: the desk of Bob, a note about Tuesday.')).toBe(
      'From: the desk of Bob, a note about Tuesday.',
    );
  });

  // Regression: a client localises the attribution, and a corpus that only
  // knows English quietly scores or mines the quoted half of every non-English
  // thread.
  it('cuts at the localised attributions', () => {
    expect(stripQuotedTail('Mine.\n\nLe 3 mars 2026, Alice a écrit :\nTheirs.')).toBe('Mine.');
    expect(stripQuotedTail('Mine.\n\nAm 03.03.2026 schrieb Alice:\nTheirs.')).toBe('Mine.');
    expect(stripQuotedTail('Mine.\n\nEl 3 mar 2026, Alice escribió:\nTheirs.')).toBe('Mine.');
  });

  // Regression: a client that indents the quote has still quoted.
  it('cuts at an indented quote prefix', () => {
    expect(stripQuotedTail('Mine.\n  > theirs')).toBe('Mine.');
  });

  // Regression: Outlook draws a rule of about thirty characters above the
  // history, but people type short ones above their own sign-off — cut at
  // those and the signature is gone.
  it("cuts at Outlook's rule but not at a hand-typed one", () => {
    expect(stripQuotedTail('Mine.\n________________________________\nFrom: Bob')).toBe('Mine.');
    expect(stripQuotedTail('Mine.\n_____\nBob Smith')).toBe('Mine.\n_____\nBob Smith');
  });
});
