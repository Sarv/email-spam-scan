import { describe, expect, it } from 'vitest';

import { hasReplyPrefix, isValidMessageId } from '../src/rfc.js';

describe('isValidMessageId', () => {
  it('accepts a well-formed angle-addr', () => {
    expect(isValidMessageId('<CAF=abc123@mail.gmail.com>')).toBe(true);
    expect(isValidMessageId('<20250919.123456.7890@sarv.com>')).toBe(true);
  });

  // Regression: these are what forged and hand-rolled Message-IDs actually get
  // wrong. Each one scores `malformed-message-id`, so a false accept here is a
  // rule that silently stops firing.
  it('rejects missing brackets, a missing domain, and a missing local part', () => {
    expect(isValidMessageId('CAF=abc@mail.gmail.com')).toBe(false);
    expect(isValidMessageId('<CAF=abc@mail.gmail.com')).toBe(false);
    expect(isValidMessageId('CAF=abc@mail.gmail.com>')).toBe(false);
    expect(isValidMessageId('<@mail.gmail.com>')).toBe(false);
    expect(isValidMessageId('<CAF=abc@>')).toBe(false);
    expect(isValidMessageId('<no-at-sign>')).toBe(false);
    expect(isValidMessageId('<>')).toBe(false);
    expect(isValidMessageId('')).toBe(false);
  });

  // Regression: a nested bracket means two ids were concatenated or one was
  // truncated; accepting it lets a malformed value through as well-formed.
  it('rejects a bracket inside the id', () => {
    expect(isValidMessageId('<a@b.com<c@d.com>')).toBe(false);
    expect(isValidMessageId('<a@b>c.com>')).toBe(false);
  });
});

describe('hasReplyPrefix', () => {
  it('matches English, German, Nordic, Dutch, French, Spanish, Italian and Portuguese prefixes', () => {
    for (const subject of [
      'Re: invoice',
      're: invoice',
      'RE: invoice',
      'Fw: invoice',
      'Fwd: invoice',
      'AW: Rechnung',
      'WG: Rechnung',
      'SV: faktura',
      'RV: factura',
      'TR: facture',
      'RIF: fattura',
      'ENC: fatura',
      'Antw: factuur',
      'Doorst: factuur',
    ]) {
      expect(hasReplyPrefix(subject), subject).toBe(true);
    }
  });

  it('matches a counted prefix in either bracket style', () => {
    expect(hasReplyPrefix('Re[2]: invoice')).toBe(true);
    expect(hasReplyPrefix('Re(2): invoice')).toBe(true);
  });

  // Regression: the `fake-reply` rule fires on a true return here, so a word
  // that merely STARTS like a prefix must not match. "Reminder:" and
  // "Reference:" begin with "re" and are ordinary subjects.
  it('does not match an ordinary subject that merely begins with those letters', () => {
    for (const subject of [
      'Reminder: standup at 10',
      'Reference: your application',
      'Results: Q3',
      'Renewal due',
      'Fixed the build',
      'SVG export is broken',
      '',
    ]) {
      expect(hasReplyPrefix(subject), subject).toBe(false);
    }
    expect(hasReplyPrefix(null)).toBe(false);
    expect(hasReplyPrefix(undefined)).toBe(false);
  });
});
