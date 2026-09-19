import { describe, expect, it } from 'vitest';

import {
  headerLookupFromText,
  headerValueFromText,
  headerValuesFromText,
} from '../src/headers/lookup.js';

const BLOCK = [
  'Received: from a.example.net (a.example.net [185.199.108.1])',
  '\tby mx.sarv.com with ESMTPS id abc123',
  'Received: from b.example.net (b.example.net [185.199.108.2])',
  '\tby a.example.net with SMTP id def456',
  'From: Alice <alice@example.net>',
  'To: bob@sarv.com,',
  ' carol@sarv.com,',
  ' dave@sarv.com',
  'Subject: hello',
  'X-Empty:',
].join('\r\n');

describe('headerValuesFromText', () => {
  // Regression: trace headers are the whole point of the multi-value form. If
  // only the first Received survives, the origin-IP walk can never reach the
  // hop that actually names the sender.
  it('returns every occurrence of a repeated header, newest hop first', () => {
    const values = headerValuesFromText(BLOCK, 'received');
    expect(values).toHaveLength(2);
    expect(values[0]).toContain('185.199.108.1');
    expect(values[1]).toContain('185.199.108.2');
  });

  // Regression: without this, a folded To/Cc list is truncated to its first
  // entry, so "no visible recipient" and recipient-count rules read a
  // three-person message as a one-person message.
  it('joins folded continuation lines into one value', () => {
    expect(headerValueFromText(BLOCK, 'to')).toBe('bob@sarv.com, carol@sarv.com, dave@sarv.com');
  });

  // Regression: header names are case-insensitive per RFC 5322; a lookup that
  // respects case silently misses every header a sender capitalised unusually.
  it('matches the header name case-insensitively', () => {
    expect(headerValueFromText(BLOCK, 'FROM')).toBe('Alice <alice@example.net>');
    expect(headerValueFromText(BLOCK, 'from')).toBe('Alice <alice@example.net>');
  });

  // Regression: a regex-special character in a caller-supplied header name
  // must not become part of the pattern. `x.spam` should not match `x-spam`.
  it('escapes regex metacharacters in the header name', () => {
    expect(headerValueFromText('X-Spam: yes', 'x.spam')).toBeNull();
    expect(headerValueFromText('X-Spam: yes', 'x-spam')).toBe('yes');
  });

  it('skips a header whose value is empty, and returns [] for an empty block', () => {
    expect(headerValuesFromText(BLOCK, 'x-empty')).toEqual([]);
    expect(headerValuesFromText('', 'from')).toEqual([]);
  });

  it('is null for an absent header', () => {
    expect(headerValueFromText(BLOCK, 'reply-to')).toBeNull();
  });

  // Regression: the final header carries no trailing newline, so the
  // terminating lookahead has to accept end-of-input as well as a newline.
  it('reads the last header in a block with no trailing newline', () => {
    expect(headerValueFromText('From: a@b.com\r\nSubject: last one', 'subject')).toBe('last one');
  });

  it('handles bare-LF blocks as well as CRLF', () => {
    expect(headerValueFromText('From: a@b.com\nSubject: unix', 'subject')).toBe('unix');
  });
});

describe('headerLookupFromText', () => {
  it('reads through to the first value, and tolerates a null block', () => {
    const get = headerLookupFromText(BLOCK);
    expect(get('subject')).toBe('hello');
    expect(get('nope')).toBeNull();
    expect(headerLookupFromText(null)('subject')).toBeNull();
    expect(headerLookupFromText(undefined)('subject')).toBeNull();
  });
});
