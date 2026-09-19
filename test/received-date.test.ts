import { describe, expect, it } from 'vitest';

import { receivedAt, receivedAtFromLine } from '../src/headers/received-date.js';

/**
 * The date-skew rule compares the sender's `Date:` against when delivery
 * actually happened. On a raw file there is no IMAP INTERNALDATE to compare
 * with, so this is the only source of the second number — and if it returns
 * null the rule silently never fires.
 */
describe('receivedAtFromLine', () => {
  it('reads the timestamp that follows the last semicolon', () => {
    expect(
      receivedAtFromLine(
        'Received: from mail.example.com (mail.example.com [203.0.113.7]) by mx.test.com with ESMTPS id abc123; Wed, 3 Sep 2026 10:11:12 +0000',
      ),
    ).toBe(Math.floor(Date.UTC(2026, 8, 3, 10, 11, 12) / 1000));
  });

  // Regression: `for <a@b>; Wed, ...` and comment clauses both contain
  // semicolons. Splitting on the FIRST one reads a hostname as a date, which
  // parses as NaN and quietly disables the skew rule for that message.
  it('is not confused by an earlier semicolon in the trace', () => {
    const line =
      'Received: from a.example (HELO a.example) by b.example (qmail 1234 invoked by uid 0; nobody) for <x@b.example>; Wed, 3 Sep 2026 10:11:12 +0000';
    expect(receivedAtFromLine(line)).toBe(Math.floor(Date.UTC(2026, 8, 3, 10, 11, 12) / 1000));
  });

  // Regression: the RFC allows a trailing comment, and many MTAs write the
  // timezone name there. Some of those forms are not parseable by `Date`.
  it('strips the trailing comment MTAs append to the timestamp', () => {
    expect(receivedAtFromLine('Received: by x; Wed, 3 Sep 2026 10:11:12 +0000 (UTC)')).toBe(
      Math.floor(Date.UTC(2026, 8, 3, 10, 11, 12) / 1000),
    );
  });

  it('is null for a line with no timestamp, no semicolon, or nothing at all', () => {
    expect(receivedAtFromLine('Received: by mail.example.com with SMTP')).toBeNull();
    expect(receivedAtFromLine('Received: from a by b; not a date')).toBeNull();
    expect(receivedAtFromLine('Received: from a by b;   ')).toBeNull();
    expect(receivedAtFromLine('')).toBeNull();
    expect(receivedAtFromLine(null)).toBeNull();
    expect(receivedAtFromLine(undefined)).toBeNull();
  });
});

describe('receivedAt', () => {
  // Regression: hops PREPEND. Reading the last line instead of the first gives
  // the time the SENDER's own machine claims, which is the very number the
  // skew rule exists to check — the rule would be comparing a lie to itself.
  it('takes the topmost line, which is the receiving end', () => {
    const lines = [
      'Received: by mx.test.com; Wed, 3 Sep 2026 10:11:12 +0000',
      'Received: by evil.example; Mon, 1 Jan 2001 00:00:00 +0000',
    ];
    expect(receivedAt(lines)).toBe(Math.floor(Date.UTC(2026, 8, 3, 10, 11, 12) / 1000));
  });

  it('falls through a hop that wrote an unreadable timestamp', () => {
    const lines = [
      'Received: by mx.test.com with SMTP',
      'Received: by b.example; Wed, 3 Sep 2026 10:11:12 +0000',
    ];
    expect(receivedAt(lines)).toBe(Math.floor(Date.UTC(2026, 8, 3, 10, 11, 12) / 1000));
  });

  it('is null when there is no trace at all', () => {
    expect(receivedAt([])).toBeNull();
    expect(receivedAt(null)).toBeNull();
    expect(receivedAt(undefined)).toBeNull();
  });
});
