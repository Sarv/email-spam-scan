// The address parser is third-party and runs on sender-chosen input. If it
// ever throws, the scan must continue and the address must be treated as
// undeliverable — not take the whole ingest down. Mocked because the real
// parser does not throw today, and this file exists to prove the fallback
// still works if a future version does.
import { describe, expect, it, vi } from 'vitest';

vi.mock('email-addresses', () => ({
  default: {
    parseOneAddress: (): never => {
      throw new Error('parser exploded');
    },
  },
}));

const { assessSpamSignals } = await import('../src/rules/header-rules.js');

describe('when the address parser throws', () => {
  it('treats the sender address as invalid and keeps scoring', () => {
    const result = assessSpamSignals({
      fromAddress: 'alice@example.net',
      toAddress: 'bob@sarv.com',
      subject: 'Hello',
      messageId: '<a@example.net>',
      date: 1_758_000_000,
      internalDate: 1_758_000_000,
    });
    expect(result.reasons.map((r) => r.id)).toContain('sender-invalid');
    expect(result.score).toBe(2);
  });
});
