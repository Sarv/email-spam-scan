import { describe, expect, it } from 'vitest';

import { FREEMAIL_DOMAINS } from '../src/data/freemail-domains.js';

/**
 * The corpus is vendored rather than installed (see the file's own header: the
 * upstream package fetches its list over the network at install time). Vendored
 * data has no publisher to check it, so these tests are the check — they are
 * what a pull request adding a domain runs into.
 */
describe('the vendored freemail corpus', () => {
  // Regression: an empty or near-empty corpus is indistinguishable from a
  // working one at the call site — `FREEMAIL.has(domain)` just quietly answers
  // false — and every freemail rule silently stops firing. That is exactly the
  // failure mode the upstream install-time fetch could produce, and the reason
  // the list was vendored in the first place.
  it('is populated', () => {
    expect(FREEMAIL_DOMAINS.length).toBeGreaterThan(10_000);
  });

  // Regression: lookups are done against a lowercased domain, so an entry with
  // a capital in it can never match and is dead weight that looks like cover.
  it('is entirely lowercase and free of surrounding whitespace', () => {
    const wrong = FREEMAIL_DOMAINS.filter((domain) => domain !== domain.toLowerCase().trim());
    expect(wrong).toEqual([]);
  });

  // Regression: a duplicate is harmless to `Set` but hides a bad merge, and a
  // list that has stopped being sorted makes every future diff unreadable —
  // which is how a domain gets added twice, or removed by accident.
  it('is sorted and deduplicated', () => {
    expect(new Set(FREEMAIL_DOMAINS).size).toBe(FREEMAIL_DOMAINS.length);
    expect([...FREEMAIL_DOMAINS]).toEqual([...FREEMAIL_DOMAINS].sort());
  });

  // Regression: every entry must be a bare registrable host. A scheme, a path,
  // a port or an address can never equal the parsed domain a lookup passes in.
  it('holds bare hostnames only', () => {
    const malformed = FREEMAIL_DOMAINS.filter(
      (domain) => !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(domain),
    );
    expect(malformed).toEqual([]);
  });

  it('contains the hosts the freemail rules exist for', () => {
    const known = [
      'gmail.com',
      'yahoo.com',
      'hotmail.com',
      'outlook.com',
      'aol.com',
      'mail.ru',
      'proton.me',
    ];
    expect(known.filter((domain) => !FREEMAIL_DOMAINS.includes(domain))).toEqual([]);
  });

  // Regression: the contributing rule the file's header states — this list is
  // free consumer mailbox hosts, never "a domain we saw spam from". Adding a
  // company's own mail domain to it scores that company's real mail as
  // freemail forever after, and nobody would find out from a bug report.
  //
  // Note the corpus keeps upstream's membership decisions rather than second-
  // guessing them one domain at a time: it includes some bulk-sending services
  // (`amazonses.com`) on the same "anyone can sign up and send from it"
  // reasoning. That is upstream's call to make; this test guards our own.
  it('does not contain corporate or provider domains that are not free mailboxes', () => {
    const notFreemail = ['sarv.com', 'anthropic.com', 'github.com', 'microsoft.com', 'apple.com'];
    expect(notFreemail.filter((domain) => FREEMAIL_DOMAINS.includes(domain))).toEqual([]);
  });
});
