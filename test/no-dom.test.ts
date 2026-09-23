// @vitest-environment node
//
// The verdict must not depend on WHERE the scan ran.
//
// This file used to pin the opposite: until v0.2 the link checks used the
// ambient `DOMParser`, so in plain Node — where mail is actually scored, at
// ingest, in a main process — every one of them returned "found nothing", and
// these tests asserted that. The result was a scanner that reported a phishing
// body had no deceptive links, and a renderer that displayed the same body and
// found them, with nothing anywhere to say the two disagreed. The rules now
// read HTML with `htmlparser2`, which is pure JavaScript and needs no platform,
// so the whole environment question is gone.
//
// The file stays, in the `node` environment, because it is the only thing that
// proves it: every other test would still pass if a DOM crept back in as a
// requirement. Its assertions are now the inverse of what they were — full
// results, with no DOM in sight.
import { describe, expect, it } from 'vitest';

import { assessContentSignals } from '../src/content/index.js';
import { assessLinks, assessPhishing, linkDomainsAllMatch, linkMismatches } from '../src/links.js';
import { assessEmailSecurity } from '../src/security.js';

const HTML = '<a href="https://evil.ru/x">paypal.com</a>';

describe('with no DOMParser at all', () => {
  it('has none, so every result below was reached without one', () => {
    expect(typeof DOMParser).toBe('undefined');
  });

  // Regression: the whole point of the change. A deceptive link must be found
  // by the process that SCORES the message, not only by the one that displays
  // it — the scoring process is the one with no browser anywhere near it.
  it('finds the deceptive link', () => {
    expect(linkMismatches(HTML)).toEqual([{ shown: 'paypal.com', actual: 'evil.ru' }]);
    expect(assessLinks(HTML)).toEqual([
      {
        kind: 'link',
        severity: 'caution',
        text: 'A link that appears to go to paypal.com actually points to evil.ru.',
      },
    ]);
  });

  // Regression: the claim is "every link stays on the sender's own domain".
  // It is now answerable in Node, so it must be answered — and answered
  // correctly in both directions.
  it('answers whether the links stay home instead of refusing to', () => {
    expect(linkDomainsAllMatch(HTML, 'example.net')).toBe(false);
    expect(linkDomainsAllMatch(HTML, 'evil.ru')).toBe(true);
    expect(linkDomainsAllMatch(null, 'example.net')).toBe(true);
  });

  it('still assesses the sender identity, which never needed a DOM', () => {
    expect(
      assessPhishing({ fromName: 'Alice', fromAddress: 'alice@example.net', html: null }).level,
    ).toBe('none');
    expect(
      assessPhishing({ fromName: 'PayPal <service@paypal.com>', fromAddress: 'billing@evil.ru' })
        .level,
    ).toBe('danger');
  });

  // Regression: the authentication verdict is the authoritative signal and
  // does not need a DOM. A server-side scan must reach `danger` on a DMARC
  // failure — and must now also report the link it found on the way.
  it('decides a security level from the authentication verdict, links included', () => {
    const result = assessEmailSecurity({
      fromAddress: 'alice@example.net',
      auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail', overall: 'fail' },
      html: HTML,
    });
    expect(result.level).toBe('danger');
    expect(result.untrustedLinks).toEqual([{ shown: 'paypal.com', actual: 'evil.ru' }]);
  });

  // Regression: the body-content stage exists to run at ingest. If it ever
  // needed a DOM it would score every message zero in the only place it runs.
  it('scores body content', () => {
    const { reasons } = assessContentSignals({ html: HTML });
    expect(reasons.map((reason) => reason.id)).toEqual(['link-display-mismatch']);
  });
});
