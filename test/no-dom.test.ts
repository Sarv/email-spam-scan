// @vitest-environment node
//
// The package must work in plain Node, where there is no DOMParser. Every
// link check degrades to "found nothing" rather than throwing: a scanner that
// cannot inspect links must not claim links are bad, and must not take the
// surrounding scan down either. Without this file the DOM-less path is never
// exercised, because every other link test runs under happy-dom.
import { afterEach, describe, expect, it } from 'vitest';

import { assessLinks, assessPhishing, linkDomainsAllMatch, linkMismatches } from '../src/links.js';
import { assessEmailSecurity } from '../src/security.js';

const HTML = '<a href="https://evil.ru/x">paypal.com</a>';

describe('with no DOMParser at all', () => {
  it('has none, so the degradation below is the real path and not a mock', () => {
    expect(typeof DOMParser).toBe('undefined');
  });

  it('finds no link mismatches instead of throwing', () => {
    expect(linkMismatches(HTML)).toEqual([]);
    expect(assessLinks(HTML)).toEqual([]);
  });

  // Regression: the claim is "every link stays on the sender's own domain".
  // With no parser nobody looked, so it must be false — otherwise a message
  // reaches the top `verified` level on evidence that was never read.
  it('refuses to assert that links stay home, but still allows a body with no links', () => {
    expect(linkDomainsAllMatch(HTML, 'example.net')).toBe(false);
    expect(linkDomainsAllMatch(null, 'example.net')).toBe(true);
  });

  it('still assesses the sender identity, which needs no DOM', () => {
    expect(
      assessPhishing({ fromName: 'Alice', fromAddress: 'alice@example.net', html: HTML }).level,
    ).toBe('none');
    expect(
      assessPhishing({ fromName: 'PayPal <service@paypal.com>', fromAddress: 'billing@evil.ru' })
        .level,
    ).toBe('danger');
  });

  // Regression: the authentication verdict is the authoritative signal and
  // does not need a DOM. A server-side scan must still reach `danger` on a
  // DMARC failure with no browser anywhere near it.
  it('still decides a security level from the authentication verdict', () => {
    const result = assessEmailSecurity({
      fromAddress: 'alice@example.net',
      auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail', overall: 'fail' },
      html: HTML,
    });
    expect(result.level).toBe('danger');
    expect(result.untrustedLinks).toEqual([]);
  });
});

describe('with a DOMParser that throws', () => {
  afterEach(() => {
    delete (globalThis as { DOMParser?: unknown }).DOMParser;
  });

  // Regression: a parser can exist and still fail on a given document. That
  // must be caught here, not surface as an exception in the caller's message
  // list, where one malformed body would blank the whole view.
  it('is caught, and reported as nothing found', () => {
    (globalThis as { DOMParser?: unknown }).DOMParser = class {
      parseFromString(): never {
        throw new Error('parser exploded');
      }
    };
    expect(linkMismatches(HTML)).toEqual([]);
    expect(linkDomainsAllMatch(HTML, 'example.net')).toBe(false);
  });
});
