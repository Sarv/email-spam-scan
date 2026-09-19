import { describe, expect, it } from 'vitest';

import {
  assessLinks,
  assessPhishing,
  linkDomainsAllMatch,
  linkMismatches,
  LINK_WRAPPER_DOMAINS,
} from '../src/links.js';

const anchor = (text: string, href: string): string => `<a href="${href}">${text}</a>`;

describe('linkMismatches', () => {
  // Regression: the whole point of the rule. Text names one registrable
  // domain, href goes to another.
  it('finds an anchor whose text names a different domain than its href', () => {
    const found = linkMismatches(anchor('paypal.com', 'https://paypal.secure-login.ru/pay'));
    expect(found).toEqual([{ shown: 'paypal.com', actual: 'secure-login.ru' }]);
  });

  // Regression: subdomains of the SAME registrable domain are not deceptive.
  // Flagging them put warnings on ordinary corporate mail.
  it('does not flag a subdomain of the same registrable domain', () => {
    expect(linkMismatches(anchor('paypal.com', 'https://mail.paypal.com/x'))).toEqual([]);
    expect(linkMismatches(anchor('www.paypal.com', 'https://paypal.com/x'))).toEqual([]);
  });

  // Regression: legitimate marketing wraps every link through an ESP. If
  // those count, the warning fires on most newsletters and stops meaning
  // anything.
  it('skips wrapper and tracker domains on either side', () => {
    expect(linkMismatches(anchor('paypal.com', 'https://sendgrid.net/ls/click?u=1'))).toEqual([]);
    expect(linkMismatches(anchor('bit.ly/xyz', 'https://example-shop.com/x'))).toEqual([]);
  });

  it('ignores non-web schemes and unparseable hrefs', () => {
    expect(linkMismatches(anchor('paypal.com', 'mailto:a@evil.ru'))).toEqual([]);
    expect(linkMismatches(anchor('paypal.com', 'javascript:alert(1)'))).toEqual([]);
    expect(linkMismatches(anchor('paypal.com', 'https://'))).toEqual([]);
    expect(linkMismatches('<a>no href</a>')).toEqual([]);
  });

  it('ignores text that names no domain at all', () => {
    expect(linkMismatches(anchor('Click here', 'https://evil.ru/x'))).toEqual([]);
  });

  it('de-duplicates identical pairs and caps the list at three', () => {
    const same = anchor('paypal.com', 'https://evil.ru/a').repeat(4);
    expect(linkMismatches(same)).toHaveLength(1);
    const many = ['a.com', 'b.com', 'c.com', 'd.com', 'e.com']
      .map((d) => anchor(d, 'https://evil.ru/x'))
      .join('');
    expect(linkMismatches(many)).toHaveLength(3);
  });

  it('is empty for absent or empty html', () => {
    expect(linkMismatches(null)).toEqual([]);
    expect(linkMismatches(undefined)).toEqual([]);
    expect(linkMismatches('')).toEqual([]);
  });

  it('takes only the first mismatching domain named in one anchor', () => {
    const found = linkMismatches(anchor('paypal.com and stripe.com', 'https://evil.ru/x'));
    expect(found).toHaveLength(1);
  });
});

describe('assessLinks', () => {
  it('phrases each mismatch as a caution', () => {
    const reasons = assessLinks(anchor('paypal.com', 'https://evil.ru/x'));
    expect(reasons).toHaveLength(1);
    expect(reasons[0]!.severity).toBe('caution');
    expect(reasons[0]!.text).toContain('paypal.com');
    expect(reasons[0]!.text).toContain('evil.ru');
  });
});

describe('linkDomainsAllMatch', () => {
  it('is true when every link stays on the sender’s own domain', () => {
    const html =
      anchor('Account', 'https://mail.example.net/a') + anchor('Help', 'https://example.net/h');
    expect(linkDomainsAllMatch(html, 'example.net')).toBe(true);
  });

  it('is false when any link points away', () => {
    const html =
      anchor('Account', 'https://example.net/a') + anchor('Track', 'https://tracker.io/t');
    expect(linkDomainsAllMatch(html, 'example.net')).toBe(false);
  });

  it('treats a body with no links, and no body at all, as staying home', () => {
    expect(linkDomainsAllMatch('<p>Just text</p>', 'example.net')).toBe(true);
    expect(linkDomainsAllMatch(null, 'example.net')).toBe(true);
    expect(linkDomainsAllMatch('', 'example.net')).toBe(true);
  });

  it('ignores non-web schemes', () => {
    expect(linkDomainsAllMatch(anchor('Mail us', 'mailto:a@example.net'), 'example.net')).toBe(
      true,
    );
  });

  // Regression: the claim being made is "everything here stays home". With no
  // sender domain there is nothing to compare against, so it must not be
  // asserted — this feeds the top `verified` level.
  it('is false when the sender domain is unknown', () => {
    expect(linkDomainsAllMatch(anchor('x', 'https://example.net/a'), null)).toBe(false);
  });
});

describe('assessPhishing', () => {
  it('is none for an ordinary message', () => {
    const result = assessPhishing({
      fromName: 'Alice',
      fromAddress: 'alice@example.net',
      html: anchor('example.net', 'https://example.net/x'),
    });
    expect(result).toEqual({ level: 'none', reasons: [] });
  });

  it('is caution for a deceptive link alone', () => {
    const result = assessPhishing({
      fromName: 'Alice',
      fromAddress: 'alice@example.net',
      html: anchor('paypal.com', 'https://evil.ru/x'),
    });
    expect(result.level).toBe('caution');
  });

  // Regression: danger must win over caution when both are present, or a
  // spoofed sender is reported with the softer of the two colours.
  it('is danger when the sender name impersonates, even alongside a caution', () => {
    const result = assessPhishing({
      fromName: 'PayPal <service@paypal.com>',
      fromAddress: 'billing@evil.ru',
      html: anchor('stripe.com', 'https://elsewhere.io/x'),
    });
    expect(result.level).toBe('danger');
    expect(result.reasons.length).toBeGreaterThan(1);
  });
});

describe('LINK_WRAPPER_DOMAINS', () => {
  // Regression: entries must be registrable domains. A full URL or a
  // subdomain never matches what `registrableDomain` returns, so it would be
  // a silently dead entry.
  it('holds bare registrable domains only', () => {
    for (const domain of LINK_WRAPPER_DOMAINS) {
      expect(domain, domain).not.toMatch(/^https?:|\/|\s/);
      expect(domain, domain).toBe(domain.toLowerCase());
      expect(domain, domain).toContain('.');
    }
  });
});
