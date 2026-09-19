import { describe, expect, it } from 'vitest';

import { anchorMismatches, linkTarget, urlsInText, LINK_WRAPPER_DOMAINS } from '../src/urls.js';

describe('linkTarget', () => {
  // Regression: every link rule keys on these five fields. Read one wrong and
  // the rule either never fires or fires on ordinary mail.
  it('reads the host, the registrable domain and the three structural tells', () => {
    expect(linkTarget('https://mail.paypal.com/x?y=1')).toMatchObject({
      host: 'mail.paypal.com',
      domain: 'paypal.com',
      isIp: false,
      hasUserinfo: false,
      isPunycode: false,
    });
  });

  // Regression: `https://paypal.com@evil.ru/` goes to evil.ru. A reader's eye
  // stops at the part before the `@`, which is the entire reason it is written.
  it('sees userinfo for what it is: the host is what follows the @', () => {
    const target = linkTarget('https://paypal.com@evil.ru/login');
    expect(target?.host).toBe('evil.ru');
    expect(target?.hasUserinfo).toBe(true);
  });

  // A password-only form of the same trick — `http://:x@evil.ru` has an empty
  // username, so testing the username alone would miss it.
  it('sees userinfo given as a password alone', () => {
    expect(linkTarget('http://:secret@evil.ru/')?.hasUserinfo).toBe(true);
  });

  // Regression: a bare IP has no registrable domain, so a rule that only
  // looked at `domain` would silently skip the oldest phishing host there is.
  it('flags a bare IP and gives it no domain', () => {
    expect(linkTarget('http://203.0.113.5/login')).toMatchObject({
      host: '203.0.113.5',
      domain: null,
      isIp: true,
    });
  });

  it('flags a punycode host', () => {
    expect(linkTarget('https://xn--pypal-4ve.com/')?.isPunycode).toBe(true);
  });

  // Regression: `mailto:` and `#top` are not places to be sent. Treating them
  // as links would charge points for the unsubscribe line of legitimate mail.
  it('returns null for anything that is not http(s), and for nothing at all', () => {
    expect(linkTarget('mailto:alice@example.com')).toBeNull();
    expect(linkTarget('#top')).toBeNull();
    expect(linkTarget('cid:part1.abc')).toBeNull();
    expect(linkTarget('javascript:alert(1)')).toBeNull();
    expect(linkTarget('')).toBeNull();
    expect(linkTarget(null)).toBeNull();
    expect(linkTarget(undefined)).toBeNull();
  });

  // Regression: an unparseable href must be nothing found, never a throw —
  // one malformed link in one message would otherwise take down the scan of
  // every message batched with it.
  it('returns null rather than throwing on an unparseable href', () => {
    expect(linkTarget('http://')).toBeNull();
    expect(linkTarget('https://[')).toBeNull();
  });
});

describe('urlsInText', () => {
  // Regression: plain-text bodies carry their links as bare text. Miss them
  // and the link rules only ever see HTML mail.
  it('finds http(s) URLs written out in prose', () => {
    expect(urlsInText('Please see https://example.com/a and http://other.example.org now')).toEqual(
      ['https://example.com/a', 'http://other.example.org'],
    );
  });

  // Regression: "see https://example.com." ends in a full stop that is not
  // part of the address. Keeping it changes the host on some inputs.
  it('trims sentence punctuation and the brackets prose puts round a URL', () => {
    expect(
      urlsInText(
        'see https://example.com. also (https://two.example.com), and <https://three.example.com>',
      ),
    ).toEqual(['https://example.com', 'https://two.example.com', 'https://three.example.com']);
  });

  it('finds nothing in text with no links, and nothing in no text', () => {
    expect(urlsInText('just words, and an ftp://example.com one')).toEqual([]);
    expect(urlsInText('')).toEqual([]);
    expect(urlsInText(null)).toEqual([]);
  });
});

describe('anchorMismatches', () => {
  // Regression: the core deceptive-link test. Compared at eTLD+1, so a
  // subdomain of the same brand is not a mismatch.
  it('reports text-says-one-domain, href-goes-to-another', () => {
    expect(anchorMismatches([{ href: 'https://evil.ru/login', text: 'paypal.com' }])).toEqual([
      { shown: 'paypal.com', actual: 'evil.ru' },
    ]);
    expect(anchorMismatches([{ href: 'https://mail.paypal.com/x', text: 'paypal.com' }])).toEqual(
      [],
    );
  });

  // Regression: legitimate marketing mail wraps every link through an ESP. A
  // warning that fires on ordinary newsletters is one people learn to ignore.
  it('skips the ESP and shortener wrappers, on either side of the comparison', () => {
    expect(anchorMismatches([{ href: 'https://sendgrid.net/ls/click', text: 'acme.com' }])).toEqual(
      [],
    );
    expect(anchorMismatches([{ href: 'https://evil.ru/x', text: 'bit.ly' }])).toEqual([]);
    expect(LINK_WRAPPER_DOMAINS.has('sendgrid.net')).toBe(true);
  });

  // Regression: a body with fifty copies of the same trick must not produce
  // fifty warnings, and the same pair twice is one finding.
  it('de-duplicates, and stops at three', () => {
    const anchors = [
      { href: 'https://a.ru/1', text: 'paypal.com' },
      { href: 'https://a.ru/2', text: 'paypal.com' },
      { href: 'https://b.ru/1', text: 'hsbc.com' },
      { href: 'https://c.ru/1', text: 'apple.com' },
      { href: 'https://d.ru/1', text: 'amazon.com' },
    ];
    expect(anchorMismatches(anchors)).toEqual([
      { shown: 'paypal.com', actual: 'a.ru' },
      { shown: 'hsbc.com', actual: 'b.ru' },
      { shown: 'apple.com', actual: 'c.ru' },
    ]);
  });

  // An anchor whose text names no domain at all ("Click here") cannot be
  // deceptive about one, and an href with no registrable domain has nothing
  // to compare.
  it('ignores anchors with nothing to compare', () => {
    expect(anchorMismatches([{ href: 'https://evil.ru/x', text: 'Click here' }])).toEqual([]);
    expect(anchorMismatches([{ href: 'http://203.0.113.5/x', text: 'paypal.com' }])).toEqual([]);
    expect(anchorMismatches([{ href: 'mailto:x@y.com', text: 'paypal.com' }])).toEqual([]);
    expect(anchorMismatches([])).toEqual([]);
  });

  // Regression: an anchor naming several domains reports the first real
  // mismatch and moves on, rather than reporting the same anchor twice.
  it('reports one mismatch per anchor', () => {
    expect(
      anchorMismatches([{ href: 'https://evil.ru/x', text: 'paypal.com or hsbc.com' }]),
    ).toHaveLength(1);
  });
});
