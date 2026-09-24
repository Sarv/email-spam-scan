import { describe, expect, it } from 'vitest';

import { assessContentSignals, bodyContent, longestShoutRun } from '../src/content/rules.js';
import { SPAM_PHRASE_GROUPS } from '../src/data/spam-phrases.js';
import { SPAM_THRESHOLD } from '../src/verdict.js';

const idsOf = (input: Parameters<typeof assessContentSignals>[0]): string[] =>
  assessContentSignals(input).reasons.map((reason) => reason.id);

describe('bodyContent', () => {
  it('joins the subject to the body, because the subject is the sender´s words too', () => {
    expect(bodyContent({ subject: 'Invoice 42', text: 'Attached.' }).words).toBe(
      'Invoice 42\nAttached.',
    );
  });

  // Regression: multipart/alternative sends the same sentence twice. Scoring
  // both halves doubles every vocabulary hit for no reason but the MIME shape.
  it('scores the HTML body instead of the plain-text part, not both', () => {
    const content = bodyContent({
      text: 'verify your password',
      html: '<p>verify your password</p>',
    });
    expect(content.words).toBe('verify your password');
  });

  it('falls back to the plain-text part when the HTML has no words', () => {
    expect(bodyContent({ text: 'hello there', html: '<style>p{color:red}</style>' }).words).toBe(
      'hello there',
    );
  });

  // Regression: the whole premise of the stage. A person who forwards a phish
  // to their IT desk must not be scored as the phisher.
  it('drops the quoted history and the links inside it', () => {
    const content = bodyContent({
      text: 'Is this real?\n\nOn Tue, 1 Jan 2030, Bank <b@bank.example> wrote:\n> Verify at http://10.0.0.1/login',
    });
    expect(content.words).toBe('Is this real?');
    expect(content.anchors).toEqual([]);
  });

  it('drops anchors inside an HTML quote but keeps the sender´s own', () => {
    const content = bodyContent({
      html: '<p>See <a href="https://ours.example/a">this</a></p><blockquote><a href="http://10.0.0.1/x">click</a></blockquote>',
    });
    expect(content.anchors).toEqual([{ href: 'https://ours.example/a', text: 'this' }]);
  });

  // Regression: a plain-text-only message still has links, as bare URLs. If
  // they are not collected, none of the link rules can ever fire on one.
  it('collects bare URLs from plain text when there is no HTML', () => {
    expect(bodyContent({ text: 'go to https://example.com/x now' }).anchors).toEqual([
      { href: 'https://example.com/x', text: '' },
    ]);
  });

  it('is empty for an empty message', () => {
    expect(bodyContent({})).toEqual({ words: '', anchors: [], hiddenText: '' });
  });
});

describe('longestShoutRun', () => {
  it('counts consecutive shouted words, resetting on an ordinary one', () => {
    expect(longestShoutRun('BUY NOW while stocks LAST')).toBe(2);
    expect(longestShoutRun('ACT NOW LIMITED TIME OFFER')).toBe(5);
    expect(longestShoutRun('quiet as anything')).toBe(0);
  });

  // Regression: a two-letter acronym is not shouting, and one three-letter one
  // in a sentence is not either. Only a run of four is.
  it('ignores short words and single acronyms', () => {
    expect(longestShoutRun('the HR and IT teams')).toBe(0);
    expect(longestShoutRun('please ask the CEO about it')).toBe(1);
  });

  // Regression: Chinese, Arabic and Hebrew have no case, so `x ===
  // x.toUpperCase()` is true for every word. Without the lowercase test, every
  // message written in them would be scored as shouting.
  it('does not count scripts that have no case as shouted', () => {
    expect(longestShoutRun('这是一封普通的邮件 请查收 谢谢 再见')).toBe(0);
    expect(longestShoutRun('שלום וברכה תודה רבה')).toBe(0);
  });
});

describe('assessContentSignals', () => {
  it('finds nothing in an ordinary message', () => {
    const assessment = assessContentSignals({
      subject: 'Q3 invoice',
      text: 'Hi Sam,\n\nThe invoice is attached. Payment is due on Friday.\n\nThanks,\nAlex',
      html: '<p>Hi Sam,</p><p>The invoice is attached. Payment is due on Friday.</p>',
    });
    expect(assessment.reasons).toEqual([]);
    expect(assessment.score).toBe(0);
    expect(assessment.isSpam).toBe(false);
    expect(assessment.suspicious).toBe(false);
  });

  it('scores spam vocabulary once per scam, with the labels in the detail', () => {
    const assessment = assessContentSignals({
      subject: 'verify your account',
      text: 'confirm your password',
    });
    expect(assessment.reasons).toHaveLength(1);
    expect(assessment.reasons[0]?.id).toBe('content-spam-vocabulary');
    expect(assessment.reasons[0]?.detail).toMatch(/credential/i);
  });

  it('scores a run of capitals, and runs of exclamation marks when there is no run of capitals', () => {
    expect(idsOf({ subject: 'ACT NOW LIMITED TIME OFFER' })).toContain('content-shouting');
    expect(idsOf({ text: 'please read this!!!' })).toEqual(['content-shouting']);
    // Only ever one shouting reason, however many ways the message shouts.
    expect(
      idsOf({ subject: 'ACT NOW LIMITED TIME OFFER!!!' }).filter((id) => id === 'content-shouting'),
    ).toHaveLength(1);
  });

  // Regression: a preheader or a tracking pixel's alt text is a handful of
  // hidden characters and entirely legitimate. Charging for those would score
  // most marketing mail ever sent.
  it('scores hidden text only when a whole paragraph is hidden', () => {
    const short = '<p>Hello</p><div style="display:none">Preheader</div>';
    expect(idsOf({ html: short })).toEqual([]);
    const long = `<p>Hello</p><div style="display:none">${'word '.repeat(40)}</div>`;
    const reason = assessContentSignals({ html: long }).reasons.find(
      (r) => r.id === 'content-hidden-text',
    );
    expect(reason?.points).toBe(2);
  });

  it('scores a link whose text shows one site and whose href goes to another', () => {
    const assessment = assessContentSignals({
      html: '<a href="https://evil.example/login">https://bank.example/login</a>',
    });
    const reason = assessment.reasons.find((r) => r.id === 'link-display-mismatch');
    expect(reason?.points).toBe(2);
    expect(reason?.detail).toContain('bank.example');
    expect(reason?.detail).toContain('evil.example');
  });

  // Regression: the Adobe Sign lure. "Sarv.com Engagement Letter" pointing at
  // kuaiyudh.top is a link dressed as the READER'S OWN organisation, worth
  // twice an anonymous mismatch; one borrowing a protected brand's domain sits
  // between. Without the recipient list the same link is an ordinary mismatch.
  it('weighs a deceptive link by whose name it borrowed: the reader’s domain, a brand, anyone', () => {
    const html = [
      '<a href="https://kuaiyudh.top/v/#reader">Sarv.com Engagement Letter - for signature</a>',
      '<a href="https://evil.example/x">https://paypal.com/login</a>',
      '<a href="https://evil.example/y">https://bank.example/login</a>',
    ].join('');
    const mismatches = (recipientDomains?: readonly (string | null | undefined)[]) =>
      assessContentSignals({ html, recipientDomains })
        .reasons.filter((r) => r.id === 'link-display-mismatch')
        .map((r) => [r.points, r.detail] as const);
    expect(mismatches(['rc@sarv.com', 'mail.sarv.com', null, undefined, ''])).toEqual([
      [4, expect.stringContaining('your own domain sarv.com')],
      [3, expect.stringContaining('PayPal (paypal.com)')],
      [2, expect.stringContaining('bank.example')],
    ]);
    expect(mismatches()[0]?.[0]).toBe(2);
    expect(mismatches([])[0]?.[0]).toBe(2);
  });

  it('scores userinfo, bare-IP and punycode targets once each', () => {
    const ids = idsOf({
      html: [
        '<a href="https://bank.example@evil.example/">one</a>',
        '<a href="http://203.0.113.9/login">two</a>',
        '<a href="http://203.0.113.10/login">three</a>',
        '<a href="https://xn--80ak6aa92e.example/">four</a>',
      ].join(''),
    });
    expect(ids.filter((id) => id === 'link-userinfo')).toHaveLength(1);
    expect(ids.filter((id) => id === 'link-bare-ip')).toHaveLength(1);
    expect(ids.filter((id) => id === 'link-punycode')).toHaveLength(1);
  });

  // Regression: THE safety property of the interpretive half of the stage.
  // A word list is a guess about what prose means, and a guess must never be
  // able to file mail on its own — the header stage has to have found
  // something too. Matching every group in the corpus and shouting the whole
  // way through is the worst an interpretation can do, and it stops short.
  it('cannot file mail on vocabulary and shouting alone, however much matched', () => {
    const shouted = SPAM_PHRASE_GROUPS.map((group) => group.phrases[0]?.toUpperCase()).join(' ');
    const assessment = assessContentSignals({ subject: 'ACT NOW!!!', text: shouted });
    expect(assessment.reasons.map((reason) => reason.id).sort()).toEqual([
      'content-shouting',
      'content-spam-vocabulary',
    ]);
    expect(assessment.score).toBeLessThan(SPAM_THRESHOLD);
    expect(assessment.isSpam).toBe(false);
  });

  // The structural half is deliberately NOT capped: four separate deceptions
  // about where a link goes are four facts, not one stronger opinion, and a
  // message carrying all of them is spam whatever its headers said. What is
  // pinned here is that no single rule can convict alone.
  it('lets structural deceptions accumulate, but no one rule is a veto', () => {
    const worst = assessContentSignals({
      subject: 'ACT NOW LIMITED TIME OFFER!!!',
      html: [
        '<p>verify your password. you have won. no prescription needed. work from home.</p>',
        `<div style="display:none">${'hidden '.repeat(40)}</div>`,
        '<a href="https://evil.example@10.0.0.1/">https://bank.example/</a>',
        '<a href="https://xn--80ak6aa92e.example/">https://paypal.example/</a>',
      ].join(''),
    });
    expect(worst.isSpam).toBe(true);
    for (const reason of worst.reasons) {
      expect(reason.points, reason.id).toBeLessThan(SPAM_THRESHOLD);
    }
    // The heaviest single rule in the stage — a link dressed as the reader's
    // own domain — is still short of the line on its own. A vendor newsletter
    // wrapping a link to the reader's site through an unlisted tracking host
    // must not be filed on that alone.
    const heaviest = assessContentSignals({
      html: '<a href="https://evil.example/x">https://reader.example/x</a>',
      recipientDomains: ['reader.example'],
    });
    expect(heaviest.score).toBe(4);
    expect(heaviest.suspicious).toBe(true);
    expect(heaviest.isSpam).toBe(false);
  });
});

describe('assessContentSignals — a caller-supplied brand list', () => {
  const ACME = { id: 'acme', name: 'Acme Corp', phrases: ['acme corp'], domains: ['acme.example'] };
  // The 3-point tier is for a link whose text names a PROTECTED brand's
  // domain; a brand the caller protects is one.
  it('weighs a link dressed as a brand only the caller protects at 3', () => {
    const html = '<a href="https://evil.example/x">https://acme.example/login</a>';
    const points = (brands?: readonly (typeof ACME)[]) =>
      assessContentSignals({ html, brands }).reasons.find((r) => r.id === 'link-display-mismatch')
        ?.points;
    expect(points()).toBe(2);
    expect(points([ACME])).toBe(3);
  });
});
