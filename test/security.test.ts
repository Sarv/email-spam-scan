import { describe, expect, it } from 'vitest';

import {
  assessEmailSecurity,
  linkRuleKey,
  parseAuthStatus,
  worstLevel,
  EMPTY_RULES,
  LEVEL_RANK,
  type LinkRuleSets,
  type SecurityLevel,
} from '../src/security.js';
import type { AuthStatus } from '../src/verdict.js';

const auth = (over: Partial<AuthStatus> = {}): AuthStatus => ({
  spf: 'pass',
  dkim: 'pass',
  dmarc: 'pass',
  overall: 'pass',
  ...over,
});

const anchor = (text: string, href: string): string => `<a href="${href}">${text}</a>`;
const SENDER = { fromName: 'Alice Example', fromAddress: 'alice@example.net' };

const levelOf = (over: Parameters<typeof assessEmailSecurity>[0] = {}): SecurityLevel =>
  assessEmailSecurity({ ...SENDER, ...over }).level;

const rules = (trusted: string[] = [], blocked: string[] = []): LinkRuleSets => ({
  trusted: new Set(trusted),
  blocked: new Set(blocked),
});

describe('parseAuthStatus', () => {
  it('reads a stored verdict', () => {
    expect(
      parseAuthStatus('{"spf":"pass","dkim":"fail","dmarc":"pass","overall":"partial"}'),
    ).toEqual({
      spf: 'pass',
      dkim: 'fail',
      dmarc: 'pass',
      overall: 'partial',
    });
  });

  // Regression: an unreadable stored value must mean "no verdict", never a
  // throw — a corrupt column would otherwise take the whole message view down.
  it('is null for anything unreadable, and defaults missing fields', () => {
    expect(parseAuthStatus('not json')).toBeNull();
    expect(parseAuthStatus('null')).toBeNull();
    expect(parseAuthStatus('"a string"')).toBeNull();
    expect(parseAuthStatus('')).toBeNull();
    expect(parseAuthStatus(null)).toBeNull();
    expect(parseAuthStatus(undefined)).toBeNull();
    expect(parseAuthStatus('{}')).toEqual({
      spf: 'unknown',
      dkim: 'unknown',
      dmarc: 'unknown',
      overall: 'none',
    });
  });
});

describe('assessEmailSecurity — the level', () => {
  it('is verified when DMARC passes and every link stays on the sender’s domain', () => {
    expect(levelOf({ auth: auth(), html: anchor('Account', 'https://example.net/a') })).toBe(
      'verified',
    );
    expect(levelOf({ auth: auth(), html: '<p>no links</p>' })).toBe('verified');
  });

  // Regression: a newsletter that passes DMARC but links to its CDN is real,
  // not "everything in this mail is the sender". Calling that verified
  // devalues the top level on exactly the mail people get most of.
  it('is authenticated, not verified, when links point off-domain', () => {
    expect(levelOf({ auth: auth(), html: anchor('Track', 'https://cdn-tracker.io/t') })).toBe(
      'authenticated',
    );
  });

  it('is unverified when no authentication verdict was recorded', () => {
    expect(levelOf({})).toBe('unverified');
    expect(
      levelOf({ auth: auth({ spf: 'none', dkim: 'none', dmarc: 'none', overall: 'none' }) }),
    ).toBe('unverified');
  });

  it('accepts SPF+DKIM both passing as authentication when DMARC is silent', () => {
    expect(levelOf({ auth: auth({ dmarc: 'none' }), html: '<p>x</p>' })).toBe('verified');
  });

  it('is danger on a DMARC failure', () => {
    expect(levelOf({ auth: auth({ dmarc: 'fail' }) })).toBe('danger');
  });

  // Regression: THE false positive this model exists to avoid. A forwarder or
  // list breaks one input while DMARC still passes; treating that as failure
  // put red shields on legitimate bank and travel mail, which teaches people
  // to ignore red.
  it('is NOT danger when a single input failed but DMARC passed', () => {
    expect(levelOf({ auth: auth({ dkim: 'fail' }), html: '<p>x</p>' })).toBe('verified');
    expect(levelOf({ auth: auth({ spf: 'fail' }), html: '<p>x</p>' })).toBe('verified');
  });

  it('falls back to both-inputs-failed only with no DMARC verdict', () => {
    expect(levelOf({ auth: auth({ spf: 'fail', dkim: 'fail', dmarc: 'none' }) })).toBe('danger');
  });

  it('is danger when the display name impersonates another domain', () => {
    expect(
      assessEmailSecurity({
        fromName: 'PayPal <service@paypal.com>',
        fromAddress: 'billing@evil.ru',
        auth: auth(),
      }).level,
    ).toBe('danger');
  });

  it('is caution for a soft SPF result', () => {
    expect(levelOf({ auth: auth({ spf: 'softfail' }) })).toBe('caution');
    expect(levelOf({ auth: auth({ spf: 'neutral' }) })).toBe('caution');
  });

  it('is caution for one failed input with no DMARC verdict to settle it', () => {
    expect(levelOf({ auth: auth({ spf: 'fail', dmarc: 'none' }) })).toBe('caution');
    expect(levelOf({ auth: auth({ dkim: 'fail', dmarc: 'none' }) })).toBe('caution');
  });

  it('is caution for an unvetted deceptive link', () => {
    expect(levelOf({ auth: auth(), html: anchor('paypal.com', 'https://evil.ru/x') })).toBe(
      'caution',
    );
  });

  // Regression: spam is unwanted, not impersonation. The reasons that make
  // spam DANGEROUS already score danger above on their own; promoting every
  // spam verdict to danger would flatten the distinction the levels exist for.
  it('is caution — not danger — when the filter scored it spam', () => {
    expect(levelOf({ auth: auth(), spamScore: 7 })).toBe('caution');
  });

  it('does not escalate for a merely suspicious score', () => {
    expect(levelOf({ auth: auth(), spamScore: 3, html: '<p>x</p>' })).toBe('verified');
  });
});

describe('assessEmailSecurity — trust and block rules', () => {
  const html = anchor('paypal.com', 'https://evil.ru/x');
  const key = linkRuleKey('example.net', 'paypal.com', 'evil.ru');

  it('a trusted pair stops being a caution', () => {
    const result = assessEmailSecurity({ ...SENDER, auth: auth(), html, rules: rules([key]) });
    expect(result.untrustedLinks).toEqual([]);
    expect(result.level).toBe('authenticated');
    expect(result.checks.find((c) => c.id === 'links')?.detail).toContain('1 pair you trust');
  });

  it('a blocked pair forces danger', () => {
    const result = assessEmailSecurity({ ...SENDER, auth: auth(), html, rules: rules([], [key]) });
    expect(result.level).toBe('danger');
    expect(result.blockedLinks).toHaveLength(1);
    expect(result.checks.find((c) => c.id === 'links')?.status).toBe('fail');
  });

  // Regression: a rule trusted for one sender must not license the same
  // redirect for every other sender — a compromised known account is the
  // usual way phishing arrives from a familiar name.
  it('a rule is scoped to the sender domain', () => {
    const result = assessEmailSecurity({
      fromName: 'Mallory',
      fromAddress: 'm@other.com',
      auth: auth(),
      html,
      rules: rules([key]),
    });
    expect(result.level).toBe('caution');
    expect(result.untrustedLinks).toHaveLength(1);
  });

  it('defaults to no rules', () => {
    expect(assessEmailSecurity({ ...SENDER, auth: auth(), html }).untrustedLinks).toHaveLength(1);
    expect(EMPTY_RULES.trusted.size + EMPTY_RULES.blocked.size).toBe(0);
  });

  it('counts additional untrusted links in the summary', () => {
    const two =
      anchor('paypal.com', 'https://evil.ru/x') + anchor('stripe.com', 'https://bad.io/y');
    const detail = assessEmailSecurity({ ...SENDER, auth: auth(), html: two }).checks.find(
      (c) => c.id === 'links',
    )?.detail;
    expect(detail).toContain('+1 more');
  });

  it('pluralises the trusted-pair count', () => {
    const two =
      anchor('paypal.com', 'https://evil.ru/x') + anchor('stripe.com', 'https://bad.io/y');
    const keys = [
      linkRuleKey('example.net', 'paypal.com', 'evil.ru'),
      linkRuleKey('example.net', 'stripe.com', 'bad.io'),
    ];
    const detail = assessEmailSecurity({
      ...SENDER,
      auth: auth(),
      html: two,
      rules: rules(keys),
    }).checks.find((c) => c.id === 'links')?.detail;
    expect(detail).toContain('2 pairs you trust');
  });

  it('lower-cases the rule key so a stored rule matches regardless of case', () => {
    expect(linkRuleKey('Example.NET', 'PayPal.com', 'Evil.RU')).toBe(
      'example.net|paypal.com|evil.ru',
    );
  });
});

describe('assessEmailSecurity — the checks it explains itself with', () => {
  it('reports each authentication result, including the absent one', () => {
    const checks = assessEmailSecurity({
      ...SENDER,
      auth: auth({ spf: 'fail', dmarc: 'none' }),
    }).checks;
    expect(checks.find((c) => c.id === 'spf')?.status).toBe('fail');
    expect(checks.find((c) => c.id === 'dkim')?.status).toBe('pass');
    expect(checks.find((c) => c.id === 'dmarc')?.status).toBe('unknown');
  });

  it('reports a soft SPF as a warning', () => {
    const spf = assessEmailSecurity({ ...SENDER, auth: auth({ spf: 'softfail' }) }).checks.find(
      (c) => c.id === 'spf',
    );
    expect(spf?.status).toBe('warn');
    expect(spf?.detail).toContain('softfail');
  });

  // Regression: the broken-signature-under-passing-DMARC case must stay
  // VISIBLE as a warning rather than vanish, so a reader can still see that
  // something was rewritten in transit.
  it('downgrades a broken DKIM under a passing DMARC to a warning, and says why', () => {
    const dkim = assessEmailSecurity({ ...SENDER, auth: auth({ dkim: 'fail' }) }).checks.find(
      (c) => c.id === 'dkim',
    );
    expect(dkim?.status).toBe('warn');
    expect(dkim?.detail).toContain('DMARC still passed');
  });

  it('reports the sender-name check both ways', () => {
    expect(assessEmailSecurity({ ...SENDER }).checks.find((c) => c.id === 'sender')?.status).toBe(
      'pass',
    );
    const spoofed = assessEmailSecurity({
      fromName: 'PayPal <service@paypal.com>',
      fromAddress: 'billing@evil.ru',
    }).checks.find((c) => c.id === 'sender');
    expect(spoofed?.status).toBe('fail');
    expect(spoofed?.detail).toContain('paypal.com');
  });

  it('reports each spam verdict, with the reasons behind it', () => {
    const reasons = '[{"id":"auth-failed","points":3,"detail":"DMARC failed"}]';
    const spam = assessEmailSecurity({ ...SENDER, spamScore: 7, spamReasons: reasons }).checks.find(
      (c) => c.id === 'spam',
    );
    expect(spam?.status).toBe('fail');
    expect(spam?.detail).toContain('DMARC failed');

    expect(
      assessEmailSecurity({ ...SENDER, spamScore: 3 }).checks.find((c) => c.id === 'spam')?.status,
    ).toBe('warn');
    expect(
      assessEmailSecurity({ ...SENDER, spamScore: 0 }).checks.find((c) => c.id === 'spam')?.status,
    ).toBe('pass');
  });

  it('reports a clean score that still carried reasons', () => {
    const reasons = '[{"id":"missing-date","points":1,"detail":"No Date header"}]';
    const detail = assessEmailSecurity({
      ...SENDER,
      spamScore: 1,
      spamReasons: reasons,
    }).checks.find((c) => c.id === 'spam')?.detail;
    expect(detail).toContain('No Date header');
  });

  // Regression: never scored and scored zero are different facts. Collapsing
  // them shows a green tick on mail nothing ever looked at.
  it('distinguishes "never scored" from "scored clean"', () => {
    const never = assessEmailSecurity({ ...SENDER }).checks.find((c) => c.id === 'spam');
    expect(never?.status).toBe('unknown');
    expect(assessEmailSecurity({ ...SENDER }).spam.verdict).toBeNull();
    const nan = assessEmailSecurity({ ...SENDER, spamScore: Number.NaN }).spam;
    expect(nan.score).toBeNull();
    expect(nan.verdict).toBeNull();
  });
});

describe('assessEmailSecurity — input shapes', () => {
  it('accepts the auth verdict as an object or as stored JSON', () => {
    const asJson = assessEmailSecurity({
      ...SENDER,
      auth: JSON.stringify(auth()),
      html: '<p>x</p>',
    });
    const asObject = assessEmailSecurity({ ...SENDER, auth: auth(), html: '<p>x</p>' });
    expect(asJson.level).toBe(asObject.level);
    expect(asJson.level).toBe('verified');
  });

  it('accepts spam reasons as an array or as stored JSON', () => {
    const array = assessEmailSecurity({
      ...SENDER,
      spamScore: 7,
      spamReasons: [{ id: 'auth-failed', points: 3, detail: 'DMARC failed' }],
    });
    expect(array.spam.reasons).toHaveLength(1);
    expect(
      assessEmailSecurity({ ...SENDER, spamScore: 7, spamReasons: 'corrupt' }).spam.reasons,
    ).toEqual([]);
  });

  // Regression: with an unusable From address there is no sender domain to
  // scope a trust rule to. The key must still be built (against an empty
  // domain) rather than crashing, and the link must stay untrusted — a rule
  // saved for a real sender must not accidentally match one with no domain.
  it('still evaluates links when the sender address yields no domain', () => {
    const result = assessEmailSecurity({
      fromAddress: 'nonsense',
      auth: auth(),
      html: anchor('paypal.com', 'https://evil.ru/x'),
      rules: rules([linkRuleKey('example.net', 'paypal.com', 'evil.ru')]),
    });
    expect(result.senderDomain).toBeNull();
    expect(result.untrustedLinks).toHaveLength(1);
    expect(result.level).toBe('caution');
  });

  it('reports the sender domain, or null when the address is unusable', () => {
    expect(assessEmailSecurity({ ...SENDER }).senderDomain).toBe('example.net');
    expect(assessEmailSecurity({ fromAddress: 'nonsense' }).senderDomain).toBeNull();
    expect(assessEmailSecurity({}).senderDomain).toBeNull();
  });
});

describe('worstLevel', () => {
  // Regression: a thread banner must escalate to its worst message. Returning
  // the first or the last mislabels a clean opener when message 14 is a spoof.
  it('returns the most dangerous level present', () => {
    expect(worstLevel(['verified', 'danger', 'authenticated'])).toBe('danger');
    expect(worstLevel(['verified', 'unverified'])).toBe('unverified');
    expect(worstLevel(['verified'])).toBe('verified');
    expect(worstLevel([])).toBe('verified');
  });

  it('ranks the levels from safest to most dangerous', () => {
    expect(LEVEL_RANK.verified).toBeLessThan(LEVEL_RANK.authenticated);
    expect(LEVEL_RANK.authenticated).toBeLessThan(LEVEL_RANK.unverified);
    expect(LEVEL_RANK.unverified).toBeLessThan(LEVEL_RANK.caution);
    expect(LEVEL_RANK.caution).toBeLessThan(LEVEL_RANK.danger);
  });
});
