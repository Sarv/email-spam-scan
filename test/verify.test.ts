import { describe, expect, it, vi } from 'vitest';

import {
  authVerificationFrom,
  verifyAuthentication,
  type MailauthResult,
  type MailauthSignature,
} from '../src/verify.js';

import {
  fakeResolver,
  hangingResolver,
  signedMessage,
  PASSING_ZONE,
  SELECTOR,
  SENDER_IP,
  SIGNING_DOMAIN,
  UNSIGNED_MESSAGE,
  type FakeZone,
} from './dkim-fixture.js';

/**
 * What this file protects: the ONE place in this package that can be wrong in
 * the direction of safety. Every other rule adds points to a suspicious
 * message; this one can declare a message authenticated. A mapping bug that
 * turned "we could not check" into `pass` puts a green tick on a spoof, and
 * nothing downstream would ever question it — the whole point of a verified
 * verdict is that the reader stops looking.
 */

/** A `mailauth`-shaped result with only the fields a case cares about. */
function result(parts: MailauthResult): MailauthResult {
  return parts;
}

const signature = (parts: MailauthSignature): MailauthSignature => parts;

describe('authVerificationFrom: SPF', () => {
  // Every word RFC 7208 defines, because the mapping table IS the module: a
  // missing row does not fail, it silently answers `unknown` for a verdict the
  // sender's own domain published.
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['pass', 'pass'],
    ['fail', 'fail'],
    ['softfail', 'softfail'],
    ['neutral', 'neutral'],
    ['none', 'none'],
    // Neither of these is a verdict: one is DNS being unavailable, the other
    // is a record too broken to evaluate. Reporting either as `neutral` would
    // claim the domain declined to assert, which it did not.
    ['temperror', 'unknown'],
    ['permerror', 'unknown'],
    ['something-new', 'unknown'],
  ];

  for (const [reported, expected] of cases) {
    it(`reads ${reported} as ${expected}`, () => {
      const verification = authVerificationFrom(
        result({
          spf: { domain: SIGNING_DOMAIN, 'client-ip': SENDER_IP, status: { result: reported } },
        }),
      );
      expect(verification.auth.spf).toBe(expected);
      expect(verification.spfDomain).toBe(SIGNING_DOMAIN);
    });
  }

  // THE regression in this module. Asked with no IP, `mailauth` still answers:
  // it reports `none` for a domain literally named "undefined". Passing that
  // through would tell a reader that a sender publishes no SPF record when
  // nobody ever looked one up — and `none` is a fact about the domain, so it
  // would be believed.
  it('reports unknown when SPF was never evaluated against an address', () => {
    for (const spf of [
      { domain: 'undefined', status: { result: 'none' } },
      false as const,
      undefined,
    ]) {
      const verification = authVerificationFrom(result({ spf }));
      expect(verification.auth.spf).toBe('unknown');
      expect(verification.spfDomain).toBeNull();
    }
  });

  // Regression: this is another package's output, and every field of it is
  // optional. A result that arrives with no status at all must be "we know
  // nothing", not a crash inside the mapper on every message that has one.
  it('reports unknown for a result that carries no status', () => {
    expect(authVerificationFrom(result({ spf: { 'client-ip': SENDER_IP } })).auth.spf).toBe(
      'unknown',
    );
  });

  it('reports no domain when the result named none', () => {
    expect(
      authVerificationFrom(result({ spf: { 'client-ip': SENDER_IP, status: { result: 'pass' } } }))
        .spfDomain,
    ).toBeNull();
  });
});

describe('authVerificationFrom: DKIM', () => {
  const withSignatures = (...signatures: MailauthSignature[]): MailauthResult =>
    result({ dkim: { results: signatures } });

  it('reads a verified signature as a pass', () => {
    expect(
      authVerificationFrom(withSignatures(signature({ status: { result: 'pass' } }))).auth.dkim,
    ).toBe('pass');
  });

  // Regression: a message may carry several signatures — a rotated key, a
  // mailing list that re-signs — and one that verifies is what DKIM asks for.
  // Reading the worst of them would fail every sender who rotates a selector.
  it('reads one verified signature among several as a pass', () => {
    expect(
      authVerificationFrom(
        withSignatures(
          signature({ status: { result: 'neutral', comment: 'no key' } }),
          signature({ status: { result: 'pass' } }),
        ),
      ).auth.dkim,
    ).toBe('pass');
  });

  // The judgement this module makes, stated as a test so a future reader can
  // see it was a decision. `mailauth` calls a body-hash mismatch, an
  // unpublished key and an expired signature `neutral`, and a short key
  // `policy` — following RFC 6376's advice to treat a broken signature as an
  // absent one. This package has one word for "did not verify", and the header
  // reader beside it sees `dkim=fail` for exactly these cases, so the two
  // producers of an AuthStatus must not disagree about the same message.
  for (const reported of ['fail', 'neutral', 'policy']) {
    it(`reads a signature that did not verify (${reported}) as a failure`, () => {
      expect(
        authVerificationFrom(withSignatures(signature({ status: { result: reported } }))).auth.dkim,
      ).toBe('fail');
    });
  }

  // ...and the exception, which is the only one that matters: DNS was
  // unreachable, so nothing was learned. Calling that a failure would score
  // every message that arrived during a resolver outage.
  for (const reported of ['temperror', 'temperr', 'something-new']) {
    it(`reads ${reported} as unknown rather than as a failure`, () => {
      expect(
        authVerificationFrom(withSignatures(signature({ status: { result: reported } }))).auth.dkim,
      ).toBe('unknown');
    });
  }

  // `none` is `mailauth`'s synthetic result for a message that carries no
  // signature at all. Most legitimate mail from small senders is unsigned;
  // reading it as a failure would flag the majority of a personal mailbox.
  it('reads an unsigned message as none, and no results at all as unknown', () => {
    expect(
      authVerificationFrom(withSignatures(signature({ status: { result: 'none' } }))).auth.dkim,
    ).toBe('none');
    expect(authVerificationFrom(result({ dkim: {} })).auth.dkim).toBe('unknown');
    expect(authVerificationFrom(result({})).auth.dkim).toBe('unknown');
  });

  // Regression: `none` and `unknown` together are `unknown`. One signature
  // that could not be checked is enough to make "this message is unsigned"
  // untrue, and reporting `none` there would describe a message nobody read.
  it('reads an unsigned result beside an unreadable one as unknown', () => {
    expect(
      authVerificationFrom(
        withSignatures(
          signature({ status: { result: 'none' } }),
          signature({ status: { result: 'temperror' } }),
        ),
      ).auth.dkim,
    ).toBe('unknown');
  });

  // Regression: the per-signature detail is the only place the difference
  // between "body hash did not verify" and "no key" survives the mapping
  // above, and those are the same verdict with completely different causes.
  it('keeps each signature with the word and the reason mailauth gave', () => {
    expect(
      authVerificationFrom(
        withSignatures(
          signature({
            signingDomain: SIGNING_DOMAIN,
            selector: SELECTOR,
            status: {
              result: 'neutral',
              comment: 'body hash did not verify',
              aligned: SIGNING_DOMAIN,
            },
          }),
        ),
      ).signatures,
    ).toEqual([
      {
        signingDomain: SIGNING_DOMAIN,
        selector: SELECTOR,
        result: 'neutral',
        comment: 'body hash did not verify',
        aligned: true,
      },
    ]);
  });

  // Regression: `mailauth` writes `comment: false` rather than omitting it,
  // and reports an unaligned signature as `aligned: false`. Both would read as
  // present if they were passed through unexamined.
  it('reports an absent comment and an unaligned signature as such', () => {
    expect(
      authVerificationFrom(
        withSignatures(signature({ status: { result: 'pass', comment: false, aligned: false } })),
      ).signatures,
    ).toEqual([
      { signingDomain: null, selector: null, result: 'pass', comment: null, aligned: false },
    ]);
  });

  it('reports a signature with no status at all as unknown', () => {
    expect(authVerificationFrom(withSignatures(signature({}))).signatures[0]?.result).toBe(
      'unknown',
    );
  });
});

describe('authVerificationFrom: DMARC', () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['pass', 'pass'],
    ['fail', 'fail'],
    ['none', 'none'],
    ['temperror', 'unknown'],
    ['permerror', 'unknown'],
  ];

  for (const [reported, expected] of cases) {
    it(`reads ${reported} as ${expected}`, () => {
      expect(
        authVerificationFrom(result({ dmarc: { status: { result: reported } } })).auth.dmarc,
      ).toBe(expected);
    });
  }

  // Regression: `false` is "the check did not run", which is not "the domain
  // publishes no policy". A UI that showed the second would be telling the
  // reader something about the sender that nobody established.
  it('reports a check that did not run as unknown, with no policy', () => {
    const verification = authVerificationFrom(result({ dmarc: false }));
    expect(verification.auth.dmarc).toBe('unknown');
    expect(verification.dmarcPolicy).toBeNull();
    expect(authVerificationFrom(result({})).dmarcPolicy).toBeNull();
  });

  it('reports unknown for a result that carries no status', () => {
    expect(authVerificationFrom(result({ dmarc: { policy: 'none' } })).auth.dmarc).toBe('unknown');
  });

  // Regression: the published policy is what separates a DMARC failure worth
  // acting on from one the sender is still testing. `p=none` and `p=reject`
  // are the same verdict and opposite instructions.
  it('reports the policy the domain published', () => {
    expect(
      authVerificationFrom(result({ dmarc: { policy: 'reject', status: { result: 'fail' } } }))
        .dmarcPolicy,
    ).toBe('reject');
  });
});

describe('authVerificationFrom: the rolled-up verdict', () => {
  it('rolls the three up the same way the header reader does', () => {
    const verification = authVerificationFrom(
      result({
        spf: { domain: SIGNING_DOMAIN, 'client-ip': SENDER_IP, status: { result: 'pass' } },
        dkim: { results: [signature({ status: { result: 'pass' } })] },
        dmarc: { policy: 'reject', status: { result: 'pass' } },
      }),
    );
    expect(verification.auth.overall).toBe('pass');
    expect(verification.completed).toBe(true);
    expect(verification.error).toBeNull();
  });
});

describe('verifyAuthentication', () => {
  // The end-to-end proof, with a real RSA signature over real bytes and a real
  // SPF evaluation — against a fixture zone, so it cannot break because
  // somebody rotated a key in DNS a year from now.
  it('verifies a properly signed message from a permitted address', async () => {
    const verification = await verifyAuthentication(await signedMessage(), {
      ip: SENDER_IP,
      helo: `mx.${SIGNING_DOMAIN}`,
      mailFrom: `ankur@${SIGNING_DOMAIN}`,
      mta: 'mx.test',
      resolver: fakeResolver(PASSING_ZONE),
    });

    expect(verification.completed).toBe(true);
    expect(verification.auth).toEqual({
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      overall: 'pass',
    });
    expect(verification.spfDomain).toBe(SIGNING_DOMAIN);
    expect(verification.dmarcPolicy).toBe('reject');
    expect(verification.signatures).toEqual([
      {
        signingDomain: SIGNING_DOMAIN,
        selector: SELECTOR,
        result: 'pass',
        comment: null,
        aligned: true,
      },
    ]);
  });

  // THE regression DKIM exists for: a body changed in transit. The signature
  // is still the sender's, the key is still published, and the message is no
  // longer the one that was signed.
  it('does not pass a message whose body was changed after signing', async () => {
    const tampered = (await signedMessage()).replace(
      'The numbers are attached.',
      'Wire the money to the account below.',
    );
    const verification = await verifyAuthentication(tampered, {
      ip: SENDER_IP,
      helo: `mx.${SIGNING_DOMAIN}`,
      mailFrom: `ankur@${SIGNING_DOMAIN}`,
      resolver: fakeResolver(PASSING_ZONE),
    });

    expect(verification.auth.dkim).toBe('fail');
    expect(verification.auth.overall).toBe('fail');
    expect(verification.signatures[0]?.comment).toBe('body hash did not verify');
  });

  // Regression: SPF is the check that says the connection was not the sender's
  // to make. An address outside the record must fail even when everything in
  // the message itself is intact.
  it('fails SPF for an address the domain does not permit', async () => {
    const verification = await verifyAuthentication(UNSIGNED_MESSAGE, {
      ip: '203.0.113.9',
      helo: 'relay.invalid',
      mailFrom: `ankur@${SIGNING_DOMAIN}`,
      resolver: fakeResolver(PASSING_ZONE),
    });

    expect(verification.auth.spf).toBe('fail');
    expect(verification.auth.dkim).toBe('none');
  });

  // Regression: without the IP of the connection there is no SPF question to
  // answer, and the library must say so rather than report what `mailauth`
  // computes about an address that does not exist.
  it('leaves SPF unknown when it was given no address', async () => {
    const verification = await verifyAuthentication(UNSIGNED_MESSAGE, {
      mailFrom: `ankur@${SIGNING_DOMAIN}`,
      resolver: fakeResolver(PASSING_ZONE),
    });

    expect(verification.completed).toBe(true);
    expect(verification.auth.spf).toBe('unknown');
    expect(verification.spfDomain).toBeNull();
  });

  // Regression: a domain that publishes nothing is ordinary — most small
  // senders do — and must come back as `none`, not as a failure.
  it('reports none for a domain that publishes no records', async () => {
    const empty: FakeZone = {};
    const verification = await verifyAuthentication(UNSIGNED_MESSAGE, {
      ip: SENDER_IP,
      helo: 'mail.example.net',
      mailFrom: `ankur@${SIGNING_DOMAIN}`,
      resolver: fakeResolver(empty),
    });

    expect(verification.auth).toEqual({
      spf: 'none',
      dkim: 'none',
      dmarc: 'none',
      overall: 'none',
    });
  });

  // THE operational regression. DNS stalls; a scanner that waits on it does
  // not fail, it stops the ingest queue, and nobody notices until the mail has
  // been missing for a day. The deadline turns that into an honest
  // "we did not find out" on one message.
  it('gives up on a resolver that never answers, and asserts nothing', async () => {
    const verification = await verifyAuthentication(UNSIGNED_MESSAGE, {
      ip: SENDER_IP,
      mailFrom: `ankur@${SIGNING_DOMAIN}`,
      resolver: hangingResolver,
      timeoutMs: 25,
    });

    expect(verification.completed).toBe(false);
    expect(verification.error).toMatch(/timed out after 25ms/);
    expect(verification.auth).toEqual({
      spf: 'unknown',
      dkim: 'unknown',
      dmarc: 'unknown',
      overall: 'none',
    });
    expect(verification.signatures).toEqual([]);
    expect(verification.spfDomain).toBeNull();
    expect(verification.dmarcPolicy).toBeNull();
  });
});

describe('verifyAuthentication: when mailauth is not what it should be', () => {
  // Regression: `mailauth` is an OPTIONAL peer dependency, so the common way
  // for this to go wrong is an install that never had it. That is a setup
  // mistake, and it must not look like a DNS outage — an installation that can
  // never verify anything would otherwise report "could not find out" forever
  // and read as a transient problem on every message.
  it('throws an actionable error when the package is not installed', async () => {
    vi.resetModules();
    vi.doMock('mailauth', () => {
      throw new Error("Cannot find package 'mailauth'");
    });

    const { verifyAuthentication: uninstalled } = await import('../src/verify.js');
    await expect(uninstalled(UNSIGNED_MESSAGE)).rejects.toThrow(/npm install mailauth/);

    vi.doUnmock('mailauth');
    vi.resetModules();
  });

  // Regression: a rejection that is not an Error — a library throwing a string
  // — must still produce a readable reason rather than "[object Object]" or a
  // crash inside the error handler.
  it('reports a non-Error rejection as its own text', async () => {
    vi.resetModules();
    vi.doMock('mailauth', () => ({
      authenticate: () => Promise.reject('the resolver exploded'),
    }));

    const { verifyAuthentication: throwing } = await import('../src/verify.js');
    const verification = await throwing(UNSIGNED_MESSAGE);
    expect(verification.completed).toBe(false);
    expect(verification.error).toBe('the resolver exploded');

    vi.doUnmock('mailauth');
    vi.resetModules();
  });
});
