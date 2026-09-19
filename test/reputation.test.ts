import { describe, expect, it, vi } from 'vitest';

import {
  assessReputation,
  blocklistQueryName,
  checkReputation,
  normalizeQueryDomain,
  readBlocklistCodes,
  reverseIpLabel,
  BLOCKLISTS,
  SPAMCOP,
  SPAMHAUS_DBL,
  SPAMHAUS_ZEN,
  type Blocklist,
  type DnsQuery,
  type ReputationResult,
} from '../src/reputation.js';

/** A public unicast address, which is the only kind this stage will ask about. */
const PUBLIC_IP = '93.184.216.34';
const PUBLIC_IP_REVERSED = '34.216.184.93';

/** A resolver that answers from a table and remembers what it was asked. */
function fakeDns(answers: Readonly<Record<string, string[] | Error>>): {
  query: DnsQuery;
  asked: string[];
} {
  const asked: string[] = [];
  const query: DnsQuery = (name, recordType) => {
    asked.push(`${recordType} ${name}`);
    const answer = answers[`${recordType} ${name}`];
    if (answer instanceof Error) return Promise.reject(answer);
    return Promise.resolve(answer ?? []);
  };
  return { query, asked };
}

const ZEN_QUERY = `A ${PUBLIC_IP_REVERSED}.zen.spamhaus.org`;
const SPAMCOP_QUERY = `A ${PUBLIC_IP_REVERSED}.bl.spamcop.net`;
const DBL_QUERY = 'A example.com.dbl.spamhaus.org';

describe('reverseIpLabel', () => {
  // The whole query is this string. Getting the order wrong asks an operator
  // about a completely different address and believes the answer.
  it('reverses the octets of an IPv4 address', () => {
    expect(reverseIpLabel(PUBLIC_IP)).toBe(PUBLIC_IP_REVERSED);
    expect(reverseIpLabel(' 8.8.4.4 ')).toBe('4.4.8.8');
  });

  // IPv6 is queried as 32 separate nibbles, fully expanded — the compressed
  // form a header carries is not a valid query and returns NXDOMAIN, which
  // would read as "not listed" on every v6 sender there is.
  it('expands an IPv6 address into reversed nibbles', () => {
    expect(reverseIpLabel('2606:2800:220:1:248:1893:25c8:1946')).toBe(
      '6.4.9.1.8.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2',
    );
  });

  // An IPv4-mapped address is an IPv4 address. Querying it as v6 nibbles asks
  // a zone that does not exist for it.
  it('treats an IPv4-mapped address as IPv4', () => {
    expect(reverseIpLabel('::ffff:93.184.216.34')).toBe(PUBLIC_IP_REVERSED);
  });

  // Regression, and the one that matters for privacy as much as correctness:
  // no operator has anything to say about an internal address, and asking
  // publishes your network layout to them one query at a time.
  it('refuses every address a blocklist cannot answer about', () => {
    for (const unusable of [
      '10.0.0.4',
      '192.168.1.1',
      '127.0.0.1',
      '100.64.0.1',
      '169.254.1.1',
      '203.0.113.9',
      'fe80::1',
      'not-an-address',
      '',
      null,
      undefined,
    ]) {
      expect(reverseIpLabel(unusable)).toBeNull();
    }
  });
});

describe('normalizeQueryDomain', () => {
  it('lowercases and drops the root dot', () => {
    expect(normalizeQueryDomain('Example.COM.')).toBe('example.com');
    expect(normalizeQueryDomain('  mail.sub.example.co.uk ')).toBe('mail.sub.example.co.uk');
  });

  // Regression: anything that is not a hostname must never become a query. A
  // whole address or a URL sent to a blocklist zone leaks the recipient's mail
  // to the operator and answers nothing.
  it('refuses anything that is not a dotted hostname', () => {
    for (const unusable of [
      'localhost',
      'user@example.com',
      'https://example.com/path',
      'two words.com',
      'example..com',
      '-example.com',
      '',
      '   ',
      `${'a'.repeat(250)}.example.com`,
      null,
      undefined,
    ]) {
      expect(normalizeQueryDomain(unusable)).toBeNull();
    }
  });
});

describe('blocklistQueryName', () => {
  it('builds the name each kind of zone is asked under', () => {
    expect(blocklistQueryName(PUBLIC_IP, SPAMHAUS_ZEN)).toBe(
      `${PUBLIC_IP_REVERSED}.zen.spamhaus.org`,
    );
    expect(blocklistQueryName('Example.com', SPAMHAUS_DBL)).toBe('example.com.dbl.spamhaus.org');
  });

  it('has no name for a target the zone cannot be asked about', () => {
    expect(blocklistQueryName('10.0.0.4', SPAMHAUS_ZEN)).toBeNull();
    expect(blocklistQueryName('not a domain', SPAMHAUS_DBL)).toBeNull();
    expect(blocklistQueryName(null, SPAMHAUS_ZEN)).toBeNull();
  });
});

describe('readBlocklistCodes', () => {
  it('reads a described code as its own meaning and its own points', () => {
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['127.0.0.2'])).toEqual({
      listings: ['127.0.0.2'],
      meanings: ['SBL: a known source of spam'],
      points: 4,
      error: null,
    });
  });

  // Regression: operators add codes. An unrecognised one is still a listing,
  // and scoring it zero would silently ignore whatever category a list
  // published most recently.
  it('scores an unrecognised listing code at the zone default', () => {
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['127.0.0.42'])).toEqual({
      listings: ['127.0.0.42'],
      meanings: [],
      points: 3,
      error: null,
    });
  });

  // A zone with no code table at all is a legitimate way to configure one.
  it('scores every listing at the zone default when the zone describes none', () => {
    const plain: Blocklist = { name: 'plain', zone: 'bl.example.org', kind: 'ip', points: 2 };
    expect(readBlocklistCodes(plain, ['127.0.0.2'])).toMatchObject({ points: 2, meanings: [] });
  });

  // Several codes is one listing seen from several angles — the strongest one
  // is what it is worth, and every meaning is reported.
  it('takes the highest points and keeps every meaning', () => {
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['127.0.0.10', '127.0.0.2'])).toEqual({
      listings: ['127.0.0.10', '127.0.0.2'],
      meanings: [
        'PBL: an address that should not deliver mail directly',
        'SBL: a known source of spam',
      ],
      points: 4,
      error: null,
    });
  });

  // THE regression in this file. Spamhaus answers a query that arrived via a
  // public resolver with 127.255.255.254, and every list in the family uses
  // 127.255.255.0/24 the same way. A boolean reading of "did it return an A
  // record" puts EVERY sender on a blocklist the moment a resolver is
  // misconfigured — which is exactly how a mail server starts filing all of
  // its mail as spam at once.
  it('reads an operator error as an error and never as a listing', () => {
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['127.255.255.254'])).toEqual({
      listings: [],
      meanings: [],
      points: 0,
      error: 'the query arrived via a public or open resolver, which the operator refuses',
    });
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['127.255.255.252']).error).toMatch(/malformed/);
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['127.255.255.255']).error).toMatch(/volume limit/);
  });

  it('reports an undescribed operator code as an operator error', () => {
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['127.255.255.7']).error).toBe(
      'the zone answered 127.255.255.7, an operator error code',
    );
  });

  // Regression: a wildcard resolver, a captive portal or a hijacked response
  // answers with a real address. No blocklist publishes a listing outside
  // 127/8, so anything else is not evidence about the sender.
  it('refuses to score an answer from outside the loopback block', () => {
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['10.0.0.1'])).toMatchObject({
      listings: [],
      points: 0,
      error: 'the zone answered 10.0.0.1, which is not a listing',
    });
  });

  // 127.0.0.1 is what a few operators answer to a query they could not parse,
  // and what an NXDOMAIN-rewriting resolver sometimes substitutes. No list
  // publishes a listing there.
  it('does not treat a loopback answer of 127.0.0.1 as a listing', () => {
    expect(readBlocklistCodes(SPAMCOP, ['127.0.0.1']).error).toMatch(/not a listing/);
  });

  it('reads no records as not listed, with no error', () => {
    expect(readBlocklistCodes(SPAMHAUS_ZEN, [])).toEqual({
      listings: [],
      meanings: [],
      points: 0,
      error: null,
    });
  });
});

describe('the published catalogue', () => {
  // The catalogue is data, and a typo in it is invisible: a code in the
  // operator-error range would be dropped rather than scored, and a duplicate
  // name would make two zones indistinguishable in a stored reason.
  it('describes only scoreable codes, under unique names', () => {
    const names = BLOCKLISTS.map((blocklist) => blocklist.name);
    expect(new Set(names).size).toBe(names.length);

    for (const blocklist of BLOCKLISTS) {
      expect(blocklist.points).toBeGreaterThan(0);
      for (const [code, described] of Object.entries(blocklist.codes ?? {})) {
        expect(readBlocklistCodes(blocklist, [code])).toMatchObject({
          listings: [code],
          points: described.points,
          error: null,
        });
      }
    }
  });
});

describe('checkReputation', () => {
  it('reports a listing with the code, the meaning and what it is worth', async () => {
    const dns = fakeDns({ [ZEN_QUERY]: ['127.0.0.2'] });
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], { query: dns.query });

    expect(result).toEqual({
      ip: PUBLIC_IP,
      domain: null,
      listed: true,
      checked: ['zen.spamhaus.org'],
      errors: [],
      completed: true,
      hits: [
        {
          name: 'spamhaus-zen',
          zone: 'zen.spamhaus.org',
          kind: 'ip',
          target: PUBLIC_IP,
          codes: ['127.0.0.2'],
          meanings: ['SBL: a known source of spam'],
          points: 4,
          text: null,
        },
      ],
    });
  });

  // NXDOMAIN is the ordinary answer, and it must read as "this zone holds
  // nothing against the sender" — reported as checked, with no error.
  it('reports a zone that answered nothing as checked and clean', async () => {
    const dns = fakeDns({});
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN, SPAMCOP], {
      query: dns.query,
    });

    expect(result.listed).toBe(false);
    expect(result.completed).toBe(true);
    expect(result.checked).toEqual(['zen.spamhaus.org', 'bl.spamcop.net']);
    expect(dns.asked).toEqual([ZEN_QUERY, SPAMCOP_QUERY]);
  });

  // Regression: a resolver failure is NOT "not listed". Collapsing the two is
  // what makes an outage look like a clean bill of health for every sender.
  it('reports a failed lookup as an error rather than as a clean result', async () => {
    const dns = fakeDns({ [ZEN_QUERY]: new Error('queryA ESERVFAIL') });
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], { query: dns.query });

    expect(result.listed).toBe(false);
    expect(result.completed).toBe(false);
    expect(result.checked).toEqual([]);
    expect(result.errors).toEqual([
      { name: 'spamhaus-zen', zone: 'zen.spamhaus.org', error: 'queryA ESERVFAIL' },
    ]);
  });

  it('reports a rejection that is not an Error as its own text', async () => {
    const query: DnsQuery = () => Promise.reject('the resolver exploded');
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], { query });

    expect(result.errors[0]?.error).toBe('the resolver exploded');
  });

  // One operator's outage must not discard another operator's listing: the
  // hit stands, and `completed` is what says the picture is incomplete.
  it('keeps the zone that answered when another one failed', async () => {
    const dns = fakeDns({
      [ZEN_QUERY]: ['127.0.0.4'],
      [SPAMCOP_QUERY]: new Error('queryA ETIMEOUT'),
    });
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN, SPAMCOP], {
      query: dns.query,
    });

    expect(result.listed).toBe(true);
    expect(result.hits).toHaveLength(1);
    expect(result.checked).toEqual(['zen.spamhaus.org']);
    expect(result.completed).toBe(false);
  });

  // The same regression as the code reader, through the whole function: an
  // operator complaint reaches `errors`, never `hits`.
  it('never turns an operator error code into a listing', async () => {
    const dns = fakeDns({ [ZEN_QUERY]: ['127.255.255.254'] });
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], { query: dns.query });

    expect(result.listed).toBe(false);
    expect(result.hits).toEqual([]);
    expect(result.errors[0]?.error).toMatch(/open resolver/);
    expect(result.completed).toBe(false);
  });

  it('asks IP zones about the address and domain zones about the domain', async () => {
    const dns = fakeDns({ [DBL_QUERY]: ['127.0.1.4'] });
    const result = await checkReputation(
      { ip: PUBLIC_IP, domain: 'example.com' },
      [SPAMHAUS_ZEN, SPAMHAUS_DBL],
      { query: dns.query },
    );

    expect(dns.asked).toEqual([ZEN_QUERY, DBL_QUERY]);
    expect(result.hits.map((hit) => hit.kind)).toEqual(['domain']);
    expect(result.hits[0]?.target).toBe('example.com');
  });

  // A domain zone with no domain to ask about is skipped, not asked with the
  // IP — which would be a query about something that does not exist and an
  // answer read as clean.
  it('skips the zones whose kind of target it was not given', async () => {
    const dns = fakeDns({});
    const result = await checkReputation({ domain: 'example.com' }, [SPAMHAUS_ZEN, SPAMHAUS_DBL], {
      query: dns.query,
    });

    expect(dns.asked).toEqual([DBL_QUERY]);
    expect(result.ip).toBeNull();
    expect(result.completed).toBe(true);
  });

  // Regression: nothing to ask about must not read as "asked and found
  // nothing". No query is made at all, and `completed` says so.
  it('asks nothing, and claims nothing, when neither target is usable', async () => {
    const dns = fakeDns({});
    for (const target of [{}, { ip: '10.0.0.4' }, { ip: null, domain: 'localhost' }]) {
      const result = await checkReputation(target, BLOCKLISTS, { query: dns.query });
      expect(result).toMatchObject({ listed: false, hits: [], checked: [], completed: false });
    }
    expect(dns.asked).toEqual([]);
  });

  it('asks nothing when no blocklist was named', async () => {
    const dns = fakeDns({});
    const result = await checkReputation({ ip: PUBLIC_IP }, [], { query: dns.query });

    expect(result.completed).toBe(false);
    expect(dns.asked).toEqual([]);
  });

  it('fetches the explanation only when asked to, and only for a listing', async () => {
    const dns = fakeDns({
      [ZEN_QUERY]: ['127.0.0.2'],
      [`TXT ${PUBLIC_IP_REVERSED}.zen.spamhaus.org`]: ['https://check.spamhaus.org/ ', 'listed'],
      [SPAMCOP_QUERY]: [],
    });
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN, SPAMCOP], {
      query: dns.query,
      includeText: true,
    });

    expect(result.hits[0]?.text).toBe('https://check.spamhaus.org/  listed');
    expect(dns.asked).not.toContain(`TXT ${PUBLIC_IP_REVERSED}.bl.spamcop.net`);
  });

  it('leaves the explanation out when it was not asked for', async () => {
    const dns = fakeDns({ [ZEN_QUERY]: ['127.0.0.2'] });
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], { query: dns.query });

    expect(result.hits[0]?.text).toBeNull();
    expect(dns.asked).toEqual([ZEN_QUERY]);
  });

  // Regression: the explanation is a nicety. A zone that publishes no TXT — or
  // one whose TXT lookup fails — must still produce the listing.
  it('keeps the listing when its explanation cannot be read', async () => {
    const dns = fakeDns({
      [ZEN_QUERY]: ['127.0.0.2'],
      [`TXT ${PUBLIC_IP_REVERSED}.zen.spamhaus.org`]: new Error('queryTxt ESERVFAIL'),
      [SPAMCOP_QUERY]: ['127.0.0.2'],
    });
    const result = await checkReputation({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN, SPAMCOP], {
      query: dns.query,
      includeText: true,
    });

    expect(result.hits[0]?.text).toBeNull();
    expect(result.hits[1]?.text).toBeNull();
    expect(result.completed).toBe(true);
  });
});

describe('checkReputation with the built-in node:dns resolver', () => {
  /** One `Resolver` double, recording how it was built and what it was asked. */
  function mockNodeDns() {
    const state = {
      built: [] as unknown[],
      servers: [] as string[][],
      asked: [] as string[],
      a: { '34.216.184.93.zen.spamhaus.org': ['127.0.0.2'] } as Record<string, string[]>,
      fail: null as Error | null,
    };

    class Resolver {
      constructor(options?: unknown) {
        state.built.push(options);
      }
      setServers(servers: string[]): void {
        state.servers.push(servers);
      }
      resolve4(name: string): Promise<string[]> {
        state.asked.push(`A ${name}`);
        if (state.fail) return Promise.reject(state.fail);
        const answer = state.a[name];
        if (answer) return Promise.resolve(answer);
        return Promise.reject(Object.assign(new Error('queryA ENOTFOUND'), { code: 'ENOTFOUND' }));
      }
      resolveTxt(name: string): Promise<string[][]> {
        state.asked.push(`TXT ${name}`);
        return Promise.resolve([['listed by', ' spamhaus']]);
      }
    }

    vi.resetModules();
    vi.doMock('node:dns/promises', () => ({ Resolver }));
    return state;
  }

  // The default path exists to be used, so it is tested as a whole: the
  // resolver is built once with the caller's timeout, asked under the right
  // name, and its answer read.
  it('builds one resolver with the timeout and reads a real answer', async () => {
    const state = mockNodeDns();
    const { checkReputation: withNodeDns } = await import('../src/reputation.js');

    const result = await withNodeDns({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN, SPAMCOP], {
      timeoutMs: 1_500,
    });

    expect(state.built).toEqual([{ timeout: 1_500, tries: 1 }]);
    expect(state.asked).toEqual([ZEN_QUERY, SPAMCOP_QUERY]);
    expect(result.hits[0]?.codes).toEqual(['127.0.0.2']);
    // SpamCop answered NXDOMAIN: checked, not listed, and not an error.
    expect(result.checked).toContain('bl.spamcop.net');
    expect(result.completed).toBe(true);

    vi.doUnmock('node:dns/promises');
    vi.resetModules();
  });

  it('falls back to the default timeout, and uses the servers it is given', async () => {
    const state = mockNodeDns();
    const { checkReputation: withNodeDns } = await import('../src/reputation.js');

    await withNodeDns({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], { servers: ['192.0.2.53'] });

    expect(state.built).toEqual([{ timeout: 5_000, tries: 1 }]);
    expect(state.servers).toEqual([['192.0.2.53']]);

    vi.doUnmock('node:dns/promises');
    vi.resetModules();
  });

  it('leaves the system resolvers alone when given an empty server list', async () => {
    const state = mockNodeDns();
    const { checkReputation: withNodeDns } = await import('../src/reputation.js');

    await withNodeDns({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], { servers: [] });

    expect(state.servers).toEqual([]);

    vi.doUnmock('node:dns/promises');
    vi.resetModules();
  });

  // Regression, at the boundary where it belongs: c-ares reports "no such
  // name" as a thrown error, and this adapter is the one place that turns it
  // into the empty answer the rest of the module reads as "not listed".
  // Everything else it throws is a genuine failure and must stay one.
  it('reads a resolver failure that is not NXDOMAIN as a failure', async () => {
    const state = mockNodeDns();
    state.fail = Object.assign(new Error('queryA ESERVFAIL'), { code: 'ESERVFAIL' });
    const { checkReputation: withNodeDns } = await import('../src/reputation.js');

    const result = await withNodeDns({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], {});

    expect(result.completed).toBe(false);
    expect(result.errors[0]?.error).toBe('queryA ESERVFAIL');

    vi.doUnmock('node:dns/promises');
    vi.resetModules();
  });

  it('joins the chunks of a TXT record', async () => {
    mockNodeDns();
    const { checkReputation: withNodeDns } = await import('../src/reputation.js');

    const result = await withNodeDns({ ip: PUBLIC_IP }, [SPAMHAUS_ZEN], { includeText: true });

    expect(result.hits[0]?.text).toBe('listed by spamhaus');

    vi.doUnmock('node:dns/promises');
    vi.resetModules();
  });
});

/** A result carrying exactly the hits a scoring test needs. */
function resultWith(hits: ReputationResult['hits']): ReputationResult {
  return {
    ip: PUBLIC_IP,
    domain: 'example.com',
    listed: hits.length > 0,
    hits,
    checked: [],
    errors: [],
    completed: true,
  };
}

function hit(
  overrides: Partial<ReputationResult['hits'][number]>,
): ReputationResult['hits'][number] {
  return {
    name: 'spamhaus-zen',
    zone: 'zen.spamhaus.org',
    kind: 'ip',
    target: PUBLIC_IP,
    codes: ['127.0.0.2'],
    meanings: ['SBL: a known source of spam'],
    points: 4,
    text: null,
    ...overrides,
  };
}

describe('assessReputation', () => {
  it('charges the listing once, and says which list and why', () => {
    const assessment = assessReputation(resultWith([hit({})]));

    expect(assessment.score).toBe(4);
    expect(assessment.reasons).toEqual([
      {
        id: 'reputation-ip-listed',
        points: 4,
        detail:
          'The sending address 93.184.216.34 is listed by spamhaus-zen (SBL: a known source of spam).',
      },
    ]);
    // Four points is deliberately short of SPAM_THRESHOLD: a listing is strong
    // evidence, not a verdict, and this package has no rule that files a
    // message on its own.
    expect(assessment.isSpam).toBe(false);
    expect(assessment.suspicious).toBe(true);
  });

  // THE scoring regression. The public lists mirror and feed each other, and
  // ZEN is itself three lists in one zone. Summing would make the score a
  // function of how many zones a deployment happens to configure rather than
  // of the message, and three correlated listings would file mail that one
  // would not.
  it('takes the strongest listing rather than adding them up', () => {
    const assessment = assessReputation(
      resultWith([
        hit({ name: 'spamcop', zone: 'bl.spamcop.net', points: 3, meanings: [] }),
        hit({ points: 4 }),
      ]),
    );

    expect(assessment.score).toBe(4);
    expect(assessment.reasons[0]?.detail).toBe(
      'The sending address 93.184.216.34 is listed by spamhaus-zen (SBL: a known source of spam) and 1 other blocklist.',
    );
  });

  it('counts the other lists in the plural when there are several', () => {
    const assessment = assessReputation(
      resultWith([hit({}), hit({ name: 'spamcop', points: 3 }), hit({ name: 'other', points: 1 })]),
    );

    expect(assessment.reasons[0]?.detail).toMatch(/and 2 other blocklists\.$/);
  });

  // The address and the domain are separate facts about separate things —
  // the machine that delivered the message, and the brand it claims — so
  // unlike two IP lists, these do add up.
  it('scores the address and the domain separately', () => {
    const assessment = assessReputation(
      resultWith([
        hit({}),
        hit({
          name: 'spamhaus-dbl',
          zone: 'dbl.spamhaus.org',
          kind: 'domain',
          target: 'example.com',
          codes: ['127.0.1.4'],
          meanings: ['a phishing domain'],
          points: 4,
        }),
      ]),
    );

    expect(assessment.score).toBe(8);
    expect(assessment.isSpam).toBe(true);
    expect(assessment.reasons.map((reason) => reason.id)).toEqual([
      'reputation-ip-listed',
      'reputation-domain-listed',
    ]);
    expect(assessment.reasons[1]?.detail).toBe(
      'The sender domain example.com is listed by spamhaus-dbl (a phishing domain).',
    );
  });

  // A zone whose code this catalogue does not describe still fires; the
  // sentence simply says less rather than inventing a meaning.
  it('reads without a meaning when the zone described none', () => {
    const assessment = assessReputation(resultWith([hit({ meanings: [], points: 3 })]));

    expect(assessment.reasons[0]?.detail).toBe(
      'The sending address 93.184.216.34 is listed by spamhaus-zen.',
    );
  });

  it('charges nothing when nothing was listed', () => {
    expect(assessReputation(resultWith([]))).toEqual({
      score: 0,
      reasons: [],
      isSpam: false,
      suspicious: false,
    });
  });
});
