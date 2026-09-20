import { describe, expect, it, vi } from 'vitest';

import {
  assessReputation,
  blocklistQueryName,
  checkReputation,
  checkReputationBatch,
  normalizeQueryDomain,
  readBlocklistCodes,
  reverseIpLabel,
  BLOCKLISTS,
  REPUTATION_MAX_POINTS,
  SPAMCOP,
  SPAMHAUS_DBL,
  SPAMHAUS_ZEN,
  SURBL,
  URIBL,
  USER_REPORT_POINTS,
  USER_REPORTS_MIN,
  type Blocklist,
  type DnsQuery,
  type ReputationResult,
} from '../src/reputation.js';

/** A public unicast address, which is the only kind this stage will ask about. */
const PUBLIC_IP = '93.184.216.34';
const PUBLIC_IP_REVERSED = '34.216.184.93';

/** A public v6 address and its 32 reversed nibbles. */
const PUBLIC_IPV6 = '2a00:1450:4001:80e::200e';
const PUBLIC_IPV6_REVERSED =
  'e.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.e.0.8.0.1.0.0.4.0.5.4.1.0.0.a.2';

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

  // Without the capability flag every v6 sender costs one wasted round trip
  // per v4-only zone, on every message, to be told NXDOMAIN by a nameserver
  // that has never published a v6 record.
  it('asks only the zones that answer for IPv6 about a v6 address', () => {
    expect(blocklistQueryName(PUBLIC_IPV6, SPAMHAUS_ZEN)).toBe(
      `${PUBLIC_IPV6_REVERSED}.zen.spamhaus.org`,
    );
    expect(blocklistQueryName(PUBLIC_IPV6, SPAMCOP)).toBeNull();
    expect(blocklistQueryName(PUBLIC_IP, SPAMCOP)).toBe(`${PUBLIC_IP_REVERSED}.bl.spamcop.net`);
  });
});

describe('readBlocklistCodes', () => {
  it('reads a described code as its own meaning and its own points', () => {
    expect(readBlocklistCodes(SPAMHAUS_ZEN, ['127.0.0.2'])).toEqual({
      listings: ['127.0.0.2'],
      meanings: ['SBL: a known source of spam'],
      categories: ['spam'],
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
      categories: [],
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
      categories: ['policy', 'spam'],
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
      categories: [],
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
      categories: [],
      points: 0,
      error: null,
    });
  });

  // Regression: the URI lists answer with a BITMASK, so a domain that is both
  // a phishing site and a malware host comes back as one address, 127.0.0.24,
  // that appears in no code table. Looking it up as an exact code finds
  // nothing and scores the zone default, which silently downgrades the worst
  // kind of listing there is.
  it('reads a combined bitmask octet as every bit it sets', () => {
    expect(readBlocklistCodes(SURBL, ['127.0.0.24'])).toEqual({
      listings: ['127.0.0.24'],
      meanings: ['a phishing domain', 'a malware domain'],
      categories: ['phishing', 'malware'],
      points: 4,
      error: null,
    });
  });

  // The same listing, sent as separate records instead of one octet. Both
  // forms are valid DNS and both mean the same thing.
  it('ORs several bitmask records into the same reading', () => {
    expect(readBlocklistCodes(SURBL, ['127.0.0.8', '127.0.0.16'])).toMatchObject({
      categories: ['phishing', 'malware'],
      points: 4,
    });
  });

  // Regression: URIBL grey is bulk mail of dubious value, not spam. Reading
  // the bitmask as a boolean "listed" would file legitimate marketing mail on
  // one list's mild opinion.
  it('scores a grey listing as the nudge it is', () => {
    expect(readBlocklistCodes(URIBL, ['127.0.0.4'])).toMatchObject({
      meanings: ['URIBL grey: a bulk sender of dubious value'],
      categories: ['grey'],
      points: 2,
    });
  });

  // A bit the catalogue does not describe is still a listing — the same rule
  // the exact-code path follows, for the same reason.
  it('scores an unrecognised bit at the zone default', () => {
    expect(readBlocklistCodes(SURBL, ['127.0.0.32'])).toEqual({
      listings: ['127.0.0.32'],
      meanings: [],
      categories: [],
      points: 3,
      error: null,
    });
  });

  // THE regression for the URI lists. Both answer 127.0.0.1 to a query from a
  // public resolver or from a querier over the free-use limit — a refusal in
  // the shape of a listing, and one that arrives for EVERY domain at once.
  it('reads a published refusal in the operator own words, never as a listing', () => {
    expect(readBlocklistCodes(SURBL, ['127.0.0.1'])).toEqual({
      listings: [],
      meanings: [],
      categories: [],
      points: 0,
      error: 'the zone declined the query, which is what it answers a public resolver',
    });
    expect(readBlocklistCodes(URIBL, ['127.0.0.1']).error).toMatch(/free-use limit/);
  });

  // A zone that answers with both has still told us something true about the
  // domain; dropping the listing because a refusal rode along with it would
  // lose the only evidence in the answer.
  it('keeps the listing when a refusal arrives beside it', () => {
    expect(readBlocklistCodes(SURBL, ['127.0.0.1', '127.0.0.8'])).toMatchObject({
      listings: ['127.0.0.8'],
      categories: ['phishing'],
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

  // The bitmask half of the same typo check: a bit that is not a power of two
  // matches other bits as well as its own, so one listing would report two
  // meanings, and a bit above 255 can never be reached at all.
  it('describes each bitmask zone with real, reachable single bits', () => {
    for (const blocklist of BLOCKLISTS) {
      for (const [bit, described] of Object.entries(blocklist.bits ?? {})) {
        const value = Number(bit);
        expect(value).toBeGreaterThan(0);
        expect(value).toBeLessThanOrEqual(255);
        expect(value & (value - 1)).toBe(0);
        expect(readBlocklistCodes(blocklist, [`127.0.0.${bit}`])).toMatchObject({
          meanings: [described.meaning],
          points: described.points,
          error: null,
        });
      }
    }
  });

  // A listing with no category cannot be grouped or re-scored by a consumer,
  // which is the entire reason the field exists. A zone may leave a code
  // undescribed; it may not describe one and then say nothing about it.
  it('gives every described code a category', () => {
    for (const blocklist of BLOCKLISTS) {
      const described = [
        ...Object.values(blocklist.codes ?? {}),
        ...Object.values(blocklist.bits ?? {}),
      ];
      expect(described.length).toBeGreaterThan(0);
      for (const code of described) expect(code.category).toBeDefined();
    }
  });

  // Regression: a zone declared with both tables is ambiguous, and the reader
  // silently prefers `bits` — which would drop a whole exact-code table
  // without a word.
  it('declares one reading per zone, never both', () => {
    for (const blocklist of BLOCKLISTS) {
      expect(blocklist.codes === undefined || blocklist.bits === undefined).toBe(true);
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
          categories: ['spam'],
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

  // Regression: a batch that built a resolver per target would open one
  // c-ares channel and one socket per row — hundreds of them for a backlog —
  // and would re-apply the caller's servers each time. The pool exists to
  // make a backlog cheap; a resolver per target gives that back.
  it('builds one resolver for the whole batch', async () => {
    const state = mockNodeDns();
    const { checkReputationBatch: batchWithNodeDns } = await import('../src/reputation.js');

    const results = await batchWithNodeDns(
      [{ ip: PUBLIC_IP }, { ip: '8.8.4.4' }, { ip: '1.1.1.1' }],
      [SPAMHAUS_ZEN],
      { timeoutMs: 1_500 },
    );

    expect(state.built).toEqual([{ timeout: 1_500, tries: 1 }]);
    expect(results.map((result) => result.listed)).toEqual([true, false, false]);

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
    categories: ['spam'],
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
  // unlike two IP lists, these do add up. They add up to the cap and stop:
  // eight points is not "spam twice", it is one stage settling the verdict
  // by itself and leaving the message nothing to say in its own defence.
  it('scores the address and the domain separately, up to the cap', () => {
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

    expect(assessment.score).toBe(REPUTATION_MAX_POINTS);
    expect(assessment.isSpam).toBe(true);
    expect(assessment.reasons.map((reason) => reason.id)).toEqual([
      'reputation-ip-listed',
      'reputation-domain-listed',
    ]);
    // The address is charged in full and the domain takes what is left, so
    // the truncated reason is always the weaker half of the evidence.
    expect(assessment.reasons.map((reason) => reason.points)).toEqual([4, 2]);
    expect(assessment.reasons[1]?.detail).toBe(
      'The sender domain example.com is listed by spamhaus-dbl (a phishing domain).',
    );
  });

  // A caller running its own points table — one that scores reputation
  // alongside signals this package never sees — has to be able to turn the
  // ceiling off rather than work backwards from a truncated number.
  it('charges every listing in full when the cap is lifted', () => {
    const assessment = assessReputation(
      resultWith([
        hit({}),
        hit({ name: 'spamhaus-dbl', kind: 'domain', target: 'example.com', points: 4 }),
      ]),
      { maxPoints: Infinity },
    );

    expect(assessment.score).toBe(8);
  });

  // Regression: once the budget is spent the remaining reason must be
  // DROPPED, not recorded at zero points. A zero-point reason reads to a user
  // as "we found this and decided it was worth nothing", which is the
  // opposite of what happened.
  it('drops a reason it has no budget left for', () => {
    const assessment = assessReputation(
      resultWith([
        hit({}),
        hit({ name: 'spamhaus-dbl', kind: 'domain', target: 'example.com', points: 4 }),
      ]),
      { maxPoints: 4 },
    );

    expect(assessment.score).toBe(4);
    expect(assessment.reasons.map((reason) => reason.id)).toEqual(['reputation-ip-listed']);
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

// The signal a lookup cannot find: how many other recipients have already
// reported this sender. It arrives as an option because only a host holding
// many mailboxes can count it.
describe('assessReputation with reports from other recipients', () => {
  it('charges a sender enough other recipients have reported', () => {
    const assessment = assessReputation(resultWith([]), { userReports: 7 });

    expect(assessment.reasons).toEqual([
      {
        id: 'reputation-user-reported',
        points: USER_REPORT_POINTS,
        detail: '7 other recipients have reported mail from example.com as spam.',
      },
    ]);
    // Three points is a crowd's opinion, not an operator's observation: real
    // evidence, and short of filing the message on its own.
    expect(assessment.isSpam).toBe(false);
  });

  // Regression: one report is one opinion. A single reader who dislikes a
  // newsletter must not be able to score every copy of it that arrives.
  it('ignores a count below the minimum', () => {
    const assessment = assessReputation(resultWith([]), { userReports: USER_REPORTS_MIN - 1 });

    expect(assessment.reasons).toEqual([]);
  });

  // A host with its own sense of how trustworthy its reporters are can move
  // the line; the sentence still has to read correctly at one report.
  it('honours a caller minimum, down to a single report', () => {
    const assessment = assessReputation(resultWith([]), {
      userReports: 1,
      minUserReports: 1,
    });

    expect(assessment.reasons[0]?.detail).toBe(
      '1 other recipient has reported mail from example.com as spam.',
    );
  });

  // Reports are charged last, out of whatever the listings left, so the
  // crowd can never push a message over the stage cap on its own.
  it('takes what the listings left of the budget', () => {
    const assessment = assessReputation(resultWith([hit({ points: 4 })]), { userReports: 5 });

    expect(assessment.score).toBe(REPUTATION_MAX_POINTS);
    expect(assessment.reasons.map((reason) => [reason.id, reason.points])).toEqual([
      ['reputation-ip-listed', 4],
      ['reputation-user-reported', 2],
    ]);
  });

  // Regression: a report is a report ABOUT a named sender. With no domain on
  // the result there is nothing to put in the sentence, so the count is
  // dropped rather than shown against a blank.
  it('says nothing about a sender it cannot name', () => {
    const assessment = assessReputation({ ...resultWith([]), domain: null }, { userReports: 9 });

    expect(assessment.reasons).toEqual([]);
  });
});

describe('checkReputationBatch', () => {
  /** A resolver that takes a turn to answer, and remembers how many overlapped. */
  function trackingDns(): { query: DnsQuery; peak: () => number; asked: string[] } {
    const asked: string[] = [];
    let inFlight = 0;
    let peak = 0;

    const query: DnsQuery = async (name) => {
      asked.push(name);
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 1));
      inFlight -= 1;
      return name.startsWith(PUBLIC_IP_REVERSED) ? ['127.0.0.2'] : [];
    };

    return { query, peak: () => peak, asked };
  }

  // Regression: a caller zips these against its own rows. A result out of
  // order, or a target silently dropped because it had nothing to ask, would
  // attach one sender's listing to a different sender's message.
  it('answers one result per target, in the order they were given', async () => {
    const dns = trackingDns();
    const results = await checkReputationBatch(
      [{ ip: '8.8.4.4' }, { ip: PUBLIC_IP }, { ip: '10.0.0.1' }],
      [SPAMHAUS_ZEN],
      { query: dns.query },
    );

    expect(results.map((result) => result.ip)).toEqual(['8.8.4.4', PUBLIC_IP, null]);
    expect(results.map((result) => result.listed)).toEqual([false, true, false]);
    // The private address was never asked about, so its empty result is
    // "nobody could be asked", not "nobody has anything against it".
    expect(results[2]?.completed).toBe(false);
  });

  // THE reason the pool exists. Six zones times a few hundred backlogged rows
  // is a thousand simultaneous queries: c-ares will not serve them, the
  // operator reads the burst as an attack and starts answering
  // 127.255.255.255, and a home router drops the rest on the floor.
  it('never runs more queries at once than it was allowed', async () => {
    const dns = trackingDns();
    const targets = Array.from({ length: 8 }, (_, index) => ({ ip: `8.8.4.${index + 1}` }));

    await checkReputationBatch(targets, [SPAMHAUS_ZEN, SPAMCOP], {
      query: dns.query,
      concurrency: 3,
    });

    expect(dns.asked).toHaveLength(16);
    expect(dns.peak()).toBe(3);
  });

  it('runs several at once by default', async () => {
    const dns = trackingDns();
    const targets = Array.from({ length: 6 }, (_, index) => ({ ip: `8.8.4.${index + 1}` }));

    await checkReputationBatch(targets, [SPAMHAUS_ZEN], { query: dns.query });

    expect(dns.peak()).toBeGreaterThan(1);
  });

  // Regression: a slot count of zero read literally is a deadlock — every
  // task waits for a slot that nothing will ever release, and the batch never
  // settles. A caller computing concurrency from a config value can reach
  // zero by accident, and a hang is the worst possible way to find out.
  it('reads a concurrency below one as one rather than hanging', async () => {
    const dns = trackingDns();
    const results = await checkReputationBatch(
      [{ ip: PUBLIC_IP }, { ip: '8.8.4.4' }],
      [SPAMHAUS_ZEN],
      { query: dns.query, concurrency: 0 },
    );

    expect(dns.peak()).toBe(1);
    expect(results).toHaveLength(2);
  });

  it('asks nothing, and answers nothing, for an empty batch', async () => {
    const dns = trackingDns();
    expect(await checkReputationBatch([], BLOCKLISTS, { query: dns.query })).toEqual([]);
    expect(dns.asked).toEqual([]);
  });

  // Regression: a batch of rows a resolver has nothing to say about — private
  // addresses, missing domains — must not build a resolver or open a socket
  // just to discover that.
  it('asks nothing when no target is worth a query', async () => {
    const dns = trackingDns();
    const results = await checkReputationBatch(
      [{ ip: '10.0.0.1' }, { domain: 'not a domain' }],
      [SPAMHAUS_ZEN],
      { query: dns.query },
    );

    expect(dns.asked).toEqual([]);
    expect(results.map((result) => result.completed)).toEqual([false, false]);
  });

  // A domain batch is the URI-list case, and it goes through the bitmask
  // reader end to end rather than only in the unit test above.
  it('reads a bitmask zone through the batch', async () => {
    const query: DnsQuery = (name) =>
      Promise.resolve(name === 'bad.example.com.multi.surbl.org' ? ['127.0.0.24'] : []);

    const results = await checkReputationBatch(
      [{ domain: 'bad.example.com' }, { domain: 'good.example.com' }],
      [SURBL],
      { query, concurrency: 2 },
    );

    expect(results[0]?.hits[0]).toMatchObject({
      name: 'surbl',
      categories: ['phishing', 'malware'],
      points: 4,
    });
    expect(results[1]?.listed).toBe(false);
  });
});
