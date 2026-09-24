import { describe, expect, it } from 'vitest';

import {
  assessDomainAge,
  domainAgePoints,
  fetchRdapBootstrap,
  lookupDomainAge,
  rdapServerFor,
  DOMAIN_AGE_MAX_POINTS,
  DOMAIN_AGE_TIERS,
  RDAP_BOOTSTRAP_URL,
  RDAP_MAX_BYTES,
  type DomainAgeLookup,
} from '../src/age.js';
import { SPAM_THRESHOLD } from '../src/verdict.js';

import { fakeFetch, type Route } from './fetch-fixture.js';
import {
  BOOTSTRAP,
  BOOTSTRAP_JSON,
  KUAIYUDH_TOP,
  LURE_ARRIVED_MS,
  POWERSUBLINKS_COM,
} from './rdap-fixture.js';

/**
 * Domain age from RDAP.
 *
 * What this protects: the lure of 2026-09-23 linked to a five-day-old domain
 * that no blocklist had heard of. This is the one signal that is true about a
 * campaign domain before anybody reports it — and it is also true about every
 * start-up's first week, which is why the safety property pinned at the bottom
 * matters as much as the detection: age alone can never file a message.
 */
const TOP = 'https://rdap.zdnsgtld.com/top/domain/kuaiyudh.top';
const COM = 'https://rdap.verisign.com/com/v1/domain/powersublinks.com';
const routes = (over: Record<string, Route> = {}): Record<string, Route> => ({
  [TOP]: { body: JSON.stringify(KUAIYUDH_TOP), type: 'application/rdap+json' },
  [COM]: { body: JSON.stringify(POWERSUBLINKS_COM), type: 'application/rdap+json' },
  ...over,
});
const lookup = (
  domain: string | null | undefined,
  over: Record<string, Route> = {},
  calls: string[] = [],
) =>
  lookupDomainAge(domain, {
    fetch: fakeFetch(routes(over), calls),
    bootstrap: BOOTSTRAP,
    now: LURE_ARRIVED_MS,
  });

describe('rdapServerFor', () => {
  it('finds the registry for a TLD and always ends the base URL with a slash', () => {
    expect(rdapServerFor('powersublinks.com', BOOTSTRAP)).toBe('https://rdap.verisign.com/com/v1/');
    expect(rdapServerFor('example.net', BOOTSTRAP)).toBe('https://rdap.verisign.com/com/v1/');
    expect(rdapServerFor('example.de', BOOTSTRAP)).toBe('https://rdap.denic.de/');
    expect(rdapServerFor('EXAMPLE.TOP', BOOTSTRAP)).toBe('https://rdap.zdnsgtld.com/top/');
  });

  // Regression: a forged date over plain HTTP can only make a domain look
  // OLDER, which loses points — so HTTP is accepted, but HTTPS is preferred
  // wherever the registry offers both.
  it('prefers HTTPS when the registry lists both, and accepts HTTP when that is all there is', () => {
    expect(rdapServerFor('x.both', BOOTSTRAP)).toBe('https://secure.example/');
    expect(rdapServerFor('x.kg', BOOTSTRAP)).toBe('http://rdap.cctld.kg/');
  });

  it('is null for a TLD the bootstrap does not list, or lists with no server', () => {
    expect(rdapServerFor('x.example', BOOTSTRAP)).toBeNull();
    expect(rdapServerFor('x.none', BOOTSTRAP)).toBeNull();
  });
});

describe('fetchRdapBootstrap', () => {
  it('reads IANA’s file', async () => {
    const calls: string[] = [];
    const got = await fetchRdapBootstrap(
      fakeFetch({ [RDAP_BOOTSTRAP_URL]: { body: BOOTSTRAP_JSON } }, calls),
    );
    expect(got?.services).toEqual(BOOTSTRAP.services);
    expect(calls).toEqual([RDAP_BOOTSTRAP_URL]);
  });

  // Regression: a bootstrap that is not the bootstrap must read as "could not
  // get it", never as an empty registry that makes every TLD unsupported.
  it('is null — never a throw — for a refusal, an outage, junk, the wrong shape, or an oversized answer', async () => {
    expect(
      await fetchRdapBootstrap(fakeFetch({ [RDAP_BOOTSTRAP_URL]: { status: 503 } })),
    ).toBeNull();
    expect(
      await fetchRdapBootstrap(fakeFetch({ [RDAP_BOOTSTRAP_URL]: { throws: true } })),
    ).toBeNull();
    expect(
      await fetchRdapBootstrap(fakeFetch({ [RDAP_BOOTSTRAP_URL]: { body: 'not json' } })),
    ).toBeNull();
    expect(
      await fetchRdapBootstrap(
        fakeFetch({ [RDAP_BOOTSTRAP_URL]: { body: '{"services":"nope"}' } }),
      ),
    ).toBeNull();
    expect(
      await fetchRdapBootstrap(
        fakeFetch({ [RDAP_BOOTSTRAP_URL]: { body: '{"services":[[["com"],"x"]]}' } }),
      ),
    ).toBeNull();
    expect(
      await fetchRdapBootstrap(
        fakeFetch({ [RDAP_BOOTSTRAP_URL]: { body: BOOTSTRAP_JSON, length: RDAP_MAX_BYTES + 1 } }),
      ),
    ).toBeNull();
  });
});

describe('lookupDomainAge', () => {
  // The lure's two domains, against the registries' own records.
  it('reads the registration date, the age and the registrar out of a real record', async () => {
    const top = await lookup('kuaiyudh.top');
    expect(top).toEqual({
      domain: 'kuaiyudh.top',
      status: 'ok',
      registered: Math.floor(Date.parse('2026-09-17T23:11:55.0Z') / 1000),
      ageDays: 5,
      registrar: 'Namecheap Inc.',
      server: 'https://rdap.zdnsgtld.com/top/',
      detail: null,
    });
    const com = await lookup('powersublinks.com');
    expect(com.status).toBe('ok');
    expect(com.ageDays).toBe(78);
    expect(com.registrar).toBe('Dynadot Inc');
  });

  it('measures the age against the real clock when the caller passes none', async () => {
    const got = await lookupDomainAge('kuaiyudh.top', {
      fetch: fakeFetch(routes()),
      bootstrap: BOOTSTRAP,
    });
    expect(got.status).toBe('ok');
    expect(got.ageDays).toBeGreaterThanOrEqual(5);
  });

  it('asks about the registrable domain, whatever host or case it was given', async () => {
    const calls: string[] = [];
    const got = await lookup('Mail.POWERSUBLINKS.com', {}, calls);
    expect(got.domain).toBe('powersublinks.com');
    expect(calls).toEqual([COM]);
  });

  // Regression: RDAP servers speak A-labels. A lookup that sent the Unicode
  // name would get a 404 — and read it as "no such domain".
  it('encodes an internationalised domain as its A-label', async () => {
    const calls: string[] = [];
    const got = await lookup('bücher.top', {}, calls);
    expect(calls).toEqual(['https://rdap.zdnsgtld.com/top/domain/xn--bcher-kva.top']);
    expect(got.status).toBe('not-found');
  });

  it('is unsupported for anything that is not a registrable domain, or a TLD with no RDAP', async () => {
    expect((await lookup('localhost')).status).toBe('unsupported');
    expect((await lookup('')).status).toBe('unsupported');
    expect((await lookup(null)).status).toBe('unsupported');
    const example = await lookup('x.example');
    expect(example.status).toBe('unsupported');
    expect(example.detail).toBe('No RDAP service is published for .example');
    expect((await lookup('x.none')).detail).toBe('No RDAP service is published for .none');
  });

  it('fetches the bootstrap itself when the caller does not pass one, and reports it when it cannot', async () => {
    const calls: string[] = [];
    const fetch = fakeFetch(routes({ [RDAP_BOOTSTRAP_URL]: { body: BOOTSTRAP_JSON } }), calls);
    const got = await lookupDomainAge('kuaiyudh.top', { fetch, now: LURE_ARRIVED_MS });
    expect(got.ageDays).toBe(5);
    expect(calls).toEqual([RDAP_BOOTSTRAP_URL, TOP]);

    const down = await lookupDomainAge('kuaiyudh.top', {
      fetch: fakeFetch(routes()),
      now: LURE_ARRIVED_MS,
    });
    expect(down.status).toBe('error');
    expect(down.detail).toBe('The RDAP bootstrap registry could not be read');
    // A caller that already failed to get it says so with null, and is not made to try again.
    const told = await lookupDomainAge('kuaiyudh.top', { bootstrap: null });
    expect(told.status).toBe('error');
  });

  // Regression: each of these is a fact about the REGISTRY or the network,
  // not about the domain, and every one must score nothing. "Could not ask" is
  // neither new nor old.
  it('separates not-found from the registry failing, and never throws', async () => {
    expect(await lookup('kuaiyudh.top', { [TOP]: { status: 404 } })).toMatchObject({
      status: 'not-found',
      server: 'https://rdap.zdnsgtld.com/top/',
      detail: 'The registry has no record of this domain',
    });
    expect((await lookup('kuaiyudh.top', { [TOP]: { status: 429 } })).detail).toBe(
      'The RDAP server answered 429',
    );
    expect((await lookup('kuaiyudh.top', { [TOP]: { throws: true } })).detail).toBe(
      'The RDAP lookup failed: ECONNRESET',
    );
    expect(
      (await lookup('kuaiyudh.top', { [TOP]: { body: '{}', length: RDAP_MAX_BYTES + 1 } })).detail,
    ).toBe('The RDAP record is too large to be one');
    expect((await lookup('kuaiyudh.top', { [TOP]: { body: '<html>busy</html>' } })).detail).toBe(
      'The RDAP record is not JSON',
    );
    const noEvents = await lookup('kuaiyudh.top', {
      [TOP]: { body: JSON.stringify({ ...KUAIYUDH_TOP, events: undefined }) },
    });
    expect(noEvents.status).toBe('unsupported');
    expect(noEvents.detail).toBe('The registry publishes no registration date for this domain');
    const noRegistration = await lookup('kuaiyudh.top', {
      [TOP]: {
        body: JSON.stringify({
          ...KUAIYUDH_TOP,
          events: [{ eventAction: 'expiration', eventDate: '2027-01-01T00:00:00Z' }, null],
        }),
      },
    });
    expect(noRegistration.status).toBe('unsupported');
    const badDate = await lookup('kuaiyudh.top', {
      [TOP]: {
        body: JSON.stringify({
          ...KUAIYUDH_TOP,
          events: [{ eventAction: 'registration', eventDate: 'yesterday' }],
        }),
      },
    });
    expect(badDate.status).toBe('error');
    expect(badDate.detail).toBe('The registration date "yesterday" is unreadable');
  });

  it('reports a body that breaks off mid-read as a failed lookup', async () => {
    const broken = fakeFetch(routes());
    const fetch = (url: string) =>
      broken(url).then((response) => ({
        ...response,
        arrayBuffer: () => Promise.reject(new Error('socket hang up')),
      }));
    const got = await lookupDomainAge('kuaiyudh.top', { fetch, bootstrap: BOOTSTRAP });
    expect(got.status).toBe('error');
    expect(got.detail).toBe('The RDAP lookup failed: socket hang up');
  });

  // Regression: a registration a few hours ahead of this machine's clock is
  // clock skew, and it is the newest a domain can be — not an error, and not
  // a negative age that some tier would read as ancient.
  it('clamps a registration in the future to today, and reads a record with no registrar as none', async () => {
    const skewed = await lookupDomainAge('kuaiyudh.top', {
      fetch: fakeFetch(routes()),
      bootstrap: BOOTSTRAP,
      now: Date.parse('2026-09-17T10:00:00Z'),
    });
    expect(skewed.ageDays).toBe(0);
    for (const entities of [
      undefined,
      'nope',
      [{ roles: 'registrar' }],
      [{ roles: ['registrar'] }],
      [{ roles: ['registrar'], vcardArray: ['vcard', 'nope'] }],
      [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', '   '], 'x']] }],
    ]) {
      const got = await lookup('kuaiyudh.top', {
        [TOP]: { body: JSON.stringify({ ...KUAIYUDH_TOP, entities }) },
      });
      expect(got.status, JSON.stringify(entities)).toBe('ok');
      expect(got.registrar, JSON.stringify(entities)).toBeNull();
    }
  });
});

describe('domainAgePoints', () => {
  it('reads each tier as "younger than"', () => {
    expect(domainAgePoints(0)).toBe(3);
    expect(domainAgePoints(6)).toBe(3);
    expect(domainAgePoints(7)).toBe(2);
    expect(domainAgePoints(29)).toBe(2);
    expect(domainAgePoints(30)).toBe(1);
    expect(domainAgePoints(89)).toBe(1);
    expect(domainAgePoints(90)).toBe(0);
    expect(domainAgePoints(10_000)).toBe(0);
    expect(DOMAIN_AGE_TIERS.map((tier) => tier.points)).toEqual([3, 2, 1]);
  });
});

describe('assessDomainAge', () => {
  const dated = (domain: string, ageDays: number): DomainAgeLookup => ({
    domain,
    status: 'ok',
    registered: Math.floor((LURE_ARRIVED_MS - ageDays * 86_400_000) / 1000),
    ageDays,
    registrar: null,
    server: 'https://rdap.example/',
    detail: null,
  });
  const unknown = (domain: string): DomainAgeLookup => ({
    domain,
    status: 'error',
    registered: null,
    ageDays: null,
    registrar: null,
    server: null,
    detail: 'down',
  });

  // The lure: a 78-day-old sender linking to a 5-day-old domain. 1 + 3.
  it('charges the sender domain and the youngest link domain, and says when each was registered', () => {
    const result = assessDomainAge({
      sender: dated('powersublinks.com', 78),
      links: [dated('cdn.example', 400), dated('kuaiyudh.top', 5), dated('other.example', 40)],
    });
    expect(result.reasons).toEqual([
      {
        id: 'reputation-domain-new',
        points: 1,
        detail: 'The sender domain powersublinks.com was registered only 78 days ago (2026-07-07)',
      },
      {
        id: 'reputation-link-new',
        points: 3,
        detail: 'Links to kuaiyudh.top, a domain registered only 5 days ago (2026-09-18)',
      },
    ]);
    expect(result.score).toBe(4);
  });

  it('phrases today and one day without a plural', () => {
    expect(assessDomainAge({ sender: dated('a.example', 0) }).reasons[0]?.detail).toMatch(
      /registered only today \(/,
    );
    expect(assessDomainAge({ links: [dated('b.example', 1)] }).reasons[0]?.detail).toMatch(
      /only 1 day ago \(/,
    );
  });

  // THE safety property. A start-up's first mail from its first domain to its
  // first prospect is every age signal at once, and it is not spam.
  it('can never reach the spam threshold on age alone, however new everything is', () => {
    const result = assessDomainAge({
      sender: dated('new.example', 0),
      links: [dated('newer.example', 0)],
    });
    expect(result.score).toBe(DOMAIN_AGE_MAX_POINTS);
    expect(result.score).toBeLessThan(SPAM_THRESHOLD);
    expect(result.isSpam).toBe(false);
    expect(result.suspicious).toBe(true);
    // The sender is charged in full and the link takes what is left.
    expect(result.reasons.map((reason) => reason.points)).toEqual([3, 1]);
  });

  it('honours a caller’s own budget, including none at all', () => {
    const both = { sender: dated('a.example', 0), links: [dated('b.example', 0)] };
    expect(assessDomainAge(both, { maxPoints: Infinity }).score).toBe(6);
    expect(assessDomainAge(both, { maxPoints: 0 }).reasons).toEqual([]);
    expect(
      assessDomainAge({ links: [{ ...dated('a.example', 1), registered: null }] }).reasons,
    ).toEqual([]);
  });

  it('scores nothing for old domains, failed lookups, a dated lookup with no age, or no subjects', () => {
    expect(
      assessDomainAge({ sender: dated('old.example', 3_000), links: [dated('older.example', 400)] })
        .reasons,
    ).toEqual([]);
    expect(
      assessDomainAge({ sender: unknown('a.example'), links: [unknown('b.example')] }).reasons,
    ).toEqual([]);
    expect(
      assessDomainAge({ sender: { ...dated('a.example', 1), ageDays: null } }).reasons,
    ).toEqual([]);
    expect(assessDomainAge({ sender: null, links: [] })).toEqual({
      score: 0,
      reasons: [],
      isSpam: false,
      suspicious: false,
    });
    expect(assessDomainAge({})).toEqual({
      score: 0,
      reasons: [],
      isSpam: false,
      suspicious: false,
    });
  });
});
