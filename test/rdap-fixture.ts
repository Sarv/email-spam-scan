/**
 * Real RDAP answers, trimmed to what the age lookup reads.
 *
 * Both domains are from the "Adobe Acrobat Sign" lure of 2026-09-23 (see
 * `phish-fixture.ts`): `powersublinks.com` sent it, `kuaiyudh.top` is where
 * every link went. Registry data is public, and these two are the evidence,
 * so nothing here is redacted. The bootstrap is a slice of IANA's file with
 * the shapes the resolver has to cope with: a URL with no trailing slash, a
 * registry on plain HTTP, one that lists both, and one that lists nothing.
 */
import type { RdapBootstrap } from '../src/age.js';

export const BOOTSTRAP: RdapBootstrap = {
  publication: '2026-09-16T19:00:03Z',
  services: [
    [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
    [['top'], ['https://rdap.zdnsgtld.com/top/']],
    [['in'], ['https://rdap.nixiregistry.in/rdap/']],
    [['de'], ['https://rdap.denic.de']],
    [['kg'], ['http://rdap.cctld.kg/']],
    [['both'], ['http://plain.example/', 'https://secure.example/']],
    [['none'], []],
  ],
};

/** As IANA serves it: the bootstrap file is JSON text on the wire. */
export const BOOTSTRAP_JSON: string = JSON.stringify({ version: '1.0', ...BOOTSTRAP });

/** `.top` registry, 2026-09-23. Five days old when the lure arrived. */
export const KUAIYUDH_TOP = {
  objectClassName: 'domain',
  ldhName: 'kuaiyudh.top',
  handle: 'D20260918G10001G_85961047-top',
  status: ['client transfer prohibited'],
  events: [
    { eventAction: 'registration', eventDate: '2026-09-17T23:11:55.0Z' },
    { eventAction: 'expiration', eventDate: '2027-09-17T23:11:55.0Z' },
    { eventAction: 'last changed', eventDate: '2026-09-23T08:37:07.0Z' },
    { eventAction: 'last update of RDAP database', eventDate: '2026-09-23T11:35:19.0Z' },
  ],
  entities: [
    {
      roles: ['registrant'],
      handle: 'C20260923C_09679415-top',
      vcardArray: ['vcard', [['fn', {}, 'text', '']]],
    },
    {
      roles: ['registrar'],
      handle: '1068',
      vcardArray: ['vcard', [['fn', {}, 'text', 'Namecheap Inc.']]],
    },
  ],
};

/** Verisign's `.com` registry, 2026-09-23. Seventy-eight days old when the lure arrived. */
export const POWERSUBLINKS_COM = {
  objectClassName: 'domain',
  ldhName: 'POWERSUBLINKS.COM',
  status: ['client transfer prohibited'],
  events: [
    { eventAction: 'registration', eventDate: '2026-07-06T13:37:38Z' },
    { eventAction: 'expiration', eventDate: '2027-07-06T13:37:38Z' },
    { eventAction: 'last changed', eventDate: '2026-07-06T13:51:07Z' },
  ],
  entities: [
    {
      objectClassName: 'entity',
      handle: '472',
      roles: ['registrar'],
      vcardArray: [
        'vcard',
        [
          ['version', {}, 'text', '4.0'],
          ['fn', {}, 'text', 'Dynadot Inc'],
        ],
      ],
    },
  ],
};

/** The moment the lure arrived, as `options.now` — unix milliseconds. */
export const LURE_ARRIVED_MS: number = Date.parse('2026-09-23T03:57:07Z');
