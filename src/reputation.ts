/**
 * `checkReputation(target, blocklists)` — what the DNS blocklists already say
 * about the address a message was delivered from, and about the domain it
 * claims to be.
 *
 * The second of the two entry points that can reach the network, and it is
 * reached the same deliberate way as the first (`verify.ts`): its own entry
 * point, never called by `scan`, with the answer handed back to the scanner as
 * a finished assessment. Nothing that scores a message offline imports this.
 *
 * WHAT A BLOCKLIST QUERY ACTUALLY IS. There is no protocol to speak of: you
 * reverse the octets of an address, append the operator's zone, and ask for an
 * `A` record. `NXDOMAIN` means "not listed". An answer inside `127.0.0.0/8`
 * means "listed", and WHICH address came back is the entire message —
 * Spamhaus returns `127.0.0.2` for a spam source, `127.0.0.4` for a
 * compromised machine and `127.0.0.10` for an address that merely has no
 * business delivering mail directly. Those are three different accusations and
 * they must not score the same.
 *
 * WHY THE PROTOCOL IS HERE AND NOT A DEPENDENCY. `dnsbl` is maintained and
 * popular, and it answers `listed: boolean` — it discards the address that
 * came back. It also collapses every resolver failure into `listed: false`,
 * and queries through public open resolvers by default. Each of those three is
 * a bug in this context: the return code IS the verdict; "could not ask" is
 * not "clean"; and every Spamhaus-family zone answers a query that arrived via
 * an open resolver with `127.255.255.254`, which a boolean reading reports as
 * a listing — scoring every message that passes through a machine whose
 * resolver is misconfigured. So the DNS itself is done by `node:dns`, which is
 * the battle-tested part, and the small pure layer on top of it lives here:
 * name construction, and what a return code means.
 *
 * NODE ONLY, AND ONLY IF YOU ASK. The default resolver is loaded from
 * `node:dns/promises` through a dynamic import, so no bundle carries it and
 * nothing resolves it until a lookup actually happens. A host without
 * `node:dns` supplies its own `query` and never reaches the import.
 *
 * WHAT IT COSTS TO ASK. A blocklist query tells someone else's nameservers
 * which addresses your users receive mail from, one query per message. The
 * public mirrors are rate-limited and, for Spamhaus, restricted by volume and
 * by commercial use — the error codes above exist because operators enforce
 * that. So there is no default list, ever: `blocklists` is a required
 * argument, the catalogue below is data you opt into by naming it, and reading
 * the operator's terms is yours to do.
 */
import ipaddr from 'ipaddr.js';

import { reasonFrom } from './cause.js';
import { nodeDnsQuery, type DnsQuery, type DnsResolverOptions } from './dns.js';
import { isPublicIp, normalizeIp } from './headers/origin-ip.js';
import {
  assessmentOf,
  SPAM_THRESHOLD,
  type SpamAssessment,
  type SpamReason,
  type SpamReasonId,
} from './verdict.js';

/** Whether a zone is queried with an IP address or with a domain name. */
export type BlocklistKind = 'ip' | 'domain';

/**
 * What KIND of accusation a return code is, across zones.
 *
 * Operators each publish their own code table, so `127.0.0.4` from one zone
 * and `127.0.1.5` from another are the same fact written twice. A consumer
 * that wants to say "this sender is a compromised machine" — to group hits, to
 * decide whether to quarantine rather than file, or to apply its own points
 * table — needs that fact, and deriving it from the code would mean copying
 * the catalogue back out of this package.
 *
 * `abused` is the one worth reading twice: a cracked WordPress install or a
 * hijacked shortener is listed, and the domain's owner is a victim rather than
 * the sender. It is deliberately cheap.
 *
 * A code with no category is not an error — it is a listing whose kind this
 * catalogue does not claim to know, and it still scores.
 */
export type BlocklistCategory =
  'spam' | 'exploited' | 'phishing' | 'malware' | 'botnet' | 'policy' | 'abused' | 'grey';

/** What one return code from one zone means, and what it is worth. */
export interface BlocklistCode {
  /** The operator's own description, shown to a reader as part of the reason. */
  meaning: string;
  points: number;
  /** The kind of accusation, for a consumer that groups hits across zones. */
  category?: BlocklistCategory;
}

/** A zone to query, and how to read what it answers. */
export interface Blocklist {
  /** Stable id, reported in every hit. Yours to choose if you add a zone. */
  name: string;
  /** The DNS zone appended to the reversed address, or to the domain. */
  zone: string;
  kind: BlocklistKind;
  /**
   * The zone answers for IPv6 addresses as well as IPv4. Default false, and
   * only meaningful for `kind: 'ip'`.
   *
   * Most operators publish v4 only and answer a 32-nibble query with
   * NXDOMAIN — a round trip spent to learn nothing, on every message from a
   * v6 sender. Declaring the capability is what keeps the query from being
   * made; reading its ABSENCE as "not listed" would be the same mistake in
   * the other direction, so an address no zone can answer for stays unknown.
   */
  ipv6?: boolean;
  /**
   * Points for a listing whose return code `codes` does not describe.
   * Operators add codes; an unrecognised one is still a listing, and scoring
   * it zero would silently ignore the newest category a list publishes.
   */
  points: number;
  /**
   * The zone's published table, read by exact return code. Spamhaus and
   * SpamCop answer this way: one address per category.
   */
  codes?: Readonly<Record<string, BlocklistCode>>;
  /**
   * The zone's published table, read as a BITMASK in the last octet — the
   * other convention, and the one the URI lists use. SURBL answers
   * `127.0.0.24` for a domain that is both phishing (8) and malware (16), and
   * there is no code table on earth that can enumerate the combinations. A
   * zone declares one or the other; `bits` wins where both are set.
   */
  bits?: Readonly<Record<number, BlocklistCode>>;
  /**
   * Answers that mean the OPERATOR declined, published outside
   * `127.255.255.0/24`. The URI lists answer `127.0.0.1` to a query from a
   * public resolver or from a querier over the free-use limit, which is a
   * refusal wearing the clothes of a listing — scoring it would put every
   * sender on a blocklist the moment a resolver was misconfigured.
   *
   * A refusal is only read as one when nothing in the same answer is a
   * listing, so a zone that returns both still reports the listing.
   */
  refusals?: Readonly<Record<string, string>>;
}

/** One zone's answer about one address or domain, when that answer is a listing. */
export interface BlocklistHit {
  name: string;
  zone: string;
  kind: BlocklistKind;
  /** The address or domain that was queried, normalised. */
  target: string;
  /** Every `A` record the zone returned, verbatim. */
  codes: string[];
  /** What the catalogue says those codes mean. Empty when it describes none. */
  meanings: string[];
  /** The kinds of accusation those codes carry. Empty when none is described. */
  categories: BlocklistCategory[];
  /** The most any one of the returned codes is worth. */
  points: number;
  /** The zone's `TXT` record, when `includeText` asked for one. */
  text: string | null;
}

/** A zone that could not be read — an outage, a refusal, an answer that made no sense. */
export interface ReputationLookupError {
  name: string;
  zone: string;
  error: string;
}

/** What to ask about. Either may be absent; an unusable one is skipped, not guessed. */
export interface ReputationTarget {
  /**
   * The address the message was received FROM — `extractOriginIp` produces
   * exactly this. Private, loopback, CGNAT and reserved addresses are skipped:
   * no operator has anything to say about `10.0.0.4`, and asking tells them
   * about your internal topology for nothing.
   */
  ip?: string | null;
  /**
   * The sender's domain, normally its registrable domain — `registrableDomain`
   * from the `/identity` entry. It is queried EXACTLY as passed, because only
   * the caller knows whether a host or its parent is the thing being judged.
   */
  domain?: string | null;
}

/** The shared DNS boundary, re-exported so this entry stands on its own. */
export type { DnsQuery, DnsRecordType, DnsResolverOptions } from './dns.js';

export interface ReputationOptions extends DnsResolverOptions {
  /**
   * Also fetch each hit's `TXT` record, which is where operators put the
   * human explanation and the delisting URL. Off by default: it doubles the
   * queries, and it is only worth asking once something is listed.
   */
  includeText?: boolean;
  /** Your own lookup, in place of `node:dns`. */
  query?: DnsQuery;
}

export interface ReputationBatchOptions extends ReputationOptions {
  /**
   * How many queries may be in flight across the whole batch. Default 8.
   *
   * It is a courtesy limit before it is a performance one: the free mirrors
   * are rate-limited per querier, and a burst is how a resolver earns a
   * `127.255.255.255` for everything that follows. Values below 1 are read as
   * 1 rather than deadlocking.
   */
  concurrency?: number;
}

export interface ReputationResult {
  /** The address actually queried, normalised, or null if none was usable. */
  ip: string | null;
  domain: string | null;
  listed: boolean;
  hits: BlocklistHit[];
  /** The zones that answered — listed or not. */
  checked: string[];
  errors: ReputationLookupError[];
  /**
   * Every lookup that was asked for answered, and at least one was asked.
   *
   * It qualifies the ABSENCE of hits, never their presence: a listing from a
   * zone that answered is evidence whatever else failed, but an empty `hits`
   * with `completed: false` means "nobody could be asked", which is not the
   * same fact as "nobody has anything against this sender".
   */
  completed: boolean;
}

/**
 * Spamhaus ZEN — SBL, XBL and PBL in one zone, queried with an IP address.
 *
 * The codes are the reason this catalogue carries data rather than a list of
 * hostnames. PBL at 2 points is not a smaller version of SBL at 4: a PBL
 * listing says an address is in a range whose operator states it should not be
 * delivering mail directly, which is true of every residential connection on
 * earth and of plenty of legitimately misconfigured servers. SBL and XBL are
 * observations of spam and of compromise.
 *
 * Free use of the public mirror is bounded by volume and excludes some
 * commercial use. Read https://www.spamhaus.org/faq/ before pointing a
 * production ingest at it.
 */
export const SPAMHAUS_ZEN: Blocklist = {
  name: 'spamhaus-zen',
  zone: 'zen.spamhaus.org',
  ipv6: true,
  kind: 'ip',
  points: 3,
  codes: {
    '127.0.0.2': { meaning: 'SBL: a known source of spam', points: 4, category: 'spam' },
    '127.0.0.3': {
      meaning: 'SBL CSS: an automated snowshoe-spam listing',
      points: 3,
      category: 'spam',
    },
    '127.0.0.4': {
      meaning: 'XBL: an exploited or compromised machine',
      points: 4,
      category: 'exploited',
    },
    '127.0.0.5': {
      meaning: 'XBL: an exploited or compromised machine',
      points: 4,
      category: 'exploited',
    },
    '127.0.0.6': {
      meaning: 'XBL: an exploited or compromised machine',
      points: 4,
      category: 'exploited',
    },
    '127.0.0.7': {
      meaning: 'XBL: an exploited or compromised machine',
      points: 4,
      category: 'exploited',
    },
    '127.0.0.9': {
      meaning: 'DROP: a hijacked or spam-operated netblock',
      points: 4,
      category: 'exploited',
    },
    '127.0.0.10': {
      meaning: 'PBL: an address that should not deliver mail directly',
      points: 2,
      category: 'policy',
    },
    '127.0.0.11': {
      meaning: 'PBL: an address that should not deliver mail directly',
      points: 2,
      category: 'policy',
    },
  },
};

/**
 * Spamhaus DBL — domains, not addresses.
 *
 * The `abused legitimate` codes are the interesting half: a compromised
 * WordPress install or a hijacked URL shortener is listed there, and the
 * domain's owner is a victim rather than the sender. Two points, not four.
 */
export const SPAMHAUS_DBL: Blocklist = {
  name: 'spamhaus-dbl',
  zone: 'dbl.spamhaus.org',
  kind: 'domain',
  points: 3,
  codes: {
    '127.0.1.2': { meaning: 'a spam domain', points: 4, category: 'spam' },
    '127.0.1.4': { meaning: 'a phishing domain', points: 4, category: 'phishing' },
    '127.0.1.5': { meaning: 'a malware domain', points: 4, category: 'malware' },
    '127.0.1.6': {
      meaning: 'a botnet command-and-control domain',
      points: 4,
      category: 'botnet',
    },
    '127.0.1.102': {
      meaning: 'a legitimate domain abused to send spam',
      points: 2,
      category: 'abused',
    },
    '127.0.1.103': {
      meaning: 'a redirector abused to send spam',
      points: 2,
      category: 'abused',
    },
    '127.0.1.104': {
      meaning: 'a legitimate domain abused for phishing',
      points: 2,
      category: 'abused',
    },
    '127.0.1.105': {
      meaning: 'a legitimate domain abused for malware',
      points: 2,
      category: 'abused',
    },
    '127.0.1.106': {
      meaning: 'a legitimate domain abused by a botnet',
      points: 2,
      category: 'abused',
    },
  },
  refusals: {
    // DBL answers an IP-shaped query inside its LISTING range rather than in
    // the operator-error range every other refusal uses. Read as a listing it
    // is a false positive of the worst kind: every domain would come back
    // listed the moment a caller asked DBL about an address.
    '127.0.1.255': 'the zone refuses IP queries, which is what this answer means',
  },
};

/** SpamCop — one code, and it means the address was reported by recipients. */
export const SPAMCOP: Blocklist = {
  name: 'spamcop',
  zone: 'bl.spamcop.net',
  kind: 'ip',
  points: 3,
  codes: {
    '127.0.0.2': {
      meaning: 'reported by recipients as a source of spam',
      points: 3,
      category: 'spam',
    },
  },
};

/**
 * Barracuda Reputation — one code, like SpamCop, and read the same way.
 *
 * The catch is not in the answer but in who may ask: the public mirror serves
 * only resolvers whose address has been registered at
 * https://www.barracudacentral.org/account/register. An unregistered querier
 * is answered NXDOMAIN — "not listed" — for every address, so this zone
 * silently contributes nothing until that registration exists. It is in the
 * catalogue because a mail host that has registered wants it, not because it
 * is free to switch on.
 */
export const BARRACUDA: Blocklist = {
  name: 'barracuda',
  zone: 'b.barracudacentral.org',
  kind: 'ip',
  points: 3,
  codes: {
    '127.0.0.2': {
      meaning: 'listed by Barracuda Reputation as a source of spam',
      points: 3,
      category: 'spam',
    },
  },
};

/**
 * SURBL — the domains found INSIDE messages, not the ones that sent them.
 *
 * The first of the two bitmask zones. A domain that is both a phishing site
 * and a malware host comes back as `127.0.0.24`, and the answer has to be read
 * bit by bit; an exact-code table would have to enumerate every combination
 * and would score the combined answer as an unrecognised listing.
 *
 * Free use is for low volume and requires your own resolver: a query arriving
 * from a public resolver is answered `127.0.0.1`, which `refusals` keeps out
 * of the score. See https://surbl.org/usage-policy.
 */
export const SURBL: Blocklist = {
  name: 'surbl',
  zone: 'multi.surbl.org',
  kind: 'domain',
  points: 3,
  bits: {
    8: { meaning: 'a phishing domain', points: 4, category: 'phishing' },
    16: { meaning: 'a malware domain', points: 4, category: 'malware' },
    64: { meaning: 'a cracked site being used to serve spam', points: 3, category: 'abused' },
    128: { meaning: 'a domain advertised in spam', points: 4, category: 'spam' },
  },
  refusals: {
    '127.0.0.1': 'the zone declined the query, which is what it answers a public resolver',
  },
};

/**
 * URIBL — the other URI list, and the other bitmask.
 *
 * `grey` is the reason the bits matter: URIBL's grey list is bulk senders of
 * dubious value rather than spam, and at 2 points it is a nudge, not a
 * verdict. Reading a grey listing as "listed" would file legitimate marketing
 * mail as spam on one list's opinion.
 *
 * Free use is capped by volume and by querier; over the limit, or through a
 * public resolver, the answer is `127.0.0.1`. See https://uribl.com/about.shtml.
 */
export const URIBL: Blocklist = {
  name: 'uribl',
  zone: 'multi.uribl.com',
  kind: 'domain',
  points: 3,
  bits: {
    2: { meaning: 'URIBL black: a domain sent in spam', points: 4, category: 'spam' },
    4: { meaning: 'URIBL grey: a bulk sender of dubious value', points: 2, category: 'grey' },
    8: { meaning: 'URIBL red: a domain seen in a live spam run', points: 4, category: 'spam' },
  },
  refusals: {
    '127.0.0.1': 'the zone refused the query, which is what it answers over the free-use limit',
  },
};

/**
 * The zones this package describes. NOT a default — nothing queries any of
 * them until a caller names it, which is the whole point of the entry.
 */
export const BLOCKLISTS: readonly Blocklist[] = [
  SPAMHAUS_ZEN,
  SPAMHAUS_DBL,
  SPAMCOP,
  BARRACUDA,
  SURBL,
  URIBL,
];

/**
 * `127.255.255.0/24` — the operator talking to YOU, not answering about the
 * address. Reading one of these as a listing is the single most expensive
 * mistake this module can make: a misconfigured resolver would put every
 * sender on a blocklist at once.
 */
const OPERATOR_ERRORS: Readonly<Record<string, string>> = {
  '127.255.255.252': 'the zone rejected the query as malformed or wrongly typed',
  '127.255.255.254': 'the query arrived via a public or open resolver, which the operator refuses',
  '127.255.255.255': "the querier is over the operator's volume limit",
};

const OPERATOR_ERROR_PREFIX = '127.255.255.';

/** Longest a domain name can be, so a hostile input cannot become a long regex run. */
const MAX_DOMAIN_LENGTH = 253;

const DOMAIN_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

/** Queries in flight across a batch, when the caller does not say. */
const DEFAULT_CONCURRENCY = 8;

/**
 * The most the whole reputation stage may add to a message by default.
 *
 * `SPAM_THRESHOLD + 1`: enough that a listed sender is spam on this evidence
 * alone, and no more. Without a cap an address listed by one zone and a
 * domain listed by another reach eight points, which is not "spam twice" —
 * it is one stage deciding the verdict on its own and leaving no room for
 * the message itself to disagree.
 */
export const REPUTATION_MAX_POINTS = SPAM_THRESHOLD + 1;

/**
 * How many other recipients must have reported a sender before it counts.
 *
 * Three. One report is one opinion — a reader who finds a newsletter
 * annoying reports it, and that is a fact about the reader. Three
 * independent ones are the smallest number that says something about the
 * sender instead.
 */
export const USER_REPORTS_MIN = 3;

/**
 * What a sender other recipients are reporting is worth.
 *
 * Three: real evidence, and deliberately short of the threshold on its own.
 * A crowd's opinion is not an operator's observation, and a crowd can be
 * confidently wrong about a sender it merely dislikes.
 */
export const USER_REPORT_POINTS = 3;

/**
 * The label an address is queried under: its octets, reversed.
 *
 * Returns null for anything a blocklist cannot answer about — an unparseable
 * address, or a private, loopback, link-local, CGNAT or otherwise reserved
 * one. `isPublicIp` is the same gate `extractOriginIp` applies, so the
 * addresses this stage asks about are exactly the addresses that stage
 * reports.
 */
export function reverseIpLabel(candidate: string | null | undefined): string | null {
  const ip = normalizeIp(candidate);
  if (ip === null || !isPublicIp(ip)) return null;
  if (!ip.includes(':')) return ip.split('.').reverse().join('.');
  // IPv6 is queried as 32 reversed nibbles. `normalizeIp` has already proved
  // the address parses, and mapped IPv4 came back without a colon above.
  const nibbles = ipaddr.IPv6.parse(ip)
    .parts.map((part) => part.toString(16).padStart(4, '0'))
    .join('');
  return [...nibbles].reverse().join('.');
}

/**
 * A domain in the form a zone is queried with: lowercase, no trailing dot.
 *
 * Null for anything that is not a dotted hostname, which keeps an address, a
 * URL, a display name or an empty string from being turned into a query that
 * would leak it to the operator and answer nothing.
 */
export function normalizeQueryDomain(candidate: string | null | undefined): string | null {
  const domain = (candidate ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (domain.length === 0 || domain.length > MAX_DOMAIN_LENGTH) return null;
  return DOMAIN_PATTERN.test(domain) ? domain : null;
}

/** The full name a lookup is made against, or null when the target is unusable. */
export function blocklistQueryName(
  target: string | null | undefined,
  blocklist: Blocklist,
): string | null {
  if (blocklist.kind !== 'ip') {
    const domain = normalizeQueryDomain(target);
    return domain === null ? null : `${domain}.${blocklist.zone}`;
  }
  // A zone that has not said it answers for IPv6 is not asked, rather than
  // asked and told NXDOMAIN by a nameserver that has never heard of v6.
  if (blocklist.ipv6 !== true && (normalizeIp(target)?.includes(':') ?? false)) return null;
  const label = reverseIpLabel(target);
  return label === null ? null : `${label}.${blocklist.zone}`;
}

/** What a zone's answer amounts to: a listing, nothing, or a complaint. */
export interface CodeReading {
  /** The returned codes that are genuinely a listing. */
  listings: string[];
  meanings: string[];
  /** The kinds of accusation those codes carry, where the table names one. */
  categories: BlocklistCategory[];
  /** The most any one listing code is worth. Zero when nothing was listed. */
  points: number;
  /** Set when the answer was not about the address at all. */
  error: string | null;
}

/**
 * Read one zone's `A` records.
 *
 * Three outcomes, and keeping them apart is the job: nothing (not listed), a
 * listing worth points, or an operator error that must never be scored. An
 * answer outside `127.0.0.0/8` is in the last category — no list publishes a
 * listing there, so it is a hijacked response or a wildcard resolver, and
 * either way it is not evidence about the sender.
 */
export function readBlocklistCodes(blocklist: Blocklist, codes: readonly string[]): CodeReading {
  const nothing = { listings: [], meanings: [], categories: [], points: 0 };

  const complaints = codes.filter((code) => code.startsWith(OPERATOR_ERROR_PREFIX));
  if (complaints.length > 0) {
    const explained = complaints.map(
      (code) => OPERATOR_ERRORS[code] ?? `the zone answered ${code}, an operator error code`,
    );
    return { ...nothing, error: explained.join('; ') };
  }

  // A code the zone has DECLARED a refusal is never a listing, wherever in
  // 127.0.0.0/8 the operator chose to publish it — DBL puts one in the middle
  // of its listing range. It is still only read as a refusal when nothing
  // else in the same answer is a listing, just below.
  const refusals = blocklist.refusals ?? {};
  const listings = codes.filter((code) => isListingCode(code) && refusals[code] === undefined);
  if (listings.length === 0) {
    if (codes.length === 0) return { ...nothing, error: null };
    // A zone that publishes its refusal inside 127.0.0.0/8 gets to say so in
    // its own words; everything else is a wildcard or a hijacked answer.
    const refused = codes.flatMap((code) => refusals[code] ?? []);
    if (refused.length > 0) return { ...nothing, error: [...new Set(refused)].join('; ') };
    return {
      ...nothing,
      error: `the zone answered ${codes.join(', ')}, which is not a listing`,
    };
  }

  const described = describeListings(blocklist, listings);
  return {
    listings,
    meanings: described.flatMap((code) => (code === undefined ? [] : [code.meaning])),
    categories: described.flatMap((code) => (code?.category === undefined ? [] : [code.category])),
    points: Math.max(...described.map((code) => code?.points ?? blocklist.points)),
    error: null,
  };
}

/**
 * What the zone's table says about the codes that came back.
 *
 * `undefined` in the result is not a failure: it is a listing the table does
 * not describe, which still scores the zone's own `points` rather than
 * nothing. Operators add codes faster than catalogues are updated, and a new
 * category must not arrive as an all-clear.
 */
function describeListings(
  blocklist: Blocklist,
  listings: readonly string[],
): (BlocklistCode | undefined)[] {
  const { bits } = blocklist;
  if (bits === undefined) return listings.map((code) => blocklist.codes?.[code]);

  // A bitmask zone may answer with several records OR with one combined
  // octet, and they mean the same thing — so OR them together and read the
  // bits, rather than looking up either form as an address.
  const mask = listings.reduce((total, code) => total | lastOctet(code), 0);
  const matched = Object.entries(bits).flatMap(([bit, described]) =>
    (mask & Number(bit)) === 0 ? [] : [described],
  );
  return matched.length > 0 ? matched : [undefined];
}

/** The last label of a dotted quad as a number. Unreadable reads as 0, which matches no bit. */
function lastOctet(code: string): number {
  return Number(code.split('.').pop()) | 0;
}

/**
 * `127.0.0.1` is excluded on purpose. No operator publishes a listing there —
 * it is what a few of them answer to a query they could not make sense of, and
 * what a resolver that rewrites NXDOMAIN sometimes substitutes.
 */
function isListingCode(code: string): boolean {
  return code.startsWith('127.') && code !== '127.0.0.1';
}

/** The address a hit is about, and the shape `Promise.all` collects per zone. */
interface Outcome {
  blocklist: Blocklist;
  hit: BlocklistHit | null;
  error: string | null;
}

async function lookupOne(
  blocklist: Blocklist,
  target: string,
  name: string,
  query: DnsQuery,
  options: ReputationOptions,
): Promise<Outcome> {
  let codes: string[];
  try {
    codes = await query(name, 'A');
  } catch (cause) {
    return { blocklist, hit: null, error: reasonFrom(cause) };
  }

  const reading = readBlocklistCodes(blocklist, codes);
  if (reading.error !== null) return { blocklist, hit: null, error: reading.error };
  if (reading.listings.length === 0) return { blocklist, hit: null, error: null };

  return {
    blocklist,
    error: null,
    hit: {
      name: blocklist.name,
      zone: blocklist.zone,
      kind: blocklist.kind,
      target,
      codes: reading.listings,
      meanings: reading.meanings,
      categories: reading.categories,
      points: reading.points,
      text: options.includeText === true ? await explanationFor(name, query) : null,
    },
  };
}

/**
 * The `TXT` record behind a listing — the operator's sentence and delisting
 * URL. A missing or failing one is not a failed lookup: the listing is already
 * established, and losing the explanation must not turn a hit into an error.
 */
async function explanationFor(name: string, query: DnsQuery): Promise<string | null> {
  try {
    const records = await query(name, 'TXT');
    return records.length > 0 ? records.join(' ') : null;
  } catch {
    return null;
  }
}

/** The address as it will be reported and queried, or null if it cannot be. */
function queryableIp(candidate: string | null | undefined): string | null {
  const ip = normalizeIp(candidate);
  return ip !== null && isPublicIp(ip) ? ip : null;
}

/**
 * Ask each blocklist about the target.
 *
 * Never rejects. A zone that times out, refuses or answers nonsense lands in
 * `errors` and leaves `completed` false; the zones that did answer are still
 * reported, because one operator's outage is not a reason to discard another
 * operator's listing.
 *
 * @param blocklists required, and deliberately so — see the note at the top of
 *   this file. Nothing here has a default zone, because a default would make
 *   somebody else's nameservers a dependency of merely calling the function.
 */
export async function checkReputation(
  target: ReputationTarget,
  blocklists: readonly Blocklist[],
  options: ReputationOptions = {},
): Promise<ReputationResult> {
  const plan = planLookups(target, blocklists);
  if (plan.jobs.length === 0) return nothingAsked(plan);

  const query = options.query ?? (await nodeDnsQuery(options));
  return runPlan(plan, query, unlimited, options);
}

/**
 * Ask about many targets at once, over one resolver and a bounded number of
 * queries in flight.
 *
 * WHY THIS EXISTS RATHER THAN A LOOP. A caller with a backlog — a mailbox
 * being scored after the fact, a queue drained on a timer — has hundreds of
 * addresses and six zones, and the two obvious shapes are both wrong.
 * Sequential is an hour of DNS round-trips; `Promise.all` over the lot opens
 * a thousand simultaneous queries, which c-ares will not serve, the operator
 * will read as an attack, and a home router will drop on the floor. The pool
 * is the only version that finishes and stays welcome.
 *
 * Results come back in the order the targets were given, so a caller can zip
 * them against its own rows. Like `checkReputation` it never rejects: a
 * target nobody could be asked about is a result with `completed: false`.
 */
export async function checkReputationBatch(
  targets: readonly ReputationTarget[],
  blocklists: readonly Blocklist[],
  options: ReputationBatchOptions = {},
): Promise<ReputationResult[]> {
  const plans = targets.map((target) => planLookups(target, blocklists));
  if (plans.every((plan) => plan.jobs.length === 0)) return plans.map(nothingAsked);

  const query = options.query ?? (await nodeDnsQuery(options));
  const limit = limiterFor(options.concurrency ?? DEFAULT_CONCURRENCY);
  return Promise.all(
    plans.map((plan) =>
      plan.jobs.length === 0 ? nothingAsked(plan) : runPlan(plan, query, limit, options),
    ),
  );
}

/** One target's usable values and the queries they turn into. */
interface LookupPlan {
  ip: string | null;
  domain: string | null;
  jobs: { blocklist: Blocklist; target: string; name: string }[];
}

/** Which zones can actually be asked about this target, and under what name. */
function planLookups(target: ReputationTarget, blocklists: readonly Blocklist[]): LookupPlan {
  const ip = queryableIp(target.ip);
  const domain = normalizeQueryDomain(target.domain);

  const jobs = blocklists.flatMap((blocklist) => {
    const value = blocklist.kind === 'ip' ? ip : domain;
    const name = blocklistQueryName(value, blocklist);
    return value === null || name === null ? [] : [{ blocklist, target: value, name }];
  });

  return { ip, domain, jobs };
}

/**
 * Nothing was asked, so nothing is known. `completed: false` is the whole
 * point: an empty `hits` here must never read as an all-clear.
 */
function nothingAsked(plan: LookupPlan): ReputationResult {
  return {
    ip: plan.ip,
    domain: plan.domain,
    listed: false,
    hits: [],
    checked: [],
    errors: [],
    completed: false,
  };
}

async function runPlan(
  plan: LookupPlan,
  query: DnsQuery,
  limit: Limiter,
  options: ReputationOptions,
): Promise<ReputationResult> {
  const outcomes = await Promise.all(
    plan.jobs.map((job) =>
      limit(() => lookupOne(job.blocklist, job.target, job.name, query, options)),
    ),
  );

  const hits = outcomes.flatMap((outcome) => (outcome.hit === null ? [] : [outcome.hit]));
  const errors = outcomes.flatMap((outcome) =>
    outcome.error === null
      ? []
      : [{ name: outcome.blocklist.name, zone: outcome.blocklist.zone, error: outcome.error }],
  );

  return {
    ip: plan.ip,
    domain: plan.domain,
    listed: hits.length > 0,
    hits,
    checked: outcomes.flatMap((outcome) =>
      outcome.error === null ? [outcome.blocklist.zone] : [],
    ),
    errors,
    completed: errors.length === 0,
  };
}

/** Runs a task, perhaps after waiting for a slot. */
type Limiter = <T>(task: () => Promise<T>) => Promise<T>;

/** One target's worth of queries is already a handful; nothing to schedule. */
const unlimited: Limiter = (task) => task();

/**
 * A slot counter with a FIFO queue of waiters.
 *
 * Hand-rolled rather than depending on `p-limit`, and deliberately: it is
 * nine lines, it is the only scheduling this package does, and a reputation
 * entry that costs a browser bundle `ipaddr.js` and nothing else is a
 * promise worth keeping.
 */
function limiterFor(concurrency: number): Limiter {
  const slots = Math.max(1, Math.floor(concurrency));
  const waiting: (() => void)[] = [];
  let active = 0;

  return async <T>(task: () => Promise<T>): Promise<T> => {
    if (active >= slots) await new Promise<void>((resolve) => waiting.push(resolve));
    active += 1;
    try {
      return await task();
    } finally {
      active -= 1;
      // Hand the slot to the next waiter rather than letting it re-check, so
      // a queue cannot stall behind a task that finished while it slept.
      const next = waiting.shift();
      if (next !== undefined) next();
    }
  };
}

export interface AssessReputationOptions {
  /**
   * The ceiling on everything this stage adds together. Default
   * `REPUTATION_MAX_POINTS`. Pass `Infinity` to score each listing in full.
   */
  maxPoints?: number;
  /**
   * How many OTHER recipients have reported mail from this sender's domain as
   * spam, if the caller is a host that counts such things.
   *
   * An option rather than something the lookup produces, because nothing here
   * can discover it: it comes from whoever holds the mailboxes, not from the
   * DNS. Ignored when the result carries no domain — a report is a report
   * about a named sender, and with no name to put to it there is nothing to
   * tell the reader.
   */
  userReports?: number;
  /**
   * Reports needed before they are charged for. Default
   * {@link USER_REPORTS_MIN}.
   */
  minUserReports?: number;
}

const REPUTATION_RULES = [
  { kind: 'ip', id: 'reputation-ip-listed', subject: 'The sending address' },
  { kind: 'domain', id: 'reputation-domain-listed', subject: 'The sender domain' },
] as const;

/**
 * Score a reputation result.
 *
 * THE HIGHEST HIT, NOT THE SUM. Three zones listing the same address is not
 * three pieces of evidence: the public lists mirror and feed each other, and
 * ZEN is itself three lists in a trenchcoat. Summing would let one observation
 * be charged for as many times as a caller happened to configure zones, which
 * would make the score a function of the deployment rather than of the
 * message. The IP and the domain ARE independent, and do add up.
 *
 * A listing is scored whether or not the run `completed` — a zone that
 * answered told the truth about what it holds, whatever happened to the
 * zone next to it.
 *
 * `options.userReports` adds the one piece of evidence a lookup cannot find:
 * how many other recipients have already reported this sender. It is charged
 * last, out of whatever the listings left.
 */
export function assessReputation(
  result: ReputationResult,
  options: AssessReputationOptions = {},
): SpamAssessment {
  const budget = options.maxPoints ?? REPUTATION_MAX_POINTS;
  const reasons: SpamReason[] = [];
  let spent = 0;

  // The address is charged first, the domain takes what is left of the budget
  // and the reports take what is left after that, so the reason that gets
  // truncated is always the weaker half of the evidence.
  const charge = (id: SpamReasonId, points: number, detail: string): void => {
    const charged = Math.min(points, budget - spent);
    if (charged <= 0) return;
    spent += charged;
    reasons.push({ id, points: charged, detail });
  };

  for (const rule of REPUTATION_RULES) {
    const hits = result.hits.filter((hit) => hit.kind === rule.kind);
    if (hits.length === 0) continue;

    const worst = hits.reduce((best, hit) => (hit.points > best.points ? hit : best));
    const meaning = worst.meanings.length > 0 ? ` (${worst.meanings.join('; ')})` : '';
    const others = hits.length - 1;
    const rest = others > 0 ? ` and ${others} other blocklist${others === 1 ? '' : 's'}` : '';

    charge(
      rule.id,
      worst.points,
      `${rule.subject} ${worst.target} is listed by ${worst.name}${meaning}${rest}.`,
    );
  }

  const reports = options.userReports ?? 0;
  if (result.domain !== null && reports >= (options.minUserReports ?? USER_REPORTS_MIN)) {
    const who = reports === 1 ? 'recipient has' : 'recipients have';
    charge(
      'reputation-user-reported',
      USER_REPORT_POINTS,
      `${reports} other ${who} reported mail from ${result.domain} as spam.`,
    );
  }

  return assessmentOf(reasons);
}
