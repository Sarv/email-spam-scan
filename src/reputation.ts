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

import { isPublicIp, normalizeIp } from './headers/origin-ip.js';
import { assessmentOf, type SpamAssessment, type SpamReason } from './verdict.js';

/** Whether a zone is queried with an IP address or with a domain name. */
export type BlocklistKind = 'ip' | 'domain';

/** What one return code from one zone means, and what it is worth. */
export interface BlocklistCode {
  /** The operator's own description, shown to a reader as part of the reason. */
  meaning: string;
  points: number;
}

/** A zone to query, and how to read what it answers. */
export interface Blocklist {
  /** Stable id, reported in every hit. Yours to choose if you add a zone. */
  name: string;
  /** The DNS zone appended to the reversed address, or to the domain. */
  zone: string;
  kind: BlocklistKind;
  /**
   * Points for a listing whose return code `codes` does not describe.
   * Operators add codes; an unrecognised one is still a listing, and scoring
   * it zero would silently ignore the newest category a list publishes.
   */
  points: number;
  codes?: Readonly<Record<string, BlocklistCode>>;
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

/**
 * A DNS query.
 *
 * Supply one to use a cache, a DoH client, your own resolver pool, or — the
 * reason it exists — a fixture in a test that must never touch a real one.
 *
 * The contract differs from `node:dns` in one deliberate way: **a name that
 * does not exist resolves to an empty array**, and a throw means the lookup
 * genuinely failed. That is the distinction the whole stage turns on, so it
 * is made once, at the boundary, rather than by every caller guessing at
 * resolver error codes.
 */
export type DnsQuery = (name: string, recordType: 'A' | 'TXT') => Promise<string[]>;

export interface ReputationOptions {
  /** Per-query timeout for the built-in resolver. Default 5000ms. */
  timeoutMs?: number;
  /**
   * Also fetch each hit's `TXT` record, which is where operators put the
   * human explanation and the delisting URL. Off by default: it doubles the
   * queries, and it is only worth asking once something is listed.
   */
  includeText?: boolean;
  /** Nameservers for the built-in resolver. Defaults to the system's. */
  servers?: readonly string[];
  /** Your own lookup, in place of `node:dns`. */
  query?: DnsQuery;
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
  kind: 'ip',
  points: 3,
  codes: {
    '127.0.0.2': { meaning: 'SBL: a known source of spam', points: 4 },
    '127.0.0.3': { meaning: 'SBL CSS: an automated snowshoe-spam listing', points: 3 },
    '127.0.0.4': { meaning: 'XBL: an exploited or compromised machine', points: 4 },
    '127.0.0.5': { meaning: 'XBL: an exploited or compromised machine', points: 4 },
    '127.0.0.6': { meaning: 'XBL: an exploited or compromised machine', points: 4 },
    '127.0.0.7': { meaning: 'XBL: an exploited or compromised machine', points: 4 },
    '127.0.0.9': { meaning: 'DROP: a hijacked or spam-operated netblock', points: 4 },
    '127.0.0.10': { meaning: 'PBL: an address that should not deliver mail directly', points: 2 },
    '127.0.0.11': { meaning: 'PBL: an address that should not deliver mail directly', points: 2 },
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
    '127.0.1.2': { meaning: 'a spam domain', points: 4 },
    '127.0.1.4': { meaning: 'a phishing domain', points: 4 },
    '127.0.1.5': { meaning: 'a malware domain', points: 4 },
    '127.0.1.6': { meaning: 'a botnet command-and-control domain', points: 4 },
    '127.0.1.102': { meaning: 'a legitimate domain abused to send spam', points: 2 },
    '127.0.1.103': { meaning: 'a redirector abused to send spam', points: 2 },
    '127.0.1.104': { meaning: 'a legitimate domain abused for phishing', points: 2 },
    '127.0.1.105': { meaning: 'a legitimate domain abused for malware', points: 2 },
    '127.0.1.106': { meaning: 'a legitimate domain abused by a botnet', points: 2 },
  },
};

/** SpamCop — one code, and it means the address was reported by recipients. */
export const SPAMCOP: Blocklist = {
  name: 'spamcop',
  zone: 'bl.spamcop.net',
  kind: 'ip',
  points: 3,
  codes: {
    '127.0.0.2': { meaning: 'reported by recipients as a source of spam', points: 3 },
  },
};

/**
 * The zones this package describes. NOT a default — nothing queries any of
 * them until a caller names it, which is the whole point of the entry.
 */
export const BLOCKLISTS: readonly Blocklist[] = [SPAMHAUS_ZEN, SPAMHAUS_DBL, SPAMCOP];

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

const DEFAULT_TIMEOUT_MS = 5_000;

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
  const label = blocklist.kind === 'ip' ? reverseIpLabel(target) : normalizeQueryDomain(target);
  return label === null ? null : `${label}.${blocklist.zone}`;
}

/** What a zone's answer amounts to: a listing, nothing, or a complaint. */
export interface CodeReading {
  /** The returned codes that are genuinely a listing. */
  listings: string[];
  meanings: string[];
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
  const nothing = { listings: [], meanings: [], points: 0 };

  const complaints = codes.filter((code) => code.startsWith(OPERATOR_ERROR_PREFIX));
  if (complaints.length > 0) {
    const explained = complaints.map(
      (code) => OPERATOR_ERRORS[code] ?? `the zone answered ${code}, an operator error code`,
    );
    return { ...nothing, error: explained.join('; ') };
  }

  const listings = codes.filter(isListingCode);
  if (listings.length === 0) {
    if (codes.length === 0) return { ...nothing, error: null };
    return {
      ...nothing,
      error: `the zone answered ${codes.join(', ')}, which is not a listing`,
    };
  }

  const described = listings.map((code) => blocklist.codes?.[code]);
  return {
    listings,
    meanings: described.flatMap((code) => (code === undefined ? [] : [code.meaning])),
    points: Math.max(...described.map((code) => code?.points ?? blocklist.points)),
    error: null,
  };
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

type NodeResolver = {
  setServers: (servers: string[]) => void;
  resolve4: (name: string) => Promise<string[]>;
  resolveTxt: (name: string) => Promise<string[][]>;
};

type ResolverConstructor = new (options?: { timeout?: number; tries?: number }) => NodeResolver;

/** A name that does not exist is the ordinary answer, and it is not an error. */
function isNameNotFound(cause: unknown): boolean {
  const code = (cause as { code?: unknown } | null | undefined)?.code;
  return code === 'ENOTFOUND' || code === 'ENODATA';
}

/**
 * The built-in resolver: one `node:dns` resolver per call, reused across the
 * zones, with the timeout enforced by c-ares rather than by a race that leaves
 * the query running.
 *
 * `tries: 1` because a blocklist answer that needed a retry has already cost
 * more than it is worth at ingest — the message still has to be delivered.
 */
async function nodeDnsQuery(options: ReputationOptions): Promise<DnsQuery> {
  const { Resolver } = (await import('node:dns/promises')) as unknown as {
    Resolver: ResolverConstructor;
  };
  const resolver = new Resolver({ timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS, tries: 1 });
  if (options.servers !== undefined && options.servers.length > 0) {
    resolver.setServers([...options.servers]);
  }

  return async (name, recordType) => {
    try {
      if (recordType === 'A') return await resolver.resolve4(name);
      return (await resolver.resolveTxt(name)).map((chunks) => chunks.join(''));
    } catch (cause) {
      if (isNameNotFound(cause)) return [];
      throw cause;
    }
  };
}

function reasonFrom(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
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
  const ip = queryableIp(target.ip);
  const domain = normalizeQueryDomain(target.domain);

  const jobs = blocklists.flatMap((blocklist) => {
    const value = blocklist.kind === 'ip' ? ip : domain;
    const name = blocklistQueryName(value, blocklist);
    return value === null || name === null ? [] : [{ blocklist, target: value, name }];
  });

  if (jobs.length === 0) {
    return { ip, domain, listed: false, hits: [], checked: [], errors: [], completed: false };
  }

  const query = options.query ?? (await nodeDnsQuery(options));
  const outcomes = await Promise.all(
    jobs.map((job) => lookupOne(job.blocklist, job.target, job.name, query, options)),
  );

  const hits = outcomes.flatMap((outcome) => (outcome.hit === null ? [] : [outcome.hit]));
  const errors = outcomes.flatMap((outcome) =>
    outcome.error === null
      ? []
      : [{ name: outcome.blocklist.name, zone: outcome.blocklist.zone, error: outcome.error }],
  );

  return {
    ip,
    domain,
    listed: hits.length > 0,
    hits,
    checked: outcomes.flatMap((outcome) =>
      outcome.error === null ? [outcome.blocklist.zone] : [],
    ),
    errors,
    completed: errors.length === 0,
  };
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
 */
export function assessReputation(result: ReputationResult): SpamAssessment {
  const reasons: SpamReason[] = [];

  for (const rule of REPUTATION_RULES) {
    const hits = result.hits.filter((hit) => hit.kind === rule.kind);
    if (hits.length === 0) continue;

    const worst = hits.reduce((best, hit) => (hit.points > best.points ? hit : best));
    const meaning = worst.meanings.length > 0 ? ` (${worst.meanings.join('; ')})` : '';
    const others = hits.length - 1;
    const rest = others > 0 ? ` and ${others} other blocklist${others === 1 ? '' : 's'}` : '';

    reasons.push({
      id: rule.id,
      points: worst.points,
      detail: `${rule.subject} ${worst.target} is listed by ${worst.name}${meaning}${rest}.`,
    });
  }

  return assessmentOf(reasons);
}
