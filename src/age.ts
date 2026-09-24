/**
 * `lookupDomainAge(domain)` — when a domain was registered, from the registry's
 * own record, and `assessDomainAge` to score what that says about a message.
 *
 * WHY AGE. The lure that motivated this — "Adobe Acrobat Sign", every link to
 * kuaiyudh.top — was sent from a domain registered 78 days earlier and linked
 * to one registered FIVE days earlier. Neither was on any blocklist, and a
 * blocklist cannot list what nobody has reported yet: fresh registration is
 * the one fact about a phishing domain that is true from the moment it is
 * used, which is exactly the window in which blocklists are blind. A
 * legitimate business is occasionally a week old too, so this is evidence
 * that corroborates, never a verdict — see `DOMAIN_AGE_MAX_POINTS`.
 *
 * WHERE THE DATE COMES FROM. RDAP (RFC 7480–7484, RFC 9083) is the registries'
 * own JSON service, the successor to port-43 WHOIS: mandatory for every gTLD
 * since 2019, free, unauthenticated, one HTTPS GET per domain. IANA publishes
 * which server answers for which TLD (the "bootstrap" file), so a lookup is
 * two requests the first time and one thereafter. Many ccTLDs publish no RDAP
 * service and some registries publish no registration date; both read as
 * `unsupported`, which scores nothing. Port-43 WHOIS is deliberately not
 * attempted: unstructured, rate-limited, blocked on many networks, and every
 * registry formats it differently.
 *
 * WHAT IT COSTS TO ASK. Every lookup tells a registry which domain your user
 * received mail from, and registries rate-limit. Nothing here caches — the
 * caller owns that, and a registration date never changes, so a caller should
 * remember an answer for weeks rather than hours. Like every other networked
 * entry the HTTPS boundary is injected (`options.fetch`), so a test hands in a
 * table and a client hands in its proxy-aware fetch.
 *
 * FAIL OPEN, ALWAYS. A registry that is down, a TLD with no RDAP, a record
 * with no date: each is `status !== 'ok'` and adds nothing. "Could not ask" is
 * not "new", and it is not "old" either. `lookupDomainAge` does not throw.
 */
import { defaultFetch, readBounded, type FetchLike } from './brand/fetch.js';
import { reasonFrom } from './cause.js';
import { registrableDomain } from './identity.js';
import {
  assessmentOf,
  SPAM_THRESHOLD,
  type SpamAssessment,
  type SpamReason,
  type SpamReasonId,
} from './verdict.js';

/** IANA's RDAP bootstrap registry for domain names (RFC 7484). */
export const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

/**
 * The most this entry reads from any one response. The bootstrap file is
 * about 70 KB and a domain object a few KB; anything approaching this is not
 * an RDAP answer.
 */
export const RDAP_MAX_BYTES = 512 * 1024;

/**
 * The bootstrap file, as IANA publishes it: each entry is a list of TLDs and
 * the list of base URLs that serve them.
 */
export interface RdapBootstrap {
  services: ReadonlyArray<readonly [readonly string[], readonly string[]]>;
  publication?: string;
}

/** What one lookup established. */
export type DomainAgeStatus = 'ok' | 'unsupported' | 'not-found' | 'error';

export interface DomainAgeLookup {
  /** The registrable domain that was asked about, lower-cased. */
  domain: string;
  status: DomainAgeStatus;
  /** The registration event, unix SECONDS; null unless `status` is `ok`. */
  registered: number | null;
  /** Whole days between registration and `now`, never negative; null unless `ok`. */
  ageDays: number | null;
  /** The registrar's name as the record gives it, when it gives one. */
  registrar: string | null;
  /** The RDAP base URL that was asked, once one was chosen. */
  server: string | null;
  /** Why the status is not `ok`, in a sentence; null when it is. */
  detail: string | null;
}

export interface DomainAgeOptions {
  /** The HTTPS boundary. Defaults to the platform `fetch`. */
  fetch?: FetchLike;
  /**
   * The bootstrap registry, if the caller already holds it. Omit it and the
   * lookup fetches IANA's file itself — on EVERY call, so a caller doing more
   * than one lookup should fetch it once with {@link fetchRdapBootstrap} and
   * pass it in. `null` says "I tried and could not get it", which the lookup
   * reports as an error rather than trying again.
   */
  bootstrap?: RdapBootstrap | null;
  /** The clock, unix MILLISECONDS. Injected for tests. */
  now?: number;
}

const isStringList = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === 'string');

function isBootstrap(value: unknown): value is RdapBootstrap {
  const services = (value as { services?: unknown } | null)?.services;
  return (
    Array.isArray(services) &&
    services.every(
      (entry) =>
        Array.isArray(entry) &&
        entry.length >= 2 &&
        isStringList(entry[0]) &&
        isStringList(entry[1]),
    )
  );
}

/** Read a body as text, or null when it is too big to be an RDAP answer. */
async function readText(response: Awaited<ReturnType<FetchLike>>): Promise<string | null> {
  const bytes = await readBounded(response, RDAP_MAX_BYTES);
  return bytes === null ? null : new TextDecoder().decode(bytes);
}

/**
 * IANA's bootstrap file, or null when it could not be fetched or is not the
 * file it should be. Never throws.
 */
export async function fetchRdapBootstrap(
  fetch: FetchLike = defaultFetch(),
): Promise<RdapBootstrap | null> {
  try {
    const response = await fetch(RDAP_BOOTSTRAP_URL);
    if (!response.ok) return null;
    const text = await readText(response);
    if (text === null) return null;
    const parsed: unknown = JSON.parse(text);
    return isBootstrap(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The RDAP base URL that serves a domain's TLD, with its trailing slash, or
 * null when the bootstrap names none.
 *
 * HTTPS is preferred where a registry lists both. A few ccTLD registries
 * publish plain HTTP only; that is accepted, because the worst an on-path
 * forgery can do to THIS check is make a new domain look old — which loses
 * points, never adds them.
 */
export function rdapServerFor(domain: string, bootstrap: RdapBootstrap): string | null {
  const tld = domain.slice(domain.lastIndexOf('.') + 1).toLowerCase();
  for (const [tlds, urls] of bootstrap.services) {
    if (!tlds.some((candidate) => candidate.toLowerCase() === tld)) continue;
    const url = urls.find((candidate) => candidate.startsWith('https://')) ?? urls[0];
    if (url === undefined) return null;
    return url.endsWith('/') ? url : `${url}/`;
  }
  return null;
}

interface RdapEvent {
  eventAction?: unknown;
  eventDate?: unknown;
}

/** The `registration` event's date, as the record wrote it, if the record has one. */
function registrationDate(record: unknown): string | null {
  const events = (record as { events?: unknown } | null)?.events;
  if (!Array.isArray(events)) return null;
  for (const event of events as RdapEvent[]) {
    if (event?.eventAction === 'registration' && typeof event.eventDate === 'string') {
      return event.eventDate;
    }
  }
  return null;
}

interface RdapEntity {
  roles?: unknown;
  vcardArray?: unknown;
}

/** The registrar's `fn` from its vCard, when the record carries a registrar entity that names itself. */
function registrarName(record: unknown): string | null {
  const entities = (record as { entities?: unknown } | null)?.entities;
  if (!Array.isArray(entities)) return null;
  for (const entity of entities as RdapEntity[]) {
    if (!isStringList(entity?.roles) || !entity.roles.includes('registrar')) continue;
    const card = Array.isArray(entity.vcardArray) ? entity.vcardArray[1] : undefined;
    if (!Array.isArray(card)) continue;
    for (const property of card as unknown[]) {
      if (Array.isArray(property) && property[0] === 'fn' && typeof property[3] === 'string') {
        const name = property[3].trim();
        if (name) return name;
      }
    }
  }
  return null;
}

/**
 * Look one domain up. Never throws: every failure is a `status` and a
 * `detail`, and none of them scores.
 */
export async function lookupDomainAge(
  domain: string | null | undefined,
  options: DomainAgeOptions = {},
): Promise<DomainAgeLookup> {
  const registrable = registrableDomain(domain);
  const base: Omit<DomainAgeLookup, 'status' | 'detail'> = {
    domain: registrable ?? (domain ?? '').trim().toLowerCase(),
    registered: null,
    ageDays: null,
    registrar: null,
    server: null,
  };
  if (!registrable) return { ...base, status: 'unsupported', detail: 'Not a registrable domain' };

  const fetch = options.fetch ?? defaultFetch();
  const bootstrap =
    options.bootstrap === undefined ? await fetchRdapBootstrap(fetch) : options.bootstrap;
  if (!bootstrap) {
    return { ...base, status: 'error', detail: 'The RDAP bootstrap registry could not be read' };
  }
  const server = rdapServerFor(registrable, bootstrap);
  if (!server) {
    const tld = registrable.slice(registrable.lastIndexOf('.') + 1);
    return { ...base, status: 'unsupported', detail: `No RDAP service is published for .${tld}` };
  }

  try {
    // `tldts` has already validated the hostname, so the URL parser cannot
    // refuse it; it is here because RDAP writes an IDN as its A-label, and the
    // URL parser is the one punycode encoder every runtime has.
    const ldh = new URL(`http://${registrable}`).hostname;
    const response = await fetch(`${server}domain/${ldh}`);
    if (response.status === 404) {
      return {
        ...base,
        server,
        status: 'not-found',
        detail: 'The registry has no record of this domain',
      };
    }
    if (!response.ok) {
      return {
        ...base,
        server,
        status: 'error',
        detail: `The RDAP server answered ${response.status}`,
      };
    }
    const text = await readText(response);
    if (text === null) {
      return { ...base, server, status: 'error', detail: 'The RDAP record is too large to be one' };
    }
    let record: unknown;
    try {
      record = JSON.parse(text);
    } catch {
      return { ...base, server, status: 'error', detail: 'The RDAP record is not JSON' };
    }

    const date = registrationDate(record);
    if (date === null) {
      return {
        ...base,
        server,
        status: 'unsupported',
        detail: 'The registry publishes no registration date for this domain',
      };
    }
    const registeredMs = Date.parse(date);
    if (Number.isNaN(registeredMs)) {
      return {
        ...base,
        server,
        status: 'error',
        detail: `The registration date "${date}" is unreadable`,
      };
    }
    const now = options.now ?? Date.now();
    return {
      domain: registrable,
      status: 'ok',
      registered: Math.floor(registeredMs / 1000),
      // A registration "in the future" is clock skew between here and the
      // registry, and a domain registered today is as new as they come.
      ageDays: Math.max(0, Math.floor((now - registeredMs) / 86_400_000)),
      registrar: registrarName(record),
      server,
      detail: null,
    };
  } catch (cause) {
    // The network, or a body that broke off mid-read. Either way: could not ask.
    return {
      ...base,
      server,
      status: 'error',
      detail: `The RDAP lookup failed: ${reasonFrom(cause)}`,
    };
  }
}

// ----------------------------------------------------------------- scoring

/**
 * What an age is worth. Under a week is the campaign domain: registered,
 * used, burned. Under a month is still far younger than almost any sender a
 * mailbox hears from. Under three months is worth a point in company. Each
 * tier is read as "younger than", so a domain exactly 7 days old is in the
 * second tier.
 */
export const DOMAIN_AGE_TIERS: ReadonlyArray<{ underDays: number; points: number }> = [
  { underDays: 7, points: 3 },
  { underDays: 30, points: 2 },
  { underDays: 90, points: 1 },
];

/**
 * `SPAM_THRESHOLD - 1`: age alone can never file a message. A start-up's first
 * mail from its first domain to its first prospect is every signal here at
 * once, and it is not spam — it needs a second kind of evidence, which the
 * header and content stages supply when there is any.
 */
export const DOMAIN_AGE_MAX_POINTS = SPAM_THRESHOLD - 1;

/** The points an age earns on its own, before any cap. */
export function domainAgePoints(ageDays: number): number {
  for (const tier of DOMAIN_AGE_TIERS) {
    if (ageDays < tier.underDays) return tier.points;
  }
  return 0;
}

/** The lookups one message's domains produced: the sender's, and the ones it links to. */
export interface DomainAgeSubjects {
  sender?: DomainAgeLookup | null;
  links?: readonly DomainAgeLookup[];
}

export interface AssessDomainAgeOptions {
  /**
   * The most the stage adds in total. Default {@link DOMAIN_AGE_MAX_POINTS};
   * a caller that has already charged for age elsewhere passes what is left.
   */
  maxPoints?: number;
}

type Dated = DomainAgeLookup & { ageDays: number; registered: number };

const isDated = (lookup: DomainAgeLookup): lookup is Dated =>
  lookup.status === 'ok' && lookup.ageDays !== null && lookup.registered !== null;

function describeAge(lookup: Dated): string {
  const date = new Date(lookup.registered * 1000).toISOString().slice(0, 10);
  if (lookup.ageDays === 0) return `today (${date})`;
  return `${lookup.ageDays} day${lookup.ageDays === 1 ? '' : 's'} ago (${date})`;
}

/**
 * Score what the ages say.
 *
 * The sender's domain is charged first and the links take what is left of
 * the budget, so the reason that gets truncated is the one the reader can
 * verify least easily. Among several link domains only the YOUNGEST is
 * charged: a page that links to three new domains is one campaign, not three.
 */
export function assessDomainAge(
  subjects: DomainAgeSubjects,
  options: AssessDomainAgeOptions = {},
): SpamAssessment {
  const budget = options.maxPoints ?? DOMAIN_AGE_MAX_POINTS;
  const reasons: SpamReason[] = [];
  let spent = 0;
  const charge = (id: SpamReasonId, points: number, detail: string): void => {
    const charged = Math.min(points, budget - spent);
    if (charged <= 0) return;
    spent += charged;
    reasons.push({ id, points: charged, detail });
  };

  const sender = subjects.sender;
  if (sender && isDated(sender)) {
    const points = domainAgePoints(sender.ageDays);
    if (points > 0) {
      charge(
        'reputation-domain-new',
        points,
        `The sender domain ${sender.domain} was registered only ${describeAge(sender)}`,
      );
    }
  }

  const youngest = (subjects.links ?? [])
    .filter(isDated)
    .reduce<Dated | null>(
      (best, lookup) => (best === null || lookup.ageDays < best.ageDays ? lookup : best),
      null,
    );
  if (youngest) {
    const points = domainAgePoints(youngest.ageDays);
    if (points > 0) {
      charge(
        'reputation-link-new',
        points,
        `Links to ${youngest.domain}, a domain registered only ${describeAge(youngest)}`,
      );
    }
  }

  return assessmentOf(reasons);
}
