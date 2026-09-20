/**
 * The DNS boundary the network-facing entries share.
 *
 * Two stages in this package ask the network a question — the blocklist
 * lookups in `reputation.ts` and the brand-indicator lookups in `brand/` —
 * and both need the same two things: a way for a caller to supply its own
 * resolver, and a default one that does not cost a browser bundle anything.
 * Both live here so the two stages cannot drift into disagreeing about what
 * "the name does not exist" means, and so one injected resolver serves both.
 *
 * Nothing in this file imports a package, and `node:dns` is reached through a
 * dynamic `import`, so a consumer that never resolves anything never resolves
 * the module either.
 */

/** The record types this package asks for. */
export type DnsRecordType = 'A' | 'TXT';

/**
 * A DNS query.
 *
 * Supply one to use a cache, a DoH client, your own resolver pool, or — the
 * reason it exists — a fixture in a test that must never touch a real one.
 *
 * The contract differs from `node:dns` in one deliberate way: **a name that
 * does not exist resolves to an empty array**, and a throw means the lookup
 * genuinely failed. That is the distinction both stages turn on — "nobody has
 * anything against this sender" and "nobody could be asked" are opposite
 * facts — so it is made once, at the boundary, rather than by every caller
 * guessing at resolver error codes.
 */
export type DnsQuery = (name: string, recordType: DnsRecordType) => Promise<string[]>;

export interface DnsResolverOptions {
  /** Per-query timeout for the built-in resolver. Default 5000ms. */
  timeoutMs?: number;
  /** Nameservers for the built-in resolver. Defaults to the system's. */
  servers?: readonly string[];
}

export const DEFAULT_DNS_TIMEOUT_MS = 5_000;

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
 * The built-in resolver: one `node:dns` resolver per call, reused across every
 * name it is asked, with the timeout enforced by c-ares rather than by a race
 * that leaves the query running.
 *
 * `tries: 1` because an answer that needed a retry has already cost more than
 * it is worth at ingest — the message still has to be delivered.
 */
export async function nodeDnsQuery(options: DnsResolverOptions = {}): Promise<DnsQuery> {
  const { Resolver } = (await import('node:dns/promises')) as unknown as {
    Resolver: ResolverConstructor;
  };
  const resolver = new Resolver({ timeout: options.timeoutMs ?? DEFAULT_DNS_TIMEOUT_MS, tries: 1 });
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
