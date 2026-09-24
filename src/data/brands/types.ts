/** One protected brand: the names it is impersonated with, and the domains it writes from. */
export interface ProtectedBrand {
  /** Stable id, and the name of the file it lives in. */
  id: string;
  /** What the brand is called in a reason shown to a reader. */
  name: string;
  /** Names the brand is impersonated with — lowercase, matched as whole words. */
  phrases: readonly string[];
  /** Registrable domains the brand itself sends from or owns. Never a free mailbox host. */
  domains: readonly string[];
  /**
   * Where the domains were checked: the brand's own page on recognising its
   * mail, a header from a message it really sent, its published SPF record.
   * HTTPS URLs. Required for every brand added after 2026-09-24 — see
   * `test/brands.test.ts` for the entries that predate it.
   */
  sources?: readonly string[];
  /** When somebody last checked `domains` against `sources`, as YYYY-MM-DD. */
  verified?: string;
}
