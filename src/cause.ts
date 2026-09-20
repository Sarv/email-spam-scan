/**
 * What went wrong, as a sentence.
 *
 * Every stage that catches something it did not throw itself — a resolver, a
 * fetch, an optional peer that would not load — has to put the cause into a
 * `detail` string a caller can show. `catch (cause)` is typed `unknown` and a
 * rejected promise may carry anything at all, so the narrowing lives here
 * once rather than in each of the six places that needs it.
 */

/** The message of a thrown value, whatever kind of value it turned out to be. */
export function reasonFrom(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
