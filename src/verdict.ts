/**
 * The stored verdict — thresholds, the reason shape, and the parser that reads
 * a verdict back out of wherever it was persisted.
 *
 * ZERO IMPORTS, on purpose, and that is a contract rather than a coincidence.
 * The process that SCORES a message and the process that DISPLAYS the score
 * are usually not the same one: mail is scanned once at ingest, on a server or
 * in a main process, and the result is read back months later by a UI that
 * wants to draw a shield and explain it. That reader needs exactly this much —
 * what the numbers mean and how to parse the reasons — and must not be made to
 * bundle a MIME parser, a public-suffix list and a word corpus to get it.
 *
 * Hence the `@sarv-in/email-spam-scan/verdict` entry point, which is browser-safe
 * by construction. The scorer imports these same constants, so the score a
 * scanner writes and the line a reader compares it against can never drift.
 */

/** Score at or above which a message IS spam: tagged, filed, kept out of the way. */
export const SPAM_THRESHOLD = 5;
/** Score at or above which a reader should warn without filing. */
export const SUSPICIOUS_THRESHOLD = 3;

/**
 * Every rule the scanner can charge points for.
 *
 * A union rather than a free string: a reader switches on these to localise a
 * message or pick an icon, and a rule renamed in a release that a reader has
 * not caught up with should fail to compile, not fall through to a blank row.
 */
export type SpamReasonId =
  | 'upstream-spam'
  | 'known-spammer'
  | 'auth-failed'
  | 'display-name-spoof'
  | 'sender-punycode'
  | 'sender-invalid'
  | 'reply-to-freemail'
  | 'reply-to-mismatch'
  | 'missing-message-id'
  | 'malformed-message-id'
  | 'missing-date'
  | 'date-skew'
  | 'fake-reply'
  | 'no-recipient'
  | 'bulk-no-unsubscribe'
  | 'precedence-junk'
  // The body-content stage. Scored on the sender's OWN words — quoted history
  // and signature removed first — so a reply that quotes a phish is not itself
  // scored as one, and a long thread does not accumulate points every time
  // somebody hits reply.
  | 'content-spam-vocabulary'
  | 'content-shouting'
  | 'content-hidden-text'
  | 'link-display-mismatch'
  | 'link-bare-ip'
  | 'link-userinfo'
  | 'link-punycode'
  // The attachment stage. Structural facts about a file — what its name
  // claims, what its declared type claims, and what its first bytes say —
  // never an opinion about its contents, which are not opened, unpacked or
  // executed. Not an antivirus: none of these means "infected", and their
  // absence means "nothing deceptive", not "safe to open".
  | 'attachment-executable'
  | 'attachment-double-extension'
  | 'attachment-name-spoof'
  | 'attachment-type-mismatch'
  | 'attachment-macro'
  | 'attachment-archive-executable'
  | 'attachment-encrypted-archive';

export interface SpamReason {
  id: SpamReasonId;
  points: number;
  /** One human-readable sentence, safe to show a reader as-is. */
  detail: string;
}

/**
 * SPF / DKIM / DMARC as the receiving server recorded them, in the shape a
 * consumer stores and reads back.
 *
 * It lives in the zero-dependency entry with the rest of the stored verdict
 * because the reader needs it and the reader is usually in a browser. Before
 * this package existed, Sarv Inbox declared this same interface twice — once
 * in its sync layer and once in its renderer — which is how a `dkim` value
 * gets a new case on one side and not the other.
 *
 * `unknown` and `none` are NOT the same thing: `none` is a policy that exists
 * and declined to assert, `unknown` is "the server recorded no verdict". A UI
 * that collapses them tells the reader a small sender failed a check nobody
 * ran.
 */
export interface AuthStatus {
  spf: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown';
  dkim: 'pass' | 'fail' | 'none' | 'unknown';
  dmarc: 'pass' | 'fail' | 'none' | 'unknown';
  /** Rolled up across the three. `fail` if ANY component failed. */
  overall: 'pass' | 'partial' | 'fail' | 'none';
}

/**
 * An `AuthStatus` that asserts nothing: three `unknown` components, `none`
 * overall.
 *
 * A factory rather than a shared frozen constant, because both producers fill
 * one in field by field and a shared object would have them writing into each
 * other's results.
 */
export function unknownAuthStatus(): AuthStatus {
  return { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown', overall: 'none' };
}

/**
 * The `overall` field, from the three component verdicts.
 *
 * One place, because TWO stages produce an `AuthStatus` — the header reader in
 * `headers/auth-results.ts`, which reports what some other machine wrote down,
 * and the DNS verifier in `verify.ts`, which works it out itself. A rollup that
 * drifted between them would show a reader a different shield for the same
 * message depending on which stage happened to run.
 *
 * `fail` beats everything: one component that actively failed is worth more
 * than two that passed, because the two that passed are the ones a sender who
 * controls their own domain can always arrange.
 */
export function rollUpAuthStatus(components: Omit<AuthStatus, 'overall'>): AuthStatus['overall'] {
  const values = [components.spf, components.dkim, components.dmarc];
  if (values.includes('fail')) return 'fail';
  const passed = values.filter((value) => value === 'pass').length;
  if (passed >= 2) return 'pass';
  if (passed >= 1) return 'partial';
  return 'none';
}

/**
 * What one stage of the scanner concluded: the points it charged, and why.
 *
 * It lives HERE, with the thresholds, rather than beside the header rules that
 * were the first to produce one. Every stage returns this same shape — headers
 * today, body content and attachments next — and a stage must be able to
 * return it without importing the stage before it. Put this type in the header
 * rules and the content rules inherit an address parser and a fourteen-thousand
 * entry domain corpus to describe a result, which is precisely the accidental
 * cost the entry-point split exists to prevent.
 */
export interface SpamAssessment {
  score: number;
  reasons: SpamReason[];
  /** score >= SPAM_THRESHOLD */
  isSpam: boolean;
  /** score >= SUSPICIOUS_THRESHOLD */
  suspicious: boolean;
}

/**
 * Sum a stage's reasons into an assessment.
 *
 * The one place the total is computed, so no stage can invent its own
 * arithmetic or its own idea of where the thresholds sit.
 */
export function assessmentOf(reasons: SpamReason[]): SpamAssessment {
  const score = reasons.reduce((sum, reason) => sum + reason.points, 0);
  return {
    score,
    reasons,
    isSpam: score >= SPAM_THRESHOLD,
    suspicious: score >= SUSPICIOUS_THRESHOLD,
  };
}

/**
 * Add several stages' assessments together into the one verdict a caller acts
 * on. Nullish parts are skipped, so a caller can pass a stage that did not run
 * — no body downloaded yet, own mail that is never content-scored — without
 * branching at the call site.
 *
 * Additive, because that is the whole scoring model: the stages are evidence
 * about the same message and no stage overrides another. Reasons keep the
 * order they were passed in, so the header rules read before the body rules in
 * whatever the user is shown.
 */
export function mergeAssessments(
  ...parts: readonly (SpamAssessment | null | undefined)[]
): SpamAssessment {
  return assessmentOf(parts.flatMap((part) => part?.reasons ?? []));
}

export type SpamVerdict = 'spam' | 'suspicious' | 'clean';

/** The verdict a stored score amounts to; null when the message was never scored. */
export function spamVerdict(score: number | null | undefined): SpamVerdict | null {
  if (typeof score !== 'number' || !Number.isFinite(score)) return null;
  if (score >= SPAM_THRESHOLD) return 'spam';
  if (score >= SUSPICIOUS_THRESHOLD) return 'suspicious';
  return 'clean';
}

export function isSpamScore(score: number | null | undefined): boolean {
  return spamVerdict(score) === 'spam';
}

/**
 * Stored reasons JSON back into objects.
 *
 * Tolerant by design: a NULL, an empty string, malformed JSON, a non-array, or
 * an array with one unrecognisable element all read as "no reasons", and the
 * good elements of a partly-bad array survive. A shield that throws on one bad
 * row is worse than one that shows less — the row it refuses to render is the
 * message the user is trying to look at.
 */
export function parseSpamReasons(json: string | null | undefined): SpamReason[] {
  if (!json) return [];
  try {
    const parsed: unknown = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (reason): reason is SpamReason =>
        !!reason &&
        typeof reason === 'object' &&
        typeof (reason as SpamReason).id === 'string' &&
        typeof (reason as SpamReason).points === 'number' &&
        typeof (reason as SpamReason).detail === 'string',
    );
  } catch {
    return [];
  }
}
