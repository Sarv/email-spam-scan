/**
 * `verifyAuthentication(message)` — SPF, DKIM and DMARC checked against DNS,
 * rather than read out of a header somebody else wrote.
 *
 * Everything else in this package is offline and synchronous by design: it
 * reads the bytes it was handed and nothing more. This module is the one
 * exception, and it is deliberately hard to reach by accident.
 *
 *   - It is its own entry point (`@sarv-in/email-spam-scan/verify`), so
 *     nothing that imports the scanner inherits it.
 *   - The DNS work is done by `mailauth`, an OPTIONAL peer dependency loaded
 *     through a dynamic import. A plain install of this package does not pull
 *     it down, and a bundler that never reaches this module never sees it.
 *   - `scan()` never calls this. A caller who wants a verified verdict calls
 *     it themselves and hands the result to `scan` as `options.auth` — so the
 *     scanner remains a function that cannot make a network call, which is a
 *     much easier thing to reason about in an ingest loop than one that only
 *     sometimes does.
 *
 * WHY A LIBRARY. SPF is a recursive macro language with a lookup budget, DKIM
 * is a canonicalisation specification with more corner cases than signature
 * algorithms, and DMARC is an alignment policy layered on both. Hand-rolling
 * any of the three is how a verifier ends up reporting `pass` on a message it
 * did not actually check. `mailauth` is the maintained implementation from the
 * same people as `postal-mime`, which this package already depends on.
 *
 * WHAT A VERDICT IS WORTH. SPF needs the IP the message was received FROM.
 * That address is not in the message — it is in the SMTP session — so a caller
 * who has no `ip` to pass gets `spf: 'unknown'` rather than a guess, and
 * `trustReceived` (read it out of the topmost `Received:`) is opt-in because
 * those headers are written by machines the reader does not control.
 */
import { reasonFrom } from './cause.js';
import { rollUpAuthStatus, unknownAuthStatus, type AuthStatus } from './verdict.js';

/** Anything `mailauth` will read a message from. */
export type VerifyInput = string | Uint8Array;

/**
 * A DNS lookup, so a caller can supply a cache, a DoH client, or — the reason
 * it exists — a fixture zone in a test that must never touch a real resolver.
 *
 * The same shape `mailauth` uses: a name and a record type in, the resolver's
 * raw answer out (an array of strings, or of string chunks for `TXT`).
 */
export type DnsResolver = (name: string, recordType: string) => Promise<unknown>;

export interface VerifyOptions {
  /**
   * The IP address the message was received from. REQUIRED for SPF — without
   * it SPF is reported `unknown`, because SPF is a question about the
   * connection and there is no honest way to answer it from the bytes.
   */
  ip?: string;
  /** The hostname the sending server announced in EHLO/HELO. */
  helo?: string;
  /** The envelope sender, from `MAIL FROM`. Not the `From:` header. */
  mailFrom?: string;
  /** Your own MX hostname, recorded in the explanatory comments. */
  mta?: string;
  /**
   * Take `ip`, `helo` and `mailFrom` from the message's own topmost
   * `Received:` and `Return-Path:` headers when they were not passed.
   *
   * Off by default, and worth leaving off unless your own MTA wrote those
   * headers: they are plain text, and a sender can write them too.
   */
  trustReceived?: boolean;
  /** Smallest DKIM public key accepted, in bits. `mailauth` defaults to 1024. */
  minBitLength?: number;
  /**
   * How long the whole verification may take, in milliseconds. Default 10000.
   *
   * A scanner that waits indefinitely on DNS does not fail, it stalls ingest —
   * and the queue behind it is invisible until somebody notices the mail has
   * stopped. On expiry the result is an honest "we did not find out"
   * (`completed: false`), never a verdict.
   */
  timeoutMs?: number;
  /** Where to send the DNS queries. Defaults to the system resolver. */
  resolver?: DnsResolver;
}

/** One DKIM signature as it was found on the message. */
export interface VerifiedSignature {
  /** The `d=` domain that signed, or null when the signature named none. */
  signingDomain: string | null;
  /** The `s=` selector the key was published under. */
  selector: string | null;
  /**
   * `mailauth`'s own word for what happened, verbatim — `pass`, `fail`,
   * `neutral`, `policy`, `temperror`, `none`.
   *
   * Kept unmapped ON PURPOSE. `AuthStatus.dkim` has four values and this has
   * seven, and the three that get collapsed are exactly the ones a person
   * debugging a delivery problem needs: "body hash did not verify" and "no
   * key" are the same verdict and completely different problems.
   */
  result: string;
  /** `mailauth`'s explanation, when it gave one. */
  comment: string | null;
  /** The signing domain aligns with the `From:` domain, as DMARC requires. */
  aligned: boolean;
}

export interface AuthVerification {
  /** The three verdicts, in the same shape a stored verdict uses. */
  auth: AuthStatus;
  /**
   * The lookups finished. `false` means the run timed out or the resolver
   * failed, and `auth` therefore asserts nothing — which is NOT the same fact
   * as a message that failed its checks.
   */
  completed: boolean;
  /** The domain SPF was evaluated for; null when SPF was not evaluated. */
  spfDomain: string | null;
  /** Every DKIM signature on the message, in the order they were verified. */
  signatures: VerifiedSignature[];
  /** The policy the From domain publishes: `none`, `quarantine` or `reject`. */
  dmarcPolicy: string | null;
  /** Why there is no verdict. Null when the run completed. */
  error: string | null;
}

/**
 * The parts of `mailauth`'s `authenticate()` result this module reads.
 *
 * Declared here rather than imported from `mailauth`, for two reasons. The
 * package is an optional peer dependency, so its types must not be needed to
 * compile a consumer who never installs it. And the declarations it ships are
 * hand-written and not always right — its documented `dkimSign` options are
 * not the ones the implementation reads — so a structural type covering only
 * the fields actually used is both smaller and more honest than a re-export of
 * something that may not describe the runtime.
 *
 * Every field is optional. This is the boundary with another package's output:
 * treating it as guaranteed is how a scanner throws on a message rather than
 * scoring it.
 */
export interface MailauthStatus {
  result?: string;
  comment?: string | false;
}

export interface MailauthSignature {
  signingDomain?: string;
  selector?: string;
  status?: MailauthStatus & { aligned?: string | false };
}

export interface MailauthSpf {
  domain?: string;
  'client-ip'?: string;
  status?: MailauthStatus;
}

export interface MailauthDmarc {
  domain?: string;
  policy?: string;
  status?: MailauthStatus;
}

export interface MailauthResult {
  spf?: MailauthSpf | false;
  dkim?: { results?: readonly MailauthSignature[] };
  dmarc?: MailauthDmarc | false;
}

/**
 * SPF's vocabulary is RFC 7208's, and `AuthStatus.spf` carries five of its
 * seven words unchanged. The two it does not — `temperror` (DNS was
 * unavailable) and `permerror` (the record is unusable) — are both "no verdict
 * was reached", which is what `unknown` means here.
 */
const SPF_STATUS: Readonly<Record<string, AuthStatus['spf']>> = {
  pass: 'pass',
  fail: 'fail',
  softfail: 'softfail',
  neutral: 'neutral',
  none: 'none',
};

/**
 * DKIM, where the mapping is a judgement rather than a rename.
 *
 * `mailauth` spreads "there is a signature and it did not verify" across three
 * words: `fail` for a bad signature, `neutral` for a body hash that did not
 * match, a key that is not published, or one that has expired, and `policy`
 * for a key below the minimum length. It is following RFC 6376's advice to
 * treat a broken signature as an absent one.
 *
 * This package cannot. `AuthStatus.dkim` has exactly one word for "did not
 * verify", and the other producer of an `AuthStatus` — the header reader —
 * sees `dkim=fail` written by Gmail and every other large MTA for precisely
 * these cases. Mapping them to `unknown` would mean the same message read as
 * `fail` when a header was believed and `unknown` when the signature was
 * actually checked, which is the worse answer of the two being the one you get
 * for doing the work.
 *
 * `temperror` is the exception and stays `unknown`: DNS was unreachable, so
 * nothing was learned about the signature at all.
 */
const DKIM_STATUS: Readonly<Record<string, AuthStatus['dkim']>> = {
  pass: 'pass',
  none: 'none',
  fail: 'fail',
  neutral: 'fail',
  policy: 'fail',
  temperror: 'unknown',
  temperr: 'unknown',
};

const DMARC_STATUS: Readonly<Record<string, AuthStatus['dmarc']>> = {
  pass: 'pass',
  fail: 'fail',
  none: 'none',
};

/** A `mailauth` comment, which is `false` rather than absent when there is none. */
function commentOf(status: MailauthStatus | undefined): string | null {
  return typeof status?.comment === 'string' ? status.comment : null;
}

/**
 * Whether SPF was evaluated against a real address.
 *
 * `mailauth` answers the question even when it was given no IP to answer it
 * about: the result comes back `none` for a domain literally named
 * `"undefined"`. That is not a verdict, so the presence of the address it
 * used is what decides whether there is one to report.
 */
function spfWasEvaluated(
  spf: MailauthSpf | false | undefined,
): spf is MailauthSpf & { 'client-ip': string } {
  return spf !== false && spf !== undefined && typeof spf['client-ip'] === 'string';
}

function dkimStatusOf(signatures: readonly MailauthSignature[]): AuthStatus['dkim'] {
  const values = signatures.map(
    (signature) => DKIM_STATUS[signature.status?.result ?? ''] ?? 'unknown',
  );
  // One signature that verifies is enough — a message may carry several, and
  // a sender who rotates keys or forwards through a signer will legitimately
  // have one that no longer checks out next to one that does.
  if (values.includes('pass')) return 'pass';
  if (values.includes('fail')) return 'fail';
  if (values.length === 0 || values.includes('unknown')) return 'unknown';
  return 'none';
}

/**
 * `mailauth`'s result into this package's shape.
 *
 * Pure, and exported: a caller who already runs `mailauth` for their own
 * reasons — a gateway usually does — can map its output into an `AuthStatus`
 * without this module doing the lookups a second time.
 */
export function authVerificationFrom(result: MailauthResult): AuthVerification {
  const { spf, dmarc } = result;
  const signatures = (result.dkim?.results ?? []).map((signature) => ({
    signingDomain: signature.signingDomain ?? null,
    selector: signature.selector ?? null,
    result: signature.status?.result ?? 'unknown',
    comment: commentOf(signature.status),
    aligned: typeof signature.status?.aligned === 'string',
  }));

  const evaluated = spfWasEvaluated(spf);
  const components: Omit<AuthStatus, 'overall'> = {
    spf: evaluated ? (SPF_STATUS[spf.status?.result ?? ''] ?? 'unknown') : 'unknown',
    dkim: dkimStatusOf(result.dkim?.results ?? []),
    dmarc: dmarc ? (DMARC_STATUS[dmarc.status?.result ?? ''] ?? 'unknown') : 'unknown',
  };

  return {
    auth: { ...components, overall: rollUpAuthStatus(components) },
    completed: true,
    spfDomain: (evaluated && spf.domain) || null,
    signatures,
    dmarcPolicy: (dmarc && dmarc.policy) || null,
    error: null,
  };
}

/** The result when nothing was found out. Never a verdict — see `completed`. */
function nothingFoundOut(error: string): AuthVerification {
  return {
    auth: unknownAuthStatus(),
    completed: false,
    spfDomain: null,
    signatures: [],
    dmarcPolicy: null,
    error,
  };
}

type Authenticate = (
  message: VerifyInput,
  options: Record<string, unknown>,
) => Promise<MailauthResult>;

let cachedAuthenticate: Authenticate | null = null;

/**
 * `mailauth`, loaded on first use.
 *
 * The dynamic import is the whole mechanism by which this package stays
 * offline: a static import would put `mailauth` and its dozen transitive
 * dependencies into every bundle that reaches this file, whether or not the
 * consumer ever verifies anything. `test/entry-points.test.ts` pins that.
 *
 * A missing package THROWS rather than returning an unverified result. It is a
 * setup mistake, not a runtime condition, and silently answering "we could not
 * find out" would let an install that can never verify anything look exactly
 * like a DNS outage.
 */
async function loadAuthenticate(): Promise<Authenticate> {
  if (cachedAuthenticate) return cachedAuthenticate;
  let loaded: { authenticate?: unknown };
  try {
    loaded = (await import('mailauth')) as unknown as { authenticate?: unknown };
  } catch {
    throw new Error(
      "verifyAuthentication() needs the optional peer dependency 'mailauth', which is not " +
        'installed. Add it (npm install mailauth) to enable DNS verification; every other part ' +
        'of this package works without it.',
    );
  }
  cachedAuthenticate = loaded.authenticate as Authenticate;
  return cachedAuthenticate;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/** Race a promise against a deadline, clearing the timer either way. */
async function withDeadline<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`authentication timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([work, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verify one message's SPF, DKIM and DMARC against DNS.
 *
 * Rejects only when `mailauth` is not installed. Every other failure — a
 * timeout, a resolver error, a message `mailauth` cannot read — comes back as
 * `completed: false` with the reason in `error`, because at ingest a message
 * that could not be checked must still be scored rather than lost.
 *
 * @param message the RAW message, byte for byte as it arrived. DKIM signs the
 *   bytes, so a message that has been re-encoded, re-wrapped or had a header
 *   normalised will not verify — and that failure is the library's, not the
 *   sender's.
 */
export async function verifyAuthentication(
  message: VerifyInput,
  options: VerifyOptions = {},
): Promise<AuthVerification> {
  const authenticate = await loadAuthenticate();
  try {
    const result = await withDeadline(
      authenticate(message, {
        ip: options.ip,
        helo: options.helo,
        sender: options.mailFrom,
        mta: options.mta,
        trustReceived: options.trustReceived === true,
        minBitLength: options.minBitLength,
        resolver: options.resolver,
      }),
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    );
    return authVerificationFrom(result);
  } catch (cause) {
    return nothingFoundOut(reasonFrom(cause));
  }
}
