/**
 * The ONE place an email's security level is decided.
 *
 * Three very different kinds of evidence feed it, and the level is honest
 * about which it has:
 *
 *   AUTHENTICATION — SPF / DKIM / DMARC as the receiving server recorded them
 *   in Authentication-Results. The only AUTHORITATIVE signal: it says whether
 *   the sending domain really sent the mail. Absent for many small senders,
 *   which is "unverifiable", not "suspicious".
 *
 *   HEURISTICS — display-name impersonation and links whose text names one
 *   domain while the href goes to another. High-signal tells, but tells, not
 *   proof; a caller's trust list can retire a pair the user has vetted.
 *
 *   SPAM SCORE — the header-stage score, as computed when the message arrived.
 *   Passed in rather than recomputed: the verdict shown to a reader must be
 *   the verdict that actually filed the message, not a fresh one from a newer
 *   rule set that would explain a decision nobody made.
 *
 *   BRAND IDENTITY — what the sender's domain publishes about its own logo,
 *   as `/brand` resolved it. Reported, never scored: a domain with no BIMI
 *   record is not suspicious, and a Verified Mark Certificate proves who owns
 *   a brand, not that this message deserves the reader's trust.
 *
 * What is deliberately NOT here: the human copy for each level. A library
 * cannot know the product's voice, its language, or its reading age. Callers
 * map the level to their own strings.
 */
import type { BimiStatus } from './brand/bimi.js';
import { assessSender, registrableDomain } from './identity.js';
import { linkDomainsAllMatch, linkMismatches, type LinkMismatch } from './links.js';
import {
  parseSpamReasons,
  spamVerdict,
  type AuthStatus,
  type SpamReason,
  type SpamVerdict,
} from './verdict.js';

/**
 * From safest to most dangerous. Ordered so callers can compare with `>`
 * via {@link LEVEL_RANK} — "escalate the thread banner to the worst message".
 */
export type SecurityLevel = 'verified' | 'authenticated' | 'unverified' | 'caution' | 'danger';

export const LEVEL_RANK: Record<SecurityLevel, number> = {
  verified: 0,
  authenticated: 1,
  unverified: 2,
  caution: 3,
  danger: 4,
};

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'unknown';

/** One line of the explanation: what was checked and how it came out. */
export interface SecurityCheck {
  id: 'spf' | 'dkim' | 'dmarc' | 'sender' | 'links' | 'spam' | 'brand';
  label: string;
  status: CheckStatus;
  /** Plain-language detail, e.g. "Text says x.com, link goes to y.com". */
  detail: string;
}

export interface LinkRuleSets {
  /** Keys from {@link linkRuleKey} the user has chosen to trust. */
  trusted: ReadonlySet<string>;
  /** Keys from {@link linkRuleKey} the user has chosen to block. */
  blocked: ReadonlySet<string>;
}

export const EMPTY_RULES: LinkRuleSets = { trusted: new Set(), blocked: new Set() };

/**
 * What the shield needs of a BIMI lookup: the standing, who proved it, and
 * why. A whole `BimiLookup` from `/brand` satisfies it, and so does the
 * handful of columns a caller cached from one — the status is the only part
 * that must be there. Typed against `/brand`'s own union so the two cannot
 * drift apart, and imported as a TYPE, so nothing about this entry's
 * dependency cost changes.
 */
export interface BrandIdentity {
  status: BimiStatus;
  organization?: string | null;
  issuer?: string | null;
  detail?: string | null;
}

export interface SecurityAssessment {
  level: SecurityLevel;
  checks: SecurityCheck[];
  /** Deceptive links found and NOT covered by a trust rule — what "I trust this" acts on. */
  untrustedLinks: LinkMismatch[];
  /** Deceptive links the user has explicitly blocked — forces `danger`. */
  blockedLinks: LinkMismatch[];
  /** Registrable domain of the sender, or null when the address is unusable. */
  senderDomain: string | null;
  /** The spam verdict; `verdict` is null when the message was never scored. */
  spam: { verdict: SpamVerdict | null; score: number | null; reasons: SpamReason[] };
}

/**
 * The identity of a trust/block rule. Scoped to the SENDER domain on purpose:
 * trusting "x.com -> y.com" for everyone would let ANY sender use that
 * redirect unflagged, and a compromised known account is the usual way
 * phishing arrives from a familiar name.
 */
export function linkRuleKey(senderDomain: string, shown: string, actual: string): string {
  return `${senderDomain}|${shown}|${actual}`.toLowerCase();
}

/** Parse a stored auth_status JSON blob; anything unreadable is "no verdict", never a throw. */
export function parseAuthStatus(raw: string | null | undefined): AuthStatus | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as Partial<AuthStatus> | null;
    if (!value || typeof value !== 'object') return null;
    return {
      spf: value.spf ?? 'unknown',
      dkim: value.dkim ?? 'unknown',
      dmarc: value.dmarc ?? 'unknown',
      overall: value.overall ?? 'none',
    };
  } catch {
    return null;
  }
}

const authCheck = (
  id: 'spf' | 'dkim' | 'dmarc',
  label: string,
  value: string | undefined,
  passText: string,
  failText: string,
): SecurityCheck => {
  if (value === 'pass') return { id, label, status: 'pass', detail: passText };
  if (value === 'fail') return { id, label, status: 'fail', detail: failText };
  if (value === 'softfail' || value === 'neutral') {
    return {
      id,
      label,
      status: 'warn',
      detail: `${label} returned ${value} — the sender's policy did not vouch for this server`,
    };
  }
  return {
    id,
    label,
    status: 'unknown',
    detail: `The receiving server recorded no ${label} verdict`,
  };
};

export interface SecurityInput {
  fromName?: string | null;
  fromAddress?: string | null;
  /** The message body as HTML, for the link checks. */
  html?: string | null;
  /** A stored `AuthStatus` — either the object, or the JSON string it was stored as. */
  auth?: AuthStatus | string | null;
  /** The header-stage score, as computed when the message arrived. */
  spamScore?: number | null;
  /** The stored reasons — either the array, or the JSON string they were stored as. */
  spamReasons?: readonly SpamReason[] | string | null;
  /** The user's trust/block rules. Defaults to none. */
  rules?: LinkRuleSets;
  /**
   * The sender domain's BIMI standing, if the caller has looked it up — a
   * `BimiLookup` from `/brand`, or the columns it cached from one.
   *
   * Three states, not two: leave it `undefined` and the shield says nothing
   * about the brand at all, pass `null` and it says "not looked up yet".
   * A reader who has been shown a tick on this sender before is owed the
   * difference between "no mark" and "we have not asked yet".
   */
  bimi?: BrandIdentity | null;
}

/** Decide the level for one message. */
export function assessEmailSecurity(input: SecurityInput): SecurityAssessment {
  const rules = input.rules ?? EMPTY_RULES;
  const senderDomain = registrableDomain(input.fromAddress?.split('@')[1] ?? null);
  const auth = typeof input.auth === 'string' ? parseAuthStatus(input.auth) : (input.auth ?? null);

  const dkimCheck = authCheck(
    'dkim',
    'DKIM',
    auth?.dkim,
    'The message signature is valid — it was not altered in transit',
    'The message signature is INVALID — it was altered or forged',
  );
  if (auth?.dkim === 'fail' && auth?.dmarc === 'pass') {
    // A broken DKIM signature under a PASSING DMARC is routine: a mailing list
    // or forwarder re-wrote the message and invalidated one signature, while
    // SPF (or another signature) still aligned with the From domain. Reporting
    // it as a failure put a red shield on bank statements — a false alarm that
    // teaches the reader to ignore red. Keep it visible, as a warning.
    dkimCheck.status = 'warn';
    dkimCheck.detail =
      'A signature was broken in transit, but DMARC still passed — the sender’s domain is confirmed';
  }
  const checks: SecurityCheck[] = [
    authCheck(
      'spf',
      'SPF',
      auth?.spf,
      'The sending server is authorised for this domain',
      'The sending server is NOT authorised for this domain',
    ),
    dkimCheck,
    authCheck(
      'dmarc',
      'DMARC',
      auth?.dmarc,
      'The domain owner’s policy accepts this message',
      'The domain owner’s policy REJECTS this message',
    ),
  ];

  // Display-name impersonation.
  const spoof = assessSender(input.fromName, input.fromAddress);
  checks.push(
    spoof.length
      ? {
          id: 'sender',
          label: 'Sender name',
          status: 'fail',
          detail: (spoof[0] as { text: string }).text,
        }
      : {
          id: 'sender',
          label: 'Sender name',
          status: 'pass',
          detail: 'The display name does not impersonate another domain',
        },
  );

  // Deceptive links, minus the pairs the user has vetted.
  const all = linkMismatches(input.html);
  const key = (m: LinkMismatch): string => linkRuleKey(senderDomain ?? '', m.shown, m.actual);
  const blockedLinks = all.filter((m) => rules.blocked.has(key(m)));
  const untrustedLinks = all.filter(
    (m) => !rules.trusted.has(key(m)) && !rules.blocked.has(key(m)),
  );
  const trustedCount = all.length - blockedLinks.length - untrustedLinks.length;

  if (blockedLinks.length) {
    const first = blockedLinks[0] as LinkMismatch;
    checks.push({
      id: 'links',
      label: 'Links',
      status: 'fail',
      detail: `A link you have blocked: text says ${first.shown}, goes to ${first.actual}`,
    });
  } else if (untrustedLinks.length) {
    const first = untrustedLinks[0] as LinkMismatch;
    checks.push({
      id: 'links',
      label: 'Links',
      status: 'warn',
      detail: `Text says ${first.shown}, link goes to ${first.actual}${
        untrustedLinks.length > 1 ? ` (+${untrustedLinks.length - 1} more)` : ''
      }`,
    });
  } else {
    checks.push({
      id: 'links',
      label: 'Links',
      status: 'pass',
      detail: trustedCount
        ? `Link domains match what they show (${trustedCount} pair${trustedCount > 1 ? 's' : ''} you trust)`
        : 'Link domains match what they show',
    });
  }

  // The spam verdict, as computed when the message arrived. Shown with its
  // reasons so "filed as spam" is never a bare adjective either.
  const spamScore =
    typeof input.spamScore === 'number' && Number.isFinite(input.spamScore)
      ? input.spamScore
      : null;
  const verdict = spamVerdict(spamScore);
  const spamReasons =
    typeof input.spamReasons === 'string'
      ? parseSpamReasons(input.spamReasons)
      : [...(input.spamReasons ?? [])];
  const spam = { verdict, score: spamScore, reasons: spamReasons };
  const spamSummary = spamReasons.map((r) => r.detail).join('; ');
  if (verdict === 'spam') {
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'fail',
      detail: `Scored ${spamScore} — ${spamSummary}`,
    });
  } else if (verdict === 'suspicious') {
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'warn',
      detail: `Scored ${spamScore} — ${spamSummary}`,
    });
  } else if (verdict === 'clean') {
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'pass',
      detail: spamReasons.length
        ? `Scored ${spamScore} — ${spamSummary}`
        : 'No spam signals in the headers',
    });
  } else {
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'unknown',
      detail: 'Not scored — this message was never put through the filter',
    });
  }

  // Brand identity (BIMI), when the caller has looked it up. The logo and the
  // tick belong to a message only on a DMARC pass: the certificate says who
  // owns the brand, DMARC says this message came from them. It is reported so
  // the shield can explain a tick's ABSENCE — a reader who saw a logo on the
  // last message from this sender will otherwise read its disappearance as
  // nothing at all.
  if (input.bimi !== undefined) {
    checks.push(brandCheck(input.bimi, auth?.dmarc === 'pass', senderDomain));
  }

  const result = (level: SecurityLevel): SecurityAssessment => ({
    level,
    checks,
    untrustedLinks,
    blockedLinks,
    senderDomain,
    spam,
  });

  // ---- the level ---------------------------------------------------------
  // Hard failures first: an authoritative FAIL, an impersonating display name,
  // or a link the user explicitly blocked. Nothing below can soften these.
  //
  // "Authoritative" means DMARC. It is the check that asks whether the domain
  // in From: is the domain that actually authenticated — the question a reader
  // cares about. SPF and DKIM are its inputs: either one can fail for benign
  // reasons (a forwarder, a list, a second signature) while DMARC still
  // passes, and treating ANY component failure as failure turned those into
  // red shields on legitimate bank and travel mail. Only when the server
  // recorded no DMARC verdict at all do we fall back to "both inputs failed".
  const dmarcKnown = auth?.dmarc === 'pass' || auth?.dmarc === 'fail';
  const authFailed =
    auth?.dmarc === 'fail' || (!dmarcKnown && auth?.spf === 'fail' && auth?.dkim === 'fail');
  if (authFailed || spoof.length > 0 || blockedLinks.length > 0) return result('danger');

  // Soft signals: an unvetted deceptive link, a policy that declined to vouch,
  // a single failed input with no DMARC verdict to settle the question — or
  // the filter having scored it spam. Spam is caution, not danger: the reasons
  // that make spam DANGEROUS (a failed DMARC, a spoofed name) already score
  // danger on their own above; the rest is unwanted, not impersonation.
  const softAuth =
    auth?.spf === 'softfail' ||
    auth?.spf === 'neutral' ||
    (!dmarcKnown && (auth?.spf === 'fail' || auth?.dkim === 'fail'));
  if (untrustedLinks.length > 0 || softAuth || verdict === 'spam') return result('caution');

  // Clean. Now: how STRONGLY do we know who sent it? DMARC pass settles it;
  // without a DMARC verdict, SPF and DKIM both passing is the next best thing.
  const authPassed =
    auth?.dmarc === 'pass' || (!dmarcKnown && auth?.spf === 'pass' && auth?.dkim === 'pass');
  if (authPassed) {
    // Fully authenticated AND every link stays on the sender's own domain (or
    // is a pair the user vetted): the top level. A newsletter that passes
    // DMARC but links out to its CDN and tracker is authenticated, not
    // verified — real, but not "everything in this mail is the sender".
    return result(linkDomainsAllMatch(input.html, senderDomain) ? 'verified' : 'authenticated');
  }
  return result('unverified');
}

/**
 * One line about the sender's mark.
 *
 * It never moves the level, in either direction. A verified mark proves who
 * owns the domain — which DMARC already settled for this message — and the
 * overwhelming majority of legitimate senders publish no mark at all, so
 * scoring its absence would put a warning on most of the world's mail.
 */
function brandCheck(
  bimi: BrandIdentity | null,
  dmarcPass: boolean,
  senderDomain: string | null,
): SecurityCheck {
  const check = (status: CheckStatus, detail: string): SecurityCheck => ({
    id: 'brand',
    label: 'Brand identity',
    status,
    detail,
  });
  if (!bimi) return check('unknown', 'Not looked up yet');
  switch (bimi.status) {
    case 'verified':
      return dmarcPass
        ? check(
            'pass',
            `${bimi.organization ?? 'The brand'} proved ownership of ${senderDomain ?? 'this domain'} with a Verified Mark Certificate from ${bimi.issuer ?? 'a Mark Verifying Authority'}`,
          )
        : check(
            'warn',
            'The domain publishes a verified logo, but this message did not pass DMARC — logo and tick withheld',
          );
    case 'logo':
      return dmarcPass
        ? check('pass', 'The domain publishes a BIMI logo, without a Verified Mark Certificate')
        : check(
            'warn',
            'The domain publishes a logo, but this message did not pass DMARC — logo withheld',
          );
    case 'declined':
      return check('unknown', 'The domain declines to show a logo');
    case 'none':
      return check('unknown', 'The domain publishes no BIMI record');
    case 'invalid':
      return check(
        'unknown',
        `BIMI record unusable: ${bimi.detail ?? 'the record could not be read'}`,
      );
  }
  // 'error' — the lookup itself did not finish. Deliberately not a warning
  // about the SENDER: a resolver timeout is a fact about the network here.
  return check(
    'unknown',
    bimi.detail ? `The brand lookup failed: ${bimi.detail}` : 'The brand lookup failed',
  );
}

/** The worst level among several messages — what a thread-level banner shows. */
export function worstLevel(levels: readonly SecurityLevel[]): SecurityLevel {
  return levels.reduce<SecurityLevel>(
    (worst, level) => (LEVEL_RANK[level] > LEVEL_RANK[worst] ? level : worst),
    'verified',
  );
}
