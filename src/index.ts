/**
 * The Node entry point: everything the package exports.
 *
 * Narrower entries exist for consumers who must not pay for all of it:
 *
 *   `/verdict`  — zero dependencies, for reading a stored score back.
 *   `/identity` — `tldts` only, for the sender rule.
 *   `/links`    — the DOM-dependent link checks.
 *   `/security` — the level decision, for a UI that displays one.
 *
 * All are re-exported here, so a Node consumer needs one import and a browser
 * consumer can still avoid the address parser and the freemail list.
 */
export {
  extractOriginIp,
  isPublicIp,
  normalizeIp,
  originIpFromAuthHeaders,
  originIpFromReceived,
  type OriginIpSources,
} from './headers/origin-ip.js';
export { extractAuthHeaderBlock, parseAuthenticationHeaders } from './headers/auth-results.js';
export {
  headerLookupFromText,
  headerValueFromText,
  headerValuesFromText,
  type HeaderLookup,
} from './headers/lookup.js';
export {
  bulkHeaderSignals,
  hasBulkHeaderSignal,
  BULK_HEADER_NAMES,
  type BulkHeaderSignals,
} from './headers/bulk.js';
export {
  assessSpamSignals,
  isFreemailAddress,
  DATE_SKEW_SECONDS,
  SPAM_HEADER_NAMES,
  type SpamAssessment,
  type SpamSignalInput,
} from './rules/header-rules.js';
export { hasReplyPrefix, isValidMessageId } from './rfc.js';
export {
  assessSender,
  domainOfAddress,
  domainsInText,
  registrableDomain,
  type PhishingReason,
} from './identity.js';
export {
  assessLinks,
  assessPhishing,
  linkDomainsAllMatch,
  linkMismatches,
  LINK_WRAPPER_DOMAINS,
  type LinkMismatch,
  type PhishingAssessment,
  type PhishingLevel,
} from './links.js';
export {
  assessEmailSecurity,
  linkRuleKey,
  parseAuthStatus,
  worstLevel,
  EMPTY_RULES,
  LEVEL_RANK,
  type CheckStatus,
  type LinkRuleSets,
  type SecurityAssessment,
  type SecurityCheck,
  type SecurityInput,
  type SecurityLevel,
} from './security.js';
export {
  isSpamScore,
  parseSpamReasons,
  spamVerdict,
  SPAM_THRESHOLD,
  SUSPICIOUS_THRESHOLD,
  type AuthStatus,
  type SpamReason,
  type SpamReasonId,
  type SpamVerdict,
} from './verdict.js';
