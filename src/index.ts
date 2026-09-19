/**
 * The Node entry point: everything the package exports.
 *
 * Two narrower entries exist for consumers who must not pay for all of it —
 * `@sarv-in/email-spam-scan/verdict` (zero dependencies, for reading a stored
 * score back) and `@sarv-in/email-spam-scan/identity` (`tldts` only, for the
 * sender rule). Both are re-exported here, so a Node consumer needs one
 * import and a browser consumer can still avoid the rest.
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
export { hasReplyPrefix, isValidMessageId } from './rfc.js';
export {
  assessSender,
  domainOfAddress,
  domainsInText,
  registrableDomain,
  type PhishingReason,
} from './identity.js';
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
