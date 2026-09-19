/**
 * The Node entry point: everything the package exports.
 *
 * Narrower entries exist for consumers who must not pay for all of it:
 *
 *   `/verdict`  — zero dependencies, for reading a stored score back.
 *   `/headers`  — zero dependencies, for reading raw header text.
 *   `/attachments` — zero dependencies, the attachment stage on its own.
 *   `/identity` — `tldts` only, for the sender rule.
 *   `/links`    — the deceptive-link checks.
 *   `/security` — the level decision, for a UI that displays one.
 *   `/content`  — the body-content stage.
 *   `/scan`     — the whole pipeline over a raw message; the one entry that
 *                 costs a MIME parser.
 *
 * All are re-exported here, so a Node consumer needs one import and a browser
 * consumer can still avoid the address parser, the freemail corpus and the
 * MIME parser.
 */
export {
  extractOriginIp,
  isPublicIp,
  normalizeIp,
  originIpFromAuthHeaders,
  originIpFromReceived,
  type OriginIpSources,
} from './headers/origin-ip.js';
export {
  bulkHeaderSignals,
  extractAuthHeaderBlock,
  hasBulkHeaderSignal,
  headerLookupFromText,
  headerValueFromText,
  headerValuesFromText,
  parseAuthenticationHeaders,
  receivedAt,
  receivedAtFromLine,
  BULK_HEADER_NAMES,
  type BulkHeaderSignals,
  type HeaderLookup,
} from './headers/index.js';
export {
  scan,
  scanMany,
  scanParsed,
  trustedAuthHeaders,
  type BulkScanInput,
  type BulkScanOptions,
  type BulkScanResult,
  type RawMessage,
  type ScannedMessage,
  type ScanOptions,
  type ScanResult,
} from './scan.js';
export {
  assessSpamSignals,
  isFreemailAddress,
  DATE_SKEW_SECONDS,
  SPAM_HEADER_NAMES,
  type SpamSignalInput,
} from './rules/header-rules.js';
export { FREEMAIL_DOMAINS } from './data/freemail-domains.js';
export { hasReplyPrefix, isValidMessageId } from './rfc.js';
export {
  assessSender,
  domainOfAddress,
  domainsInText,
  registrableDomain,
  type PhishingReason,
} from './identity.js';
export {
  anchorMismatches,
  linkTarget,
  urlsInText,
  LINK_WRAPPER_DOMAINS,
  type AnchorLike,
  type LinkMismatch,
  type LinkTarget,
} from './urls.js';
export {
  assessLinks,
  assessPhishing,
  linkDomainsAllMatch,
  linkMismatches,
  type PhishingAssessment,
  type PhishingLevel,
} from './links.js';
export {
  assessContentSignals,
  bodyContent,
  collapseWhitespace,
  containsPhrase,
  extractHtml,
  longestShoutRun,
  matchSpamVocabulary,
  normalizeForMatching,
  ownWords,
  vocabularyPoints,
  SPAM_PHRASE_GROUPS,
  VOCABULARY_CAP,
  type BodyContent,
  type ContentSignalInput,
  type HtmlAnchor,
  type HtmlExtract,
  type SpamPhraseGroup,
  type VocabularyHit,
} from './content/index.js';
export {
  asBytes,
  assessAttachmentSignals,
  expectedTypesForExtension,
  expectedTypesForMimeType,
  extensionsOf,
  inspectAttachment,
  inspectFilename,
  isExecutableType,
  listZipEntries,
  sniffFileType,
  stripBidiControls,
  ARCHIVE_EXECUTABLE_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  DECOY_EXTENSIONS,
  EXECUTABLE_EXTENSIONS,
  MACRO_ENABLED_EXTENSIONS,
  type AttachmentContent,
  type AttachmentFacts,
  type AttachmentInput,
  type FilenameFacts,
  type SniffedType,
  type TypeMismatch,
  type ZipEntry,
  type ZipListing,
} from './attachments/index.js';
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
  assessmentOf,
  isSpamScore,
  mergeAssessments,
  parseSpamReasons,
  rollUpAuthStatus,
  spamVerdict,
  unknownAuthStatus,
  SPAM_THRESHOLD,
  SUSPICIOUS_THRESHOLD,
  type AuthStatus,
  type SpamAssessment,
  type SpamReason,
  type SpamReasonId,
  type SpamVerdict,
} from './verdict.js';
