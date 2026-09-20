/**
 * `@sarv-in/email-spam-scan/brand` — who a message says it is FROM, shown as
 * a mark: the BIMI logo a domain publishes, the Verified Mark Certificate
 * that turns that logo into a verified identity, and the favicon that stands
 * in when a domain publishes neither.
 *
 * This is the only entry in the package that both reaches the network and can
 * run in a browser: DNS and HTTPS are injected, the certificate work lives
 * behind optional peer dependencies loaded dynamically, and every byte
 * operation goes through the web platform rather than `node:buffer`.
 */
export {
  BIMI_EVIDENCE_MAX_BYTES,
  BIMI_SELECTOR,
  lookupBimi,
  type BimiLookup,
  type BimiOptions,
  type BimiStatus,
} from './bimi.js';
export {
  defaultFetch,
  fetchBounded,
  type FetchBoundedOptions,
  type FetchedBytes,
  type FetchLike,
  type FetchResponse,
} from './fetch.js';
export {
  discoverFavicon,
  extractIconLinks,
  faviconHosts,
  rankIconCandidates,
  sniffImageType,
  FAVICON_MAX_BYTES,
  HOMEPAGE_MAX_BYTES,
  type FaviconOptions,
  type FaviconResult,
  type FaviconStatus,
  type IconCandidate,
} from './favicon.js';
export { decodeLogoDataUri, extractLogotypeEvidence, type LogotypeEvidence } from './logotype.js';
export { MVA_ROOTS, type MarkVerifyingAuthorityRoot } from './mva-roots.js';
export {
  dmarcEnforcesBimi,
  parseBimiRecord,
  parseDmarcRecord,
  type BimiRecord,
  type DmarcPolicyValue,
  type DmarcRecord,
} from './records.js';
export { checkBimiSvg, BIMI_LOGO_MAX_BYTES, type SvgCheck } from './svg.js';
export {
  fingerprintHex,
  validateVmc,
  vmcDomains,
  BIMI_EKU_OID,
  LOGOTYPE_EXTENSION_OID,
  type ValidateVmcOptions,
  type VmcResult,
  type VmcStatus,
} from './vmc.js';
