/**
 * The protected brands, as data.
 *
 * WHAT THIS IS FOR. "Adobe Acrobat Sign" <Adobesign@powersublinks.com> passed
 * SPF, DKIM and DMARC — for powersublinks.com, a domain the attacker owns and
 * had every right to authenticate. Authentication answers "did this domain
 * send it?", never "is this domain who the name says it is?". The one check
 * that can answer the second question without a network is to know which
 * domains a brand actually sends from, and that is what this file holds: a
 * name people are impersonated with, and the registrable domains its owner
 * writes from. The rule that reads it (`brandsNamedIn`, `brandOwningDomain` in
 * `../identity.ts`) fires when the display name borrows a name from this list
 * and the address does not belong to any of its domains.
 *
 * THE BAR FOR A PHRASE — in order of how often it is got wrong:
 *
 *  1. A NAME nobody else uses. "PayPal", "DocuSign" and "Acrobat Sign" are
 *     one company each. "Apple", "Chase", "Visa" and "Zoom" are a fruit, a
 *     surname, a travel document and a verb, and each appears in honest
 *     display names — "Visa Services", "Chase Whitfield" — so a bare word
 *     like that is NOT an entry. Qualify it into something only the brand
 *     would call itself: `apple id`, `zoom video communications`.
 *  2. A NAME the brand uses AS A SENDER. The rule is about display names, so
 *     a phrase earns its place by being what the brand's own mail says in the
 *     From header — "Microsoft account team", "Google Workspace" — not by
 *     being a product somebody might discuss. "Google Ads" is how a
 *     thousand agencies describe their trade; it does not belong here.
 *  3. Lowercase, whole words, no regular expression. Matching is done on
 *     NFKC-normalised, case-folded text with zero-width characters stripped —
 *     see `../text.ts` — so `ＰａｙＰａｌ` and `Pay<U+200B>Pal` both match and
 *     `paypalooza` does not.
 *
 * THE BAR FOR A DOMAIN. The REGISTRABLE domain (eTLD+1) the brand sends mail
 * from or publishes as its own, taken from the brand's own documentation or
 * its own message headers — never a domain a reseller or an ESP uses on its
 * behalf, and never one somebody registered to look like the brand. A domain
 * added here is a domain that may wear the name unchallenged, so the list
 * must be short and provably the brand's. Subdomains are implied: an entry of
 * `adobe.com` covers `documents.adobe.com`.
 *
 * WHICH BRANDS. The ones phishing actually impersonates, by volume: the
 * quarterly brand-phishing reports from Check Point Research and the APWG
 * Phishing Activity Trends Reports put Microsoft, Google, Apple, Amazon,
 * DHL, LinkedIn, PayPal, Netflix, Adobe, DocuSign, Meta and the large banks
 * at the top year after year. The Indian entries are here because the first
 * consumer of this package is an Indian mail client and payment and bank
 * lures there name Indian brands.
 *
 * ONE FILE PER BRAND, in this folder, named by the brand's id and exporting
 * that one brand: reviewable on its own, a history of its own, room for a
 * note on why a domain is or is not there, and no two contributors editing
 * the same file. This barrel only assembles them, sorted by id; a test checks
 * that the folder and this list agree.
 *
 * PROVENANCE. `sources` and `verified` (see `types.ts`) record where a
 * brand's domains were checked and when. The 39 brands that predate the
 * fields were written from general knowledge and audited on 2026-09-24 with
 * `scripts/verify-brands.mjs`, which found every one registered and nine
 * consumer mailbox domains that did not belong (removed; see google.ts,
 * microsoft.ts, apple.ts). New brands cite sources. Run the script after any
 * edit here; CI runs it weekly.
 */

import { adobe } from './adobe.js';
import { amazon } from './amazon.js';
import { americanExpress } from './american-express.js';
import { apple } from './apple.js';
import { axisBank } from './axis-bank.js';
import { bankOfAmerica } from './bank-of-america.js';
import { barclays } from './barclays.js';
import { binance } from './binance.js';
import { citi } from './citi.js';
import { coinbase } from './coinbase.js';
import { dhl } from './dhl.js';
import { docusign } from './docusign.js';
import { dropbox } from './dropbox.js';
import { ebay } from './ebay.js';
import { fedex } from './fedex.js';
import { github } from './github.js';
import { godaddy } from './godaddy.js';
import { google } from './google.js';
import { hdfcBank } from './hdfc-bank.js';
import { hsbc } from './hsbc.js';
import { iciciBank } from './icici-bank.js';
import { incomeTaxIndia } from './income-tax-india.js';
import { intuit } from './intuit.js';
import { irctc } from './irctc.js';
import { kotak } from './kotak.js';
import { linkedin } from './linkedin.js';
import { meta } from './meta.js';
import { metamask } from './metamask.js';
import { microsoft } from './microsoft.js';
import { netflix } from './netflix.js';
import { paypal } from './paypal.js';
import { paytm } from './paytm.js';
import { phonepe } from './phonepe.js';
import { sbi } from './sbi.js';
import { spotify } from './spotify.js';
import type { ProtectedBrand } from './types.js';
import { usps } from './usps.js';
import { wellsFargo } from './wells-fargo.js';
import { wetransfer } from './wetransfer.js';
import { zoom } from './zoom.js';

export type { ProtectedBrand };

/** Every protected brand, sorted by id. Treat it as immutable: the lookups index it once. */
export const PROTECTED_BRANDS: readonly ProtectedBrand[] = [
  adobe,
  amazon,
  americanExpress,
  apple,
  axisBank,
  bankOfAmerica,
  barclays,
  binance,
  citi,
  coinbase,
  dhl,
  docusign,
  dropbox,
  ebay,
  fedex,
  github,
  godaddy,
  google,
  hdfcBank,
  hsbc,
  iciciBank,
  incomeTaxIndia,
  intuit,
  irctc,
  kotak,
  linkedin,
  meta,
  metamask,
  microsoft,
  netflix,
  paypal,
  paytm,
  phonepe,
  sbi,
  spotify,
  usps,
  wellsFargo,
  wetransfer,
  zoom,
];
