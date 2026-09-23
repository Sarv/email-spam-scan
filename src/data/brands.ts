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
 * Entries stay sorted by id, one brand per object, so diffs stay readable and
 * two contributors do not silently conflict.
 */

export interface ProtectedBrand {
  /** Stable id, used in tests. */
  id: string;
  /** What the brand is called in a reason shown to a reader. */
  name: string;
  /** Names the brand is impersonated with — lowercase, matched as whole words. */
  phrases: readonly string[];
  /** Registrable domains the brand itself sends from or owns. */
  domains: readonly string[];
}

export const PROTECTED_BRANDS: readonly ProtectedBrand[] = [
  {
    id: 'adobe',
    name: 'Adobe',
    phrases: [
      'acrobat sign',
      'adobe acrobat',
      'adobe account',
      'adobe document cloud',
      'adobe id',
      'adobe sign',
      'adobesign',
      'echosign',
    ],
    domains: ['acrobat.com', 'adobe.com', 'adobelogin.com', 'adobesign.com', 'echosign.com'],
  },
  {
    id: 'amazon',
    name: 'Amazon',
    phrases: [
      'amazon account',
      'amazon customer service',
      'amazon payments',
      'amazon prime',
      'amazon security',
      'amazon support',
      'amazon web services',
    ],
    domains: [
      'amazon.ae',
      'amazon.ca',
      'amazon.co.jp',
      'amazon.co.uk',
      'amazon.com',
      'amazon.com.au',
      'amazon.com.br',
      'amazon.com.mx',
      'amazon.de',
      'amazon.es',
      'amazon.fr',
      'amazon.in',
      'amazon.it',
      'amazon.nl',
      'amazon.sg',
      'amazonaws.com',
      'amazonpay.in',
      'amazonses.com',
      'primevideo.com',
    ],
  },
  {
    id: 'american-express',
    name: 'American Express',
    phrases: ['american express', 'amex'],
    domains: ['aexp.com', 'americanexpress.com'],
  },
  {
    id: 'apple',
    name: 'Apple',
    phrases: [
      'app store',
      'apple account',
      'apple id',
      'apple pay',
      'apple support',
      'icloud',
      'itunes',
    ],
    domains: ['apple.com', 'icloud.com', 'itunes.com', 'mac.com', 'me.com'],
  },
  {
    id: 'axis-bank',
    name: 'Axis Bank',
    phrases: ['axis bank'],
    domains: ['axisbank.com'],
  },
  {
    id: 'bank-of-america',
    name: 'Bank of America',
    phrases: ['bank of america'],
    domains: ['bankofamerica.com', 'bofa.com'],
  },
  {
    id: 'barclays',
    name: 'Barclays',
    phrases: ['barclays'],
    domains: ['barclays.co.uk', 'barclays.com'],
  },
  {
    id: 'binance',
    name: 'Binance',
    phrases: ['binance'],
    domains: ['binance.com', 'binance.us'],
  },
  {
    id: 'citi',
    name: 'Citi',
    phrases: ['citibank'],
    domains: ['citi.com', 'citibank.co.in', 'citibank.com'],
  },
  {
    id: 'coinbase',
    name: 'Coinbase',
    phrases: ['coinbase'],
    domains: ['coinbase.com'],
  },
  {
    id: 'dhl',
    name: 'DHL',
    phrases: ['dhl'],
    domains: ['dhl.com', 'dhl.de', 'dpdhl.com'],
  },
  {
    id: 'docusign',
    name: 'DocuSign',
    phrases: ['docusign'],
    domains: ['docusign.com', 'docusign.net'],
  },
  {
    id: 'dropbox',
    name: 'Dropbox',
    phrases: ['dropbox'],
    domains: ['dropbox.com', 'dropboxmail.com'],
  },
  {
    id: 'ebay',
    name: 'eBay',
    phrases: ['ebay'],
    domains: ['ebay.co.uk', 'ebay.com', 'ebay.de'],
  },
  {
    id: 'fedex',
    name: 'FedEx',
    phrases: ['fedex'],
    domains: ['fedex.com'],
  },
  {
    id: 'github',
    name: 'GitHub',
    phrases: ['github'],
    domains: ['github.com'],
  },
  {
    id: 'godaddy',
    name: 'GoDaddy',
    phrases: ['godaddy'],
    domains: ['godaddy.com', 'secureserver.net'],
  },
  {
    id: 'google',
    name: 'Google',
    phrases: [
      'gmail team',
      'google account',
      'google cloud',
      'google docs',
      'google drive',
      'google pay',
      'google play',
      'google security',
      'google support',
      'google team',
      'google workspace',
    ],
    domains: [
      'gmail.com',
      'google.ca',
      'google.co.in',
      'google.co.uk',
      'google.com',
      'google.com.au',
      'google.de',
      'google.fr',
      'googlemail.com',
      'withgoogle.com',
      'youtube.com',
    ],
  },
  {
    id: 'hdfc-bank',
    name: 'HDFC Bank',
    phrases: ['hdfc bank'],
    domains: ['hdfcbank.com', 'hdfcbank.net'],
  },
  {
    id: 'hsbc',
    name: 'HSBC',
    phrases: ['hsbc'],
    domains: ['hsbc.co.in', 'hsbc.co.uk', 'hsbc.com', 'hsbc.com.hk'],
  },
  {
    id: 'icici-bank',
    name: 'ICICI Bank',
    phrases: ['icici bank'],
    domains: ['icicibank.com'],
  },
  {
    id: 'income-tax-india',
    name: 'the Income Tax Department',
    phrases: ['income tax department'],
    domains: ['incometax.gov.in', 'incometaxindia.gov.in'],
  },
  {
    id: 'intuit',
    name: 'Intuit',
    phrases: ['intuit', 'quickbooks'],
    domains: ['intuit.com', 'quickbooks.com'],
  },
  {
    id: 'irctc',
    name: 'IRCTC',
    phrases: ['irctc'],
    domains: ['irctc.co.in', 'irctc.com'],
  },
  {
    id: 'kotak',
    name: 'Kotak Mahindra Bank',
    phrases: ['kotak bank', 'kotak mahindra bank'],
    domains: ['kotak.com'],
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    phrases: ['linkedin'],
    domains: ['linkedin.com'],
  },
  {
    id: 'meta',
    name: 'Meta',
    phrases: [
      'facebook security',
      'facebook support',
      'facebook team',
      'facebookmail',
      'instagram support',
      'instagram team',
      'meta business',
      'meta for business',
      'whatsapp security',
      'whatsapp support',
      'whatsapp team',
    ],
    domains: [
      'facebook.com',
      'facebookmail.com',
      'fb.com',
      'instagram.com',
      'messenger.com',
      'meta.com',
      'metamail.com',
      'whatsapp.com',
      'whatsapp.net',
      'workplace.com',
    ],
  },
  {
    id: 'metamask',
    name: 'MetaMask',
    phrases: ['metamask'],
    domains: ['metamask.io'],
  },
  {
    id: 'microsoft',
    name: 'Microsoft',
    phrases: [
      'microsoft 365',
      'microsoft account',
      'microsoft azure',
      'microsoft online',
      'microsoft outlook',
      'microsoft security',
      'microsoft support',
      'microsoft teams',
      'office 365',
      'office365',
      'onedrive',
      'outlook team',
      'sharepoint',
    ],
    domains: [
      'azure.com',
      'azurecomm.net',
      'hotmail.com',
      'live.com',
      'microsoft.com',
      'microsoft365.com',
      'microsoftonline.com',
      'microsoftsupport.com',
      'msn.com',
      'office.com',
      'office365.com',
      'onedrive.com',
      'outlook.com',
      'sharepoint.com',
      'skype.com',
      'windows.com',
    ],
  },
  {
    id: 'netflix',
    name: 'Netflix',
    phrases: ['netflix'],
    domains: ['netflix.com'],
  },
  {
    id: 'paypal',
    name: 'PayPal',
    phrases: ['paypal'],
    domains: [
      'paypal-communication.com',
      'paypal-corp.com',
      'paypal.co.uk',
      'paypal.com',
      'paypal.de',
      'paypal.me',
      'paypalobjects.com',
    ],
  },
  {
    id: 'paytm',
    name: 'Paytm',
    phrases: ['paytm'],
    domains: ['paytm.com', 'paytmbank.com'],
  },
  {
    id: 'phonepe',
    name: 'PhonePe',
    phrases: ['phonepe'],
    domains: ['phonepe.com'],
  },
  {
    id: 'sbi',
    name: 'State Bank of India',
    phrases: ['state bank of india'],
    domains: ['onlinesbi.sbi', 'sbi.co.in'],
  },
  {
    id: 'spotify',
    name: 'Spotify',
    phrases: ['spotify'],
    domains: ['spotify.com', 'spotifymail.com'],
  },
  {
    id: 'usps',
    name: 'USPS',
    phrases: ['usps'],
    domains: ['usps.com', 'usps.gov'],
  },
  {
    id: 'wells-fargo',
    name: 'Wells Fargo',
    phrases: ['wells fargo'],
    domains: ['wellsfargo.com'],
  },
  {
    id: 'wetransfer',
    name: 'WeTransfer',
    phrases: ['wetransfer'],
    domains: ['wetransfer.com'],
  },
  {
    id: 'zoom',
    name: 'Zoom',
    phrases: ['zoom meetings', 'zoom video communications'],
    domains: ['zoom.com', 'zoom.us'],
  },
];
