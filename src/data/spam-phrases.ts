/**
 * The spam vocabulary, as data.
 *
 * Grouped by the SCAM, not by the word. A group is a thing someone is trying
 * to do to the reader — harvest a credential, collect an advance fee, sell an
 * unlicensed drug — and its phrases are the ways that attempt is worded. That
 * shape is what lets the reason shown to a user say "language typical of
 * credential phishing" instead of listing words back at them, and it is what
 * keeps a contributor honest: a phrase belongs in this file only if you can
 * name which scam it serves.
 *
 * HOW THEY ARE SCORED. Each group charges its weight ONCE, however many of its
 * phrases matched — twelve pharmacy words are one pharmacy spam, not twelve
 * signals. The total from this file is then capped (see `VOCABULARY_CAP`) below
 * the spam threshold, so vocabulary can never file mail on its own. That cap
 * is the whole reason this list is safe to grow: the worst a wrong entry can
 * do is add points to a message that other rules already doubted.
 *
 * WHAT NOT TO ADD, in order of how often it is got wrong:
 *
 *  1. A word that is ordinary in some industry. "Invoice", "urgent", "payment
 *     overdue", "password" and "click here" are how real businesses write. A
 *     phrase earns its place by being odd in legitimate mail, not by being
 *     common in spam — those are different tests and only the first one
 *     protects the reader.
 *  2. A single word where a phrase will do. `winner` appears in sports
 *     newsletters; `you have been selected as a winner` does not.
 *  3. Anything in a language you do not read. A mistranslation here silently
 *     files that language's ordinary mail.
 *  4. A brand name. Impersonating a brand is caught by the sender and link
 *     rules, which compare domains and cannot be defeated by spelling.
 *
 * Phrases are lowercase and matched whole, on word boundaries, against text
 * that has already been case-folded, NFKC-normalised and stripped of the
 * zero-width characters spam inserts to break exactly this kind of matching.
 * A phrase may contain spaces; it may not contain a regular expression.
 */

export interface SpamPhraseGroup {
  /** Stable id, used in the reason detail and in tests. */
  id: string;
  /** What the group is, in the words a user would be shown. */
  label: string;
  /** Points charged once if ANY phrase in the group matches. */
  weight: number;
  phrases: readonly string[];
}

/**
 * The most this file can contribute to one message, no matter how many groups
 * match.
 *
 * Two, which is below `SUSPICIOUS_THRESHOLD` and well below `SPAM_THRESHOLD`.
 * Word lists are the oldest spam signal and the one that ages worst: the
 * vocabulary of a scam changes in a week, ordinary business writing does not,
 * and a filter that can convict on vocabulary alone is a filter that
 * eventually eats somebody's mail about a lottery syndicate at work. Capped
 * here, vocabulary does what it is actually good for — turning a message other
 * rules already found odd into one that crosses the line.
 */
export const VOCABULARY_CAP = 2;

export const SPAM_PHRASE_GROUPS: readonly SpamPhraseGroup[] = [
  {
    id: 'credential-phishing',
    label: 'language typical of credential phishing',
    weight: 2,
    phrases: [
      'confirm your password',
      'verify your password',
      'validate your email account',
      'revalidate your account',
      'reactivate your account',
      'your account will be suspended',
      'your account has been suspended',
      'your account will be closed',
      'your account will be terminated',
      'update your billing information',
      'confirm your billing information',
      'verify your billing details',
      'unusual sign-in activity',
      'unusual sign in activity',
      'suspicious sign-in attempt',
      'your mailbox is full and will be',
      'your mailbox has exceeded its storage limit',
      'your email account will be deactivated',
      'failure to verify will result in',
      'click here to verify your identity',
      'sign in to avoid suspension',
      'confirm your identity to continue using',
    ],
  },
  {
    id: 'advance-fee',
    label: 'language typical of an advance-fee (419) scam',
    weight: 2,
    phrases: [
      'next of kin',
      'unclaimed funds',
      'dormant account',
      'transfer of the said fund',
      'beneficiary of the sum',
      'sum of usd',
      'business proposal of mutual benefit',
      'i am contacting you in confidence',
      'this transaction is one hundred percent risk free',
      'strictly confidential and top secret',
      'my late husband deposited',
      'the deceased customer',
      'i am a barrister',
      'attorney to the late',
      'compensation fund approved',
      'united nations compensation',
      'your payment has been approved by the imf',
    ],
  },
  {
    id: 'prize-lottery',
    label: 'language typical of a prize or lottery scam',
    weight: 2,
    phrases: [
      'you have won',
      'you are a lucky winner',
      'you have been selected as a winner',
      'claim your prize',
      'claim your winnings',
      'lottery winning notification',
      'your email address won',
      'ticket number has won',
      'to claim your reward',
    ],
  },
  {
    id: 'unlicensed-pharmacy',
    label: 'language typical of unlicensed pharmacy spam',
    weight: 2,
    phrases: [
      'no prescription needed',
      'no prescription required',
      'without a prescription',
      'cheap meds',
      'discount pharmacy online',
      'male enhancement',
      'penis enlargement',
      'weight loss miracle',
      'lose weight without dieting',
    ],
  },
  {
    id: 'investment-fraud',
    label: 'language typical of investment fraud',
    weight: 1,
    phrases: [
      'guaranteed returns',
      'guaranteed profit',
      'risk-free investment',
      'risk free investment',
      'double your investment',
      'double your bitcoin',
      'crypto giveaway',
      'bitcoin giveaway',
      'send 1 eth and receive',
      'insider trading signals',
      'this stock is about to explode',
      'turn your savings into',
    ],
  },
  {
    id: 'work-from-home',
    label: 'language typical of a work-from-home or money-mule pitch',
    weight: 1,
    phrases: [
      'make money fast',
      'earn money from home',
      'work from home and earn',
      'be your own boss',
      'financial freedom in weeks',
      'no experience necessary apply now',
      'receive payments on our behalf',
      'process payments for our company',
    ],
  },
  {
    id: 'pressure',
    label: 'pressure to act before thinking',
    weight: 1,
    phrases: [
      'urgent action required',
      'immediate action is required',
      'act now before it is too late',
      'this is your final notice',
      'this is your last warning',
      'your immediate response is required',
      'failure to respond within 24 hours',
      'within 48 hours or your account',
    ],
  },
];
