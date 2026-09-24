import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { PROTECTED_BRANDS, type ProtectedBrand } from '../src/data/brands/index.js';
import { FREEMAIL_DOMAINS } from '../src/data/freemail-domains.js';
import { registrableDomain } from '../src/identity.js';
import { normalizeForMatching } from '../src/text.js';

const BRANDS_DIR = resolve(__dirname, '../src/data/brands');
/** The brand files: everything in the folder but the barrel and the type. */
const brandFiles = (): string[] =>
  readdirSync(BRANDS_DIR)
    .filter((file) => file.endsWith('.ts') && file !== 'index.ts' && file !== 'types.ts')
    .sort();

/**
 * The brand list is data contributors edit, and a bad entry is a bad entry
 * for everyone: a phrase that is also an ordinary word puts a red shield on an
 * honest sender, and a domain that is not the brand's lets a phish wear the
 * name unchallenged. The rule's premises are pinned here so a pull request
 * cannot break them without a test saying so.
 */
describe('PROTECTED_BRANDS', () => {
  it('has unique ids, sorted, one brand per entry', () => {
    const ids = PROTECTED_BRANDS.map((brand) => brand.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual([...ids].sort());
    for (const brand of PROTECTED_BRANDS) expect(brand.name.trim(), brand.id).not.toBe('');
  });

  // A phrase is matched against text that has ALREADY been folded — case,
  // NFKC, invisible characters, whitespace. A phrase that is not itself in
  // that form can never match anything, and would sit in the list looking
  // like protection.
  it('writes every phrase in the folded form the matcher sees, once across the whole list', () => {
    const all: string[] = [];
    for (const brand of PROTECTED_BRANDS) {
      expect(brand.phrases.length, brand.id).toBeGreaterThan(0);
      for (const phrase of brand.phrases) {
        expect(phrase, `${brand.id}: ${phrase}`).toBe(normalizeForMatching(phrase));
        all.push(phrase);
      }
    }
    expect(new Set(all).size).toBe(all.length);
  });

  // The rule compares REGISTRABLE domains, so an entry that is not one — a
  // subdomain, a URL, a bare word — could never equal a sender's domain, and
  // the brand it belongs to would be impersonated by its own mail.
  it('lists registrable domains only, lowercase, sorted, once across the whole list', () => {
    const all: string[] = [];
    for (const brand of PROTECTED_BRANDS) {
      expect(brand.domains.length, brand.id).toBeGreaterThan(0);
      for (const domain of brand.domains) {
        expect(domain, `${brand.id}: ${domain}`).toBe(registrableDomain(domain));
        all.push(domain);
      }
      expect([...brand.domains], brand.id).toEqual([...brand.domains].sort());
    }
    expect(new Set(all).size).toBe(all.length);
  });

  // The name-carrying exemption keys on the labels of the brand's own domains
  // (`axisbank` from axisbank.com). A brand whose every domain has a label
  // shorter than three characters could never be recognised writing from an
  // unlisted domain, and its genuine mail would be flagged.
  it('gives every brand at least one domain label the exemption can use', () => {
    for (const brand of PROTECTED_BRANDS) {
      const labels = brand.domains.map((domain) => domain.split('.')[0] ?? '');
      expect(
        labels.some((label) => label.length >= 3),
        brand.id,
      ).toBe(true);
    }
  });

  // The false positive the file header warns about, pinned: a bare word that
  // is also a fruit, a surname, a travel document or a verb fires on honest
  // display names — "Visa Services", "Chase Whitfield", "Apple Tree Nursery".
  // Qualify such a name or leave the brand out; never list the bare word.
  it('holds no bare word that is also an ordinary English word', () => {
    const ordinary = ['apple', 'chase', 'meta', 'signal', 'stripe', 'uber', 'ups', 'visa', 'zoom'];
    for (const phrase of PROTECTED_BRANDS.flatMap((brand) => brand.phrases)) {
      expect(ordinary, phrase).not.toContain(phrase);
    }
  });
});

describe('src/data/brands/ — one file per brand', () => {
  // Regression: a brand file that exists but is not in the barrel protects
  // nobody, and nothing else would say so. The folder and the list must be
  // the same set, each file exporting exactly the brand it is named after.
  it('assembles exactly the files in the folder, each exporting the brand its file is named after', async () => {
    const files = brandFiles();
    const barrel = readFileSync(join(BRANDS_DIR, 'index.ts'), 'utf8');
    const imported = [...barrel.matchAll(/^import \{ \w+ \} from '\.\/([\w-]+)\.js';$/gm)].map(
      (match) => `${match[1]}.ts`,
    );
    expect(imported.sort()).toEqual(files);
    expect(PROTECTED_BRANDS.map((brand) => `${brand.id}.ts`)).toEqual(files);
    for (const file of files) {
      const module = (await import(`../src/data/brands/${file.replace(/\.ts$/, '.js')}`)) as Record<
        string,
        ProtectedBrand
      >;
      const exported = Object.values(module);
      expect(exported, file).toHaveLength(1);
      expect(exported[0]?.id, file).toBe(file.replace(/\.ts$/, ''));
    }
  });
});

/**
 * Where a domain in the list came from. The 39 brands below were written from
 * general knowledge before these fields existed, and were audited on
 * 2026-09-24 with `scripts/verify-brands.mjs` (every domain registered; nine
 * consumer mailbox domains removed). This list can only SHRINK: a brand added
 * from now on cites its sources, and a legacy brand that gains them must leave
 * the list — the last test below fails until it does.
 */
const UNSOURCED_BEFORE_PROVENANCE: readonly string[] = [
  'adobe',
  'amazon',
  'american-express',
  'apple',
  'axis-bank',
  'bank-of-america',
  'barclays',
  'binance',
  'citi',
  'coinbase',
  'dhl',
  'docusign',
  'dropbox',
  'ebay',
  'fedex',
  'github',
  'godaddy',
  'google',
  'hdfc-bank',
  'hsbc',
  'icici-bank',
  'income-tax-india',
  'intuit',
  'irctc',
  'kotak',
  'linkedin',
  'meta',
  'metamask',
  'microsoft',
  'netflix',
  'paypal',
  'paytm',
  'phonepe',
  'sbi',
  'spotify',
  'usps',
  'wells-fargo',
  'wetransfer',
  'zoom',
];

describe('provenance', () => {
  const today = new Date().toISOString().slice(0, 10);

  // A domain in this list may wear the brand's name unchallenged, so where it
  // came from has to be written down. Sources are HTTPS pages a reviewer can
  // open; `verified` is the day someone opened them.
  it('requires every brand added since the fields existed to cite sources and a verification date', () => {
    for (const brand of PROTECTED_BRANDS) {
      if (UNSOURCED_BEFORE_PROVENANCE.includes(brand.id)) continue;
      expect(brand.sources?.length ?? 0, `${brand.id} cites no source`).toBeGreaterThan(0);
      for (const source of brand.sources ?? []) expect(source, brand.id).toMatch(/^https:\/\/\S+$/);
      expect(brand.verified, `${brand.id} has no verification date`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(Number.isNaN(Date.parse(brand.verified ?? '')), brand.id).toBe(false);
      expect((brand.verified ?? '') <= today, `${brand.id} is verified in the future`).toBe(true);
    }
  });

  it('never has a verification date without sources, or sources without a date', () => {
    for (const brand of PROTECTED_BRANDS) {
      expect(brand.sources === undefined, brand.id).toBe(brand.verified === undefined);
    }
  });

  // The ratchet: the legacy list names only brands that exist and still lack
  // sources. Sourcing one means taking it off the list.
  it('lets the legacy list only shrink', () => {
    const ids = new Set(PROTECTED_BRANDS.map((brand) => brand.id));
    for (const id of UNSOURCED_BEFORE_PROVENANCE) {
      expect(ids.has(id), `${id} no longer exists; remove it from the legacy list`).toBe(true);
      const brand = PROTECTED_BRANDS.find((candidate) => candidate.id === id);
      expect(
        brand?.sources,
        `${id} now cites sources; remove it from the legacy list`,
      ).toBeUndefined();
    }
  });
});

/**
 * Domains in the vendored freemail corpus that are NOT places anybody can open
 * a mailbox today. The corpus is a list of domains seen as free email, and it
 * is noisy; each exception says why the brand may keep the domain.
 */
const NOT_A_MAILBOX_HOST: Readonly<Record<string, string>> = {
  'amazonses.com':
    'Amazon SES sends only as identities its customers verify; nobody can verify amazonses.com',
  'facebook.com': 'Facebook closed its @facebook.com mailboxes in 2014',
  'facebookmail.com': "Meta's notification domain; it has never offered mailboxes",
  'spotify.com': 'Spotify has never offered mailboxes; the corpus lists it in error',
};

describe('free mailbox hosts', () => {
  // Regression, found by the 2026-09-24 audit: gmail.com, hotmail.com,
  // outlook.com, icloud.com and five more were listed as brand domains, so
  // "Microsoft account team" <anyone@outlook.com> — one of the commonest lures
  // there is — was exempt from the rule written for it. A domain where anybody
  // can register an address can never vouch for a brand.
  it('lists no domain where anybody can open a mailbox', () => {
    const freemail = new Set<string>(FREEMAIL_DOMAINS);
    for (const brand of PROTECTED_BRANDS) {
      for (const domain of brand.domains) {
        if (!freemail.has(domain)) continue;
        expect(
          NOT_A_MAILBOX_HOST[domain],
          `${brand.id} lists the mailbox host ${domain}`,
        ).toBeDefined();
      }
    }
  });

  it('keeps an exception only for a domain that is both listed and in the corpus', () => {
    const listed = new Set(PROTECTED_BRANDS.flatMap((brand) => brand.domains));
    const freemail = new Set<string>(FREEMAIL_DOMAINS);
    for (const domain of Object.keys(NOT_A_MAILBOX_HOST)) {
      expect(listed.has(domain) && freemail.has(domain), domain).toBe(true);
    }
  });
});
