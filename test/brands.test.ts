import { describe, expect, it } from 'vitest';

import { PROTECTED_BRANDS } from '../src/data/brands.js';
import { registrableDomain } from '../src/identity.js';
import { normalizeForMatching } from '../src/text.js';

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
