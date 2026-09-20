import { describe, expect, it } from 'vitest';

import { dmarcEnforcesBimi, parseBimiRecord, parseDmarcRecord } from '../src/brand/records.js';

/**
 * The two TXT records the brand stage reads.
 *
 * What this protects: a logo beside a message is read as identity. These two
 * records decide whether one is shown at all — the BIMI record says which
 * picture, the DMARC record says whether the domain has made spoofing it
 * hard. Misreading either is how a phisher ends up wearing a bank's mark.
 */
describe('parseBimiRecord', () => {
  it('reads the logo and evidence URLs, whatever the tag case and spacing', () => {
    expect(
      parseBimiRecord('v=BIMI1; l=https://x.example/logo.svg; a=https://x.example/vmc.pem'),
    ).toEqual({
      logoUrl: 'https://x.example/logo.svg',
      evidenceUrl: 'https://x.example/vmc.pem',
      declined: false,
    });
    expect(parseBimiRecord(' V=bimi1 ;L=https://x.example/l.svg ')).toMatchObject({
      logoUrl: 'https://x.example/l.svg',
      evidenceUrl: null,
    });
  });

  // `l=` present and empty is the spec's "we decline" — a different answer
  // from "no record", and one that must never fall through to a fetch.
  it('recognises an explicit decline', () => {
    expect(parseBimiRecord('v=BIMI1; l=;')).toEqual({
      logoUrl: null,
      evidenceUrl: null,
      declined: true,
    });
  });

  // A plain-http logo is a downgrade a spoofer on the path could swap.
  it('drops non-https URLs and rejects non-BIMI records', () => {
    expect(parseBimiRecord('v=BIMI1; l=http://x.example/logo.svg')).toMatchObject({
      logoUrl: null,
      declined: false,
    });
    expect(parseBimiRecord('v=spf1 include:_spf.example.com ~all')).toBeNull();
    expect(parseBimiRecord('')).toBeNull();
  });

  // Real records carry junk: a stray semicolon, a tag with no name, a value
  // that is not a URL at all. None of it may throw, and none of it may
  // become a logo.
  it('survives malformed tags and unparseable URLs', () => {
    expect(parseBimiRecord('v=BIMI1; =orphan; nonsense; l=not a url; a=also not')).toEqual({
      logoUrl: null,
      evidenceUrl: null,
      declined: false,
    });
  });
});

describe('parseDmarcRecord / dmarcEnforcesBimi', () => {
  it('parses policy, subdomain policy and pct (defaulting to 100)', () => {
    expect(parseDmarcRecord('v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:d@x.example')).toEqual(
      { policy: 'reject', subdomainPolicy: 'none', pct: 50 },
    );
    expect(parseDmarcRecord('v=DMARC1; p=quarantine')).toEqual({
      policy: 'quarantine',
      subdomainPolicy: null,
      pct: 100,
    });
    expect(parseDmarcRecord('v=DKIM1; k=rsa')).toBeNull();
    // A TXT record with no v= at all is not a policy either, whatever else
    // it carries: DMARC requires v=DMARC1 first.
    expect(parseDmarcRecord('p=reject; pct=100')).toBeNull();
  });

  // A `pct` that is not a number is not a reason to treat the domain as
  // unprotected — the spec's default stands.
  it('ignores an unreadable pct and an unknown policy word', () => {
    expect(parseDmarcRecord('v=DMARC1; p=reject; pct=abc')?.pct).toBe(100);
    expect(parseDmarcRecord('v=DMARC1; p=maybe')?.policy).toBeNull();
  });

  // THE premise of BIMI: a logo only under a policy that stops spoofing.
  it('allows BIMI only under quarantine/reject applied to all mail', () => {
    expect(dmarcEnforcesBimi(parseDmarcRecord('v=DMARC1; p=reject'), false)).toBe(true);
    expect(dmarcEnforcesBimi(parseDmarcRecord('v=DMARC1; p=quarantine'), false)).toBe(true);
    expect(dmarcEnforcesBimi(parseDmarcRecord('v=DMARC1; p=none'), false)).toBe(false);
    expect(dmarcEnforcesBimi(parseDmarcRecord('v=DMARC1; p=reject; pct=50'), false)).toBe(false);
    expect(dmarcEnforcesBimi(null, false)).toBe(false);
  });

  it('uses the subdomain policy for a subdomain when one is published', () => {
    const record = parseDmarcRecord('v=DMARC1; p=reject; sp=none');
    expect(dmarcEnforcesBimi(record, true)).toBe(false);
    expect(dmarcEnforcesBimi(record, false)).toBe(true);
    expect(dmarcEnforcesBimi(parseDmarcRecord('v=DMARC1; p=reject'), true)).toBe(true);
  });
});
