import { describe, expect, it } from 'vitest';

import { bulkHeaderSignals, hasBulkHeaderSignal, BULK_HEADER_NAMES } from '../src/headers/bulk.js';
import { headerLookupFromText } from '../src/headers/lookup.js';
import type { HeaderLookup } from '../src/headers/lookup.js';

const lookup =
  (headers: Record<string, string>): HeaderLookup =>
  (name) =>
    headers[name] ?? null;

describe('bulkHeaderSignals', () => {
  it('is all false for a plain person-to-person message', () => {
    const signals = bulkHeaderSignals(lookup({ from: 'alice@example.net' }));
    expect(Object.values(signals).every((v) => v === false)).toBe(true);
    expect(hasBulkHeaderSignal(lookup({ from: 'alice@example.net' }))).toBe(false);
  });

  it('reads each RFC bulk header', () => {
    expect(bulkHeaderSignals(lookup({ 'list-id': '<l.example.net>' })).listId).toBe(true);
    expect(bulkHeaderSignals(lookup({ 'list-unsubscribe': '<https://x/u>' })).listUnsubscribe).toBe(
      true,
    );
    expect(bulkHeaderSignals(lookup({ 'feedback-id': '1:2:3:mc' })).feedbackId).toBe(true);
  });

  it('treats bulk, list and junk as a bulk Precedence, but not a made-up value', () => {
    expect(bulkHeaderSignals(lookup({ precedence: 'bulk' })).precedenceBulk).toBe(true);
    expect(bulkHeaderSignals(lookup({ precedence: 'LIST' })).precedenceBulk).toBe(true);
    expect(bulkHeaderSignals(lookup({ precedence: 'junk' })).precedenceBulk).toBe(true);
    expect(bulkHeaderSignals(lookup({ precedence: 'first-class' })).precedenceBulk).toBe(false);
  });

  // Regression: RFC 3834 says `no` is the one value meaning a person sent it.
  // Inverting this marks every human message auto-submitted, which exempts it
  // from the no-unsubscribe rule and silently disables that rule everywhere.
  it('treats every Auto-Submitted value except "no" as a machine, parameters included', () => {
    expect(bulkHeaderSignals(lookup({ 'auto-submitted': 'no' })).autoSubmitted).toBe(false);
    expect(bulkHeaderSignals(lookup({ 'auto-submitted': 'auto-generated' })).autoSubmitted).toBe(
      true,
    );
    expect(
      bulkHeaderSignals(lookup({ 'auto-submitted': 'auto-replied; owner=x' })).autoSubmitted,
    ).toBe(true);
    expect(bulkHeaderSignals(lookup({ 'auto-submitted': 'no; x=y' })).autoSubmitted).toBe(false);
    expect(bulkHeaderSignals(lookup({ 'auto-submitted': '  ' })).autoSubmitted).toBe(false);
  });

  it('detects vendor trace headers by presence', () => {
    for (const name of ['x-campaign', 'x-mailgun-tag', 'x-mc-user', 'x-ses-outgoing', 'x-sg-eid']) {
      expect(bulkHeaderSignals(lookup({ [name]: 'v' })).espTrace, name).toBe(true);
    }
  });

  // Regression: every mail client sets X-Mailer, so presence alone would mark
  // all mail as bulk. Only a value naming a mass-mailer counts.
  it('requires X-Mailer to NAME a mass-mailer, not merely be present', () => {
    expect(
      bulkHeaderSignals(lookup({ 'x-mailer': 'Apple Mail (2.3654.120.0.1.13)' })).espTrace,
    ).toBe(false);
    expect(bulkHeaderSignals(lookup({ 'x-mailer': 'Microsoft Outlook 16.0' })).espTrace).toBe(
      false,
    );
    expect(bulkHeaderSignals(lookup({ 'x-mailer': 'MailChimp Mailer - **CID**' })).espTrace).toBe(
      true,
    );
    expect(bulkHeaderSignals(lookup({ 'x-mailer': 'Constant  Contact' })).espTrace).toBe(true);
  });

  it('works over a raw header block through headerLookupFromText', () => {
    const block = 'List-Id: <news.example.net>\r\nPrecedence: bulk\r\nFrom: n@example.net';
    const signals = bulkHeaderSignals(headerLookupFromText(block));
    expect(signals.listId).toBe(true);
    expect(signals.precedenceBulk).toBe(true);
    expect(signals.listUnsubscribe).toBe(false);
  });

  // Regression: a header named here but never fetched is a signal that
  // silently never fires. This pins the fetch list to the rules that read it.
  it('names every RFC header the signals read', () => {
    expect([...BULK_HEADER_NAMES].sort()).toEqual(
      ['auto-submitted', 'feedback-id', 'list-id', 'list-unsubscribe', 'precedence'].sort(),
    );
  });
});
