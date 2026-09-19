/**
 * Which bulk-mail headers a message carries.
 *
 * Only the HEADER layer lives here — what a bulk sender is REQUIRED to set:
 * RFC 2919 `List-Id`, RFC 2369 `List-Unsubscribe`, `Precedence`, RFC 3834
 * `Auto-Submitted`, and the `Feedback-ID` bulk senders add for Google
 * Postmaster. Cheap, unambiguous, and available before the body is downloaded.
 *
 * This is NOT a "is this bulk mail" classifier, and it is not a spam signal on
 * its own: a newsletter you asked for sets every one of these. The spam rules
 * use it only to ask a narrower question — does a message that DECLARES itself
 * bulk also offer the unsubscribe route it is obliged to offer?
 */
import type { HeaderLookup } from './lookup.js';

/**
 * The headers {@link bulkHeaderSignals} reads. Exported so an IMAP fetch can
 * ask for exactly these — a header this list names but the fetch omits is a
 * signal that silently never fires.
 */
export const BULK_HEADER_NAMES: readonly string[] = [
  'list-id',
  'list-unsubscribe',
  'precedence',
  'auto-submitted',
  'feedback-id',
];

export interface BulkHeaderSignals {
  /** RFC 2919 `List-Id`. */
  listId: boolean;
  /** RFC 2369 `List-Unsubscribe`. */
  listUnsubscribe: boolean;
  /** `Precedence: bulk | list | junk`. */
  precedenceBulk: boolean;
  /** RFC 3834 `Auto-Submitted`, anything but the explicit `no`. */
  autoSubmitted: boolean;
  /** `Feedback-ID`, added by bulk senders for Google Postmaster Tools. */
  feedbackId: boolean;
  /**
   * A mass-mailer's own tracing header (`X-Campaign`, `X-Mailgun-Tag`,
   * `X-MC-User`, `X-SES-Outgoing`, or an ESP `X-Mailer`). Only ever true when
   * the caller holds the FULL header block — an ingest fetch that asks only for
   * {@link BULK_HEADER_NAMES} will leave this false and the RFC headers decide.
   */
  espTrace: boolean;
}

/** Vendor tracing headers. Presence alone is the signal, except `x-mailer`,
 *  whose value has to name a mass-mailer (every mail client sets `X-Mailer`). */
const ESP_TRACE_HEADERS: readonly string[] = [
  'x-campaign',
  'x-mailgun-tag',
  'x-mc-user',
  'x-ses-outgoing',
  'x-sg-eid',
];
const ESP_MAILER_RE =
  /mailchimp|sendgrid|mailgun|sparkpost|constant\s*contact|hubspot|marketo|klaviyo|braze|iterable/i;

/**
 * Takes a lookup rather than a header blob so a caller holding parsed headers
 * and one holding raw text run the SAME rules over their own storage.
 */
export function bulkHeaderSignals(get: HeaderLookup): BulkHeaderSignals {
  const value = (name: string): string => (get(name) || '').trim();

  // RFC 3834: `no` is the one value that means "a person sent this". Anything
  // else — auto-generated, auto-replied, auto-notified — is a machine, and the
  // value may carry parameters after a semicolon.
  const autoSubmittedValue = (value('auto-submitted').split(';')[0] as string).trim().toLowerCase();
  const precedence = value('precedence').toLowerCase();

  return {
    listId: value('list-id') !== '',
    listUnsubscribe: value('list-unsubscribe') !== '',
    precedenceBulk: precedence === 'bulk' || precedence === 'list' || precedence === 'junk',
    autoSubmitted: autoSubmittedValue !== '' && autoSubmittedValue !== 'no',
    feedbackId: value('feedback-id') !== '',
    espTrace:
      ESP_TRACE_HEADERS.some((name) => value(name) !== '') || ESP_MAILER_RE.test(value('x-mailer')),
  };
}

/** True when ANY bulk-mail header is present. */
export function hasBulkHeaderSignal(get: HeaderLookup): boolean {
  return Object.values(bulkHeaderSignals(get)).some(Boolean);
}
