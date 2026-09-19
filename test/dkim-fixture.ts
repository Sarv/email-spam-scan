/**
 * A signed message and a DNS zone to check it against, with no network.
 *
 * The point of this file: a test that verified a signature against a real
 * selector in real DNS would be a test that fails when somebody else rotates a
 * key, and passes for reasons nothing in this repository controls. So the key
 * is generated here, the message is signed with it here, and the "DNS" is an
 * object literal — which makes the failure cases (no key published, wrong key,
 * a resolver that hangs) constructible rather than hypothetical.
 */
import { generateKeyPairSync } from 'node:crypto';

import { dkimSign } from 'mailauth';

import type { DnsResolver } from '../src/verify.js';

export const SIGNING_DOMAIN = 'example.com';
export const SELECTOR = 'sel';
export const SENDER_IP = '198.51.100.7';

// One 2048-bit key for the whole run. Generating one per test is seconds of
// CPU for no extra coverage.
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

/** The `p=` value a DKIM TXT record publishes: the key, stripped of its PEM armour. */
const publicKeyBase64 = publicKey.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');

/** A TXT record the fake resolver returns, in the chunked shape a resolver uses. */
const txt = (value: string): string[][] => [[value]];

/** Records keyed by name, then by record type, as a resolver would answer them. */
export type FakeZone = Record<string, Record<string, unknown>>;

/** The zone in which the signed message below passes all three checks. */
export const PASSING_ZONE: FakeZone = {
  [`${SELECTOR}._domainkey.${SIGNING_DOMAIN}`]: { TXT: txt(`v=DKIM1;k=rsa;p=${publicKeyBase64}`) },
  [SIGNING_DOMAIN]: { TXT: txt(`v=spf1 ip4:${SENDER_IP} -all`) },
  [`_dmarc.${SIGNING_DOMAIN}`]: { TXT: txt('v=DMARC1; p=reject') },
};

/**
 * A resolver over a fixture zone.
 *
 * Absent names raise `ENOTFOUND`, exactly as a real resolver does, because
 * "the record is not published" is the branch most of the failure cases run
 * through and a resolver that returned an empty array instead would test a
 * path no real deployment takes.
 */
export function fakeResolver(zone: FakeZone): DnsResolver {
  return async (name, recordType) => {
    const answer = zone[name.toLowerCase().replace(/\.$/, '')]?.[recordType];
    if (answer === undefined) {
      const error: NodeJS.ErrnoException = new Error(`ENOTFOUND ${name}`);
      error.code = 'ENOTFOUND';
      throw error;
    }
    return answer;
  };
}

/** A resolver that never answers, for the deadline. */
export const hangingResolver: DnsResolver = () => new Promise(() => {});

export const UNSIGNED_MESSAGE = [
  `From: Ankur <ankur@${SIGNING_DOMAIN}>`,
  'To: reader@example.org',
  'Subject: Quarterly numbers',
  'Date: Thu, 18 Sep 2026 10:00:00 +0000',
  'Message-ID: <numbers@example.com>',
  '',
  'The numbers are attached.',
  '',
].join('\r\n');

/** The same message with a real DKIM signature over it. */
export async function signedMessage(raw = UNSIGNED_MESSAGE): Promise<string> {
  // `signatureData`, not the top-level `signingDomain`/`selector` its shipped
  // type declarations describe — those are silently ignored and the result is
  // an unsigned message and an empty error list.
  const signed = await dkimSign(raw, {
    canonicalization: 'relaxed/relaxed',
    signatureData: [{ signingDomain: SIGNING_DOMAIN, selector: SELECTOR, privateKey }],
  } as unknown as Parameters<typeof dkimSign>[1]);
  return signed.signatures + raw;
}
