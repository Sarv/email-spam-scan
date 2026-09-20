import 'reflect-metadata'; // before @peculiar/x509 on the next line: its DI container needs the polyfill

import { X509Certificate } from '@peculiar/x509';
import { beforeAll, describe, expect, it } from 'vitest';

import { decodeLogoDataUri, extractLogotypeEvidence } from '../src/brand/logotype.js';
import { MVA_ROOTS } from '../src/brand/mva-roots.js';
import { fingerprintHex, validateVmc, vmcDomains } from '../src/brand/vmc.js';

import {
  asCertificate,
  base64Of,
  descriptorFor,
  digestOf,
  future,
  gzipOf,
  logotypeDer,
  makeCrossSignedLoop,
  makeIntermediate,
  makeLeaf,
  makeRoot,
  past,
  pemOf,
  testPki,
  utf8,
  NOW,
  OTHER_SVG,
  SHA1_OID,
  SVG,
  type Pki,
} from './vmc-fixture.js';

/**
 * BIMI's Verified Mark Certificate — the thing behind the tick.
 *
 * What this protects: the tick is a promise that a third party checked who
 * owns this brand. Every shortcut in the chain — a root nobody pinned, a
 * certificate for another domain, a logo the certificate never saw, an
 * expired issuer — is a way for a phisher to wear a bank's logo with our
 * blessing. So each requirement is pinned on BOTH sides: the real thing
 * verifies, and each single defect is named and refused.
 */
let pki: Pki;
beforeAll(async () => {
  pki = await testPki();
});

const options = (): { roots: [Awaited<ReturnType<typeof descriptorFor>>]; now: Date } => ({
  roots: [pki.rootDescriptor],
  now: NOW,
});

describe('the logotype extension', () => {
  const hexOf = async (bytes: Uint8Array): Promise<string> =>
    [...(await digestOf('SHA-256', bytes))]
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');

  // THE real-world shape (Apple's, DigiCert's): the AlgorithmIdentifier
  // carries NULL parameters, so the hash sequence has three children, not two.
  it('reads a hash whose AlgorithmIdentifier carries NULL parameters', async () => {
    const evidence = await extractLogotypeEvidence(await logotypeDer(SVG, { nullParams: true }));
    expect(evidence.sha256).toEqual([await hexOf(SVG)]);
  });

  // THE crash on the first real VMC: an unknown hash algorithm made the
  // walker step INTO the ObjectIdentifier, whose "children" are arc records
  // with no value block at all. It must walk past, report no digest, and
  // still find the embedded logo.
  it('walks past an unknown hash algorithm without crashing', async () => {
    const evidence = await extractLogotypeEvidence(
      await logotypeDer(SVG, { hashOid: '2.16.840.1.101.3.4.2.3', nullParams: true }), // SHA-512
    );
    expect(evidence.sha256).toEqual([]);
    expect(evidence.sha1).toEqual([]);
    expect(evidence.dataUris).toHaveLength(1);
  });

  it('reads a SHA-1 hash as well, as RFC 3709 and Apple both do', async () => {
    const sha1 = await digestOf('SHA-1', SVG);
    const evidence = await extractLogotypeEvidence(
      await logotypeDer(SVG, { hash: sha1, hashOid: SHA1_OID, nullParams: true, embed: false }),
    );
    expect(evidence.sha1).toEqual([
      [...sha1].map((byte) => byte.toString(16).padStart(2, '0')).join(''),
    ]);
    expect(evidence.sha256).toEqual([]);
  });

  it('extracts the digest and the embedded gzipped logo, walking the ASN.1 generically', async () => {
    const evidence = await extractLogotypeEvidence(await logotypeDer(SVG));
    expect(evidence.sha256).toEqual([await hexOf(SVG)]);
    expect(evidence.dataUris).toHaveLength(1);
    expect(await decodeLogoDataUri(evidence.dataUris[0] ?? '')).toEqual(SVG);
  });

  // An AlgorithmIdentifier with nothing in it is not a digest — and must not
  // be mistaken for one, nor stop the walk finding the embedded copy.
  it('ignores a hash whose algorithm names nothing', async () => {
    const evidence = await extractLogotypeEvidence(
      await logotypeDer(SVG, { emptyAlgorithm: true }),
    );
    expect(evidence.sha256).toEqual([]);
    expect(evidence.dataUris).toHaveLength(1);
  });

  it('is empty for garbage', async () => {
    expect(await extractLogotypeEvidence(new Uint8Array([0x30, 0x03, 0x02, 0x01]))).toEqual({
      sha256: [],
      sha1: [],
      dataUris: [],
    });
  });

  it('decodes a plain, a percent-encoded and a gzipped data URI, and refuses the rest', async () => {
    expect(await decodeLogoDataUri(`data:image/svg+xml;base64,${base64Of(SVG)}`)).toEqual(SVG);
    expect(await decodeLogoDataUri('data:image/svg+xml,%3Csvg%3E')).toEqual(utf8('<svg>'));
    expect(
      await decodeLogoDataUri(`data:image/svg+xml;base64,${base64Of(await gzipOf(SVG))}`),
    ).toEqual(SVG);
    expect(await decodeLogoDataUri('nonsense')).toBeNull();
    expect(await decodeLogoDataUri('data:image/svg+xml;base64,!!!!')).toBeNull();
    expect(await decodeLogoDataUri('data:image/svg+xml,%E0%A4%A')).toBeNull();
    const corrupt = new Uint8Array([0x1f, 0x8b, ...utf8('not gzip at all')]);
    expect(await decodeLogoDataUri(`data:image/svg+xml;base64,${base64Of(corrupt)}`)).toBeNull();
  });
});

describe('validateVmc', () => {
  // THE happy path: a real chain to a pinned MVA root, for this domain, for
  // this logo.
  it('verifies a chain to a pinned root for the covered domain and the bound logo', async () => {
    const leaf = await makeLeaf();
    const result = await validateVmc(pemOf(leaf, pki.root.cert), 'example.com', SVG, options());
    expect(result.status).toBe('verified');
    expect(result.organization).toBe('Example Inc');
    expect(result.issuer).toBe('Test Verified Mark Root');
    expect(result.issuerOrganization).toBe('Test MVA');
    expect(result.detail).toContain('Example Inc');
    expect(result.notAfter).toBe(Math.floor(future(365).getTime() / 1000));
  });

  it('verifies a subdomain of a covered domain, and when the root is not in the file', async () => {
    const leaf = await makeLeaf({ domains: ['example.com'] });
    expect((await validateVmc(pemOf(leaf), 'mail.example.com', SVG, options())).status).toBe(
      'verified',
    );
  });

  it('verifies through an issuing intermediate', async () => {
    const issuing = await makeIntermediate('CN=Test VMC Issuing CA, O=Test MVA', pki.root);
    const leaf = await makeLeaf({ issuer: issuing });
    const result = await validateVmc(pemOf(leaf, issuing.cert), 'example.com', SVG, options());
    expect(result.status).toBe('verified');
  });

  // THE forgery guard. Anyone can mint a chain with the right OIDs and names;
  // only the anchor tells a Mark Verifying Authority from a laptop.
  it('refuses a chain that ends at a root nobody pinned', async () => {
    const leaf = await makeLeaf({ issuer: pki.otherRoot });
    const result = await validateVmc(
      pemOf(leaf, pki.otherRoot.cert),
      'example.com',
      SVG,
      options(),
    );
    expect(result.status).toBe('untrusted-root');
    expect(result.detail).toContain('Someone Else Root');
  });

  // Defaulting to the real pinned authorities — and to the wall clock — is
  // what makes the check mean anything to a consumer who passes neither. A
  // certificate from an authority the package does not ship cannot reach a
  // root at all, which is where it stops.
  it('defaults to the shipped Mark Verifying Authorities, and to the wall clock', async () => {
    const leaf = await makeLeaf({
      notBefore: new Date(Date.now() - 86_400_000),
      notAfter: new Date(Date.now() + 86_400_000),
    });
    expect((await validateVmc(pemOf(leaf, pki.root.cert), 'example.com', SVG, {})).status).toBe(
      'untrusted-root',
    );
    expect(
      (await validateVmc(pemOf(leaf), 'example.com', SVG, { roots: [pki.rootDescriptor] })).status,
    ).toBe('verified');
  });

  it('refuses a leaf whose issuer cannot be found or verified', async () => {
    const leaf = await makeLeaf({ issuer: pki.otherRoot });
    // The other root is neither in the file nor pinned: the chain stops at the leaf.
    expect((await validateVmc(pemOf(leaf), 'example.com', SVG, options())).status).toBe(
      'broken-chain',
    );
  });

  // Two CAs that signed each other and no self-signed root: the builder
  // walks in a circle and throws rather than returning a chain. A throw here
  // must read as a chain that could not be built, not as a crash out of the
  // whole lookup.
  it('refuses a chain that loops instead of reaching a root', async () => {
    const [alpha, beta] = await makeCrossSignedLoop();
    if (alpha === undefined || beta === undefined) throw new Error('fixture');
    const leaf = await makeLeaf({ issuer: alpha });
    const result = await validateVmc(
      pemOf(leaf, alpha.cert, beta.cert),
      'example.com',
      SVG,
      options(),
    );
    expect(result.status).toBe('broken-chain');
    expect(result.detail).toContain('The certificate chain could not be built');
  });

  it('refuses an expired or not-yet-valid certificate', async () => {
    expect(
      (
        await validateVmc(
          pemOf(await makeLeaf({ notAfter: past(1) })),
          'example.com',
          SVG,
          options(),
        )
      ).status,
    ).toBe('expired');
    expect(
      (
        await validateVmc(
          pemOf(await makeLeaf({ notBefore: future(1) })),
          'example.com',
          SVG,
          options(),
        )
      ).status,
    ).toBe('not-yet-valid');
  });

  // An issuing CA that has expired invalidates everything under it, however
  // fresh the leaf's own dates look.
  it('refuses a chain whose issuing certificate has expired', async () => {
    const issuing = await makeIntermediate('CN=Lapsed Issuing CA, O=Test MVA', pki.root, {
      notAfter: past(1),
    });
    const leaf = await makeLeaf({ issuer: issuing });
    const result = await validateVmc(pemOf(leaf, issuing.cert), 'example.com', SVG, options());
    expect(result.status).toBe('expired');
    expect(result.detail).toContain('Lapsed Issuing CA');
  });

  // A bank's VMC must not verify a look-alike domain, however real the cert.
  it('refuses a certificate issued for another domain', async () => {
    const result = await validateVmc(
      pemOf(await makeLeaf({ domains: ['other.example'] })),
      'example.com',
      SVG,
      options(),
    );
    expect(result.status).toBe('domain-mismatch');
    expect(result.detail).toContain('other.example');
  });

  it('refuses a certificate without the BIMI key usage or without a logotype', async () => {
    expect(
      (await validateVmc(pemOf(await makeLeaf({ eku: false })), 'example.com', SVG, options()))
        .status,
    ).toBe('not-vmc');
    expect(
      (await validateVmc(pemOf(await makeLeaf({ logotype: null })), 'example.com', SVG, options()))
        .status,
    ).toBe('not-vmc');
  });

  // The tick vouches for a PICTURE. The domain may serve any SVG it likes,
  // but only the one the authority saw is verified.
  it('refuses a logo the certificate was not issued for', async () => {
    expect(
      (await validateVmc(pemOf(await makeLeaf()), 'example.com', OTHER_SVG, options())).status,
    ).toBe('logo-mismatch');
  });

  it('accepts a logo bound by SHA-1 alone (Apple’s certificate shape)', async () => {
    const leaf = await makeLeaf({
      logotype: await logotypeDer(SVG, {
        hash: await digestOf('SHA-1', SVG),
        hashOid: SHA1_OID,
        nullParams: true,
        embed: false,
      }),
    });
    expect((await validateVmc(pemOf(leaf), 'example.com', SVG, options())).status).toBe('verified');
    expect((await validateVmc(pemOf(leaf), 'example.com', OTHER_SVG, options())).status).toBe(
      'logo-mismatch',
    );
  });

  it('accepts the logo by hash alone, or by the embedded copy alone', async () => {
    const hashOnly = await makeLeaf({ logotype: await logotypeDer(SVG, { embed: false }) });
    expect((await validateVmc(pemOf(hashOnly), 'example.com', SVG, options())).status).toBe(
      'verified',
    );
    const embedOnly = await makeLeaf({ logotype: await logotypeDer(SVG, { hash: null }) });
    expect((await validateVmc(pemOf(embedOnly), 'example.com', SVG, options())).status).toBe(
      'verified',
    );
  });

  it('reports an unparseable or empty file as such, never as verified', async () => {
    expect((await validateVmc('not a certificate', 'example.com', SVG, options())).status).toBe(
      'unparseable',
    );
    expect(
      (
        await validateVmc(
          '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----',
          'example.com',
          SVG,
          options(),
        )
      ).status,
    ).toBe('unparseable');
    const empty = await validateVmc('', 'example.com', SVG, options());
    expect(empty).toMatchObject({
      status: 'unparseable',
      detail: 'The certificate file contains no certificate',
    });
  });

  it('lists the SAN domains', async () => {
    expect(
      await vmcDomains(asCertificate(await makeLeaf({ domains: ['A.example', 'b.example'] }))),
    ).toEqual(['a.example', 'b.example']);
  });

  // The pinned roots themselves: each must parse and match its recorded
  // fingerprint, or the anchor has silently rotted.
  it('ships pinned MVA roots whose fingerprints match their PEM', async () => {
    expect(MVA_ROOTS.length).toBeGreaterThanOrEqual(3);
    for (const root of MVA_ROOTS) {
      const certificate = new X509Certificate(root.pem);
      expect(fingerprintHex(await certificate.getThumbprint('SHA-256'))).toBe(root.sha256);
      expect(await certificate.isSelfSigned()).toBe(true);
      expect(certificate.notAfter.getTime()).toBeGreaterThan(Date.now());
    }
  });
});

describe('edges the main paths never reach', () => {
  // A name with no registrable domain under it (a bare host, an intranet
  // name) still has to be matched against the certificate as itself.
  it('matches a domain that has no organisational domain', async () => {
    const leaf = await makeLeaf({ domains: ['localhost'] });
    expect((await validateVmc(pemOf(leaf), 'localhost', SVG, options())).status).toBe('verified');
  });

  it('fingerprints an ArrayBuffer as well as a view', () => {
    const bytes = new Uint8Array([0xab, 0xcd]);
    expect(fingerprintHex(bytes)).toBe('AB:CD');
    expect(fingerprintHex(bytes.buffer)).toBe('AB:CD');
    expect(fingerprintHex(new Uint8Array(0))).toBe('');
  });

  it('refuses when a pinned root cannot even be loaded', async () => {
    const result = await validateVmc(pemOf(await makeLeaf()), 'example.com', SVG, {
      roots: [{ ...pki.rootDescriptor, pem: 'garbage' }],
      now: NOW,
    });
    expect(result.status).toBe('untrusted-root');
    expect(result.detail).toContain('Pinned root could not be loaded');
  });

  it('names the problem when the certificate lists no domain at all', async () => {
    const result = await validateVmc(
      pemOf(await makeLeaf({ san: false })),
      'example.com',
      SVG,
      options(),
    );
    expect(result).toMatchObject({
      status: 'domain-mismatch',
      detail: 'The certificate names no domain',
    });
  });

  it('falls back to the hash when the embedded copy cannot be decoded', async () => {
    const withBadUri = await makeLeaf({
      logotype: await logotypeDer(SVG, { dataUri: 'data:image/svg+xml;base64,!!!!' }),
    });
    expect((await validateVmc(pemOf(withBadUri), 'example.com', SVG, options())).status).toBe(
      'verified',
    );
    const noBinding = await makeLeaf({
      logotype: await logotypeDer(SVG, { hash: null, dataUri: 'data:image/svg+xml;base64,!!!!' }),
    });
    expect((await validateVmc(pemOf(noBinding), 'example.com', SVG, options())).status).toBe(
      'logo-mismatch',
    );
  });

  // A file holding nothing but a self-signed root: every certificate in it is
  // somebody's issuer, so "the one nobody signed" finds nothing and the first
  // certificate has to stand in. It is not a VMC, and that is what it says.
  it('treats a file of nothing but a root as the certificate it is', async () => {
    expect((await validateVmc(pemOf(pki.root.cert), 'example.com', SVG, options())).status).toBe(
      'not-vmc',
    );
  });

  // Distinguished names are not guaranteed to carry a CN or an O. A missing
  // one is a blank, never a crash, and the authority's own name stands in.
  it('reports a brand and an authority whose DNs carry no CN or O', async () => {
    const plainRoot = await makeRoot('OU=Anonymous Authority');
    const leaf = await makeLeaf({ issuer: plainRoot, organization: null });
    const untrusted = await validateVmc(pemOf(leaf, plainRoot.cert), 'example.com', SVG, options());
    expect(untrusted.status).toBe('untrusted-root');
    expect(untrusted.detail).toContain('OU=Anonymous Authority');
    expect(untrusted.organization).toBeNull();

    const verified = await validateVmc(pemOf(leaf, plainRoot.cert), 'example.com', SVG, {
      roots: [await descriptorFor(plainRoot, 'The Unnamed Authority')],
      now: NOW,
    });
    expect(verified.status).toBe('verified');
    expect(verified.issuer).toBeNull();
    expect(verified.issuerOrganization).toBe('The Unnamed Authority');
    expect(verified.detail).toBe(
      'The brand proved ownership of example.com to The Unnamed Authority',
    );
  });
});
