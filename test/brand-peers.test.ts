import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * The optional peers the certificate check needs.
 *
 * What this protects: `@peculiar/x509` and `asn1js` are optional peer
 * dependencies, so an install that only wanted the logo has neither. That is
 * a SETUP fact and must read as one — an error naming the package to install
 * — rather than as a mysterious failure blamed on the brand's certificate.
 * Each loader also caches, because a lookup per message would otherwise
 * re-resolve the module every time.
 */
afterEach(() => {
  vi.resetModules();
  vi.doUnmock('@peculiar/x509');
  vi.doUnmock('asn1js');
});

describe('the optional peer loaders', () => {
  it('names @peculiar/x509 and what it is for when it is not installed', async () => {
    vi.doMock('@peculiar/x509', () => {
      throw new Error("Cannot find package '@peculiar/x509'");
    });
    const { loadX509 } = await import('../src/brand/peers.js');
    await expect(loadX509()).rejects.toThrow(
      /optional peer dependency '@peculiar\/x509'.*npm install @peculiar\/x509/s,
    );
  });

  it('names asn1js the same way', async () => {
    vi.doMock('asn1js', () => {
      throw new Error("Cannot find package 'asn1js'");
    });
    const { loadAsn1 } = await import('../src/brand/peers.js');
    await expect(loadAsn1()).rejects.toThrow(/optional peer dependency 'asn1js'/);
  });

  // One resolution per process, not one per message.
  it('loads each module once and hands back the same one after that', async () => {
    const { loadAsn1, loadX509 } = await import('../src/brand/peers.js');
    expect(await loadX509()).toBe(await loadX509());
    expect(await loadAsn1()).toBe(await loadAsn1());
  });
});
