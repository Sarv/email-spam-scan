import { describe, expect, it } from 'vitest';

import { BIMI_LOGO_MAX_BYTES, checkBimiSvg } from '../src/brand/svg.js';

import { SVG, utf8 } from './vmc-fixture.js';

/**
 * Is a published logo safe to render?
 *
 * What this protects: the logo is shown as an `<img>` from a `data:` URI,
 * where script does not run — so every check here is the second line. It
 * still has to hold on its own, because the day the logo is ever rendered
 * inline (a signature block, an export, a print stylesheet) is the day the
 * first line is gone and nobody remembers this file exists. The one that
 * matters even inside an `<img>` is the external reference: a logo that
 * fetches something is a tracking pixel wearing a brand.
 */
describe('checkBimiSvg', () => {
  it('accepts a Tiny PS logo and notes the profile', () => {
    expect(checkBimiSvg(SVG)).toEqual({ ok: true, reason: null, tinyPs: true });
    expect(
      checkBimiSvg(utf8('<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>')),
    ).toMatchObject({ ok: true, tinyPs: false });
    // The spec spells it `baseProfile`; a lower-cased one still counts.
    expect(checkBimiSvg(utf8('<svg baseprofile="tiny-ps"><rect/></svg>')).tinyPs).toBe(true);
  });

  it('rejects script, event handlers, embedded documents and external references', () => {
    expect(
      checkBimiSvg(utf8('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'))
        .reason,
    ).toMatch(/script/);
    expect(checkBimiSvg(utf8('<svg onload="alert(1)"></svg>')).reason).toMatch(/event handler/);
    expect(checkBimiSvg(utf8('<svg><foreignObject><body/></foreignObject></svg>')).reason).toMatch(
      /foreignobject/,
    );
    expect(
      checkBimiSvg(utf8('<svg><image href="https://evil.example/track.png"/></svg>')).reason,
    ).toMatch(/external reference in href/);
    expect(
      checkBimiSvg(utf8('<svg><use xlink:href="https://evil.example/x.svg#a"/></svg>')).reason,
    ).toMatch(/external reference in xlink:href/);
    expect(
      checkBimiSvg(utf8('<svg><image src="http://evil.example/x.png"/></svg>')).reason,
    ).toMatch(/external reference in src/);
    expect(
      checkBimiSvg(utf8('<svg><rect style="fill:url(https://evil.example/p)"/></svg>')).reason,
    ).toMatch(/style/);
    expect(
      checkBimiSvg(utf8('<svg><style>@import url(https://evil.example/a.css);</style></svg>'))
        .reason,
    ).toMatch(/stylesheet/);
  });

  it('allows same-document references and an empty reference', () => {
    expect(
      checkBimiSvg(
        utf8(
          '<svg><defs><linearGradient id="g"/></defs><use href="#g"/><rect fill="url(#g)"/></svg>',
        ),
      ).ok,
    ).toBe(true);
    // An empty value refers to nothing, which is harmless rather than external.
    expect(checkBimiSvg(utf8('<svg><rect href=""/></svg>')).ok).toBe(true);
  });

  it('rejects an oversized, empty or non-SVG file', () => {
    expect(checkBimiSvg(new Uint8Array(BIMI_LOGO_MAX_BYTES + 1).fill(0x20)).reason).toMatch(
      /64 KB/,
    );
    expect(checkBimiSvg(new Uint8Array(0)).reason).toBe('empty file');
    expect(checkBimiSvg(utf8('<html><body>not a logo</body></html>')).reason).toBe(
      'not an SVG document',
    );
    expect(checkBimiSvg(utf8('plain text')).reason).toBe('not an SVG document');
  });

  // Regression: the first refusal must stand. A walker that kept overwriting
  // `reason` would report the last problem in the file, and a file crafted to
  // end with something innocuous would be reported as innocuous.
  it('keeps the first reason when a file is wrong in several ways', () => {
    const check = checkBimiSvg(
      utf8(
        '<svg><script>x</script><rect onclick="y"/><style>@import url(https://e.example/a)</style></svg>',
      ),
    );
    expect(check.reason).toBe('contains <script>');
  });
});
