import { describe, expect, it } from 'vitest';

import { collapseWhitespace, extractHtml } from '../src/content/html-text.js';

describe('extractHtml', () => {
  it('returns nothing for no HTML at all', () => {
    expect(extractHtml(null)).toEqual({ text: '', quotedText: '', hiddenText: '', anchors: [] });
    expect(extractHtml('')).toEqual({ text: '', quotedText: '', hiddenText: '', anchors: [] });
  });

  // Regression: without a separator between block elements, `<p>pay</p><p>pal</p>`
  // reads as the single word `paypal`. Welding two words into a third is how a
  // corpus match appears in a message that never contained the phrase.
  it('breaks lines at block elements so adjacent words stay separate words', () => {
    expect(extractHtml('<p>pay</p><p>pal</p>').text).toBe('pay pal');
    expect(extractHtml('one<br>two').text).toBe('one two');
  });

  // Regression: a stylesheet is not prose. Counting it would fire the
  // hidden-text rule on every HTML newsletter ever sent.
  it('drops script, style and head content entirely rather than calling it hidden', () => {
    const extract = extractHtml(
      '<head><title>t</title></head><body><style>.a{color:red}</style><script>var x=1</script><noscript>js off</noscript>Hello</body>',
    );
    expect(extract.text).toBe('Hello');
    expect(extract.hiddenText).toBe('');
  });

  // Regression: the quoted history is somebody else's writing. Score it and a
  // thread gets worse every time a person replies to it.
  it('separates quoted history from the sender own words', () => {
    const extract = extractHtml(
      '<div>My answer</div><blockquote>You have won a prize</blockquote>',
    );
    expect(extract.text).toBe('My answer');
    expect(extract.quotedText).toBe('You have won a prize');
  });

  // Clients that wrap the history in a plain div instead of a blockquote, and
  // the prefixed forms they acquire after an Exchange or Gmail round-trip.
  it('recognises the client quote containers, prefixed or not', () => {
    expect(extractHtml('<div>mine</div><div class="gmail_quote">theirs</div>').quotedText).toBe(
      'theirs',
    );
    expect(extractHtml('<div>mine</div><div class="x_gmail_quote">theirs</div>').quotedText).toBe(
      'theirs',
    );
    expect(extractHtml('<div>mine</div><div id="divRplyFwdMsg">theirs</div>').quotedText).toBe(
      'theirs',
    );
    expect(
      extractHtml('<div>mine</div><div class="protonmail_quote">theirs</div>').quotedText,
    ).toBe('theirs');
  });

  // Regression: the hidden-text rule exists because there is no honest reason
  // to hide a paragraph. Each of these is a way mail actually does it.
  it('collects text the styling hides from the reader', () => {
    expect(extractHtml('<div style="display:none">secret</div>shown').hiddenText).toBe('secret');
    expect(extractHtml('<div style="display : none">secret</div>').hiddenText).toBe('secret');
    expect(extractHtml('<div style="visibility:hidden">secret</div>').hiddenText).toBe('secret');
    expect(extractHtml('<div style="opacity:0">secret</div>').hiddenText).toBe('secret');
    expect(extractHtml('<span style="font-size:0px">secret</span>').hiddenText).toBe('secret');
    expect(extractHtml('<div style="max-height:0">secret</div>').hiddenText).toBe('secret');
    expect(extractHtml('<div hidden>secret</div>').hiddenText).toBe('secret');
  });

  // Regression: hiding is inherited. A paragraph inside a hidden div is hidden
  // even though the paragraph's own markup says nothing.
  it('inherits hidden, quoted and non-prose down the tree', () => {
    const extract = extractHtml(
      '<div style="display:none"><p>deep secret</p></div><blockquote><p>deep quote</p></blockquote>',
    );
    expect(extract.hiddenText).toBe('deep secret');
    expect(extract.quotedText).toBe('deep quote');
    expect(extract.text).toBe('');
  });

  // Regression: `<a href><span>paypal.com</span></a>` is how real mail marks
  // up a link. Reading only text that is an immediate child of the anchor
  // reports an empty label, and an empty label can never be a mismatch.
  it('gives an anchor the label the reader sees, however deeply nested', () => {
    expect(
      extractHtml('<a href="https://evil.ru"><span><b>paypal.com</b></span></a>').anchors,
    ).toEqual([{ href: 'https://evil.ru', text: 'paypal.com', quoted: false }]);
  });

  it('flags anchors inside the quoted history as quoted', () => {
    const { anchors } = extractHtml(
      '<a href="https://a.example">mine</a><blockquote><a href="https://b.example">theirs</a></blockquote>',
    );
    // Anchors are reported as they CLOSE, so the sender's own link — which
    // opened and closed before the blockquote did — comes first.
    expect(anchors).toEqual([
      { href: 'https://a.example', text: 'mine', quoted: false },
      { href: 'https://b.example', text: 'theirs', quoted: true },
    ]);
  });

  // An anchor is still the link it is even when it sits inside invisible text.
  it('keeps an anchor that is hidden', () => {
    expect(
      extractHtml('<div style="display:none"><a href="https://evil.ru">x</a></div>').anchors,
    ).toEqual([{ href: 'https://evil.ru', text: 'x', quoted: false }]);
  });

  it('ignores an anchor with no href, which is not a link', () => {
    expect(extractHtml('<a name="top">anchor</a>').anchors).toEqual([]);
  });

  // Regression: mail HTML is the worst HTML there is. Every one of these is a
  // way to show a reader one thing and a naive scanner another; a tolerant
  // parser has to resolve them the way a mail client would, without throwing.
  it('survives the malformed markup that real mail is made of', () => {
    expect(extractHtml('<p>unclosed <b>bold').text).toBe('unclosed bold');
    expect(extractHtml('</div>stray close').text).toBe('stray close');
    expect(extractHtml('<a href=https://evil.ru>paypal.com</a>').anchors[0]?.href).toBe(
      'https://evil.ru',
    );
    expect(extractHtml('<!-- comment -->visible<!-- more -->').text).toBe('visible');
    expect(extractHtml('bare text with no tags at all').text).toBe('bare text with no tags at all');
    expect(extractHtml('<<<>>>').text).toBe('<<<>>>');
  });

  // Regression: entity-encoded text is what the reader sees. Leave it encoded
  // and `&#118;iagra` matches nothing in the corpus.
  it('decodes entities, because that is what the reader reads', () => {
    expect(extractHtml('<p>caf&eacute; &amp; bar</p>').text).toBe('café & bar');
    expect(extractHtml('<p>&#118;erify your password</p>').text).toBe('verify your password');
  });
});

describe('collapseWhitespace', () => {
  it('folds every run of whitespace to one space and trims the ends', () => {
    expect(collapseWhitespace('  a \n\t b  ')).toBe('a b');
    expect(collapseWhitespace('')).toBe('');
  });
});
