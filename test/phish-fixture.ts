/**
 * A real credential-phishing lure, redacted: the "Adobe Acrobat Sign" campaign
 * of September 2026, as received by the first consumer of this package.
 *
 * What makes it worth keeping is what it PASSED. SPF, DKIM and DMARC all held
 * — for powersublinks.com, a domain the attacker registered and authenticated
 * — so every check that asks "did this domain send it?" said yes, and the
 * shield was green. The tells are elsewhere: a display name borrowing Adobe's
 * product name, an In-Reply-To that names the message's own Message-ID, and a
 * link whose text names the recipient's own domain while its href goes to
 * kuaiyudh.top. The body even signs the request with the recipient's own name
 * and address, and hot-links its logos from Adobe's real CDN, which is why it
 * looks right: nothing the reader is shown is the attacker's own.
 *
 * Redactions: the recipient is `reader@example.org` (the original named a real
 * person and their employer, and the link text named that employer's domain,
 * as it does here). The Received trace is reduced to the one hop the rules
 * read. The sender, the link target and the wording are as they arrived —
 * those are the evidence.
 */
export const ADOBE_SIGN_LURE: string = [
  'Received: from mail.powersublinks.com (mail.powersublinks.com [89.117.49.3]) by mx.example.org with ESMTPS id abc; Tue, 23 Sep 2026 03:57:07 +0000',
  'Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=powersublinks.com; dkim=pass header.d=powersublinks.com; dmarc=pass header.from=powersublinks.com',
  'Message-ID: <H2BLQ5A3-RI5-GI-AJND-A8RLMHOF4SX3@powersublinks.com>',
  'In-Reply-To: <H2BLQ5A3-RI5-GI-AJND-A8RLMHOF4SX3@powersublinks.com>',
  'Date: Tue, 23 Sep 2026 03:57:00 +0000',
  'From: "Adobe Acrobat Sign" <Adobesign@powersublinks.com>',
  'To: reader@example.org',
  'Subject: Signature requested on "Example.org Engagement Letter - 23 Sep 2026"',
  'MIME-Version: 1.0',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<html><body style="font-size: 14px; font-family: Helvetica, Verdana, Arial, sans-serif">',
  '<div><center><table style="max-width:600px"><tbody><tr><td>',
  '<img src="https://eu1.documents.adobe.com/images/emailNextGen/email-adobe-sign-logo.3@2x.png" alt="Adobe Acrobat Sign">',
  '<p>Please review and sign Example.org Settlement Agreement . Thanks,</p>',
  '<p>your signature requests on <a href="https://kuaiyudh.top/v/#reader@example.org">Example.org Engagement Letter - for signature</a></p>',
  '<p><a href="https://kuaiyudh.top/v/#reader@example.org">Review and sign</a></p>',
  '<p>Please review and sign Example.org Engagement Letter . Thanks,</p>',
  '<p>Reader<br>reader@example.org</p>',
  '<p>After you sign Example.org Engagement Letter for signature, all parties will receive a final PDF copy by email.</p>',
  '<img src="https://eu1.documents.adobe.com/images/emailNextGen/email-powered-by-adobe-sign-logo.3@2x.png" alt="Powered by Adobe Acrobat Sign">',
  '</td></tr></tbody></table></center></div></body></html>',
].join('\r\n');
