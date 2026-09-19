/**
 * What a filename CLAIMS a file is, as data.
 *
 * Four lists, each answering a different question about the same string, and
 * none of them a judgement about the bytes — the bytes are `magic.ts`'s job.
 * An extension is a claim the sender made and the reader's operating system
 * will act on, which is exactly why it is worth reading: the deception this
 * stage catches is a file whose name and whose contents disagree.
 *
 * HOW THEY ARE SCORED. Every rule that reads these lists charges 2 points at
 * the most, and fires ONCE per message however many attachments matched — ten
 * executables in one archive is one decision the sender made, not ten. An
 * executable attachment alone therefore reaches neither threshold: this is a
 * spam scanner, not an antivirus, and a developer mailing a build to a
 * colleague must not have it filed. What the lists are good for is the
 * combination — an executable whose name pretends to be a PDF, whose bytes
 * disagree with both, arriving inside an encrypted archive.
 *
 * WHAT NOT TO ADD, in order of how often it is got wrong:
 *
 *  1. An extension that is ordinary in some trade. `.psd`, `.dwg`, `.sql` and
 *     `.csv` all look alarming to somebody and are somebody else's Tuesday.
 *     An extension earns a place in `EXECUTABLE_EXTENSIONS` only if a double
 *     click RUNS it — not if it is merely unusual, large or proprietary.
 *  2. An extension because malware used it once. The question is what the
 *     operating system does with the file, which does not change with the
 *     campaign.
 *  3. A duplicate in a different case, or with a leading dot. Entries are
 *     lowercase, dot-free and sorted; the tests enforce all three.
 */

/**
 * Extensions an operating system will EXECUTE, given a double click.
 *
 * Interpreters count: a `.js` or `.vbs` file is run by Windows Script Host
 * from a double click exactly as a `.exe` is, which is why script droppers
 * have outlived every wave of binary ones. `.lnk`, `.url`, `.scf` and
 * `.settingcontent-ms` count too — they execute something else, which is the
 * same thing from the reader's side.
 *
 * `.jar` is here and not in `ARCHIVE_EXTENSIONS` for that reason: it is a zip,
 * but it is a zip the Java runtime runs.
 */
export const EXECUTABLE_EXTENSIONS: readonly string[] = [
  'apk',
  'app',
  'appimage',
  'application',
  'bat',
  'chm',
  'cmd',
  'com',
  'command',
  'cpl',
  'deb',
  'dll',
  'dmg',
  'ex_',
  'exe',
  'gadget',
  'hta',
  'inf',
  'ins',
  'ipa',
  'isp',
  'jar',
  'js',
  'jse',
  'ksh',
  'lnk',
  'msc',
  'msh',
  'msh1',
  'msh1xml',
  'msh2',
  'msh2xml',
  'mshxml',
  'msi',
  'msix',
  'msp',
  'mst',
  'ocx',
  'pif',
  'pkg',
  'pl',
  'ps1',
  'ps1xml',
  'ps2',
  'ps2xml',
  'psc1',
  'psc2',
  'py',
  'pyc',
  'pyo',
  'reg',
  'rpm',
  'run',
  'scf',
  'scpt',
  'scr',
  'sct',
  'settingcontent-ms',
  'sh',
  'shs',
  'sys',
  'vb',
  'vbe',
  'vbs',
  'vbscript',
  'ws',
  'wsc',
  'wsf',
  'wsh',
  'xll',
];

/**
 * The narrower set that counts when found INSIDE an archive.
 *
 * Deliberately not `EXECUTABLE_EXTENSIONS`, and the difference is the whole
 * reason there are two lists. A `.js` file attached to an email is a dropper:
 * nobody mails a loose script to a colleague, and Windows Script Host runs it
 * from a double click. A `.js` file inside a zip is `node_modules`. The same
 * goes for `.py`, `.sh`, `.pl` and `.dll` — ordinary freight in a zipped
 * project, and scoring them would file every developer's mail.
 *
 * What survives the cut is the set that has no innocent reason to be zipped
 * up and mailed to somebody: Windows binaries, script-host formats, shortcuts
 * and installers. Those are what the archive is FOR when the archive is the
 * attack — the container exists to get the payload past a scanner that stops
 * at the envelope, and to stop the reader seeing the extension.
 */
export const ARCHIVE_EXECUTABLE_EXTENSIONS: readonly string[] = [
  'application',
  'bat',
  'chm',
  'cmd',
  'com',
  'cpl',
  'ex_',
  'exe',
  'hta',
  'jar',
  'jse',
  'lnk',
  'msi',
  'msix',
  'msp',
  'pif',
  'ps1',
  'reg',
  'scf',
  'scr',
  'settingcontent-ms',
  'vbe',
  'vbs',
  'ws',
  'wsf',
  'wsh',
];

/**
 * Containers whose contents this stage LISTS rather than trusts.
 *
 * A container is not a danger; it is a place a danger hides from the reader
 * and from every scanner that stops at the envelope. Disk images (`.iso`,
 * `.img`, `.vhd`) are here because Windows mounts them from a double click
 * and, historically, did not carry the mark-of-the-web across the mount —
 * which is precisely why malware started arriving in them.
 *
 * Only zip-shaped members can actually be listed (see `zip.ts`); the rest are
 * here so a future reader knows the set was considered, and so the type
 * mismatch rule knows what their bytes should look like.
 */
export const ARCHIVE_EXTENSIONS: readonly string[] = [
  '7z',
  'ace',
  'arj',
  'bz2',
  'cab',
  'gz',
  'img',
  'iso',
  'lzh',
  'rar',
  'tar',
  'tgz',
  'vhd',
  'vhdx',
  'xz',
  'z',
  'zip',
  'zipx',
];

/**
 * Office formats whose very extension says "this file may carry macros".
 *
 * The `m` suffix on an OOXML extension is Microsoft's own declaration: `.docx`
 * cannot hold a VBA project and `.docm` can. That makes the extension alone a
 * fact worth reading, without opening anything.
 *
 * The legacy binary formats — `.doc`, `.xls`, `.ppt` — are deliberately NOT
 * here. Every one of them CAN hold macros and almost none of them does; there
 * is no way to tell which without parsing an OLE compound file, and charging
 * points for the format would score every document a law firm has sent since
 * 1997. See `rules.ts`: when the bytes are a zip we look inside for the VBA
 * project instead, which is an answer rather than a guess.
 */
export const MACRO_ENABLED_EXTENSIONS: readonly string[] = [
  'docm',
  'dotm',
  'potm',
  'ppam',
  'ppsm',
  'pptm',
  'sldm',
  'xlam',
  'xlsb',
  'xlsm',
  'xltm',
];

/**
 * The harmless-looking extensions a double extension hides BEHIND.
 *
 * `invoice.pdf.exe` works because the reader reads the part they recognise and
 * the operating system reads the part at the end. The rule needs this list so
 * that `archive.tar.gz` and `report.2024.xlsx` — two extensions, no deception
 * — are not accused of the same thing: the trick is specifically a document or
 * an image name in front of something that runs.
 */
export const DECOY_EXTENSIONS: readonly string[] = [
  'avi',
  'bmp',
  'csv',
  'doc',
  'docx',
  'gif',
  'htm',
  'html',
  'jpeg',
  'jpg',
  'mov',
  'mp3',
  'mp4',
  'msg',
  'odt',
  'pdf',
  'png',
  'ppt',
  'pptx',
  'rtf',
  'svg',
  'txt',
  'xls',
  'xlsx',
  'xml',
  'zip',
];
