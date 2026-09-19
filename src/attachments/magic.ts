/**
 * What the BYTES say a file is, regardless of what its name and its MIME type
 * claim.
 *
 * This is the only question in the attachment stage that a sender cannot
 * answer for themselves. A filename is a claim, a `Content-Type` is a claim,
 * and both are written by whoever sent the message; the first few bytes are
 * what the reader's software will actually act on. When the three disagree,
 * the disagreement is the signal — `payslip.pdf`, declared
 * `application/pdf`, whose bytes begin `MZ`, is not a mistake anybody makes
 * by accident.
 *
 * WHY THIS IS HAND-ROLLED, against the usual rule of preferring a library.
 * `file-type` is the obvious dependency and was rejected on two counts: from
 * v19 it is ESM-only, which would break every CommonJS consumer of a package
 * that ships both, and it identifies several hundred formats by reading deep
 * into the file. Neither is wanted here. This stage needs to answer one
 * narrow question — "is this file the KIND of thing its name says?" — over
 * about twenty families, from a fixed prefix, with no allocation and no
 * seeking. That is a table, not a dependency, and it is small enough to read
 * in one sitting and test exhaustively.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It does not identify a format precisely:
 * `.docx`, `.xlsx`, `.odt`, `.epub`, `.apk` and `.jar` are all `zip` here,
 * because they are all a zip and telling them apart means reading the
 * directory — which `zip.ts` does, when a rule actually needs it. Nor does it
 * ever return a guess: an unrecognised prefix is `null`, and every rule
 * treats `null` as "no opinion" rather than "suspicious". Plain text, CSV,
 * and half the formats in the world have no magic number at all, and a
 * scanner that finds those suspicious is a scanner that flags everything.
 */
import { asBytes, hasSignature, type AttachmentContent } from './bytes.js';

/**
 * The file families this table can name.
 *
 * Coarse on purpose — a family is a set of formats that share a container, so
 * `zip` covers every OOXML and OpenDocument file, and `ole` covers the legacy
 * Office binaries along with `.msg`. The rules compare families, never exact
 * formats, because "the name says PDF and the bytes say zip" is the whole
 * question and "which flavour of zip" is not.
 */
export type SniffedType =
  | '7z'
  | 'bzip2'
  | 'cab'
  | 'class'
  | 'elf'
  | 'gif'
  | 'gzip'
  | 'jpeg'
  | 'mach-o'
  | 'ole'
  | 'pdf'
  | 'png'
  | 'rar'
  | 'rtf'
  | 'script'
  | 'windows-pe'
  | 'xz'
  | 'zip';

interface Signature {
  readonly type: SniffedType;
  readonly bytes: readonly number[];
}

/**
 * Prefix signatures, longest-first where two could both match.
 *
 * `windows-pe` is last of the executables for that reason: `MZ` is only two
 * bytes and would otherwise shadow nothing, but keeping the specific ones
 * above it makes the ordering rule visible rather than accidental.
 */
const SIGNATURES: readonly Signature[] = [
  // Zip, in its three central-directory-bearing forms. `PK\x03\x04` is a
  // local header, `PK\x05\x06` an empty archive, `PK\x07\x08` a spanned one.
  { type: 'zip', bytes: [0x50, 0x4b, 0x03, 0x04] },
  { type: 'zip', bytes: [0x50, 0x4b, 0x05, 0x06] },
  { type: 'zip', bytes: [0x50, 0x4b, 0x07, 0x08] },
  // OLE2 / Compound File Binary: .doc, .xls, .ppt and .msg.
  { type: 'ole', bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] },
  { type: 'pdf', bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] }, // %PDF-
  { type: 'rtf', bytes: [0x7b, 0x5c, 0x72, 0x74, 0x66] }, // {\rtf
  { type: 'gzip', bytes: [0x1f, 0x8b] },
  { type: 'bzip2', bytes: [0x42, 0x5a, 0x68] }, // BZh
  { type: 'xz', bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { type: '7z', bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { type: 'rar', bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] }, // Rar!
  { type: 'cab', bytes: [0x4d, 0x53, 0x43, 0x46] }, // MSCF
  { type: 'elf', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  // Mach-O, 32- and 64-bit, both byte orders.
  { type: 'mach-o', bytes: [0xfe, 0xed, 0xfa, 0xce] },
  { type: 'mach-o', bytes: [0xfe, 0xed, 0xfa, 0xcf] },
  { type: 'mach-o', bytes: [0xce, 0xfa, 0xed, 0xfe] },
  { type: 'mach-o', bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  // CAFEBABE is a Java class file AND a Mach-O universal binary. Both run, so
  // the ambiguity costs the rules nothing: they only ask "does this execute?"
  { type: 'class', bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { type: 'png', bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: 'jpeg', bytes: [0xff, 0xd8, 0xff] },
  { type: 'gif', bytes: [0x47, 0x49, 0x46, 0x38] }, // GIF8
  { type: 'script', bytes: [0x23, 0x21] }, // #! shebang
  { type: 'windows-pe', bytes: [0x4d, 0x5a] }, // MZ
];

/** The families that RUN, whatever the file is called. */
const EXECUTABLE_TYPES: ReadonlySet<SniffedType> = new Set<SniffedType>([
  'class',
  'elf',
  'mach-o',
  'script',
  'windows-pe',
]);

/**
 * The family a file's first bytes belong to, or `null` for "no opinion".
 *
 * Pure, allocation-free and content-length independent: it reads at most the
 * first eight bytes, so it costs the same on a 40 MB attachment as on an
 * empty one.
 */
export function sniffFileType(content: AttachmentContent | null | undefined): SniffedType | null {
  const bytes = asBytes(content);
  if (!bytes) return null;
  return SIGNATURES.find((signature) => hasSignature(bytes, signature.bytes))?.type ?? null;
}

/** Whether a sniffed family is one the operating system will execute. */
export function isExecutableType(type: SniffedType | null): boolean {
  return type !== null && EXECUTABLE_TYPES.has(type);
}

/**
 * What each extension's bytes SHOULD look like.
 *
 * Only extensions with an unambiguous signature are listed. An absent
 * extension means "no expectation", which is the honest answer for `.txt`,
 * `.csv`, `.svg` and everything else that is just characters — and it is what
 * keeps the mismatch rule quiet on the overwhelming majority of real mail.
 *
 * Several extensions map to more than one family because more than one family
 * is correct: a `.docx` is a zip, but Word will also open an OLE2 file that
 * somebody renamed, and Office itself emits both for `.xls`.
 */
const EXPECTED_BY_EXTENSION: Readonly<Record<string, readonly SniffedType[]>> = {
  '7z': ['7z'],
  apk: ['zip'],
  bz2: ['bzip2'],
  cab: ['cab'],
  com: ['windows-pe'],
  dll: ['windows-pe'],
  doc: ['ole', 'zip', 'rtf'],
  docm: ['zip'],
  docx: ['zip', 'ole'],
  dotm: ['zip'],
  epub: ['zip'],
  exe: ['windows-pe'],
  gif: ['gif'],
  gz: ['gzip'],
  jar: ['zip'],
  jpeg: ['jpeg'],
  jpg: ['jpeg'],
  msg: ['ole'],
  msi: ['ole'],
  odp: ['zip'],
  ods: ['zip'],
  odt: ['zip'],
  pdf: ['pdf'],
  png: ['png'],
  ppt: ['ole', 'zip'],
  pptm: ['zip'],
  pptx: ['zip', 'ole'],
  rar: ['rar'],
  rtf: ['rtf'],
  scr: ['windows-pe'],
  tgz: ['gzip'],
  xls: ['ole', 'zip'],
  xlsb: ['zip', 'ole'],
  xlsm: ['zip'],
  xlsx: ['zip', 'ole'],
  xz: ['xz'],
  zip: ['zip'],
};

/**
 * What each declared MIME type's bytes SHOULD look like.
 *
 * `application/octet-stream` is not here and never should be: it is what a
 * sender writes when they are not claiming anything, and treating "no claim"
 * as a false claim would fire this rule on a large fraction of ordinary mail.
 * The same goes for every `text/*` type.
 */
const EXPECTED_BY_MIME: Readonly<Record<string, readonly SniffedType[]>> = {
  'application/gzip': ['gzip'],
  'application/msword': ['ole', 'zip', 'rtf'],
  'application/pdf': ['pdf'],
  'application/rtf': ['rtf'],
  'application/vnd.ms-excel': ['ole', 'zip'],
  'application/vnd.ms-powerpoint': ['ole', 'zip'],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['zip', 'ole'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['zip', 'ole'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['zip', 'ole'],
  'application/x-7z-compressed': ['7z'],
  'application/x-rar-compressed': ['rar'],
  'application/zip': ['zip'],
  'image/gif': ['gif'],
  'image/jpeg': ['jpeg'],
  'image/png': ['png'],
};

/** The families an extension's bytes should belong to; empty when unknown. */
export function expectedTypesForExtension(extension: string | null): readonly SniffedType[] {
  return (extension && EXPECTED_BY_EXTENSION[extension]) || [];
}

/**
 * The families a declared MIME type's bytes should belong to; empty when the
 * type is unknown, absent, or one of the ones that claim nothing.
 */
export function expectedTypesForMimeType(
  mimeType: string | null | undefined,
): readonly SniffedType[] {
  if (!mimeType) return [];
  // `text/plain; charset=utf-8` — the parameters say nothing about the bytes.
  // `split` always yields a first element, so the cast replaces a `?? ''` that
  // no input could reach and the coverage gate could never honestly meet.
  const bare = (mimeType.split(';')[0] as string).trim().toLowerCase();
  return EXPECTED_BY_MIME[bare] ?? [];
}
