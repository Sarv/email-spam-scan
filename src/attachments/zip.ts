/**
 * Listing what is inside a zip — WITHOUT unpacking any of it.
 *
 * This reads the central directory and stops: the names, the declared sizes,
 * and the flag that says an entry is encrypted. It never inflates a byte.
 *
 * THAT IS THE POINT, not an optimisation. Decompressing an untrusted archive
 * is how a scanner becomes the attack: a 42-kilobyte zip bomb expands to
 * several petabytes, and every scanner that unpacks what it is given has to
 * carry a budget, a timeout and a recursion limit to survive being mailed
 * one. Reading the directory costs a bounded walk of a structure the archive
 * declares about itself, which is all four of this stage's questions need —
 * is there an executable in here, is it encrypted, does it claim to be
 * enormous, does it carry a VBA project.
 *
 * It is also why there is no dependency here. `fflate` and `jszip` are both
 * fine libraries and both are built to EXTRACT; taking one on would mean
 * importing an inflater into a package whose whole discipline is that
 * nothing dangerous gets executed, evaluated or expanded. What is left after
 * that is about eighty lines of fixed-offset reads against a format that was
 * frozen in 1989 — small, pure, and tested against hand-built archives.
 *
 * WHAT IT IS NOT. Not a zip implementation. It does not verify anything, does
 * not read local headers (a mismatch between them and the directory is a
 * signal, but one for a scanner that unpacks), and answers `null` for
 * anything it cannot make sense of. A caller treats `null` as "no opinion",
 * never as "safe" — an archive this cannot read is one the rules stay quiet
 * about rather than guess at.
 */
import { asBytes, type AttachmentContent } from './bytes.js';

/** `PK\x05\x06`, the End Of Central Directory record. */
const EOCD_SIGNATURE = 0x06054b50;
/** `PK\x01\x02`, one central directory entry. */
const CENTRAL_SIGNATURE = 0x02014b50;
/** An EOCD with no archive comment: the smallest a zip can end. */
const EOCD_SIZE = 22;
/** The fixed part of a central directory entry, before the name. */
const CENTRAL_HEADER_SIZE = 46;
/** The archive comment length field is 16 bits, so the EOCD is at most this far back. */
const MAX_COMMENT_SIZE = 0xffff;
/** General purpose bit 0: the entry's data is encrypted. */
const ENCRYPTED_FLAG = 0x0001;
/** A 32-bit size field saturated at this value means "see the ZIP64 record". */
const ZIP64_SENTINEL = 0xffffffff;

/**
 * How many entries to read before giving up and saying so.
 *
 * The count in the EOCD is 16-bit and attacker-controlled, and the walk is
 * linear in it. Two thousand names is far more than any real attachment and
 * bounds the work regardless; past that the listing comes back `truncated`,
 * and the rules charge on what they saw rather than pretending they saw
 * everything.
 */
const MAX_ENTRIES = 2000;

/** UTF-8 for names; see `decodeName`. */
const NAME_DECODER = new TextDecoder('utf-8');

/** One member of an archive, as the archive describes itself. */
export interface ZipEntry {
  /** The path as stored, e.g. `docs/invoice.pdf.exe`. */
  name: string;
  /** True for a directory record — a name ending in `/`, with no content. */
  directory: boolean;
  /** True when the entry's data is password-protected. */
  encrypted: boolean;
  /** Stored size in bytes; null when the archive defers to a ZIP64 record. */
  compressedSize: number | null;
  /** Declared size once expanded; null when the archive defers to a ZIP64 record. */
  uncompressedSize: number | null;
}

export interface ZipListing {
  entries: ZipEntry[];
  /**
   * True when the directory ran out, disagreed with itself, or was longer
   * than `MAX_ENTRIES`. The entries returned are still real; there are just
   * more of them than were read.
   */
  truncated: boolean;
}

/**
 * The offset of the EOCD record, scanning backwards from the end.
 *
 * Backwards because the record is last, and bounded by the 16-bit comment
 * length because no valid EOCD can sit further back than that — which also
 * caps the scan on a large attachment at 64 KB rather than the whole file.
 */
function findEndOfCentralDirectory(view: DataView): number | null {
  const start = view.byteLength - EOCD_SIZE;
  const limit = Math.max(0, start - MAX_COMMENT_SIZE);
  for (let offset = start; offset >= limit; offset -= 1) {
    if (view.getUint32(offset, true) === EOCD_SIGNATURE) return offset;
  }
  return null;
}

/**
 * A stored name as text.
 *
 * Always UTF-8, non-fatal. A zip may flag its names as CP437 instead, and
 * `TextDecoder` has no CP437; the difference only touches accented characters
 * in names, and every rule that reads a name here is looking at the ASCII
 * extension at the end of it. A name that decodes imperfectly still has the
 * right extension, which is the fact being tested.
 */
function decodeName(bytes: Uint8Array): string {
  return NAME_DECODER.decode(bytes);
}

/** A 32-bit size field, or null when it defers to ZIP64. */
function sizeOrNull(size: number): number | null {
  return size === ZIP64_SENTINEL ? null : size;
}

/**
 * List a zip's members from its central directory.
 *
 * Returns `null` when the content is not a readable zip at all — too short,
 * no EOCD, or a directory that does not start where the EOCD says it does.
 * Every OOXML document (`.docx`, `.xlsx`, `.pptx`), every OpenDocument file,
 * every `.jar` and every `.apk` is a zip, so this runs on a great deal of
 * ordinary mail and must stay cheap and quiet.
 */
export function listZipEntries(content: AttachmentContent | null | undefined): ZipListing | null {
  const bytes = asBytes(content);
  if (!bytes || bytes.byteLength < EOCD_SIZE) return null;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocd = findEndOfCentralDirectory(view);
  if (eocd === null) return null;

  const declared = view.getUint16(eocd + 10, true);
  const wanted = Math.min(declared, MAX_ENTRIES);
  const entries: ZipEntry[] = [];
  let truncated = declared > MAX_ENTRIES;
  let offset = view.getUint32(eocd + 16, true);

  while (entries.length < wanted) {
    // Either the directory is shorter than it claimed or it never began where
    // the EOCD pointed. Both are malformed, and both are read as "everything
    // up to here is what this archive actually told us".
    if (
      offset + CENTRAL_HEADER_SIZE > view.byteLength ||
      view.getUint32(offset, true) !== CENTRAL_SIGNATURE
    ) {
      truncated = true;
      break;
    }

    const flags = view.getUint16(offset + 8, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const nameStart = offset + CENTRAL_HEADER_SIZE;
    const name = decodeName(bytes.subarray(nameStart, nameStart + nameLength));

    entries.push({
      name,
      directory: name.endsWith('/'),
      encrypted: (flags & ENCRYPTED_FLAG) !== 0,
      compressedSize: sizeOrNull(compressedSize),
      uncompressedSize: sizeOrNull(uncompressedSize),
    });

    offset = nameStart + nameLength + extraLength + commentLength;
  }

  return { entries, truncated };
}
