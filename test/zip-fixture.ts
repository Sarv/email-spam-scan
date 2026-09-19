/**
 * Builds REAL zip archives, in memory, for the attachment-stage tests.
 *
 * Real, not a stub of the parts `listZipEntries` happens to read: the output
 * starts with a local file header, so the magic-number sniffer recognises it
 * the way it would recognise a `.docx` off the wire, stores each member
 * uncompressed with a correct CRC-32, and ends with a central directory and
 * an EOCD record that agree with both. Any zip tool can open what this
 * produces.
 *
 * That matters because the thing under test is a parser of somebody else's
 * format. A fixture built to match the parser's assumptions tests that the
 * parser agrees with itself; one built to match the SPECIFICATION tests that
 * it agrees with the world. The overrides below exist so a test can then
 * break the specification deliberately — a directory that claims more entries
 * than it holds, a member flagged encrypted — and watch what the parser does
 * with an archive that lies.
 */

const LOCAL_SIGNATURE = 0x04034b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const EOCD_SIGNATURE = 0x06054b50;
const LOCAL_HEADER_SIZE = 30;
const CENTRAL_HEADER_SIZE = 46;
const EOCD_SIZE = 22;
const ENCRYPTED_FLAG = 0x0001;

const encoder = new TextEncoder();

/** CRC-32, the one a zip stores per member. */
function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export interface ZipFixtureEntry {
  /** The stored path, e.g. `word/vbaProject.bin`. */
  name: string;
  /** Member content, stored uncompressed. Defaults to the name. */
  content?: string;
  /** Set the "this member is encrypted" flag without encrypting anything. */
  encrypted?: boolean;
  /** Write a size field as the ZIP64 sentinel instead of the real size. */
  zip64Sizes?: boolean;
}

export interface ZipFixtureOptions {
  /**
   * Override the entry count written into the EOCD. A directory that claims
   * more members than it holds is malformed in exactly the way a hostile one
   * would be.
   */
  declaredEntryCount?: number;
  /** Bytes of archive comment to append after the EOCD. */
  commentLength?: number;
}

const ZIP64_SENTINEL = 0xffffffff;

/** A zip file, as bytes. */
export function buildZip(
  entries: readonly ZipFixtureEntry[],
  options: ZipFixtureOptions = {},
): Uint8Array {
  const members = entries.map((entry) => {
    const name = encoder.encode(entry.name);
    const content = encoder.encode(entry.content ?? entry.name);
    return {
      name,
      content,
      crc: crc32(content),
      flags: entry.encrypted === true ? ENCRYPTED_FLAG : 0,
      size: entry.zip64Sizes === true ? ZIP64_SENTINEL : content.byteLength,
    };
  });

  const commentLength = options.commentLength ?? 0;
  const localSize = members.reduce(
    (total, member) =>
      total + LOCAL_HEADER_SIZE + member.name.byteLength + member.content.byteLength,
    0,
  );
  const centralSize = members.reduce(
    (total, member) => total + CENTRAL_HEADER_SIZE + member.name.byteLength,
    0,
  );
  const bytes = new Uint8Array(localSize + centralSize + EOCD_SIZE + commentLength);
  const view = new DataView(bytes.buffer);

  let offset = 0;
  const localOffsets: number[] = [];
  for (const member of members) {
    localOffsets.push(offset);
    view.setUint32(offset, LOCAL_SIGNATURE, true);
    view.setUint16(offset + 4, 20, true); // version needed
    view.setUint16(offset + 6, member.flags, true);
    view.setUint16(offset + 8, 0, true); // stored, not deflated
    view.setUint32(offset + 14, member.crc, true);
    view.setUint32(offset + 18, member.size, true);
    view.setUint32(offset + 22, member.size, true);
    view.setUint16(offset + 26, member.name.byteLength, true);
    bytes.set(member.name, offset + LOCAL_HEADER_SIZE);
    bytes.set(member.content, offset + LOCAL_HEADER_SIZE + member.name.byteLength);
    offset += LOCAL_HEADER_SIZE + member.name.byteLength + member.content.byteLength;
  }

  const centralStart = offset;
  members.forEach((member, index) => {
    view.setUint32(offset, CENTRAL_SIGNATURE, true);
    view.setUint16(offset + 4, 20, true); // version made by
    view.setUint16(offset + 6, 20, true); // version needed
    view.setUint16(offset + 8, member.flags, true);
    view.setUint16(offset + 10, 0, true); // stored
    view.setUint32(offset + 16, member.crc, true);
    view.setUint32(offset + 20, member.size, true);
    view.setUint32(offset + 24, member.size, true);
    view.setUint16(offset + 28, member.name.byteLength, true);
    view.setUint32(offset + 42, localOffsets[index] as number, true);
    bytes.set(member.name, offset + CENTRAL_HEADER_SIZE);
    offset += CENTRAL_HEADER_SIZE + member.name.byteLength;
  });

  const declared = options.declaredEntryCount ?? members.length;
  view.setUint32(offset, EOCD_SIGNATURE, true);
  view.setUint16(offset + 8, declared, true); // entries on this disk
  view.setUint16(offset + 10, declared, true); // entries in total
  view.setUint32(offset + 12, offset - centralStart, true);
  view.setUint32(offset + 16, centralStart, true);
  view.setUint16(offset + 20, commentLength, true);

  return bytes;
}
