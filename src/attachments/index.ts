/**
 * The attachment stage, as its own entry point.
 *
 * Zero third-party dependencies, by contract and by design — the whole stage
 * is a signature table, a filename reader and a zip directory walk, none of
 * which needs a package. That makes `@sarv-in/mailguard/attachments`
 * safe anywhere: a renderer deciding whether to put a warning on a paperclip
 * icon gets the same answers as the scanner that filed the message, without
 * pulling in a MIME parser, an address parser or a public-suffix list.
 *
 * It is also the stage a consumer is most likely to want on its own. The
 * header and content stages need a whole message; this one needs a filename,
 * a declared type and — when they are to hand — the bytes, which is exactly
 * what a client already has after parsing a message's structure.
 */
export {
  assessAttachmentSignals,
  inspectAttachment,
  type AttachmentFacts,
  type AttachmentInput,
  type TypeMismatch,
} from './rules.js';
export { asBytes, type AttachmentContent } from './bytes.js';
export {
  expectedTypesForExtension,
  expectedTypesForMimeType,
  isExecutableType,
  sniffFileType,
  type SniffedType,
} from './magic.js';
export {
  extensionsOf,
  inspectFilename,
  stripBidiControls,
  type FilenameFacts,
} from './filename.js';
export { listZipEntries, type ZipEntry, type ZipListing } from './zip.js';
export {
  ARCHIVE_EXECUTABLE_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  DECOY_EXTENSIONS,
  EXECUTABLE_EXTENSIONS,
  MACRO_ENABLED_EXTENSIONS,
} from '../data/attachment-extensions.js';
