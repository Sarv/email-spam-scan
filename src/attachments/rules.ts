/**
 * The attachment stage: what is safely knowable about a file WITHOUT
 * executing, unpacking, or trusting a word of what it says about itself.
 *
 * Three sources of truth, and the value is in where they disagree:
 *
 *   the NAME   — a claim the sender wrote, which the reader's operating
 *                system will nonetheless act on (`filename.ts`);
 *   the TYPE   — a claim the sender wrote in a MIME header;
 *   the BYTES  — the only one of the three the sender cannot lie about,
 *                because it is what software will actually do (`magic.ts`),
 *                and, for a zip, the directory it declares (`zip.ts`).
 *
 * Every rule below is STRUCTURAL in the sense the content stage uses the
 * word: a fact about the bytes, not a reading of them. So they accumulate,
 * uncapped — several at once is not a stronger opinion, it is several
 * separate deceptions, and a file that is executable, misnamed, misdeclared
 * and locked inside an encrypted archive is not four versions of one doubt.
 *
 * WHAT THIS IS NOT. It is not an antivirus and must not be mistaken for one:
 * no signature database, no emulation, nothing unpacked, and a clean result
 * here means "nothing structurally deceptive", never "safe to open". That is
 * also why no single rule is worth more than 2 points and why a bare
 * executable attachment reaches neither threshold on its own — a developer
 * mailing a build to a colleague sends the same bytes as a dropper, and the
 * difference is not visible from here. What IS visible, and what this stage
 * is good at, is the combination that has no innocent version: a file whose
 * name, type and bytes each say something different.
 *
 * ONE REASON PER MESSAGE, per rule. Ten executables in one archive is one
 * decision the sender made, not ten, and a reason list that repeats itself
 * ten times is a list nobody reads. Each rule names the first attachment
 * that triggered it and counts the others.
 *
 * WORKS WITHOUT THE BYTES. A caller that has only the MIME structure — a
 * client listing attachments before it has downloaded any — gets the
 * name-based rules and nothing else, rather than an error or a false clean.
 */
import {
  ARCHIVE_EXECUTABLE_EXTENSIONS,
  DECOY_EXTENSIONS,
  EXECUTABLE_EXTENSIONS,
  MACRO_ENABLED_EXTENSIONS,
} from '../data/attachment-extensions.js';
import {
  assessmentOf,
  type SpamAssessment,
  type SpamReason,
  type SpamReasonId,
} from '../verdict.js';

import type { AttachmentContent } from './bytes.js';
import { inspectFilename } from './filename.js';
import {
  expectedTypesForExtension,
  expectedTypesForMimeType,
  isExecutableType,
  sniffFileType,
  type SniffedType,
} from './magic.js';
import { listZipEntries, type ZipListing } from './zip.js';

const EXECUTABLE = new Set<string>(EXECUTABLE_EXTENSIONS);
const ARCHIVE_EXECUTABLE = new Set<string>(ARCHIVE_EXECUTABLE_EXTENSIONS);
const MACRO_ENABLED = new Set<string>(MACRO_ENABLED_EXTENSIONS);
const DECOY = new Set<string>(DECOY_EXTENSIONS);

/**
 * The part of a VBA project an Office file cannot carry macros without.
 *
 * Present in a `.docm` by design and in a `.docx` never: the `x` formats are
 * defined as macro-free, so a zip named `.docx` that contains this is a file
 * whose own extension contradicts its contents.
 */
const VBA_PROJECT = 'vbaproject.bin';

/** One attachment, in the shape any MIME parser can supply. */
export interface AttachmentInput {
  filename?: string | null;
  /** The declared `Content-Type`, parameters and all. */
  mimeType?: string | null;
  /** The decoded bytes, when the caller has them. Omitting them is fine. */
  content?: AttachmentContent | null;
}

/** What the file claimed to be, against what its bytes actually are. */
export interface TypeMismatch {
  /** The claim: an extension (`.pdf`) or the declared MIME type. */
  claimed: string;
  /** The family the bytes belong to. */
  actual: SniffedType;
}

/** Everything this stage could determine about one attachment. */
export interface AttachmentFacts {
  /** The name as software reads it — display-reordering characters removed. */
  filename: string;
  /** The extension that decides what a double click does. */
  extension: string | null;
  /** The declared type, as written. */
  mimeType: string | null;
  /** What the first bytes say the file is; null for no bytes, or no opinion. */
  sniffed: SniffedType | null;
  /** Runs on a double click, by extension or by bytes. */
  executable: boolean;
  /** The document-looking extension in front of an executable one, if any. */
  decoyExtension: string | null;
  /** The name carries characters that reorder how it is displayed. */
  reorderedName: boolean;
  /** The claim the bytes contradict, or null when nothing disagrees. */
  mismatch: TypeMismatch | null;
  /** Carries, or declares itself able to carry, a VBA macro project. */
  macro: boolean;
  /** The zip directory, when the bytes were a readable zip. */
  archive: ZipListing | null;
  /** Names inside the archive that the operating system would run. */
  archiveExecutables: string[];
  /** The archive holds password-protected entries. */
  encryptedArchive: boolean;
}

/** The claim the bytes contradict, preferring the extension's claim. */
function typeMismatch(
  extension: string | null,
  mimeType: string | null,
  sniffed: SniffedType | null,
): TypeMismatch | null {
  if (sniffed === null) return null;

  const byExtension = expectedTypesForExtension(extension);
  // `extension` is a string whenever there were expectations for it — an
  // absent extension has none — so the claim can be built without a fallback
  // branch that no input reaches and the coverage gate could never meet.
  if (byExtension.length > 0 && !byExtension.includes(sniffed)) {
    return { claimed: `.${extension as string}`, actual: sniffed };
  }

  const byMimeType = expectedTypesForMimeType(mimeType);
  if (byMimeType.length > 0 && !byMimeType.includes(sniffed)) {
    return { claimed: mimeType as string, actual: sniffed };
  }

  return null;
}

/**
 * Read one attachment into facts. Pure: no network, no execution, nothing
 * unpacked, and at most a bounded walk of a zip's own directory.
 */
export function inspectAttachment(input: AttachmentInput): AttachmentFacts {
  const { name, extension, extensions, reordered } = inspectFilename(input.filename);
  const mimeType = input.mimeType ?? null;
  const content = input.content ?? null;
  const sniffed = sniffFileType(content);
  const executableExtension = extension !== null && EXECUTABLE.has(extension);

  // Only a zip has a directory to read, and the BYTES say whether it is one —
  // the extension does not get a vote, which is what catches the `.pdf` that
  // is really a zip full of shortcuts.
  const archive = sniffed === 'zip' ? listZipEntries(content) : null;
  const members = archive?.entries.filter((entry) => !entry.directory) ?? [];

  return {
    filename: name,
    extension,
    mimeType,
    sniffed,
    executable: executableExtension || isExecutableType(sniffed),
    decoyExtension: executableExtension
      ? (extensions.slice(0, -1).find((token) => DECOY.has(token)) ?? null)
      : null,
    reorderedName: reordered,
    mismatch: typeMismatch(extension, mimeType, sniffed),
    macro:
      (extension !== null && MACRO_ENABLED.has(extension)) ||
      members.some((entry) => entry.name.toLowerCase().endsWith(VBA_PROJECT)),
    archive,
    archiveExecutables: members
      .map((entry) => entry.name)
      .filter((entryName) => {
        const inner = inspectFilename(entryName).extension;
        return inner !== null && ARCHIVE_EXECUTABLE.has(inner);
      }),
    encryptedArchive: members.some((entry) => entry.encrypted),
  };
}

/** How a reason names the attachment it is about, plus "and N others". */
function subject(facts: AttachmentFacts, others: number): string {
  const named = facts.filename || 'an unnamed attachment';
  if (others === 0) return named;
  return `${named} (and ${others} other attachment${others === 1 ? '' : 's'})`;
}

/**
 * Score one message's attachments. Pure, and safe on anything: an empty list,
 * attachments with no content, a corrupt archive.
 *
 * Returns the same assessment shape every stage uses, so a caller merges it
 * with the header and content stages through `mergeAssessments` rather than
 * adding numbers by hand.
 */
export function assessAttachmentSignals(
  attachments: readonly AttachmentInput[] | null | undefined,
): SpamAssessment {
  const all = (attachments ?? []).map(inspectAttachment);
  const reasons: SpamReason[] = [];

  /**
   * Charge a rule once, on the first attachment that triggered it.
   *
   * `evidence` returns what the rule found, or null for "did not fire", and
   * that value is handed to `detail` — so a reason is written from the thing
   * the rule actually matched, with no re-checking and no fallback for a
   * value that cannot be absent by the time the sentence is built.
   */
  const rule = <Evidence>(
    id: SpamReasonId,
    points: number,
    evidence: (facts: AttachmentFacts) => Evidence | null,
    detail: (found: Evidence, facts: AttachmentFacts, others: number) => string,
  ): void => {
    const hits = all
      .map((facts) => ({ facts, found: evidence(facts) }))
      .filter((hit): hit is { facts: AttachmentFacts; found: Evidence } => hit.found !== null);
    const first = hits[0];
    if (first === undefined) return;
    reasons.push({ id, points, detail: detail(first.found, first.facts, hits.length - 1) });
  };

  // 1. The name reorders itself. There is no honest use of a bidirectional
  //    override in a filename; its only effect is to show the reader an
  //    extension other than the one that will run.
  rule(
    'attachment-name-spoof',
    2,
    (facts) => facts.reorderedName || null,
    (_found, facts, others) =>
      `The attachment ${subject(facts, others)} uses text-direction characters to disguise its real extension`,
  );

  // 2. A document name in front of something that runs.
  rule(
    'attachment-double-extension',
    2,
    (facts) => facts.decoyExtension,
    (decoy, facts, others) =>
      `The attachment ${subject(facts, others)} looks like a .${decoy} file but is really a .${facts.extension as string} that runs when opened`,
  );

  // 3. Something that runs, however it is named. Two points: on its own that
  //    is below both thresholds, because a legitimate sender can attach a
  //    program and sometimes does.
  rule(
    'attachment-executable',
    2,
    (facts) => facts.executable || null,
    (_found, facts, others) =>
      `The attachment ${subject(facts, others)} is a program, not a document`,
  );

  // 4. The bytes contradict the name or the declared type. The sender wrote
  //    both claims; only one of the three can be checked, and this is it.
  rule(
    'attachment-type-mismatch',
    2,
    (facts) => facts.mismatch,
    (mismatch, facts, others) =>
      `The attachment ${subject(facts, others)} is sent as ${mismatch.claimed} but its contents are a ${mismatch.actual} file`,
  );

  // 5. A macro project: either the extension declares one, or the file itself
  //    contains one whatever the extension says.
  rule(
    'attachment-macro',
    2,
    (facts) => facts.macro || null,
    (_found, facts, others) =>
      `The attachment ${subject(facts, others)} carries macros, which run code when the document is opened`,
  );

  // 6. An executable hidden inside an archive — the container is there to get
  //    it past whatever stops at the envelope.
  rule(
    'attachment-archive-executable',
    2,
    (facts) => facts.archiveExecutables[0] ?? null,
    (inner, facts, others) => `The archive ${subject(facts, others)} contains a program (${inner})`,
  );

  // 7. Encryption. One point, not two: sending a document under a password is
  //    something careful people genuinely do. It is notable only because it
  //    also puts the contents beyond every scanner between here and the reader.
  rule(
    'attachment-encrypted-archive',
    1,
    (facts) => facts.encryptedArchive || null,
    (_found, facts, others) =>
      `The archive ${subject(facts, others)} is password-protected, so nothing can check what is inside it`,
  );

  return assessmentOf(reasons);
}
