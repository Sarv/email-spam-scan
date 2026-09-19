import { describe, expect, it } from 'vitest';

import {
  assessAttachmentSignals,
  inspectAttachment,
  type AttachmentInput,
} from '../src/attachments/rules.js';
import { SPAM_THRESHOLD, SUSPICIOUS_THRESHOLD, type SpamReasonId } from '../src/verdict.js';

import { buildZip } from './zip-fixture.js';

/** U+202E by code point — see the note in `attachment-filename.test.ts`. */
const RLO = String.fromCodePoint(0x202e);

const PE = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
const PDF = new TextEncoder().encode('%PDF-1.7\n1 0 obj\n');
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const ids = (attachments: readonly AttachmentInput[]): SpamReasonId[] =>
  assessAttachmentSignals(attachments).reasons.map((reason) => reason.id);

const detailOf = (attachments: readonly AttachmentInput[], id: SpamReasonId): string =>
  assessAttachmentSignals(attachments).reasons.find((reason) => reason.id === id)?.detail ?? '';

describe('inspectAttachment', () => {
  it('reads a name-only attachment without needing its bytes', () => {
    // A client listing attachments before it has downloaded any must still
    // get the name-based rules rather than an error or a false clean.
    expect(inspectAttachment({ filename: 'invoice.pdf.exe' })).toMatchObject({
      filename: 'invoice.pdf.exe',
      extension: 'exe',
      sniffed: null,
      executable: true,
      decoyExtension: 'pdf',
      mismatch: null,
      archive: null,
      archiveExecutables: [],
      encryptedArchive: false,
    });
  });

  // Regression: an ordinary document must come back with every flag clear.
  // A stage that finds something wrong with a PDF finds something wrong with
  // most mail, and the resulting scores are noise.
  it('finds nothing to say about an ordinary document', () => {
    expect(
      inspectAttachment({
        filename: 'Quarterly report.pdf',
        mimeType: 'application/pdf',
        content: PDF,
      }),
    ).toMatchObject({
      sniffed: 'pdf',
      executable: false,
      decoyExtension: null,
      reorderedName: false,
      mismatch: null,
      macro: false,
      archive: null,
    });
  });

  // Regression: whether to read a zip directory is decided by the BYTES, not
  // the extension. Deciding it by extension is what lets a zip full of
  // shortcuts arrive named `.pdf` and never get looked inside.
  it('reads the directory of anything whose bytes are a zip, whatever it is called', () => {
    const facts = inspectAttachment({
      filename: 'statement.pdf',
      content: buildZip([{ name: 'open me.lnk' }]),
    });

    expect(facts.sniffed).toBe('zip');
    expect(facts.archive?.entries).toHaveLength(1);
    expect(facts.archiveExecutables).toEqual(['open me.lnk']);
  });

  // Regression: a file that is not a zip must not be handed to the zip
  // parser at all — `.docx` and `.exe` are both common and only one has a
  // directory to read.
  it('does not look for a directory in something that is not a zip', () => {
    expect(inspectAttachment({ filename: 'setup.exe', content: PE }).archive).toBeNull();
  });

  // Regression: directory records are not members. A zip whose only entries
  // are folders must not be read as containing programs.
  it('ignores directory records when reading what an archive contains', () => {
    const facts = inspectAttachment({
      filename: 'project.zip',
      content: buildZip([{ name: 'bin/', content: '' }, { name: 'bin/readme.txt' }]),
    });

    expect(facts.archiveExecutables).toEqual([]);
    expect(facts.macro).toBe(false);
  });
});

describe('the type mismatch', () => {
  // The signal the stage exists for: the one claim of the three that the
  // sender cannot write for themselves contradicts the other two.
  it('reports the extension the bytes contradict', () => {
    expect(
      inspectAttachment({ filename: 'payslip.pdf', mimeType: 'application/pdf', content: PE })
        .mismatch,
    ).toEqual({ claimed: '.pdf', actual: 'windows-pe' });
  });

  // Regression: the extension gets the first vote because it is what the
  // operating system acts on, but a truthful extension must not excuse a
  // false MIME type — a client that files by declared type is still lied to.
  it('falls through to the declared type when the extension is honest', () => {
    expect(
      inspectAttachment({
        filename: 'photos.zip',
        mimeType: 'application/pdf',
        content: buildZip([]),
      }).mismatch,
    ).toEqual({ claimed: 'application/pdf', actual: 'zip' });
  });

  it('reports the declared type when the extension has no expectation of its own', () => {
    expect(
      inspectAttachment({ filename: 'export.dat', mimeType: 'image/png', content: PDF }).mismatch,
    ).toEqual({ claimed: 'image/png', actual: 'pdf' });
  });

  // Regression, and the one that keeps this rule usable: several extensions
  // legitimately have more than one correct shape, and no bytes at all is
  // not a disagreement. Getting either wrong fires the rule across ordinary
  // mail, where nobody would connect the score to this table.
  it('stays quiet when nothing actually disagrees', () => {
    const quiet: AttachmentInput[] = [
      // A .docx IS a zip.
      { filename: 'report.docx', mimeType: 'application/zip', content: buildZip([]) },
      // No bytes to contradict anything.
      { filename: 'payslip.pdf', mimeType: 'application/pdf' },
      // Bytes with no signature: no opinion, not a contradiction.
      { filename: 'notes.txt', mimeType: 'text/plain', content: new TextEncoder().encode('hi') },
      // An extension and a type that both claim nothing.
      { filename: 'export.dat', mimeType: 'application/octet-stream', content: PE },
      // The claim is true.
      { filename: 'logo.png', mimeType: 'image/png', content: PNG },
    ];

    for (const attachment of quiet) {
      expect(inspectAttachment(attachment).mismatch).toBeNull();
    }
  });
});

describe('assessAttachmentSignals', () => {
  // Regression: most mail has no attachments, and the stage runs on all of
  // it. Absent, empty and ordinary must all score zero without branching at
  // the call site.
  it('scores nothing for no attachments and for ordinary ones', () => {
    for (const nothing of [null, undefined, []]) {
      expect(assessAttachmentSignals(nothing)).toEqual({
        score: 0,
        reasons: [],
        isSpam: false,
        suspicious: false,
      });
    }

    expect(
      assessAttachmentSignals([
        { filename: 'Quarterly report.pdf', mimeType: 'application/pdf', content: PDF },
        { filename: 'logo.png', mimeType: 'image/png', content: PNG },
        { filename: 'notes.txt', mimeType: 'text/plain; charset=utf-8' },
        // An inline part with no name at all — ordinary, not a signal.
        { mimeType: 'image/png', content: PNG },
      ]).score,
    ).toBe(0);
  });

  it('charges the name-direction trick', () => {
    expect(ids([{ filename: `cv${RLO}fdp.exe` }])).toContain('attachment-name-spoof');
    expect(detailOf([{ filename: `cv${RLO}fdp.exe` }], 'attachment-name-spoof')).toBe(
      'The attachment cvfdp.exe uses text-direction characters to disguise its real extension',
    );
  });

  it('charges a document name in front of something that runs', () => {
    expect(detailOf([{ filename: 'Invoice 4471.pdf.exe' }], 'attachment-double-extension')).toBe(
      'The attachment Invoice 4471.pdf.exe looks like a .pdf file but is really a .exe that runs when opened',
    );
  });

  // Regression: two extensions are not a deception. `archive.tar.gz` and
  // `report.2024.xlsx` are how people name files, and a rule that scores
  // them scores everybody.
  it('does not charge an ordinary name that happens to have two extensions', () => {
    expect(ids([{ filename: 'archive.tar.gz' }, { filename: 'report.2024.xlsx' }])).not.toContain(
      'attachment-double-extension',
    );
  });

  // Regression, deliberate and load-bearing: a developer mailing a build to
  // a colleague sends the same bytes as a dropper. An executable alone must
  // stay below BOTH thresholds; only the combinations get filed.
  it('leaves a bare executable below both thresholds', () => {
    const assessment = assessAttachmentSignals([{ filename: 'setup.exe', content: PE }]);

    expect(assessment.reasons.map((reason) => reason.id)).toEqual(['attachment-executable']);
    expect(assessment.score).toBe(2);
    expect(assessment.score).toBeLessThan(SUSPICIOUS_THRESHOLD);
    expect(assessment.suspicious).toBe(false);
    expect(assessment.isSpam).toBe(false);
  });

  // Regression: the bytes are the vote the sender cannot rig, so a program
  // named `.pdf` scores as a program even though its extension does not.
  it('charges an executable identified by its bytes alone', () => {
    expect(detailOf([{ content: PE }], 'attachment-executable')).toBe(
      'The attachment an unnamed attachment is a program, not a document',
    );
  });

  it('charges a macro-enabled extension and a hidden VBA project alike', () => {
    expect(ids([{ filename: 'Budget.xlsm' }])).toContain('attachment-macro');
    expect(
      detailOf(
        [
          {
            filename: 'Contract.docx',
            content: buildZip([{ name: '[Content_Types].xml' }, { name: 'word/vbaProject.bin' }]),
          },
        ],
        'attachment-macro',
      ),
    ).toBe(
      'The attachment Contract.docx carries macros, which run code when the document is opened',
    );
  });

  it('charges a program inside an archive, and a locked archive', () => {
    const zip = buildZip([
      { name: 'Invoice/readme.txt' },
      { name: 'Invoice/open.scr', encrypted: true },
    ]);
    const assessment = assessAttachmentSignals([{ filename: 'Invoice.zip', content: zip }]);

    expect(assessment.reasons.map((reason) => reason.id)).toEqual([
      'attachment-archive-executable',
      'attachment-encrypted-archive',
    ]);
    expect(assessment.reasons.map((reason) => reason.detail)).toEqual([
      'The archive Invoice.zip contains a program (Invoice/open.scr)',
      'The archive Invoice.zip is password-protected, so nothing can check what is inside it',
    ]);
    expect(assessment.score).toBe(3);
  });

  // Regression: the inside-an-archive list is the narrow one. A zipped
  // project directory is ordinary mail, and scoring its scripts would file
  // every developer's attachments.
  it('does not charge the scripts that are ordinary freight in a zipped project', () => {
    const project = buildZip([
      // A member with no extension at all, which must not be read as one.
      { name: 'LICENSE' },
      { name: 'src/index.js' },
      { name: 'scripts/build.sh' },
      { name: 'tools/report.py' },
      { name: 'vendor/native.dll' },
    ]);

    expect(assessAttachmentSignals([{ filename: 'project.zip', content: project }]).score).toBe(0);
  });

  // Regression: encryption alone is one point, not two. Sending a document
  // under a password is something careful people genuinely do, and it must
  // not on its own push a message towards a folder nobody reads.
  it('charges a password-protected archive a single point', () => {
    const assessment = assessAttachmentSignals([
      { filename: 'Statements.zip', content: buildZip([{ name: 'march.pdf', encrypted: true }]) },
    ]);

    expect(assessment.reasons.map((reason) => reason.points)).toEqual([1]);
    expect(assessment.suspicious).toBe(false);
  });

  // The combination is the thing this stage is actually good at: a name, a
  // type and a set of bytes that each say something different is a message
  // with no innocent version, and it must clear the spam threshold on the
  // attachments alone.
  it('files a message whose name, type and bytes each say something different', () => {
    const assessment = assessAttachmentSignals([
      { filename: `Invoice${RLO}fdp.exe`, mimeType: 'application/pdf', content: PE },
    ]);

    expect(assessment.reasons.map((reason) => reason.id)).toEqual([
      'attachment-name-spoof',
      'attachment-executable',
      'attachment-type-mismatch',
    ]);
    expect(assessment.score).toBeGreaterThanOrEqual(SPAM_THRESHOLD);
    expect(assessment.isSpam).toBe(true);
  });

  it('reports the mismatch in the sentence a reader has to act on', () => {
    expect(
      detailOf(
        [{ filename: 'payslip.pdf', mimeType: 'application/pdf', content: PE }],
        'attachment-type-mismatch',
      ),
    ).toBe('The attachment payslip.pdf is sent as .pdf but its contents are a windows-pe file');
  });

  // Regression: one reason per rule per message. Ten executables in one
  // message is one decision the sender made, and a reason list that repeats
  // itself ten times is a list nobody reads.
  it('charges each rule once however many attachments matched, and counts the rest', () => {
    const two = assessAttachmentSignals([{ filename: 'one.exe' }, { filename: 'two.exe' }]);
    expect(two.reasons).toHaveLength(1);
    expect(two.score).toBe(2);
    expect(two.reasons[0]?.detail).toBe(
      'The attachment one.exe (and 1 other attachment) is a program, not a document',
    );

    const three = assessAttachmentSignals([
      { filename: 'one.exe' },
      { filename: 'two.exe' },
      { filename: 'three.scr' },
    ]);
    expect(three.reasons).toHaveLength(1);
    expect(three.reasons[0]?.detail).toBe(
      'The attachment one.exe (and 2 other attachments) is a program, not a document',
    );
  });

  // Regression: the rule names the first attachment that TRIGGERED it, not
  // the first attachment. A message whose second file is the executable must
  // not report the innocent first one by name.
  it('names the attachment that triggered the rule, not the first one', () => {
    expect(
      detailOf(
        [
          { filename: 'Cover letter.pdf', content: PDF },
          { filename: 'cv.scr', content: PE },
        ],
        'attachment-executable',
      ),
    ).toBe('The attachment cv.scr is a program, not a document');
  });
});
