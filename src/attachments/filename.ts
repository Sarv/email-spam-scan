/**
 * Reading an attachment's NAME: what the reader sees, versus what the
 * operating system will do with it.
 *
 * Every deception here works on the same gap. A filename is shown to a person
 * and interpreted by a machine, and the two read it differently — the person
 * reads left to right and stops at the part they recognise, the machine reads
 * the last extension and nothing else. `invoice.pdf.exe` is the plain version
 * of that gap. The other version puts a RIGHT-TO-LEFT OVERRIDE (U+202E) in the
 * middle of the name, so that `invoice` + U+202E + `fdp.exe` is stored and run
 * as an `.exe` while every mail client in the world DISPLAYS it as
 * `invoiceexe.pdf`. Nothing else can do that, and no honest sender does it.
 *
 * There is not one of those characters anywhere in this file, escaped or
 * otherwise, and the set below is written as code points for that reason: a
 * raw override in source reorders the SOURCE, which is the trojan-source bug
 * (CVE-2021-42574). A package that flags the trick should not ship it in a
 * comment explaining the trick.
 *
 * Nothing here looks at bytes and nothing charges points; it produces facts
 * about a string, and `rules.ts` decides what they are worth. It is also used
 * on the names INSIDE an archive, which is why it handles path separators: a
 * zip entry is `docs/invoice.pdf.exe`, not a bare name.
 */

/**
 * Characters that change the ORDER a name is displayed in without changing
 * the name.
 *
 * The bidirectional embedding and override family (U+202A to U+202E) and the
 * isolates (U+2066 to U+2069) reorder what follows them; the left- and
 * right-to-left marks (U+200E, U+200F) set the direction of the neutral
 * characters around them. All of them are legitimate in Arabic and Hebrew
 * prose and none of them has any business in a filename: a name is an
 * identifier, not a sentence, and the only thing reordering one can achieve
 * is showing the reader an extension that is not the one that will run.
 */
const BIDI_CONTROLS: ReadonlySet<number> = new Set([
  0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
]);

/**
 * What counts as an extension token: short and alphanumeric.
 *
 * Deliberately narrow, because the alternative is treating every dot-separated
 * fragment as an extension. `minutes.2026-03-04.notes from the call.pdf` has
 * four dot-separated pieces and one extension, and a rule that thinks
 * otherwise reports a double extension on somebody's meeting notes.
 * `settingcontent-ms` is why the hyphen is allowed.
 */
const EXTENSION_TOKEN = /^[a-z0-9][a-z0-9-]{0,16}$/;

/** The last path segment of a name, for zip entries like `docs/run.exe`. */
function baseName(name: string): string {
  const separator = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
  return name.slice(separator + 1);
}

/**
 * A name with its display-reordering characters removed.
 *
 * Spread-and-filter rather than a regular expression, so that the code points
 * stay code points and this file never contains one of the characters it is
 * removing. Iterating a string yields whole code points, so `codePointAt(0)`
 * is always a number here — the cast stands in for a `?? -1` branch no input
 * can reach and the coverage gate could never honestly meet.
 */
export function stripBidiControls(name: string): string {
  return [...name].filter((char) => !BIDI_CONTROLS.has(char.codePointAt(0) as number)).join('');
}

/**
 * The extension-looking tokens trailing a name, in the order they are written.
 *
 * `archive.tar.gz` gives `['tar', 'gz']`; `report.pdf` gives `['pdf']`; a name
 * with no dot, or a dot with nothing usable after it, gives `[]`. The leading
 * segment is always the stem and never an extension, so a dotfile (`.bashrc`)
 * correctly has none.
 */
export function extensionsOf(name: string): string[] {
  // The leading dot of a hidden file is not an extension separator: `.bashrc`
  // is a name with no extension, which is how the operating system reads it
  // too. Stripping it first also keeps `.pdf.exe` honest — `pdf` is the stem.
  const segments = baseName(stripBidiControls(name)).replace(/^\.+/, '').split('.');
  return segments
    .slice(1)
    .map((segment) => segment.trim().toLowerCase())
    .filter((segment) => EXTENSION_TOKEN.test(segment));
}

/** What a filename claims, once the display tricks are taken out of it. */
export interface FilenameFacts {
  /** The name as the operating system reads it: reordering characters removed. */
  name: string;
  /** The extension that decides what happens on a double click; null if none. */
  extension: string | null;
  /** Every extension-looking token, in written order. */
  extensions: string[];
  /** True when the name carries characters that reorder how it is displayed. */
  reordered: boolean;
}

/**
 * Read a filename into the facts the rules ask about.
 *
 * An absent name is not a signal and not an error: plenty of legitimate
 * inline parts — a signature image, a calendar invitation — arrive without
 * one, and they get an empty name and no extension rather than a point.
 */
export function inspectFilename(name: string | null | undefined): FilenameFacts {
  const raw = name ?? '';
  const stripped = stripBidiControls(raw);
  const extensions = extensionsOf(raw);
  return {
    name: stripped,
    extension: extensions[extensions.length - 1] ?? null,
    extensions,
    reordered: stripped !== raw,
  };
}
