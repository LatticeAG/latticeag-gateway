/**
 * Terminal/UI text sanitization (spec §7.3 / TV-GW-42).
 *
 * Untrusted event text rendered into a terminal, log viewer, or SSE
 * stream is projected to *inert* text before display:
 *
 *  - ANSI/VT escape sequences are removed entirely: CSI (ESC [ … final),
 *    OSC (ESC ] … BEL|ST — including OSC-8 hyperlinks), DCS/SOS/PM/APC
 *    (ESC P|X|^|_ … ST), and every remaining ESC-prefixed or bare escape
 *    byte. A hostile hyperlink or screen-manipulation sequence can never
 *    reach a terminal emulator, so no terminal-driven network fetch or
 *    display forgery is possible.
 *  - C0 controls other than LF and TAB are removed (CR and BEL included —
 *    both can forge display state); DEL and the whole C1 range go too,
 *    which also kills the single-byte CSI/OSC forms (0x9B/0x9D).
 *  - Bidi embedding/override/isolate characters, directional marks,
 *    zero-width and other invisible format characters are removed so
 *    rendered order always matches logical order (no bidi spoofing).
 *  - Markup characters are *not* rewritten: <, >, & remain literal
 *    characters. Sanitized text is inert because it is rendered as text,
 *    never interpreted as HTML — and it carries no control or format
 *    bytes a renderer could act on.
 *
 * The function is pure: it never mutates its input, never performs IO,
 * and never fetches. The raw bytes and digest of the source record are
 * unchanged by projection (the sanitized form is a display copy).
 */

const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const BS = String.fromCharCode(0x5c);

/** Contiguous code-point range as a char-class fragment. */
function span(lo: number, hi: number): string {
  let out = "";
  for (let cp = lo; cp <= hi; cp += 1) out += String.fromCharCode(cp);
  return out;
}

/** ESC ]|P|X|^|_ … string sequences terminated by BEL or ESC + backslash (ST). */
const ST_SEQUENCE = new RegExp(
  ESC + "[" + BS + "]PX^_][\\s\\S]*?(?:" + BEL + "|" + ESC + BS + BS + ")",
  "g",
);

/** CSI: ESC [ + params/intermediates + final byte. */
const CSI_SEQUENCE = new RegExp(ESC + BS + "[[0-?]*[ -/]*[@-~]", "g");

/** Any remaining ESC + optional intermediates/final, and bare ESC. */
const ESC_REST = new RegExp(ESC + "[ -/]*[0-~]|" + ESC, "g");

/** C0 except LF/TAB, DEL, and the whole C1 range. */
const CONTROL = new RegExp(
  "[" + span(0x00, 0x08) + span(0x0b, 0x1f) + span(0x7f, 0x9f) + "]",
  "g",
);

/**
 * Invisible/format characters that reorder or hide text: soft hyphen,
 * grapheme joiner, Arabic letter mark, Hangul fillers, Khmer inherent
 * marks, Mongolian vowel separator, zero-width spaces and joiners,
 * directional marks, bidi embeddings/overrides/isolates and their
 * terminators, word joiner + invisible operators, halfwidth filler,
 * BOM/ZWNBSP.
 */
const FORMAT = new RegExp(
  "[" +
    String.fromCharCode(
      0x00ad, 0x034f, 0x061c, 0x180e,
      0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
      0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
      0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2065,
      0x2066, 0x2067, 0x2068, 0x2069,
      0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f,
      0x3164, 0xfeff, 0xffa0,
    ) +
    span(0x115f, 0x1160) +
    span(0x17b4, 0x17b5) +
    "]",
  "g",
);

/**
 * Project untrusted text to its inert terminal-safe form. The result is
 * printable text plus LF and TAB only — suitable for direct terminal/log
 * output without a renderer interpreting control, sequence, or bidi
 * content.
 */
export function sanitizeTerminalText(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  return input
    .replace(ST_SEQUENCE, "")
    .replace(CSI_SEQUENCE, "")
    .replace(ESC_REST, "")
    .replace(CONTROL, "")
    .replace(FORMAT, "");
}

/** True when text contains nothing a terminal could act on. */
export function isTerminalSafe(text: string): boolean {
  return sanitizeTerminalText(text) === text;
}
