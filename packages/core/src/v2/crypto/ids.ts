/**
 * Identifier, token, pairing-code, and transport-cursor primitives.
 *
 *  - Control IDs use the Proof Id grammar `^[A-Za-z][A-Za-z0-9_-]{0,63}$`
 *    carrying 128 random bits (spec §2.2): `"g"` + base64url(16 CSPRNG bytes).
 *  - Access/refresh tokens are 32 CSPRNG bytes encoded canonical base64url
 *    (spec §4.3); the server stores only H(token).
 *  - Invitation codes are 10 Crockford-base32 characters = 50 bits
 *    (spec §4.2), alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I/L/O/U).
 *  - Delivery cursors have the spec §8/SSE lexical form
 *    `c<16 lowercase hex>:<canonical decimal ordinal>`; they are transport
 *    metadata, never event identities or authorization.
 */
import { randomBytes } from "node:crypto";
import { CryptoError } from "./errors.js";

/** Proof Id grammar: `^[A-Za-z][A-Za-z0-9_-]{0,63}$`. */
export const ID_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

/** Crockford base32 alphabet (no I, L, O, U); each char carries 5 bits. */
export const CROCKFORD32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Invitation-code lexical form: 10 Crockford base32 chars (50 bits). */
export const PAIR_CODE_RE = /^[0-9A-HJKMNP-TV-Z]{10}$/;

const CURSOR_LANE_RE = /^[0-9a-f]{16}$/;
const CURSOR_RE = /^c([0-9a-f]{16}):([0-9]+)$/;
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;

/** True when `value` satisfies the Proof Id grammar. */
export function isId(value: unknown): value is string {
  return typeof value === "string" && ID_RE.test(value);
}

/** True when `value` satisfies the Proof Id grammar (control-id alias). */
export function isControlId(value: unknown): value is string {
  return isId(value);
}

/** New control ID: `"g"` + base64url(128 random bits) — 23 chars. */
export function newControlId(): string {
  return `g${randomBytes(16).toString("base64url")}`;
}

/** New access/refresh token: 32 CSPRNG bytes, canonical base64url (43 chars). */
export function newToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * New invitation code: 10 Crockford-base32 characters = 50 random bits.
 * `byte & 0x1f` is unbiased because 256 is a multiple of 32.
 */
export function newPairCode(): string {
  const raw = randomBytes(10);
  let out = "";
  for (const byte of raw) {
    out += CROCKFORD32_ALPHABET[byte & 0x1f];
  }
  return out;
}

/** True when `code` is 10 Crockford-base32 characters. */
export function isPairCode(code: unknown): code is string {
  return typeof code === "string" && PAIR_CODE_RE.test(code);
}

function ordinalText(ordinal: number | string): string {
  if (typeof ordinal === "number") {
    if (!Number.isSafeInteger(ordinal) || ordinal < 0) {
      throw new CryptoError(
        "CURSOR_INVALID",
        "cursor ordinal must be a nonnegative safe integer",
      );
    }
    return String(ordinal);
  }
  if (!DECIMAL_RE.test(ordinal)) {
    throw new CryptoError(
      "CURSOR_INVALID",
      "cursor ordinal must be a canonical decimal string",
    );
  }
  return ordinal;
}

/**
 * Format a transport cursor `c<lane>:<ordinal>` where `lane` is exactly 16
 * lowercase hex characters and `ordinal` is a canonical decimal.
 */
export function formatCursor(
  laneOrdinal16hex: string,
  ordinal: number | string,
): string {
  if (!CURSOR_LANE_RE.test(laneOrdinal16hex)) {
    throw new CryptoError(
      "CURSOR_INVALID",
      "cursor lane must be exactly 16 lowercase hex characters",
    );
  }
  return `c${laneOrdinal16hex}:${ordinalText(ordinal)}`;
}

/**
 * Convenience cursor constructor: `seq` is rendered as the 16-hex lane,
 * `ordinal` as the decimal ordinal. `newCursor(1, 7)` → `c0000000000000001:7`.
 */
export function newCursor(seq: number, ordinal: number | string): string {
  if (!Number.isSafeInteger(seq) || seq < 0) {
    throw new CryptoError(
      "CURSOR_INVALID",
      "cursor seq must be a nonnegative safe integer",
    );
  }
  const lane = seq.toString(16).padStart(16, "0");
  return formatCursor(lane, ordinal);
}

export type ParsedCursor = {
  /** The 16-lowercase-hex lane component (no `c` prefix). */
  lane: string;
  /** Canonical decimal ordinal, kept as text to avoid lossy conversion. */
  ordinal: string;
};

/**
 * Parse a cursor of form `c<16 lowercase hex>:<canonical decimal ordinal>`.
 * Returns null for any malformed input.
 */
export function parseCursor(cursor: unknown): ParsedCursor | null {
  if (typeof cursor !== "string") {
    return null;
  }
  const match = CURSOR_RE.exec(cursor);
  if (match === null) {
    return null;
  }
  const lane = match[1];
  const ordinal = match[2];
  if (lane === undefined || ordinal === undefined || !DECIMAL_RE.test(ordinal)) {
    return null;
  }
  return { lane, ordinal };
}
