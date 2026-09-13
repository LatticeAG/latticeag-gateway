/**
 * SHA-256 helpers matching the §13.1 fixture `H` (`sha256` over UTF-8 for
 * string input, hex output) plus the lexical Hash refinement check.
 */
import { createHash } from "node:crypto";

/** Lexical form of a Proof/World hash: exactly 64 lowercase hex chars. */
export const HASH64_RE = /^[0-9a-f]{64}$/;

/** True when `value` is exactly 64 lowercase hex characters. */
export function isHash64(value: unknown): value is string {
  return typeof value === "string" && HASH64_RE.test(value);
}

/** SHA-256 of `data` as a lowercase hex string. Strings hash as UTF-8. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** SHA-256 of `data` as raw bytes. Strings hash as UTF-8. */
export function sha256Bytes(data: string | Uint8Array): Uint8Array {
  return createHash("sha256").update(data).digest();
}
