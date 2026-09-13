/**
 * P01 canonical JSON — the §13.1 fixture `J` semantics, made strict.
 *
 * Fixture reference (GATEWAY_SPEC_EXTREME §13.1):
 *
 *   const J = (x) =>
 *     Array.isArray(x)
 *       ? "[" + x.map(J).join(",") + "]"
 *       : x !== null && typeof x === "object"
 *         ? "{" + Object.keys(x).sort().map((k) => JSON.stringify(k) + ":" + J(x[k])).join(",") + "}"
 *         : JSON.stringify(x);
 *
 * Object keys sort by `Array.prototype.sort()` default ordering, which is
 * UTF-16 code-unit order — the same ordering RFC 8785 (JCS) mandates.
 *
 * STRICT DOMAIN: this encoder accepts only the fixture's scalar domain —
 * `null`, booleans, well-formed UTF-16 strings, and safe integers — plus
 * plain objects and arrays built from them. It REJECTS `undefined`,
 * functions, symbols, bigint, non-finite numbers, non-safe-integer numbers
 * (e.g. 0.5, 2**53), lone surrogates, and non-plain objects (Date, Map,
 * class instances). Note this is deliberately narrower than full RFC 8785:
 * production callers that must canonicalize arbitrary JSON numbers
 * (fractions, -0 edge cases, exponents) need a real RFC 8785 parser with
 * the ES-number-to-shortest-roundtrip serialization. Here the input is
 * already a JS value tree, so we fix the safe-integer domain the fixture
 * exercises rather than reimplementing the parser half of JCS.
 *
 * Nesting depth is the caller's concern (spec envelope rules cap inbound
 * JSON at depth 32 before values reach this module).
 */
import { CryptoError } from "./errors.js";

/** Scalars admitted by the strict canonical domain. */
export type CanonicalScalar = null | boolean | string | number;

/** Recursive shape admitted by {@link isCanonicalDomainValue}. */
export type CanonicalValue =
  | CanonicalScalar
  | CanonicalValue[]
  | { [key: string]: CanonicalValue };

/** True when `s` contains no lone (unpaired) UTF-16 surrogates. */
function isWellFormedUtf16(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      // charCodeAt past the end returns NaN, which fails both bounds → reject.
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false;
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** Only `{}`/`Object.create(null)` literal-style objects are in-domain. */
function isPlainObject(value: object): value is Record<string, unknown> {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Structural guard for the strict canonical domain. Returns true iff
 * `canonicalJson` can encode `value` without throwing.
 */
export function isCanonicalDomainValue(value: unknown): boolean {
  if (value === null) {
    return true;
  }
  switch (typeof value) {
    case "boolean":
      return true;
    case "string":
      return isWellFormedUtf16(value);
    case "number":
      // Safe integers only: finite, integral, |n| <= 2^53 - 1.
      return Number.isSafeInteger(value);
    case "object": {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (!isCanonicalDomainValue(item)) {
            return false;
          }
        }
        return true;
      }
      if (!isPlainObject(value)) {
        return false;
      }
      for (const key of Object.keys(value)) {
        if (!isWellFormedUtf16(key)) {
          return false;
        }
        if (!isCanonicalDomainValue(value[key])) {
          return false;
        }
      }
      return true;
    }
    default:
      // "undefined" | "function" | "symbol" | "bigint" — all rejected.
      return false;
  }
}

/**
 * Canonical JSON encoding with fixture `J` semantics: object keys sorted by
 * UTF-16 code unit, scalars via JSON.stringify, recursive, no whitespace.
 *
 * @throws {CryptoError} with code `CANONICAL_DOMAIN` when `value` is outside
 *   the strict domain described above.
 */
export function canonicalJson(value: unknown): string {
  if (!isCanonicalDomainValue(value)) {
    throw new CryptoError(
      "CANONICAL_DOMAIN",
      "value is outside the strict canonical JSON domain " +
        "(only null/boolean/string/safe-integer scalars, arrays, and plain objects are allowed)",
    );
  }
  return encode(value as CanonicalValue);
}

function encode(value: CanonicalValue): string {
  if (Array.isArray(value)) {
    return `[${value.map(encode).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    const parts = keys.map(
      (key) => `${JSON.stringify(key)}:${encode(value[key] as CanonicalValue)}`,
    );
    return `{${parts.join(",")}}`;
  }
  return JSON.stringify(value);
}
