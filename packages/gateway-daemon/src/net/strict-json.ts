/**
 * Strict JSON admission parse (spec §2.1 P01, §3.1).
 *
 * `JSON.parse` alone cannot enforce the wire contract, so bodies go through
 * a small recursive-descent parser that rejects, all as `JSON_INVALID`:
 *
 *  - a UTF-8 BOM (`EF BB BF`) or a leading U+FEFF after decode;
 *  - bytes that are not strict UTF-8 (fatal TextDecoder);
 *  - duplicate object keys (JSON.parse silently keeps the last);
 *  - lone/unpaired UTF-16 surrogates, in escapes or raw form;
 *  - nesting deeper than `ENVELOPE_LIMITS.maxJsonDepth` (32);
 *  - non-JSON literals (NaN/Infinity tokens), non-finite results (1e999),
 *    unescaped control characters in strings, trailing input;
 *  - (optionally) a non-object top level.
 *
 * Numbers use the exact JSON grammar and `Number(text)` so accepted values
 * match `JSON.parse` semantics; objects are built with own enumerable
 * properties (`__proto__` is a real key, never a prototype write).
 */
import { ENVELOPE_LIMITS } from "../core-v2.js";

export interface StrictJsonFailure {
  ok: false;
  code: "JSON_INVALID";
  /** Duplicate key / offending token name when one exists. */
  field: string | null;
  message: string;
}

export type StrictJsonResult =
  | { ok: true; value: unknown }
  | StrictJsonFailure;

export interface StrictJsonOptions {
  /** Maximum container nesting depth (default 32, spec §3.1). */
  maxDepth?: number;
  /** Reject when the top-level value is not a plain object. */
  requireObject?: boolean;
}

class JsonInvalid extends Error {
  readonly field: string | null;
  constructor(message: string, field: string | null = null) {
    super(message);
    this.name = "JsonInvalid";
    this.field = field;
  }
}

function fail(message: string, field: string | null = null): never {
  throw new JsonInvalid(message, field);
}

/** Decode bytes to text, enforcing strict UTF-8 and rejecting any BOM. */
function decodeStrict(body: Uint8Array | string): string {
  let text: string;
  if (typeof body === "string") {
    text = body;
  } else {
    const bytes =
      body instanceof Uint8Array ? body : new Uint8Array(body);
    if (
      bytes.length >= 3 &&
      bytes[0] === 0xef &&
      bytes[1] === 0xbb &&
      bytes[2] === 0xbf
    ) {
      fail("byte-order mark is not accepted");
    }
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      fail("body is not strict UTF-8");
    }
  }
  if (text.length > 0 && text.charCodeAt(0) === 0xfeff) {
    fail("byte-order mark is not accepted");
  }
  return text;
}

class Parser {
  private pos = 0;
  private depth = 0;
  private readonly maxDepth: number;

  constructor(
    private readonly text: string,
    maxDepth: number,
  ) {
    this.maxDepth = maxDepth;
  }

  private peek(): number {
    return this.pos < this.text.length ? this.text.charCodeAt(this.pos) : -1;
  }

  private ws(): void {
    for (;;) {
      const c = this.peek();
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
        this.pos += 1;
      } else {
        return;
      }
    }
  }

  private expect(code: number): void {
    if (this.peek() !== code) {
      fail(`expected ${JSON.stringify(String.fromCharCode(code))}`);
    }
    this.pos += 1;
  }

  private enter(): void {
    this.depth += 1;
    if (this.depth > this.maxDepth) {
      fail(`JSON nesting exceeds depth ${this.maxDepth}`);
    }
  }

  private leave(): void {
    this.depth -= 1;
  }

  value(): unknown {
    this.ws();
    const v = this.any();
    this.ws();
    if (this.pos !== this.text.length) {
      fail("trailing bytes after JSON value");
    }
    return v;
  }

  private any(): unknown {
    const c = this.peek();
    switch (c) {
      case -1:
        fail("unexpected end of input");
      case 0x7b /* { */:
        return this.object();
      case 0x5b /* [ */:
        return this.array();
      case 0x22 /* " */:
        return this.string();
      case 0x74 /* t */:
        return this.literal("true", true);
      case 0x66 /* f */:
        return this.literal("false", false);
      case 0x6e /* n */:
        return this.literal("null", null);
      default:
        if (c === 0x2d /* - */ || (c >= 0x30 && c <= 0x39)) {
          return this.number();
        }
        fail("unexpected character");
    }
  }

  private literal(word: string, value: unknown): unknown {
    if (!this.text.startsWith(word, this.pos)) {
      fail(`invalid literal (wanted ${word})`);
    }
    this.pos += word.length;
    return value;
  }

  private object(): Record<string, unknown> {
    this.pos += 1; // {
    this.enter();
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.ws();
    if (this.peek() === 0x7d /* } */) {
      this.pos += 1;
      this.leave();
      return out;
    }
    for (;;) {
      this.ws();
      if (this.peek() !== 0x22) fail("object keys must be strings");
      const key = this.string();
      if (seen.has(key)) fail(`duplicate key ${JSON.stringify(key)}`, key);
      seen.add(key);
      this.ws();
      this.expect(0x3a /* : */);
      this.ws();
      const value = this.any();
      // Own enumerable property even for "__proto__" (JSON.parse parity).
      Object.defineProperty(out, key, {
        value,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      this.ws();
      const c = this.peek();
      if (c === 0x2c /* , */) {
        this.pos += 1;
        continue;
      }
      if (c === 0x7d /* } */) {
        this.pos += 1;
        this.leave();
        return out;
      }
      fail("expected ',' or '}' in object");
    }
  }

  private array(): unknown[] {
    this.pos += 1; // [
    this.enter();
    const out: unknown[] = [];
    this.ws();
    if (this.peek() === 0x5d /* ] */) {
      this.pos += 1;
      this.leave();
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.any());
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.pos += 1;
        continue;
      }
      if (c === 0x5d) {
        this.pos += 1;
        this.leave();
        return out;
      }
      fail("expected ',' or ']' in array");
    }
  }

  private string(): string {
    this.pos += 1; // "
    const start = this.pos;
    let out = "";
    let chunk = start;
    for (;;) {
      const c = this.peek();
      if (c === -1) fail("unterminated string");
      if (c === 0x22 /* " */) {
        out += this.text.slice(chunk, this.pos);
        this.pos += 1;
        return out;
      }
      if (c === 0x5c /* \ */) {
        out += this.text.slice(chunk, this.pos);
        this.pos += 1;
        out += this.escape();
        chunk = this.pos;
        continue;
      }
      if (c < 0x20) fail("unescaped control character in string");
      // Lone UTF-16 surrogates are impossible from strict UTF-8 decode, but
      // a caller may hand us a JS string directly — still reject.
      if (c >= 0xd800 && c <= 0xdfff) {
        const next = this.text.charCodeAt(this.pos + 1);
        const paired =
          c <= 0xdbff && next >= 0xdc00 && next <= 0xdfff;
        if (!paired) fail("lone UTF-16 surrogate in string");
        this.pos += 2;
        continue;
      }
      this.pos += 1;
    }
  }

  private hex4(): number {
    let v = 0;
    for (let i = 0; i < 4; i += 1) {
      const c = this.text.charCodeAt(this.pos + i);
      const d =
        c >= 0x30 && c <= 0x39
          ? c - 0x30
          : c >= 0x61 && c <= 0x66
            ? c - 0x57
            : c >= 0x41 && c <= 0x46
              ? c - 0x37
              : -1;
      if (d < 0) fail("invalid \\u escape");
      v = v * 16 + d;
    }
    this.pos += 4;
    return v;
  }

  private escape(): string {
    const c = this.peek();
    this.pos += 1;
    switch (c) {
      case 0x22:
        return '"';
      case 0x5c:
        return "\\";
      case 0x2f:
        return "/";
      case 0x62:
        return "\b";
      case 0x66:
        return "\f";
      case 0x6e:
        return "\n";
      case 0x72:
        return "\r";
      case 0x74:
        return "\t";
      case 0x75 /* u */: {
        const hi = this.hex4();
        if (hi >= 0xd800 && hi <= 0xdbff) {
          // Must be followed by a low-surrogate escape.
          if (
            this.text.charCodeAt(this.pos) === 0x5c &&
            this.text.charCodeAt(this.pos + 1) === 0x75
          ) {
            this.pos += 2;
            const lo = this.hex4();
            if (lo >= 0xdc00 && lo <= 0xdfff) {
              return String.fromCharCode(hi, lo);
            }
            fail("invalid low surrogate in \\u escape");
          }
          fail("unpaired high surrogate in \\u escape");
        }
        if (hi >= 0xdc00 && hi <= 0xdfff) {
          fail("lone low surrogate in \\u escape");
        }
        return String.fromCharCode(hi);
      }
      default:
        fail("invalid escape sequence");
    }
  }

  private number(): number {
    const start = this.pos;
    if (this.peek() === 0x2d) this.pos += 1;
    const c = this.peek();
    if (c === 0x30) {
      this.pos += 1;
    } else if (c >= 0x31 && c <= 0x39) {
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.pos += 1;
    } else {
      fail("invalid number");
    }
    if (this.peek() === 0x2e /* . */) {
      this.pos += 1;
      if (!(this.peek() >= 0x30 && this.peek() <= 0x39)) {
        fail("invalid number fraction");
      }
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.pos += 1;
    }
    const e = this.peek();
    if (e === 0x65 /* e */ || e === 0x45 /* E */) {
      this.pos += 1;
      const s = this.peek();
      if (s === 0x2b || s === 0x2d) this.pos += 1;
      if (!(this.peek() >= 0x30 && this.peek() <= 0x39)) {
        fail("invalid number exponent");
      }
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.pos += 1;
    }
    const n = Number(this.text.slice(start, this.pos));
    if (!Number.isFinite(n)) fail("number is not finite");
    return n;
  }
}

/**
 * Parse a request/response body under the strict wire rules.
 * `Uint8Array` input is decoded with a fatal UTF-8 decoder first.
 */
export function parseStrictJson(
  body: Uint8Array | string,
  opts: StrictJsonOptions = {},
): StrictJsonResult {
  const maxDepth = opts.maxDepth ?? ENVELOPE_LIMITS.maxJsonDepth;
  try {
    const text = decodeStrict(body);
    const value = new Parser(text, maxDepth).value();
    if (opts.requireObject === true) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        fail("top-level JSON value must be an object");
      }
    }
    return { ok: true, value };
  } catch (e) {
    if (e instanceof JsonInvalid) {
      return { ok: false, code: "JSON_INVALID", field: e.field, message: e.message };
    }
    throw e;
  }
}

/** Strict-parse and require a closed object top level. */
export function parseStrictJsonObject(
  body: Uint8Array | string,
  opts: Omit<StrictJsonOptions, "requireObject"> = {},
):
  | { ok: true; value: Record<string, unknown> }
  | StrictJsonFailure {
  const r = parseStrictJson(body, { ...opts, requireObject: true });
  if (!r.ok) return r;
  return { ok: true, value: r.value as Record<string, unknown> };
}
