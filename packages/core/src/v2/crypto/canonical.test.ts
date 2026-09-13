import { describe, expect, test } from "vitest";
import { canonicalJson, isCanonicalDomainValue } from "./canonical.js";
import { CryptoError } from "./errors.js";

/** §13.1 fixture J, transcribed verbatim for differential testing. */
const J = (x: unknown): string =>
  Array.isArray(x)
    ? `[${x.map(J).join(",")}]`
    : x !== null && typeof x === "object"
      ? `{${Object.keys(x)
          .sort()
          .map((k) => `${JSON.stringify(k)}:${J((x as Record<string, unknown>)[k])}`)
          .join(",")}}`
      : (JSON.stringify(x) as string);

describe("canonicalJson", () => {
  test("sorts object keys and drops no fields", () => {
    expect(canonicalJson({ b: 1, a: { d: [2, null, "x"], c: true } })).toBe(
      '{"a":{"c":true,"d":[2,null,"x"]},"b":1}',
    );
  });

  test("matches fixture J on a battery of in-domain values", () => {
    const values: unknown[] = [
      null,
      true,
      false,
      0,
      -0,
      42,
      -9007199254740991,
      9007199254740991,
      "",
      "plain",
      'esc"aped\n\t\\ text',
      "ünïcødé — こんにちは",
      "emoji 😀 pair",
      [],
      [1, "a", null, [true]],
      {},
      { z: 1, A: 2, a: 3, "0": 4, "é": 5 },
      { nested: { deep: { list: [{ k: "v" }, [null]] } } },
      { v: 1, kind: "request", issued_ms: 1789257600000 },
    ];
    for (const value of values) {
      expect(isCanonicalDomainValue(value)).toBe(true);
      expect(canonicalJson(value)).toBe(J(value));
    }
  });

  test("rejects non-safe-integer and non-finite numbers", () => {
    for (const bad of [
      2 ** 53,
      -(2 ** 53),
      0.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      1e100,
    ]) {
      expect(isCanonicalDomainValue(bad)).toBe(false);
      expect(() => canonicalJson(bad)).toThrow(CryptoError);
      expect(() => canonicalJson(bad)).toThrow(/canonical JSON domain/);
    }
  });

  test("rejects bigint, undefined, functions, symbols", () => {
    for (const bad of [
      10n,
      undefined,
      () => 1,
      Symbol("s"),
      { a: undefined },
      [undefined],
      { f: () => 1 },
    ]) {
      expect(isCanonicalDomainValue(bad)).toBe(false);
      expect(() => canonicalJson(bad)).toThrow(CryptoError);
    }
  });

  test("rejects non-plain objects", () => {
    for (const bad of [new Date(0), new Map(), new Uint8Array(4)]) {
      expect(isCanonicalDomainValue(bad)).toBe(false);
      expect(() => canonicalJson(bad)).toThrow(CryptoError);
    }
  });

  test("rejects lone surrogates in strings and keys", () => {
    for (const bad of ["\ud800", "\udfff", { "\ud800": 1 }, "ok\ud800x"]) {
      expect(isCanonicalDomainValue(bad)).toBe(false);
      expect(() => canonicalJson(bad)).toThrow(CryptoError);
    }
  });
});
