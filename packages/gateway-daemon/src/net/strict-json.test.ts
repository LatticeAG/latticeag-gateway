/** Strict JSON admission tests (spec §2.1/§3.1). */
import { describe, expect, test } from "vitest";
import { parseStrictJson, parseStrictJsonObject } from "./strict-json.js";

describe("parseStrictJson", () => {
  test("accepts a normal object body", () => {
    const r = parseStrictJson('{"v":2,"id":"q1","method":"daemon.hello"}');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).toEqual({ v: 2, id: "q1", method: "daemon.hello" });
  });

  test("rejects duplicate object keys", () => {
    const r = parseStrictJson('{"a":1,"a":2}');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("JSON_INVALID");
      expect(r.field).toBe("a");
    }
  });

  test("rejects duplicate keys nested inside params", () => {
    const r = parseStrictJson('{"params":{"x":1,"x":2}}');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("JSON_INVALID");
  });

  test("rejects depth 33", () => {
    const deep = "[".repeat(33) + "]".repeat(33);
    const r = parseStrictJson(deep);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("JSON_INVALID");
  });

  test("accepts depth 32", () => {
    const deep = "[".repeat(32) + "]".repeat(32);
    expect(parseStrictJson(deep).ok).toBe(true);
  });

  test("rejects a UTF-8 BOM", () => {
    const body = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("{}")]);
    const r = parseStrictJson(body);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("JSON_INVALID");
  });

  test("rejects a leading U+FEFF in string input", () => {
    const r = parseStrictJson("\ufeff{}");
    expect(r.ok).toBe(false);
  });

  test("rejects lone surrogate escapes", () => {
    const r = parseStrictJson('{"k":"\\ud800"}');
    expect(r.ok).toBe(false);
    const r2 = parseStrictJson('{"k":"\\udc00"}');
    expect(r2.ok).toBe(false);
  });

  test("accepts a paired surrogate escape", () => {
    const r = parseStrictJson('{"k":"\\ud83d\\ude00"}');
    expect(r.ok).toBe(true);
    if (r.ok) expect((r.value as { k: string }).k).toBe("😀");
  });

  test("rejects non-object top level when required", () => {
    const r = parseStrictJsonObject('"x"');
    expect(r.ok).toBe(false);
    expect(parseStrictJsonObject("{}").ok).toBe(true);
  });

  test("rejects malformed UTF-8", () => {
    const r = parseStrictJson(new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]));
    expect(r.ok).toBe(false);
  });

  test("rejects non-finite numbers", () => {
    expect(parseStrictJson("[1e999]").ok).toBe(false);
    expect(parseStrictJson("[NaN]").ok).toBe(false);
    expect(parseStrictJson("[Infinity]").ok).toBe(false);
  });

  test("rejects trailing content and unterminated input", () => {
    expect(parseStrictJson("{} garbage").ok).toBe(false);
    expect(parseStrictJson('{"a":').ok).toBe(false);
    expect(parseStrictJson("").ok).toBe(false);
  });
});
