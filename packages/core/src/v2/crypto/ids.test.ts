import { Buffer } from "node:buffer";
import { describe, expect, test } from "vitest";
import { CryptoError } from "./errors.js";
import {
  CROCKFORD32_ALPHABET,
  ID_RE,
  PAIR_CODE_RE,
  formatCursor,
  isControlId,
  isPairCode,
  newControlId,
  newCursor,
  newPairCode,
  newToken,
  parseCursor,
} from "./ids.js";

describe("ids", () => {
  test("newControlId matches the Proof Id grammar with 128 random bits", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const id = newControlId();
      expect(id).toMatch(ID_RE);
      expect(isControlId(id)).toBe(true);
      expect(id.startsWith("g")).toBe(true);
      expect(id).toHaveLength(23); // "g" + base64url(16 bytes) = 1 + 22
      seen.add(id);
    }
    expect(seen.size).toBe(200);
  });

  test("newToken is 32 CSPRNG bytes as canonical base64url (43 chars)", () => {
    const token = newToken();
    expect(token).toHaveLength(43);
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(token, "base64url")).toHaveLength(32);
    expect(Buffer.from(token, "base64url").toString("base64url")).toBe(token);
    expect(newToken()).not.toBe(token);
  });

  test("newPairCode is 10 Crockford-base32 chars (50 bits, no I/L/O/U)", () => {
    expect(CROCKFORD32_ALPHABET).toHaveLength(32);
    for (let i = 0; i < 200; i += 1) {
      const code = newPairCode();
      expect(code).toHaveLength(10);
      expect(code).toMatch(PAIR_CODE_RE);
      expect(isPairCode(code)).toBe(true);
      expect(code).not.toMatch(/[ILOU]/);
    }
  });

  test("isPairCode / invite-code shape edge cases", () => {
    expect(isPairCode("6J7K8M9N2P")).toBe(true); // fixture code
    for (const bad of [
      "6J7K8M9N2I",
      "6J7K8M9N2L",
      "6J7K8M9N2O",
      "6J7K8M9N2U",
      "6j7k8m9n2p",
      "6J7K8M9N2",
      "6J7K8M9N2PQ",
      "",
      123,
      null,
    ]) {
      expect(isPairCode(bad)).toBe(false);
    }
  });

  test("formatCursor/newCursor produce c<16 hex>:<ordinal>", () => {
    expect(formatCursor("0000000000000001", 7)).toBe("c0000000000000001:7");
    expect(newCursor(1, 7)).toBe("c0000000000000001:7"); // fixture cursor
    expect(newCursor(0, "0")).toBe("c0000000000000000:0");
    expect(formatCursor("ffffffffffffffff", 99)).toBe("cffffffffffffffff:99");
  });

  test("cursor constructors reject malformed parts", () => {
    for (const lane of ["", "1", "00000000000000001", "ABCDEF0123456789"]) {
      expect(() => formatCursor(lane, 1)).toThrow(CryptoError);
    }
    for (const ordinal of [-1, 0.5, Number.NaN, "01", "x", ""]) {
      expect(() => formatCursor("0000000000000001", ordinal)).toThrow(
        CryptoError,
      );
    }
    expect(() => newCursor(-1, 0)).toThrow(CryptoError);
    expect(() => newCursor(1.5, 0)).toThrow(CryptoError);
  });

  test("parseCursor round-trips and rejects bad lexical forms", () => {
    expect(parseCursor("c0000000000000001:7")).toEqual({
      lane: "0000000000000001",
      ordinal: "7",
    });
    const c = newCursor(255, 9007199254740991);
    const parsed = parseCursor(c);
    expect(parsed).not.toBeNull();
    expect(formatCursor(parsed!.lane, parsed!.ordinal)).toBe(c);
    for (const bad of [
      "c0000000000000001:07", // non-canonical decimal
      "c000000000000001:7", // 15 hex digits
      "C0000000000000001:7", // uppercase C
      "cABCDEF0123456789:7", // uppercase hex
      "c0000000000000001:", // missing ordinal
      "c0000000000000001:-1",
      "c0000000000000001:7:8",
      "",
      null,
      42,
    ]) {
      expect(parseCursor(bad)).toBeNull();
    }
  });
});
