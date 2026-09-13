import { describe, expect, it } from "vitest";
import { CATALOG_LIMITS, catalogFresh } from "./catalog.js";
import { validateRange, SEMVER_RE, SLUG_RE, PRODUCT_LIMITS } from "./product.js";

const INDEX = { issued_ms: 1_000_000, expires_ms: 2_000_000 };
const MAX_AGE_S = 604_800;

describe("catalogFresh (§9.4)", () => {
  it("returns CURRENT inside every bound", () => {
    expect(catalogFresh(INDEX, 1_500_000, MAX_AGE_S)).toBe("CURRENT");
    // issued_ms may be up to 5000 ms in the future.
    expect(catalogFresh({ issued_ms: 1_005_000, expires_ms: 2_000_000 }, 1_000_000, MAX_AGE_S)).toBe(
      "CURRENT",
    );
  });

  it("is not CURRENT at expires_ms equality (TV-GW-45)", () => {
    const r = catalogFresh(INDEX, INDEX.expires_ms, MAX_AGE_S);
    expect(r).not.toBe("CURRENT");
    expect(r).toBe("TRUST_EXPIRED");
    expect(catalogFresh(INDEX, INDEX.expires_ms + 1, MAX_AGE_S)).toBe("TRUST_EXPIRED");
  });

  it("rejects future-dated indexes beyond the 5 s skew", () => {
    expect(
      catalogFresh({ issued_ms: 1_006_000, expires_ms: 2_000_000 }, 1_000_000, MAX_AGE_S),
    ).toBe("TRUST_EXPIRED");
  });

  it("returns STALE past the configured max_age window", () => {
    // issued 1_000_000, max_age 10 s → stale once now >= issued+10_000.
    expect(catalogFresh(INDEX, 1_010_000, 10)).toBe("STALE");
    expect(catalogFresh(INDEX, 1_009_999, 10)).toBe("CURRENT");
    // max_age 0 makes anything past issue stale but not trust-expired.
    expect(catalogFresh(INDEX, 1_000_001, 0)).toBe("STALE");
  });

  it("declares §9.4 caps", () => {
    expect(CATALOG_LIMITS.indexBytes).toBe(8 * 1024 * 1024);
    expect(CATALOG_LIMITS.maxEntries).toBe(10_000);
    expect(CATALOG_LIMITS.maxSignatures).toBe(16);
    expect(CATALOG_LIMITS.maxRedirects).toBe(2);
  });
});

describe("product lexical rules (§5.1)", () => {
  it("matches slug and semver grammars", () => {
    expect(SLUG_RE.test("lexverdict")).toBe(true);
    expect(SLUG_RE.test("Lexverdict")).toBe(false);
    expect(SLUG_RE.test("-bad")).toBe(false);
    expect(SEMVER_RE.test("0.1.0")).toBe(true);
    expect(SEMVER_RE.test("1.2.3-rc.1+build.7")).toBe(true);
    expect(SEMVER_RE.test("1.2")).toBe(false);
    expect(SEMVER_RE.test("v1.2.3")).toBe(false);
    expect(PRODUCT_LIMITS.archiveMaxFiles).toBe(10_000);
  });

  it("validateRange accepts bounded ranges only", () => {
    for (const ok of [
      "1.2.3",
      ">=1.2.3 <2.0.0",
      "^1.2.3",
      "~1.2.3",
      "1.2.3 - 2.0.0",
      "=1.2.3",
    ]) {
      expect(validateRange(ok).ok, ok).toBe(true);
    }
    for (const bad of [
      "*",
      "latest",
      "1.x",
      ">=1.0.0",
      "<2.0.0",
      "main",
      "https://example.com/pkg.tgz",
      "git+https://example.com/repo.git#abc",
      "",
      "1.2.3 || 2.0.0",
    ]) {
      expect(validateRange(bad).ok, bad).toBe(false);
    }
  });
});
