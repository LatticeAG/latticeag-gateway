import { describe, expect, test } from "vitest";

import { F } from "@latticeag/testkit";

import { manifestDigestOf, parseProductManifest } from "./manifest.js";

const manifestBytes = (): Uint8Array =>
  new Uint8Array(Buffer.from(F.release1.wire.manifest.content, "base64url"));

const parse = (mutate: (m: Record<string, unknown>) => void): Uint8Array => {
  const m = JSON.parse(Buffer.from(manifestBytes()).toString("utf8"));
  mutate(m);
  return new Uint8Array(Buffer.from(JSON.stringify(m), "utf8"));
};

const code = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code ?? "??";
  }
  return "NO_THROW";
};

describe("parseProductManifest", () => {
  test("parses the §13.1 fixture manifest", () => {
    const m = parseProductManifest(manifestBytes());
    expect(m.schema).toBe("gateway.product/1");
    expect(m.slug).toBe("lexverdict");
    expect(m.version).toBe("0.1.0");
    expect(m.adapter.contract).toBe("gateway-adapter/1");
    expect(manifestDigestOf(manifestBytes())).toBe(F.release1.wire.manifest.ref.digest);
  });

  test("rejects non-JSON and oversized blobs", () => {
    expect(code(() => parseProductManifest(new Uint8Array([0xff, 0xfe])))).toBe("SCHEMA_INVALID");
    // Byte cap is the OBJECT_LIMIT class, not a schema violation.
    expect(code(() => parseProductManifest(new Uint8Array(256 * 1024 + 1)))).toBe("OBJECT_LIMIT");
  });

  test("rejects wrong schema id / bad slug / non-exact version", () => {
    expect(code(() => parseProductManifest(parse((m) => { m.schema = "other/1"; })))).toBe("SCHEMA_INVALID");
    expect(code(() => parseProductManifest(parse((m) => { m.slug = "Bad_Slug"; })))).toBe("SCHEMA_INVALID");
    expect(code(() => parseProductManifest(parse((m) => { m.version = "0.1"; })))).toBe("SCHEMA_INVALID");
  });

  test("rejects unknown enum values rather than normalizing them", () => {
    expect(code(() => parseProductManifest(parse((m) => { m.series = "bogus"; })))).toBe("SCHEMA_INVALID");
    expect(code(() => parseProductManifest(parse((m) => { (m.surfaces as { tier: string }).tier = "platinum"; })))).toBe("SCHEMA_INVALID");
    expect(code(() => parseProductManifest(parse((m) => { (m.runtime as { sandbox: string }).sandbox = "docker"; })))).toBe("SCHEMA_INVALID");
    expect(code(() => parseProductManifest(parse((m) => { (m.runtime as { os: string[] }).os = ["plan9"]; })))).toBe("SCHEMA_INVALID");
  });

  test("rejects unpinned adapter contract and unsafe paths", () => {
    expect(code(() => parseProductManifest(parse((m) => { (m.adapter as { contract: string }).contract = "gateway-adapter/2"; })))).toBe("UNSUPPORTED_COMPOSITION");
    expect(code(() => parseProductManifest(parse((m) => { (m.adapter as { entry: string }).entry = "../escape.mjs"; })))).toBe("SCHEMA_INVALID");
    expect(code(() => parseProductManifest(parse((m) => { (m.adapter as { entry: string }).entry = "/abs.mjs"; })))).toBe("SCHEMA_INVALID");
    expect(code(() => parseProductManifest(parse((m) => { (m.adapter as { entry: string }).entry = "a\\b.mjs"; })))).toBe("SCHEMA_INVALID");
  });

  test("rejects floating dependency ranges", () => {
    const setDep = (range: string): Uint8Array =>
      parse((m) => {
        m.dependencies = [{ slug: "other", range, kind: "required", edge: null, capability: null, pin: null }];
      });
    for (const range of ["*", "latest", "1.x", ">=1.0.0", "https://x/t.tgz", "git://r"]) {
      expect(code(() => parseProductManifest(setDep(range))), range).toBe("SCHEMA_INVALID");
    }
  });
});
