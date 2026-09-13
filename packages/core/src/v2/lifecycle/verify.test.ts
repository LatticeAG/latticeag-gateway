import { describe, expect, test } from "vitest";

import { F, now } from "@latticeag/testkit";

import type { Release } from "../protocol/product.js";
import { isRevoked, verifyRelease } from "./verify.js";
import { fixtureTrust } from "./testbed.js";

const wire1 = (): Release => structuredClone(F.release1.wire) as Release;

const ctx = { archive: F.release1.archive, os: "linux", arch: "x64", node: "v24.0.0" };

describe("verifyRelease (§5.1)", () => {
  test("fixture release verifies: 2 signers, provenance, digest bound", () => {
    const v = verifyRelease(wire1(), fixtureTrust(), ctx);
    expect(v.manifest.slug).toBe("lexverdict");
    expect(v.manifestDigest).toBe(F.release1.wire.manifest.ref.digest);
    expect(v.archiveDigest).toBe(F.release1.manifest.package.archive.digest);
    expect(v.releaseSigners).toHaveLength(2);
    expect(v.provenance.builder).toBe("fixture-builder");
  });

  test("TV-GW-05: corrupted signature → SIGNATURE_INVALID", () => {
    const wire = wire1();
    wire.signatures[0]!.signature_hex =
      wire.signatures[0]!.signature_hex.slice(0, -2) + "00";
    expect(() => verifyRelease(wire, fixtureTrust(), ctx)).toThrowError(
      expect.objectContaining({ code: "SIGNATURE_INVALID" }),
    );
  });

  test("unauthorized extra signature fails the set (no threshold gaming)", () => {
    const wire = wire1();
    const bogus = structuredClone(wire.signatures[0]!);
    bogus.signature_hex = "0".repeat(128);
    wire.signatures.push(bogus);
    expect(() => verifyRelease(wire, fixtureTrust(), ctx)).toThrowError(
      expect.objectContaining({ code: "SIGNATURE_INVALID" }),
    );
  });

  test("TV-GW-06: unapproved builder → PROVENANCE_INVALID", () => {
    const trust = fixtureTrust({ builders: new Set(["someone-else"]) });
    expect(() => verifyRelease(wire1(), trust, ctx)).toThrowError(
      expect.objectContaining({ code: "PROVENANCE_INVALID" }),
    );
  });

  test("archive bytes that do not match the manifest digest → ARTIFACT_MISMATCH", () => {
    expect(() =>
      verifyRelease(wire1(), fixtureTrust(), { ...ctx, archive: new Uint8Array([1, 2, 3]) }),
    ).toThrowError(expect.objectContaining({ code: "ARTIFACT_MISMATCH" }));
  });

  test("revoked archive digest → POLICY_DENIED", () => {
    const trust = fixtureTrust({
      revocations: new Set([F.release1.manifest.package.archive.digest]),
    });
    expect(() => verifyRelease(wire1(), trust, ctx)).toThrowError(
      expect.objectContaining({ code: "POLICY_DENIED" }),
    );
    expect(isRevoked(trust.revocations, F.release1.manifest.package.archive.digest)).toBe(true);
  });

  test("platform mismatch → UNSUPPORTED_COMPOSITION", () => {
    expect(() =>
      verifyRelease(wire1(), fixtureTrust(), { ...ctx, os: "win32" }),
    ).toThrowError(expect.objectContaining({ code: "UNSUPPORTED_COMPOSITION" }));
    expect(() =>
      verifyRelease(wire1(), fixtureTrust(), { ...ctx, node: "v99.0.0" }),
    ).toThrowError(expect.objectContaining({ code: "UNSUPPORTED_COMPOSITION" }));
  });

  test("TV-GW-45: expired index → TRUST_EXPIRED unless pinned", () => {
    const expired = { ...ctx, now: now + 365 * 86_400_000, indexExpiresMs: now + 604_800_000 };
    expect(() => verifyRelease(wire1(), fixtureTrust(), expired)).toThrowError(
      expect.objectContaining({ code: "TRUST_EXPIRED" }),
    );
    // pinned/offline installs are unaffected
    expect(() =>
      verifyRelease(wire1(), fixtureTrust(), { ...expired, pinned: true }),
    ).not.toThrow();
  });
});
