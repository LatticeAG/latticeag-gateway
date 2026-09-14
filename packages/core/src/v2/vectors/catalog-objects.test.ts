/**
 * TV-GW catalog/store/object-limit conformance vectors (spec §13.2):
 * TV-GW-18 (OBJECT_LIMIT before allocation), TV-GW-44 (rollback),
 * TV-GW-45 (expiry boundary vs pinned installs), TV-GW-46 (strict +
 * empty allowlist), TV-GW-47 (malformed extra signature on releases and
 * the index). Each vector also runs through the lifecycle seam so the
 * store verdict is shown to reach product.plan / the engine.
 */
import { describe, expect, test, vi } from "vitest";

import {
  F,
  H,
  J,
  auditor,
  blob,
  makeKey,
  now,
  origin,
  sunlight,
} from "@latticeag/testkit";
import type { FixtureKey } from "@latticeag/testkit";

import { catalogFresh } from "../protocol/catalog.js";
import type { Release } from "../protocol/product.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import { CatalogStore } from "../catalog/index.js";
import { createCatalogService } from "../catalog/service.js";
import { createMemoryCatalogPorts } from "../catalog/ports.js";
import type { CatalogTrustView, IndexFetch, MemoryCatalogPorts } from "../catalog/ports.js";
import { createObjectService } from "../platform/objects.js";
import { createMemoryPlatformPorts } from "../platform/testing.js";

import { StubAdapterChild } from "../lifecycle/testing.js";
import type { StubScript } from "../lifecycle/testing.js";
import { createProductService } from "../lifecycle/service.js";
import { verifyRelease } from "../lifecycle/verify.js";
import { schema } from "@latticeag/testkit";
import {
  fixturePorts,
  fixtureTrust,
  REVIEW,
} from "../lifecycle/testbed.js";

const third = makeKey(
  "3a7bd2f1c9e4a806d5b194e0f7c2a391b8d4e6f0a1c3b5d7e9f0a2c4b6d8e0f1a3",
  3,
);
const roots = new Map<string, string>([
  [origin.sunlight, origin.material.public],
  [auditor.sunlight, auditor.material.public],
  [third.sunlight, third.material.public],
]);

/** Sign an index's canonical bytes with the given catalog-root keys. */
function signedIndex(
  index: unknown,
  keys: FixtureKey[],
  idOffset = 0,
): IndexFetch {
  const content = blob(J(index));
  return {
    index,
    signatures: keys.map((k, i) => sunlight(content, k, idOffset + i + 1)),
  };
}

function indexOf(revision: string, overrides: Record<string, unknown> = {}) {
  return { ...(F.index as object), revision, ...overrides };
}

function mkPorts(trust: Partial<CatalogTrustView> = {}): MemoryCatalogPorts {
  return createMemoryCatalogPorts({
    now,
    trust: { roots, quorum: 2, channel: "stable", ...trust },
  });
}

const okAdapter: StubScript["methods"] = {
  describe: () => ({
    contract: "gateway-adapter/1",
    product: "lexverdict",
    config_schema_digest: schema.ref.digest,
    profiles: ["@latticeag/events@0.1.0"],
  }),
  configure: (p) => ({ generation: p.generation ?? "1", accepted: true }),
  start: (p) => ({ state: "RUNNING", generation: p.generation ?? "1" }),
  health: () => ({
    liveness: true,
    readiness: true,
    dependencies: [],
    native: { status: "ok" },
  }),
  drain: () => ({ in_flight: 0, uncertain: [] }),
  snapshot: () => ({ supported: false, objects: [] }),
  stop: () => ({ state: "STOPPED", uncertain: [] }),
};

const stubSpawn = () => new StubAdapterChild({ methods: okAdapter });

const MALFORMED_STATEMENT = {
  body: { v: "sunlight.statement/1" },
  hash: "sha256:" + "0".repeat(64),
  signature_hex: "f".repeat(128),
};

// ── TV-GW-18 oversized object reference ──────────────────────────────────

describe("TV-GW-18: object ref over the 1 MiB cap", () => {
  test('ObjectRef.bytes="1048577" → OBJECT_LIMIT before allocation or import', async () => {
    const ports = createMemoryPlatformPorts();
    const objects = createObjectService(ports);
    const putSpy = vi.spyOn(ports.store, "putObject");
    const getSpy = vi.spyOn(ports.store, "getObject");
    const oversized = {
      digest: "0".repeat(64),
      bytes: "1048577", // 1 MiB + 1
      media: "application/octet-stream" as const,
    };
    await expect(
      objects.put({
        action: F.nativeRef,
        blob: { ref: oversized, content: "AA" },
      }),
    ).rejects.toMatchObject({ code: "OBJECT_LIMIT", field: "blob.ref.bytes" });
    // No allocation, no remote import, no store mutation, no chunking.
    expect(putSpy).not.toHaveBeenCalled();
    expect(getSpy).not.toHaveBeenCalled();
    expect(ports.store.objects.size).toBe(0);
    // The declared-size guard also precedes action resolution — the same
    // rejection fires for an unknown action too.
    await expect(
      objects.put({
        action: { object_id: "never-committed" } as never,
        blob: { ref: oversized, content: "AA" },
      }),
    ).rejects.toMatchObject({ code: "OBJECT_LIMIT" });
    expect(putSpy).not.toHaveBeenCalled();
  });
});

// ── TV-GW-44 catalog rollback ────────────────────────────────────────────

describe("TV-GW-44: refresh below the cached revision", () => {
  test("cached rev16 + validly signed rev15 → CATALOG_ROLLBACK; cache and highest-seen byte-identical", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    await store.refresh({
      source: "configured",
      provided: signedIndex(indexOf("16"), [origin, auditor]),
    });
    const cachedRaw = ports.cache!.raw;
    const cachedDigest = ports.cache!.digest;
    const cachedSigs = ports.cache!.signatures;
    const highestBefore = ports.highest;

    await expect(
      store.refresh({
        source: "configured",
        provided: signedIndex(indexOf("15"), [origin, auditor]),
      }),
    ).rejects.toMatchObject({ code: "CATALOG_ROLLBACK", field: "revision" });

    // The original verified cache is byte-identical — not re-verified,
    // not re-signed, not partially overwritten.
    expect(ports.cache!.raw).toBe(cachedRaw);
    expect(ports.cache!.digest).toBe(cachedDigest);
    expect(ports.cache!.signatures).toBe(cachedSigs);
    expect(ports.cache!.index.revision).toBe("16");
    // The highest-seen high-water mark did not move.
    expect(ports.highest).toEqual(highestBefore);
    expect(ports.highest!.revision).toBe("16");
    // No equivocation was recorded for a strictly-lower revision.
    expect(ports.equivocationLog).toHaveLength(0);
  });
});

// ── TV-GW-45 expiry boundary vs pinned installs ──────────────────────────

describe("TV-GW-45: index at exactly expires_ms", () => {
  test("new unpinned install → TRUST_EXPIRED; installed pinned release continues, stale", async () => {
    // Store level: boundary is `now === expires_ms` → TRUST_EXPIRED.
    const cports = mkPorts();
    const store = new CatalogStore(cports);
    await store.refresh({
      source: "configured",
      provided: signedIndex(F.index, [origin, auditor]),
    });
    const cservice = createCatalogService(cports);
    await cservice.pin({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
      expected_revision: cports.pinsRevision(),
    });
    cports.advance(F.index.expires_ms - now); // exactly at the boundary
    expect(catalogFresh(F.index, F.index.expires_ms, 604_800)).toBe("TRUST_EXPIRED");
    expect(store.freshness()).toBe("TRUST_EXPIRED"); // UI shows stale
    expect(() =>
      store.authorizeInstall({
        slug: "otherprod",
        version: "0.1.1",
        digest: `sha256:${H("otherprod")}`,
      }),
    ).toThrowError(expect.objectContaining({ code: "TRUST_EXPIRED" }));
    const auth = store.authorizeInstall({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
    });
    expect(auth).toEqual({
      ok: true,
      pinned: true,
      freshness: "TRUST_EXPIRED",
      stale: true,
    });

    // Lifecycle level: release1 already installed stays READY; a new
    // unpinned plan at the boundary fails TRUST_EXPIRED; an exact pinned
    // update plan still verifies and activates offline.
    const ports = fixturePorts({ spawnAdapter: stubSpawn });
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      const { plan } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      const acc = await svc.product.install({ plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.state).toBe("READY");

      ports.advance(F.index.expires_ms - now); // now === expires_ms
      // The already-installed release is unaffected and healthy.
      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.0");
      expect(active.state).toBe("READY");
      const health = await svc.product.health({ slug: "lexverdict" });
      expect(health.readiness).toBe(true);

      // A new unpinned plan at the boundary is TRUST_EXPIRED.
      await expect(
        svc.product.plan({
          kind: "update",
          source: "lexverdict",
          version: "0.1.1",
        }),
      ).rejects.toMatchObject({ code: "TRUST_EXPIRED" });

      // The exact pinned release verifies and activates under expired
      // metadata (the pin carries slug+version+archive+index digests).
      const pinnedPlan = await svc.product.plan({
        kind: "update",
        source: "lexverdict",
        version: "0.1.1",
        pinned: true,
      } as Parameters<typeof svc.product.plan>[0]);
      const upAcc = await svc.product.update({
        plan: pinnedPlan.plan,
        review: REVIEW,
      });
      const upOp = await svc.waitOperation(upAcc.operation);
      expect(upOp.state).toBe("READY");
      expect(ports.productRegistry.active("lexverdict")!.version).toBe("0.1.1");
      expect(ports.spawned).toHaveLength(2);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

// ── TV-GW-46 strict + empty allowlist ────────────────────────────────────

describe("TV-GW-46: catalog.strict=true with an empty allowlist", () => {
  test("validly signed pinned release → POLICY_DENIED at store and plan", async () => {
    const cports = mkPorts({ strict: true, allowlist: [] });
    const store = new CatalogStore(cports);
    await store.refresh({
      source: "configured",
      provided: signedIndex(F.index, [origin, auditor]),
    });
    // An exact pin is present and still authorizes nothing.
    const cservice = createCatalogService(cports);
    await cservice.pin({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
      expected_revision: cports.pinsRevision(),
    });
    expect(() =>
      store.authorizeInstall({
        slug: "lexverdict",
        version: "0.1.0",
        digest: F.archiveDigest,
      }),
    ).toThrowError(expect.objectContaining({ code: "POLICY_DENIED" }));

    // The same policy reaches the lifecycle resolver: plan() refuses
    // before any fetch/generation/spawn.
    const ports = fixturePorts({
      spawnAdapter: stubSpawn,
      policy: { strict: true, allowlist: [] },
    });
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await expect(
        svc.product.plan({
          kind: "install",
          source: "lexverdict",
          version: "0.1.0",
        }),
      ).rejects.toMatchObject({ code: "POLICY_DENIED" });
      expect(ports.productRegistry.all()).toHaveLength(0);
      expect(ports.journalLog).toHaveLength(0);
      expect(ports.spawned).toHaveLength(0);
      expect(ports.events).toHaveLength(0);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

// ── TV-GW-47 malformed extra signature ───────────────────────────────────

describe("TV-GW-47: extra malformed/unauthorized signature", () => {
  test("release wire: two valid + one malformed → SIGNATURE_INVALID; no install effects", async () => {
    const wire = structuredClone(F.release1.wire) as Release;
    wire.signatures.push(MALFORMED_STATEMENT as never);

    // Unit level: the verifier fails the whole set — the extra is never
    // discarded to meet the threshold.
    expect(() =>
      verifyRelease(wire, fixtureTrust(), {
        archive: F.release1.archive,
        os: process.platform === "darwin" ? "darwin" : "linux",
        arch: process.arch === "arm64" ? "arm64" : "x64",
        node: `v${process.versions.node}`,
        now,
        indexExpiresMs: F.index.expires_ms,
      }),
    ).toThrowError(expect.objectContaining({ code: "SIGNATURE_INVALID" }));

    // Engine level: the same release cannot reach READY.
    const ports = fixturePorts({ spawnAdapter: stubSpawn });
    ports.putRelease(wire, F.release1.archive);
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      const { plan } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      const acc = await svc.product.install({ plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.error?.code).toBe("SIGNATURE_INVALID");
      expect(ports.spawned).toHaveLength(0);
      expect(ports.productRegistry.active("lexverdict")).toBeUndefined();
      // An unauthorized third signer's statement also fails the set.
      const stranger = makeKey("9".repeat(64), 9);
      const wire2 = structuredClone(F.release1.wire) as Release;
      const extra = sunlight(blob(J(wire2.manifest)), stranger, 99);
      wire2.signatures.push(extra as never);
      expect(() =>
        verifyRelease(wire2, fixtureTrust(), {
          archive: F.release1.archive,
          os: "linux",
          arch: "x64",
          node: "v24.0.0",
          now,
          indexExpiresMs: F.index.expires_ms,
        }),
      ).toThrowError(expect.objectContaining({ code: "SIGNATURE_INVALID" }));
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });

  test("catalog index: two valid + one malformed → SIGNATURE_INVALID; cache untouched", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    const good = signedIndex(F.index, [origin, auditor]);
    await expect(
      store.refresh({
        source: "configured",
        provided: {
          index: F.index,
          signatures: [...good.signatures, MALFORMED_STATEMENT],
        },
      }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID", field: "signatures" });
    // Nothing was persisted: no cache, no highest-seen movement.
    expect(ports.cache).toBeNull();
    expect(ports.highest).toBeNull();
    expect(ports.equivocationLog).toHaveLength(0);
  });
});
