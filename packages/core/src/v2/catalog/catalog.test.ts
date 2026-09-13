/**
 * Gateway v2 catalog — signed index store and §3.3 service shapes.
 * Covers TV-GW-44 (rollback), TV-GW-45 (trust expiry vs pins),
 * TV-GW-46 (strict + empty allowlist), TV-GW-47 (malformed extra
 * signature), equivocation retention, channel switching, and the
 * OFFLINE_PINNED snapshot path (spec §9.4).
 */
import { describe, expect, it } from "vitest";
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
import type { Count } from "../protocol/refs.js";
import { catalogFresh } from "../protocol/catalog.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import { CatalogStore } from "./index.js";
import { createCatalogService } from "./service.js";
import { createMemoryCatalogPorts } from "./ports.js";
import type {
  CatalogTrustView,
  IndexFetch,
  MemoryCatalogPorts,
} from "./ports.js";

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
  return { ...F.index, revision, ...overrides };
}

function mkPorts(trust: Partial<CatalogTrustView> = {}): MemoryCatalogPorts {
  return createMemoryCatalogPorts({
    now,
    trust: { roots, quorum: 2, channel: "stable", ...trust },
  });
}

describe("index verification", () => {
  it("accepts a 2-of-3 signed index and serves entries", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    const fetch = signedIndex(F.index, [origin, auditor]);
    const res = await store.refresh({ source: "configured", provided: fetch });
    expect(res).toEqual({
      revision: "1",
      entries: 1,
      freshness: "CURRENT",
    });
    expect(store.entries()).toHaveLength(1);
    expect(store.entries()[0]!.slug).toBe("lexverdict");
    expect(ports.cache?.raw).toBe(canonicalJson(F.index));
    expect(ports.highest?.revision).toBe("1");
  });

  it("fails below quorum and on unsigned binding mismatches", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    // One valid signature: quorum 2 not met.
    await expect(
      store.refresh({
        source: "configured",
        provided: signedIndex(F.index, [origin]),
      }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
    // Signatures over different bytes do not bind the index.
    const other = signedIndex(indexOf("2"), [origin, auditor]);
    await expect(
      store.refresh({
        source: "configured",
        provided: { index: F.index, signatures: other.signatures },
      }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });
});

describe("TV-GW-47 malformed extra signature", () => {
  it("two valid + one malformed signature fails the whole set", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    const good = signedIndex(F.index, [origin, auditor]);
    const malformed = {
      body: { v: "sunlight.statement/1" },
      hash: "sha256:" + "0".repeat(64),
      signature_hex: "f".repeat(128),
    };
    await expect(
      store.refresh({
        source: "configured",
        provided: {
          index: F.index,
          signatures: [...good.signatures, malformed],
        },
      }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
    // An unauthorized third root also fails — extras are never discarded.
    const stranger = makeKey(
      "9".repeat(64),
      9,
    );
    const mixed = signedIndex(F.index, [origin, auditor, stranger]);
    await expect(
      store.refresh({ source: "configured", provided: mixed }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });
});

describe("TV-GW-44 rollback protection", () => {
  it("rejects a lower revision with CATALOG_ROLLBACK; cache byte-identical", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    await store.refresh({
      source: "configured",
      provided: signedIndex(indexOf("16"), [origin, auditor]),
    });
    const cachedBefore = ports.cache!.raw;
    const highestBefore = ports.highest;
    await expect(
      store.refresh({
        source: "configured",
        provided: signedIndex(indexOf("15"), [origin, auditor]),
      }),
    ).rejects.toMatchObject({ code: "CATALOG_ROLLBACK" });
    expect(ports.cache!.raw).toBe(cachedBefore);
    expect(ports.highest).toEqual(highestBefore);
  });

  it("equal revision with a different digest retains equivocation", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    await store.refresh({
      source: "configured",
      provided: signedIndex(indexOf("7"), [origin, auditor]),
    });
    const equivocated = indexOf("7", { revocations: [] , issued_ms: now - 1000 });
    await expect(
      store.refresh({
        source: "configured",
        provided: signedIndex(equivocated, [origin, auditor]),
      }),
    ).rejects.toMatchObject({ code: "REVISION_CONFLICT" });
    expect(ports.equivocationLog).toHaveLength(1);
    expect(ports.equivocationLog[0]!.revision).toBe("7");
    // Both candidates retained: persisted current + recorded candidate.
    expect(ports.equivocationLog[0]!.current).toBe(ports.cache!.digest);
    expect(ports.equivocationLog[0]!.candidate).not.toBe(ports.cache!.digest);
  });
});

describe("channel trust", () => {
  it("an untrusted channel cannot switch stable → preview", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    await expect(
      store.refresh({
        source: "configured",
        provided: signedIndex(indexOf("2", { channel: "preview" }), [
          origin,
          auditor,
        ]),
      }),
    ).rejects.toMatchObject({ code: "POLICY_DENIED", field: "channel" });
    expect(ports.cache).toBeNull();
  });
});

describe("TV-GW-45 expired trust vs installed pins", () => {
  it("expired metadata blocks new unpinned installs; pins keep working", async () => {
    const ports = mkPorts();
    const store = new CatalogStore(ports);
    await store.refresh({
      source: "configured",
      provided: signedIndex(F.index, [origin, auditor]),
    });
    const service = createCatalogService(ports);
    // Pin the installed release under the pins CAS.
    const pinned = await service.pin({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
      expected_revision: ports.pinsRevision(),
    });
    expect(pinned.pin.slug).toBe("lexverdict");

    // Move past the index expiry: signed validity window has failed.
    ports.advance(F.index.expires_ms - now + 1);
    expect(store.freshness()).toBe("TRUST_EXPIRED");

    // New unpinned install → TRUST_EXPIRED.
    expect(() =>
      store.authorizeInstall({
        slug: "otherprod",
        version: "0.1.1",
        digest: "sha256:" + H("other"),
      }),
    ).toThrowError(expect.objectContaining({ code: "TRUST_EXPIRED" }));

    // The installed exact pin keeps working — flagged stale, not CURRENT.
    const auth = store.authorizeInstall({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
    });
    expect(auth.ok).toBe(true);
    expect(auth.pinned).toBe(true);
    expect(auth.stale).toBe(true);
  });
});

describe("TV-GW-46 strict + empty allowlist", () => {
  it("authorizes no installs", async () => {
    const ports = mkPorts({ strict: true, allowlist: [] });
    const store = new CatalogStore(ports);
    await store.refresh({
      source: "configured",
      provided: signedIndex(F.index, [origin, auditor]),
    });
    expect(() =>
      store.authorizeInstall({
        slug: "lexverdict",
        version: "0.1.0",
        digest: F.archiveDigest,
      }),
    ).toThrowError(expect.objectContaining({ code: "POLICY_DENIED" }));
  });
});

describe("offline snapshot", () => {
  it("OFFLINE_PINNED authorizes exact pins only, never CURRENT", async () => {
    const ports = mkPorts();
    ports.snapshot = signedIndex(F.index, [origin, auditor]);
    const service = createCatalogService(ports);
    const res = await service.refresh({ source: "configured", offline: true });
    expect(res.freshness).toBe("OFFLINE_PINNED");
    const store = new CatalogStore(ports);
    expect(store.freshness()).toBe("OFFLINE_PINNED");
    await expect(
      service.pin({
        slug: "lexverdict",
        version: "0.1.0",
        digest: F.archiveDigest,
        expected_revision: ports.pinsRevision(),
      }),
    ).resolves.toMatchObject({ pin: { slug: "lexverdict" } });
    const auth = store.authorizeInstall({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
    });
    expect(auth.pinned).toBe(true);
    // Unpinned install under an offline snapshot is denied.
    expect(() =>
      store.authorizeInstall({
        slug: "otherprod",
        version: "0.1.1",
        digest: "sha256:" + H("other"),
      }),
    ).toThrowError(expect.objectContaining({ code: "POLICY_DENIED" }));
  });
});

describe("catalog service §3.3 shapes", () => {
  it("refresh/search/show/pin/unpin", async () => {
    const ports = mkPorts();
    ports.fetchPayloads.set(
      "configured",
      signedIndex(F.index, [origin, auditor]),
    );
    const service = createCatalogService(ports);

    const refreshed = await service.refresh({ source: "configured" });
    expect(refreshed).toEqual({
      revision: "1",
      entries: 1,
      freshness: "CURRENT",
    });

    const page = await service.search({
      q: "lex",
      series: null,
      after: null,
      limit: 10,
    });
    expect(page.items).toHaveLength(1);
    expect(page.items[0]!.slug).toBe("lexverdict");
    expect(page.next).toBeNull();
    const filtered = await service.search({
      q: "",
      series: "vek",
      after: null,
      limit: 10,
    });
    expect(filtered.items).toHaveLength(0);

    const shown = await service.show({ slug: "lexverdict", version: "0.1.0" });
    expect(shown.entry.slug).toBe("lexverdict");
    expect(shown.entry.adapter_status).toBe("available");
    expect((shown.entry as { freshness?: string }).freshness).toBe("CURRENT");
    await expect(
      service.show({ slug: "lexverdict", version: "9.9.9" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });

    const rev0: Count = ports.pinsRevision();
    const pinRes = await service.pin({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
      expected_revision: rev0,
    });
    expect(pinRes.pin).toMatchObject({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
      index: "sha256:" + sha256Hex(canonicalJson(F.index)),
    });
    await expect(
      service.pin({
        slug: "lexverdict",
        version: "0.1.0",
        digest: F.archiveDigest,
        expected_revision: rev0,
      }),
    ).rejects.toMatchObject({ code: "REVISION_CONFLICT" });

    const unpin = await service.unpin({
      slug: "lexverdict",
      expected_revision: pinRes.revision,
    });
    expect(unpin.revision).toBe(
      (BigInt(pinRes.revision) + 1n).toString(),
    );
    expect(ports.pins()).toHaveLength(0);
  });

  it("rejects over-limit queries and bad series", async () => {
    const ports = mkPorts();
    const service = createCatalogService(ports);
    await expect(
      service.search({ q: "x".repeat(200), series: null, after: null, limit: 1 }),
    ).rejects.toMatchObject({ code: "SCHEMA_INVALID", field: "q" });
    await expect(
      service.search({
        q: "",
        series: "bogus" as never,
        after: null,
        limit: 1,
      }),
    ).rejects.toMatchObject({ code: "SCHEMA_INVALID", field: "series" });
  });
});

describe("catalogFresh", () => {
  const idx = { issued_ms: now - 1000, expires_ms: now + 60_000 };
  it("CURRENT within window, STALE past max_age, TRUST_EXPIRED at expiry", () => {
    expect(catalogFresh(idx, now, 604_800)).toBe("CURRENT");
    expect(catalogFresh(idx, now, 1)).toBe("STALE"); // issued 1s ago > 1s age
    expect(catalogFresh({ ...idx, issued_ms: now + 10_000 }, now, 604_800)).toBe(
      "TRUST_EXPIRED",
    );
    expect(catalogFresh(idx, now + 61_000, 604_800)).toBe("TRUST_EXPIRED");
  });
});
