/**
 * TV-GW SYNC / STORAGE conformance vectors — consolidated suite
 * (spec §13.2). One named test per vector id, each asserting the
 * vector's forbidden side effects — not merely its status/error code:
 *
 *  - TV-GW-29..33  outbox/disclosure: no records for unconsented
 *    streams, no secret values in exported bytes, immutable payloads,
 *    no resend of an ACKed batch, identical retry bytes, one logical
 *    import after a lost commit ACK, retained slot conflicts.
 *  - TV-GW-34      approval expiry at exact boundary; no native dispatch.
 *  - TV-GW-44..47  catalog rollback/expiry/strict/signature-set rules.
 *  - TV-GW-51/52   declared-size gate before decode/materialization;
 *    no inferred native lineage without a bound adapter.
 *  - TV-GW-53..56  resolver edge codes before allocation; E35 handoff
 *    mismatch evidence retained with no ACK; frozen golden chain.
 *  - TV-GW-57..62  §4.4 connector-family transcripts validate end to end
 *    with real REQUEST/1 proofs, ADAPTER_REQUIRED mesh state, and each
 *    family's forbidden-effect rule.
 *  - TV-GW-63/64   sync configure review binding + fail-on-sync-status;
 *    personal/CIS receipt denial before any object or digest export.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Buffer } from "node:buffer";

import { describe, expect, test, vi } from "vitest";

import {
  F,
  H,
  J,
  adapterSource,
  artifact,
  auditor,
  blob,
  collectPeerTranscript,
  makeKey,
  native,
  now,
  observation,
  origin,
  ref,
  schema,
  sunlight,
  tar,
} from "@latticeag/testkit";
import type { FixtureKey } from "@latticeag/testkit";

import { RpcError } from "../protocol/errors.js";
import type { Count, Hash, JsonObject, NativeRef } from "../protocol/refs.js";
import type { CatalogIndex } from "../protocol/catalog.js";
import { catalogFresh } from "../protocol/catalog.js";
import type { Dependency, ProductManifest, Release } from "../protocol/product.js";
import type { OutboxItem, StreamName } from "../protocol/sync.js";
import { STREAMS } from "../protocol/sync.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";

import { OutboxEngine } from "../sync/outbox.js";
import type { EnqueueArgs } from "../sync/outbox.js";
import {
  createMemorySyncPorts,
  streamConsent,
} from "../sync/ports.js";
import type { MemorySyncPorts } from "../sync/ports.js";
import {
  DISCLOSURE_SCHEMA,
  WITHHELD,
  projectForStream,
} from "../sync/disclosure.js";
import {
  MemoryProofDestination,
  MemoryVekInbox,
  createMemorySink,
  createProofImportSink,
  createVekInboxSink,
} from "../sync/sinks.js";
import {
  createSyncService,
  makeReviewValidator,
  reviewBindingHash,
} from "../sync/service.js";
import type { SyncServicePorts } from "../sync/service.js";

import { ApprovalManager } from "../approvals/approvals.js";
import { createMemoryApprovalPorts } from "../approvals/ports.js";

import { CatalogStore } from "../catalog/index.js";
import { createCatalogService } from "../catalog/service.js";
import { createMemoryCatalogPorts } from "../catalog/ports.js";
import type {
  CatalogTrustView,
  IndexFetch,
  MemoryCatalogPorts,
} from "../catalog/ports.js";

import { createObjectService } from "../platform/objects.js";
import { createMemoryPlatformPorts } from "../platform/testing.js";
import type { MemoryPlatformPorts } from "../platform/testing.js";
import { createPlatformServices } from "../platform/index.js";
import type { PlatformServices } from "../platform/index.js";

import {
  DependencyConflictError,
  edgeDisposition,
  resolvePlan,
} from "../lifecycle/resolve.js";
import { createProductService } from "../lifecycle/service.js";
import { StubAdapterChild } from "../lifecycle/testing.js";
import type { StubScript } from "../lifecycle/testing.js";
import {
  checkSunlightHandoff,
  VISLINEAGE_BUNDLE_FORMAT,
} from "../lifecycle/handoff.js";
import type { HandoffMismatch } from "../lifecycle/handoff.js";
import {
  dep,
  fixturePorts,
  fixtureTrust,
  manifestPatched,
  REVIEW,
} from "../lifecycle/testbed.js";
import { verifyRelease } from "../lifecycle/verify.js";

import {
  CONNECTOR_FAMILIES,
  CONNECTOR_FAMILY_NAMES,
  familyAssertions,
  peerTranscriptValidation,
  type ConnectorFamilyName,
} from "../peers/families.js";

const THROUGH = F.cursor as string; // "c0000000000000001:7"

function srcRef(objectId: string, commitment: string | null = null): NativeRef {
  return {
    profile: "fixture.event/1",
    namespace: "fixture",
    object_id: objectId,
    commitment,
    raw_sha256: H(`fixture/${objectId}/${commitment ?? ""}`),
    bytes: "10",
  };
}

function args(
  overrides: Partial<EnqueueArgs> & { stream: StreamName },
): EnqueueArgs {
  return {
    source: srcRef(overrides.source?.object_id ?? "evt1"),
    envelope: { kind: "fixture", n: 1 },
    through: THROUGH,
    ...overrides,
  };
}

function payloadOf(ports: MemorySyncPorts, item: OutboxItem): string {
  const bytes = ports.objects.get(item.payload.digest);
  expect(bytes).toBeTypeOf("string");
  return bytes!;
}

// ── approvals helpers ────────────────────────────────────────────────────

function approvalParams(expiresMs: number): {
  action: NativeRef;
  target: string;
  expires_ms: number;
  native: { digest: string; bytes: string; media: "application/json" };
} {
  return {
    action: F.nativeRef as NativeRef,
    target: "product1",
    expires_ms: expiresMs,
    native: F.intent.ref,
  };
}

// ── catalog helpers (same shape as the catalog vector harness) ───────────

const thirdKey = makeKey(
  "3a7bd2f1c9e4a806d5b194e0f7c2a391b8d4e6f0a1c3b5d7e9f0a2c4b6d8e0f1a3",
  3,
);
const roots = new Map<string, string>([
  [origin.sunlight, origin.material.public],
  [auditor.sunlight, auditor.material.public],
  [thirdKey.sunlight, thirdKey.material.public],
]);

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

function indexOf(
  revision: string,
  overrides: Record<string, unknown> = {},
): CatalogIndex {
  return {
    ...(F.index as CatalogIndex),
    revision,
    ...overrides,
  } as CatalogIndex;
}

function mkCatalogPorts(
  trust: Partial<CatalogTrustView> = {},
): MemoryCatalogPorts {
  return createMemoryCatalogPorts({
    now,
    trust: { roots, quorum: 2, channel: "stable", ...trust },
  });
}

const MALFORMED_STATEMENT = {
  body: { v: "sunlight.statement/1" },
  hash: "sha256:" + "0".repeat(64),
  signature_hex: "f".repeat(128),
};

// ── platform helpers (objects/lineage vectors) ───────────────────────────

const OPERATOR_CTX = {
  principal: { id: "operator1", role: "local_operator" as const },
};

function seededPlatform(opts: Parameters<typeof createMemoryPlatformPorts>[0] = {}): {
  ports: MemoryPlatformPorts;
  svc: PlatformServices;
} {
  const ports = createMemoryPlatformPorts({
    now,
    workspace: "ws1",
    instance: "gw1",
    auditKey: auditor.secret,
    ...opts,
  });
  ports.store.seedSource({
    source: "src1",
    key_id: origin.material.id,
    public: origin.material.public,
    owner: "operator1",
  });
  ports.store.seedConfig(F.config2, "1");
  return { ports, svc: createPlatformServices(ports, OPERATOR_CTX) };
}

async function publishAllFixtureEvents(svc: PlatformServices): Promise<void> {
  for (let i = 0; i < F.events.length; i += 1) {
    await svc.events.publish({
      profile: "proof-evidence/1",
      topic: "telemetry",
      producer: "src1",
      seq: String(i + 1),
      record: blob(J(F.events[i])),
    });
  }
}

// ── lifecycle helpers (edge vectors) ─────────────────────────────────────

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

/** A complete signed fixture release with dependency/emit knobs. */
function buildRelease(
  opts: {
    version?: string;
    slug?: string;
    builder?: string;
    dependencies?: Dependency[];
    emit?: string[];
    extraSignatures?: unknown[];
  } = {},
): typeof F.release1 {
  const version = opts.version ?? "0.1.0";
  const slug = opts.slug ?? "lexverdict";
  const builder = opts.builder ?? "fixture-builder";
  const files = {
    "package/package.json": J({
      name: `@latticeag/fixture-${slug}`,
      version,
      type: "module",
      license: "MIT",
    }),
    "package/adapter.mjs": adapterSource,
    "package/config.schema.json": Buffer.from(schema.content, "base64url"),
    "package/gateway-adapter.json": J({
      contract: "gateway-adapter/1",
      entry: "adapter.mjs",
      config_schema: "config.schema.json",
    }),
  };
  const archive = tar(files);
  const ar = artifact(archive);
  const lockfile = artifact("lockfileVersion: '9.0'\nimporters: {}\n");
  const sbom = blob(
    J({
      schema: "gateway.sbom/1",
      packages: [
        {
          name: `@latticeag/fixture-${slug}`,
          version,
          license: "MIT",
          archive: ar.digest,
        },
      ],
    }),
  );
  const provenance = blob(
    J({
      schema: "gateway.build/1",
      builder,
      repository: "LatticeAG/latticeag-gateway",
      commit: "1".repeat(40),
      command: "pnpm build",
      materials: [lockfile],
      sbom: sbom.ref,
      outputs: [ar],
    }),
  );
  const ps = [sunlight(provenance, origin, 21), sunlight(provenance, auditor, 22)];
  const base = F.release1.manifest as ProductManifest;
  const manifest: ProductManifest = {
    ...base,
    slug,
    version,
    package: {
      ...base.package,
      name: `@latticeag/fixture-${slug}`,
      archive: ar as ProductManifest["package"]["archive"],
    },
    provenance: {
      ...base.provenance,
      descriptor: provenance.ref as ProductManifest["provenance"]["descriptor"],
      statements: ps.map(native),
      builder,
      lockfile: lockfile as ProductManifest["provenance"]["lockfile"],
      sbom: sbom.ref as ProductManifest["provenance"]["sbom"],
    },
    dependencies: opts.dependencies ?? [],
    capabilities: {
      ...base.capabilities,
      emit: opts.emit ?? base.capabilities.emit,
    },
  };
  const m = blob(J(manifest));
  const signatures = [
    sunlight(m, origin, 23),
    sunlight(m, auditor, 24),
    ...(opts.extraSignatures ?? []),
  ];
  return {
    archive,
    files,
    sbom,
    manifest,
    wire: {
      manifest: m,
      signatures,
      provenance,
      provenance_signatures: ps,
    },
  };
}

function installInput(
  manifest: ProductManifest,
  extra: Record<string, unknown> = {},
): Parameters<typeof resolvePlan>[0] {
  return {
    kind: "install",
    source: "lexverdict",
    version: "0.1.0",
    target: {
      manifest,
      manifestDigest: H(J(manifest)) as Hash,
    },
    manifests: new Map<string, ProductManifest[]>([
      ["lexverdict", [manifest]],
    ]),
    index: null,
    installed: [],
    opts: { now },
    ...extra,
  } as Parameters<typeof resolvePlan>[0];
}

async function expectCode(fn: () => Promise<unknown> | unknown, code: string) {
  try {
    await fn();
  } catch (e) {
    expect(e).toMatchObject({ code });
    return e;
  }
  expect.unreachable(`expected ${code}`);
}

// ═════════════════════════════════════════════════════════════════════════
// SYNC vectors
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-29: receipts-only metadata export — zero records on unconsented streams, no secret value in exported bytes, signed original untouched", async () => {
  const ports = createMemorySyncPorts();
  const sink = createMemorySink();
  ports.sinks.set("proof-native-import", sink);
  ports.consents.set(
    "receipts",
    streamConsent({ destination: "proof-native-import" }),
  );
  const engine = new OutboxEngine(ports);

  // Forbidden side effect: records for streams that were never consented.
  for (const stream of ["runs", "approvals", "lineage", "watch", "mesh"] as const) {
    expect(engine.enqueue(args({ stream }))).toBeNull();
  }
  expect(ports.items.size).toBe(0);

  const envelope = {
    kind: "receipt",
    action: "action1",
    authorization: "secret-value",
    nested: { Api_Key: "ak-secret-value-2", note: "ok" },
    detail: "proxy-authorization: secret-value",
    list: [{ password: "pw-secret-value-3" }],
  };
  const before = structuredClone(envelope);
  const objectBody = { secret_key: "obj-secret-value-9" };
  const objectDigest = sha256Hex(J(objectBody));
  const objects = { [objectDigest]: objectBody };

  // Projection level (metadata profile): secret keys redacted at every
  // depth, the object body is never exported, and the withheld inventory
  // marks the digest WITHOUT exposing its content.
  const projection = projectForStream(
    "receipts",
    {
      source: srcRef("receipt1"),
      envelope,
      signed: true,
      objects,
      consent: { existence: true, hashes: true, ids: true },
    },
    "metadata",
  );
  expect(projection.ok).toBe(true);
  if (projection.ok) {
    expect(projection.export.schema).toBe(DISCLOSURE_SCHEMA);
    expect(projection.export.objects).toEqual({});
    expect(projection.export.withheld).toEqual([
      { digest: objectDigest, availability: WITHHELD },
    ]);
    const body = JSON.stringify(projection.export.body);
    expect(body).not.toContain("secret-value");
    expect(body).not.toContain("pw-secret-value-3");
    expect(body).toContain("[REDACTED]");
    const whole = JSON.stringify(projection.export);
    expect(whole).not.toContain("secret-value");
    expect(whole).not.toContain("obj-secret-value-9");
  }

  // Engine level: the persisted immutable payload carries the same
  // sanitized projection; the wire sends exactly that.
  const item = engine.enqueue(
    args({ stream: "receipts", envelope, objects, signed: true }),
  )!;
  const bytes = payloadOf(ports, item);
  expect(bytes).not.toContain("secret-value");
  expect(bytes).not.toContain("obj-secret-value-9");
  expect(bytes).toContain(WITHHELD);

  const res = await engine.flush(["receipts"], 60_000);
  expect(res.pending).toBe(0);
  expect(item.state).toBe("ACKED");
  expect(sink.attempts).toHaveLength(1);
  const wire = sink.sent[0]!.items[0]!;
  expect(ports.objects.get(wire.payload.digest)).toBe(bytes);
  // Forbidden side effect: the signed source envelope was edited in
  // place — assert it is byte-for-byte untouched.
  expect(envelope).toEqual(before);
});

test("TV-GW-30: immutable outbox retry — ACKed batch never resent; timed-out batch retries with identical hash/cursor; remote logical count two", async () => {
  const ports = createMemorySyncPorts();
  const sink = createMemorySink();
  ports.sinks.set("vekinbox-compatible", sink);
  ports.consents.set(
    "approvals",
    streamConsent({ destination: "vekinbox-compatible" }),
  );
  const engine = new OutboxEngine(ports);

  const a = engine.enqueue(
    args({ stream: "approvals", source: srcRef("cardA", H("a")) }),
  )!;
  await engine.flush(["approvals"], 60_000);
  expect(a.state).toBe("ACKED");
  expect(sink.attempts).toHaveLength(1);
  const firstHash = sink.attempts[0]!.hash;
  const firstThrough = sink.attempts[0]!.through;

  sink.failWith.push("timeout");
  const b = engine.enqueue(
    args({
      stream: "approvals",
      source: srcRef("cardB", H("b")),
      through: "c0000000000000001:9",
    }),
  )!;
  const res = await engine.flush(["approvals"], 120_000);
  expect(res.pending).toBe(0);
  expect(b.state).toBe("ACKED");

  // Three attempts: batch1 ACK, batch2 timeout, batch2 retry — and the
  // remote saw exactly two logical deliveries.
  expect(sink.attempts).toHaveLength(3);
  expect(sink.sent).toHaveLength(2);
  const [first, timedOut, retried] = sink.attempts;
  expect(first!.hash).toBe(firstHash);
  expect(retried!.hash).toBe(timedOut!.hash);
  expect(retried!.through).toBe(timedOut!.through);
  expect(retried!.through).toBe("c0000000000000001:9");
  // Identical member payload bytes (immutable) on retry.
  expect(retried!.items.map((i) => i.payload.digest)).toEqual(
    timedOut!.items.map((i) => i.payload.digest),
  );
  // Forbidden side effect: the ACKed batch-1 item was never a member of
  // any later send.
  expect(timedOut!.items.map((i) => i.id)).toEqual([b.id]);
  expect(retried!.items.map((i) => i.id)).toEqual([b.id]);
  expect(first!.items.map((i) => i.id)).toEqual([a.id]);
});

test("TV-GW-31: lost import.commit ACK — sender restart resolves the SAME stage via import.get; remote event count unchanged; no second logical import", async () => {
  const ports = createMemorySyncPorts();
  const dest = new MemoryProofDestination();
  dest.dropAcks = true; // durable commit, lost ACK
  ports.sinks.set("proof-native-import", createProofImportSink(dest));
  ports.consents.set(
    "receipts",
    streamConsent({ destination: "proof-native-import" }),
  );
  const engine = new OutboxEngine(ports);

  const item = engine.enqueue(args({ stream: "receipts" }))!;
  const res = await engine.flush(["receipts"], 120_000);
  expect(res.pending).toBe(0);
  expect(item.state).toBe("ACKED");

  // Exactly one stage exists; the durable commit was applied once; the
  // recovery path queried it (import.get) instead of restaging.
  expect(dest.stages.size).toBe(1);
  expect(dest.commits).toBe(1);
  expect(item.remote_stage).toBe("stage1");
  // Forbidden side effect: remote logical event count is exactly the one
  // imported item — no second logical import, no duplicate event.
  expect(dest.imported).toHaveLength(1);
});

test("TV-GW-32: two valid signatures bind different bodies to one slot — both retained, CONFLICTED, zero authority, no timestamp winner", async () => {
  const ports = createMemorySyncPorts();
  const dest = new MemoryProofDestination();
  ports.sinks.set("proof-native-import", createProofImportSink(dest));
  ports.consents.set(
    "receipts",
    streamConsent({ destination: "proof-native-import" }),
  );
  const engine = new OutboxEngine(ports);

  // Same (namespace, object_id) slot, different signed bodies.
  const a = engine.enqueue(
    args({ stream: "receipts", source: srcRef("slotX", H("body-a")) }),
  )!;
  const b = engine.enqueue(
    args({ stream: "receipts", source: srcRef("slotX", H("body-b")) }),
  )!;
  expect(a.id).not.toBe(b.id);
  await engine.flush(["receipts"], 120_000);

  const slot = "fixture/slotX";
  const candidates = dest.slots.candidates(slot);
  // Both candidates retained in arrival order; slot is CONFLICTED.
  expect(candidates).toHaveLength(2);
  expect(candidates.map((c) => c.hash)).toEqual([H("body-a"), H("body-b")]);
  expect(dest.slots.isConflicted(slot)).toBe(true);
  // Forbidden side effects: no last-write-wins winner — the second
  // candidate never overwrote the first (imported holds only the first
  // ACCEPTED admission), and neither outbox item claims a clean cut.
  expect(dest.imported).toHaveLength(1);
  expect(a.state).toBe("BLOCKED");
  expect(b.state).toBe("BLOCKED");
  expect(engine.blockedCodeOf(a.id)).toBe("OBJECT_CONFLICT");
  expect(engine.blockedCodeOf(b.id)).toBe("OBJECT_CONFLICT");
});

test("TV-GW-33: local deny commits at revision 2; remote/local approve expecting revision 1 → REVISION_CONFLICT; no resurrection or native execution", async () => {
  const ports = createMemoryApprovalPorts({ now });
  const manager = new ApprovalManager(ports);

  const rec = manager.request(approvalParams(now + 300_000));
  expect(rec.revision).toBe("1");
  expect(rec.state).toBe("PENDING");

  // Local deny at revision 1 commits → revision 2 DENIED is retained.
  const denied = manager.decide(
    {
      approval: rec.approval,
      expected_revision: "1",
      action: F.nativeRef as NativeRef,
      decision: "deny",
      reason: "scope_not_approved",
    },
    { id: "operator1", role: "local_operator", reviewer: true },
  );
  expect(denied.state).toBe("DENIED");
  expect(denied.revision).toBe("2");

  // A remote/other approve expecting revision 1 conflicts — never merges.
  await expectCode(
    () =>
      manager.decide(
        {
          approval: rec.approval,
          expected_revision: "1",
          action: F.nativeRef as NativeRef,
          decision: "approve",
          reason: "late remote approve",
        },
        { id: "peer1", role: "agent", reviewer: true },
      ),
    "REVISION_CONFLICT",
  );
  const after = ports.approvals.get(rec.approval)!;
  // Forbidden side effects: denied row was not resurrected, no native
  // dispatch, no authority was conferred, decision metadata kept "deny".
  expect(after.state).toBe("DENIED");
  expect(after.revision).toBe("2");
  expect(after.decision).toBe("deny");
  expect(after.native_status).toBe("NOT_DISPATCHED");
  expect(after.authority).toBe("NONE");
  expect(after.decided_ms).toBe(denied.decided_ms);

  // The VekInbox-compatible remote write path obeys the same CAS: a card
  // upsert at a stale expected revision conflicts instead of overwriting.
  const syncPorts = createMemorySyncPorts();
  const inbox = new MemoryVekInbox();
  syncPorts.sinks.set("vekinbox-compatible", createVekInboxSink(inbox));
  syncPorts.consents.set(
    "approvals",
    streamConsent({ destination: "vekinbox-compatible" }),
  );
  const engine = new OutboxEngine(syncPorts);
  const deny = engine.enqueue(
    args({
      stream: "approvals",
      source: srcRef("card1", H("deny")),
      envelope: { card_id: "card1", action: "deny" },
    }),
  )!;
  await engine.flush(["approvals"], 60_000);
  expect(deny.state).toBe("ACKED");
  expect(inbox.cards.get("card1")?.revision).toBe(1n);

  const approve = engine.enqueue(
    args({
      stream: "approvals",
      source: srcRef("card1", H("approve")),
      envelope: { card_id: "card1", action: "approve" },
    }),
  )!;
  await engine.flush(["approvals"], 120_000);
  expect(approve.state).toBe("BLOCKED");
  expect(engine.blockedCodeOf(approve.id)).toBe("REVISION_CONFLICT");
  // Deny revision retained remote-side; the card body is still the deny
  // item's payload ref — the conflicting approve never overwrote it.
  expect(inbox.cards.get("card1")?.revision).toBe(1n);
  expect(inbox.cards.get("card1")?.body).toEqual(deny.payload);
});

test("TV-GW-34: approval exactly at expires_ms → APPROVAL_EXPIRED; no native dispatch, no decision recorded", () => {
  const boundary = now + 60_000;
  const ports = createMemoryApprovalPorts({ now });
  const manager = new ApprovalManager(ports);

  const rec = manager.request(approvalParams(boundary));
  expect(rec.state).toBe("PENDING");

  // One millisecond before the boundary a decision still commits —
  // equality is the exact expiry edge (P10).
  const second = manager.request(approvalParams(boundary));
  ports.advance(60_000 - 1);
  const early = manager.decide(
    {
      approval: second.approval,
      expected_revision: "1",
      action: F.nativeRef as NativeRef,
      decision: "approve",
      reason: "just inside the window",
    },
    { id: "operator1", role: "local_operator", reviewer: true },
  );
  expect(early.state).toBe("APPROVED");

  // At exactly expires_ms the first approval is EXPIRED on read and any
  // decide is APPROVAL_EXPIRED — nothing dispatches.
  ports.advance(1); // now === expires_ms
  expectCode(
    () =>
      manager.decide(
        {
          approval: rec.approval,
          expected_revision: "1",
          action: F.nativeRef as NativeRef,
          decision: "approve",
          reason: "at the boundary",
        },
        { id: "operator1", role: "local_operator", reviewer: true },
      ),
    "APPROVAL_EXPIRED",
  );
  const stored = ports.approvals.get(rec.approval)!;
  expect(stored.state).toBe("EXPIRED");
  // Forbidden side effects: no decision, no reviewer, no native dispatch,
  // no authority — and the CAS revision never moved.
  expect(stored.decision).toBeNull();
  expect(stored.reviewer).toBeNull();
  expect(stored.decided_ms).toBeNull();
  expect(stored.revision).toBe("1");
  expect(stored.native_status).toBe("NOT_DISPATCHED");
  expect(stored.authority).toBe("NONE");

  // Past the boundary nothing resurrects it.
  ports.advance(60_000);
  expectCode(
    () =>
      manager.decide(
        {
          approval: rec.approval,
          expected_revision: "1",
          action: F.nativeRef as NativeRef,
          decision: "deny",
          reason: "far too late",
        },
        { id: "operator1", role: "local_operator", reviewer: true },
      ),
    "APPROVAL_EXPIRED",
  );
});

// ═════════════════════════════════════════════════════════════════════════
// CATALOG vectors
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-44: refresh below the cached revision → CATALOG_ROLLBACK; verified cache byte-identical, high-water unmoved", async () => {
  const ports = mkCatalogPorts();
  const store = new CatalogStore(ports);
  await store.refresh({
    source: "configured",
    provided: signedIndex(indexOf("16"), [origin, auditor]),
  });
  const cachedRaw = ports.cache!.raw;
  const cachedDigest = ports.cache!.digest;
  const cachedSigs = ports.cache!.signatures;
  const highestBefore = ports.highest;

  await expectCode(
    () =>
      store.refresh({
        source: "configured",
        provided: signedIndex(indexOf("15"), [origin, auditor]),
      }),
    "CATALOG_ROLLBACK",
  );

  // Forbidden side effects: the last verified cache is not replaced,
  // re-signed, or partially overwritten; the highest-seen mark stays.
  expect(ports.cache!.raw).toBe(cachedRaw);
  expect(ports.cache!.digest).toBe(cachedDigest);
  expect(ports.cache!.signatures).toBe(cachedSigs);
  expect(ports.cache!.index.revision).toBe("16");
  expect(ports.highest).toEqual(highestBefore);
  expect(ports.highest!.revision).toBe("16");
  // A strictly-lower candidate is rollback, not equivocation.
  expect(ports.equivocationLog).toHaveLength(0);
  // The cache still serves the retained revision.
  expect(store.freshness()).toBe("CURRENT");
});

test("TV-GW-45: index at exactly expires_ms — new unpinned installs blocked TRUST_EXPIRED; exact pinned digest installs continue, marked stale", async () => {
  const ports = mkCatalogPorts();
  const store = new CatalogStore(ports);
  // An index issued now and expiring 60s out keeps the expiry boundary
  // INSIDE the max-age freshness window, isolating the `>=` edge.
  const boundaryIndex = indexOf("2", {
    issued_ms: now,
    expires_ms: now + 60_000,
  });
  await store.refresh({
    source: "configured",
    provided: signedIndex(boundaryIndex, [origin, auditor]),
  });
  const cservice = createCatalogService(ports);
  await cservice.pin({
    slug: "lexverdict",
    version: "0.1.0",
    digest: F.archiveDigest,
    expected_revision: ports.pinsRevision(),
  });

  // The boundary is `now >= expires_ms` — one ms before stays CURRENT.
  ports.advance(60_000 - 1);
  expect(store.freshness()).toBe("CURRENT");
  ports.advance(1); // exactly at expires_ms
  expect(
    catalogFresh(boundaryIndex as CatalogIndex, boundaryIndex.expires_ms, 604_800),
  ).toBe("TRUST_EXPIRED");
  expect(store.freshness()).toBe("TRUST_EXPIRED"); // UI-visible stale flag

  // Forbidden side effect: a NEW unpinned install is authorized anyway.
  expectCode(
    () =>
      store.authorizeInstall({
        slug: "otherprod",
        version: "0.1.1",
        digest: `sha256:${H("otherprod")}`,
      }),
    "TRUST_EXPIRED",
  );
  // The exact pinned digest still installs — flagged stale.
  expect(
    store.authorizeInstall({
      slug: "lexverdict",
      version: "0.1.0",
      digest: F.archiveDigest,
    }),
  ).toEqual({ ok: true, pinned: true, freshness: "TRUST_EXPIRED", stale: true });

  // The resolver carries the same contract: unpinned at boundary throws
  // TRUST_EXPIRED before any dependency work; pinned proceeds.
  const manifest = manifestPatched(F.release1, {});
  await expectCode(
    () =>
      resolvePlan({
        ...installInput(manifest),
        index: boundaryIndex as CatalogIndex,
        opts: { now: boundaryIndex.expires_ms },
      }),
    "TRUST_EXPIRED",
  );
  const pinnedPlan = resolvePlan({
    ...installInput(manifest),
    index: boundaryIndex as CatalogIndex,
    opts: { now: boundaryIndex.expires_ms, pinned: true },
  });
  expect(pinnedPlan.summary.slug).toBe("lexverdict");
});

test("TV-GW-46: catalog.strict=true with an empty allowlist authorizes zero new installs — even a validly signed pinned release", async () => {
  const ports = mkCatalogPorts({ strict: true, allowlist: [] });
  const store = new CatalogStore(ports);
  await store.refresh({
    source: "configured",
    provided: signedIndex(F.index, [origin, auditor]),
  });
  const cservice = createCatalogService(ports);
  await cservice.pin({
    slug: "lexverdict",
    version: "0.1.0",
    digest: F.archiveDigest,
    expected_revision: ports.pinsRevision(),
  });
  // Exact pin present; still authorizes nothing under strict+empty.
  expectCode(
    () =>
      store.authorizeInstall({
        slug: "lexverdict",
        version: "0.1.0",
        digest: F.archiveDigest,
      }),
    "POLICY_DENIED",
  );

  // The same policy reaches the lifecycle resolver before any effect.
  const lports = fixturePorts({
    spawnAdapter: stubSpawn,
    policy: { strict: true, allowlist: [] },
  });
  const svc = createProductService(lports, { engine: { liveProbes: false } });
  try {
    await expectCode(
      () =>
        svc.product.plan({
          kind: "install",
          source: "lexverdict",
          version: "0.1.0",
        }),
      "POLICY_DENIED",
    );
    // Forbidden side effects: no generation row, no journal, no spawn,
    // no emitted event — plan() refused before allocation.
    expect(lports.productRegistry.all()).toHaveLength(0);
    expect(lports.journalLog).toHaveLength(0);
    expect(lports.spawned).toHaveLength(0);
    expect(lports.events).toHaveLength(0);
  } finally {
    await svc.engine.close();
    lports.cleanup();
  }
});

test("TV-GW-47: malformed or unauthorized extra signature invalidates the whole set — release AND index; zero install effects", async () => {
  // Release wire: two valid + one malformed → the set fails; the extra
  // is never discarded to reach quorum.
  const wire = structuredClone(F.release1.wire) as Release;
  wire.signatures.push(MALFORMED_STATEMENT as never);
  const env = {
    archive: F.release1.archive,
    os: process.platform === "darwin" ? ("darwin" as const) : ("linux" as const),
    arch: process.arch === "arm64" ? ("arm64" as const) : ("x64" as const),
    node: `v${process.versions.node}`,
    now,
    indexExpiresMs: F.index.expires_ms,
  };
  expectCode(() => verifyRelease(wire, fixtureTrust(), env), "SIGNATURE_INVALID");

  // An unauthorized third signer's well-formed statement also fails.
  const stranger = makeKey("9".repeat(64), 9);
  const wire2 = structuredClone(F.release1.wire) as Release;
  wire2.signatures.push(sunlight(blob(J(wire2.manifest)), stranger, 99) as never);
  expectCode(() => verifyRelease(wire2, fixtureTrust(), env), "SIGNATURE_INVALID");

  // Index refresh with the same malformed extra → SIGNATURE_INVALID and
  // nothing persists.
  const ports = mkCatalogPorts();
  const store = new CatalogStore(ports);
  const good = signedIndex(F.index, [origin, auditor]);
  await expectCode(
    () =>
      store.refresh({
        source: "configured",
        provided: {
          index: F.index,
          signatures: [...good.signatures, MALFORMED_STATEMENT],
        },
      }),
    "SIGNATURE_INVALID",
  );
  expect(ports.cache).toBeNull();
  expect(ports.highest).toBeNull();
  expect(ports.equivocationLog).toHaveLength(0);

  // Engine level: the malformed-set release cannot reach READY; no
  // process is spawned and no active row exists.
  const lports = fixturePorts({ spawnAdapter: stubSpawn });
  lports.putRelease(wire, F.release1.archive);
  const svc = createProductService(lports, { engine: { liveProbes: false } });
  try {
    const { plan } = await svc.product.plan({
      kind: "install",
      source: "lexverdict",
      version: "0.1.0",
    });
    const acc = await svc.product.install({ plan, review: REVIEW });
    const op = await svc.waitOperation(acc.operation);
    expect(op.error?.code).toBe("SIGNATURE_INVALID");
    expect(lports.spawned).toHaveLength(0);
    expect(lports.productRegistry.active("lexverdict")).toBeUndefined();
  } finally {
    await svc.engine.close();
    lports.cleanup();
  }
});

// ═════════════════════════════════════════════════════════════════════════
// STORAGE / OBJECT / LINEAGE vectors
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-51: declared object size over the 1 MiB cap is rejected before decoding or materializing content", async () => {
  const ports = createMemoryPlatformPorts();
  const objects = createObjectService(ports);
  const putSpy = vi.spyOn(ports.store, "putObject");
  const getSpy = vi.spyOn(ports.store, "getObject");
  const oversized = {
    digest: "0".repeat(64),
    bytes: "1048577", // 1 MiB + 1
    media: "application/octet-stream" as const,
  };
  // Deliberately malformed content proves the declared-size gate fires
  // BEFORE base64url decode — OBJECT_LIMIT wins over SCHEMA_INVALID.
  await expect(
    objects.put({
      action: F.nativeRef,
      blob: { ref: oversized, content: "!!not-base64url!!" },
    }),
  ).rejects.toMatchObject({ code: "OBJECT_LIMIT", field: "blob.ref.bytes" });
  // Forbidden side effects: no allocation, no store mutation, no import,
  // and the guard precedes action resolution (unknown action too).
  expect(putSpy).not.toHaveBeenCalled();
  expect(getSpy).not.toHaveBeenCalled();
  expect(ports.store.objects.size).toBe(0);
  await expect(
    objects.put({
      action: { object_id: "never-committed" } as never,
      blob: { ref: oversized, content: "AA" },
    }),
  ).rejects.toMatchObject({ code: "OBJECT_LIMIT" });
  expect(putSpy).not.toHaveBeenCalled();

  // And content that decodes over the cap is still rejected at the same
  // boundary (defense in depth), again with no store mutation.
  const overCap = Buffer.alloc(1_048_577, 0x41);
  await expect(
    objects.put({
      action: F.nativeRef,
      blob: {
        ref: {
          digest: sha256Hex(overCap),
          bytes: "1048576", // declared under cap, content over
          media: "application/octet-stream",
        },
        content: overCap.toString("base64url"),
      },
    }),
  ).rejects.toMatchObject({ code: "OBJECT_LIMIT" });
  expect(ports.store.objects.size).toBe(0);
});

test("TV-GW-52: no native lineage adapter → native_assessment NOT_EVALUATED with the adapter gap; zero inferred authority", async () => {
  const { svc, ports } = seededPlatform(); // nativeLineageBound defaults false
  await publishAllFixtureEvents(svc);
  await ports.store.putObject(
    Buffer.from(observation.content, "base64url"),
    1_048_576,
  );

  const result = await svc.lineage.query({
    action: F.pointer as never,
    max_nodes: 64,
    max_depth: 16,
  });
  // The action node is returned but NOTHING is inferred: no fabricated
  // edges, the adapter gap is reported, and the assessment is the honest
  // NOT_EVALUATED — never a synthesized native verdict.
  expect(result).toEqual({
    nodes: [F.pointer],
    edges: [],
    gaps: ["CAP_ADAPTER_UNAVAILABLE"],
    native_assessment: "NOT_EVALUATED",
  });
  expect(result.native_assessment).toBe("NOT_EVALUATED");
  // Forbidden side effect: no authority field or inferred verdict is
  // attached to the result.
  expect(Object.keys(result).sort()).toEqual(
    ["edges", "gaps", "native_assessment", "nodes"].sort(),
  );
});

// ═════════════════════════════════════════════════════════════════════════
// LIFECYCLE EDGE + HANDOFF + FIXTURE vectors
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-53: required E17 Charter→Mint edge → UNSUPPORTED_COMPOSITION before allocation; no synthesized authority/precedent root", async () => {
  // The §5.3 edge table marks E17 required-blocking with this code.
  expect(edgeDisposition("E17")).toMatchObject({
    code: "UNSUPPORTED_COMPOSITION",
    blocksRequired: true,
  });
  const manifest = manifestPatched(F.release1, {
    dependencies: [
      { ...dep("charter", "1.0.0", "required", "E17"), capability: "precedent" },
    ],
  });
  // Pure resolver: throws before any plan/dependency is produced.
  await expectCode(() => resolvePlan(installInput(manifest)), "UNSUPPORTED_COMPOSITION");

  // Service level: plan() refuses; nothing is allocated, spawned, or
  // journaled, and no authority/precedent artifacts exist anywhere.
  const rel = buildRelease({
    dependencies: [
      { ...dep("charter", "1.0.0", "required", "E17"), capability: "precedent" },
    ],
  });
  const ports = fixturePorts({ spawnAdapter: stubSpawn });
  ports.putRelease(rel.wire as Release, rel.archive);
  const svc = createProductService(ports, { engine: { liveProbes: false } });
  try {
    await expectCode(
      () => svc.product.plan({ kind: "install", source: "lexverdict", version: "0.1.0" }),
      "UNSUPPORTED_COMPOSITION",
    );
    expect(ports.spawned).toHaveLength(0);
    expect(ports.productRegistry.all()).toHaveLength(0);
    expect(ports.journalLog).toHaveLength(0);
    expect(ports.events).toHaveLength(0);
    const observable = JSON.stringify({
      events: ports.events,
      journal: ports.journalLog,
      plans: [...svc.plans.values()],
    });
    // Forbidden side effect: synthesized Charter/Mint authority.
    expect(observable).not.toContain("precedent_root");
    expect(observable).not.toContain("constitution");
  } finally {
    await svc.engine.close();
    ports.cleanup();
  }
});

test("TV-GW-54: required E38 Mint→Bond edge → MINT_EXCLUSIVE_HOLD_UNAVAILABLE before allocation or collateral reuse", async () => {
  expect(edgeDisposition("E38")).toMatchObject({
    code: "MINT_EXCLUSIVE_HOLD_UNAVAILABLE",
    blocksRequired: true,
  });
  const manifest = manifestPatched(F.release1, {
    dependencies: [
      { ...dep("bond", "1.0.0", "required", "E38"), capability: "bond.exclusive_hold" },
    ],
  });
  await expectCode(
    () => resolvePlan(installInput(manifest)),
    "MINT_EXCLUSIVE_HOLD_UNAVAILABLE",
  );

  const rel = buildRelease({
    emit: ["task.fund", "settlement.execute"],
    dependencies: [
      { ...dep("bond", "1.0.0", "required", "E38"), capability: "bond.exclusive_hold" },
    ],
  });
  const ports = fixturePorts({ spawnAdapter: stubSpawn });
  ports.putRelease(rel.wire as Release, rel.archive);
  const svc = createProductService(ports, { engine: { liveProbes: false } });
  try {
    await expectCode(
      () => svc.product.plan({ kind: "install", source: "lexverdict", version: "0.1.0" }),
      "MINT_EXCLUSIVE_HOLD_UNAVAILABLE",
    );
    // Forbidden side effects: no Bond reserve/create ran, no collateral
    // was reused — the edge rejects at plan time before any allocation.
    expect(ports.spawned).toHaveLength(0);
    expect(ports.productRegistry.all()).toHaveLength(0);
    expect(ports.journalLog).toHaveLength(0);
    expect(ports.events).toHaveLength(0);
    const observable = JSON.stringify({
      events: ports.events,
      journal: ports.journalLog,
      plans: [...svc.plans.values()],
    });
    expect(observable).not.toContain("reserve");
    expect(observable).not.toContain("collateral");
  } finally {
    await svc.engine.close();
    ports.cleanup();
  }
});

test("TV-GW-55: E35 VisLineage→Sunlight handoff distinguishes native commitment from raw artifact digest — mismatch → PROVENANCE_INVALID, evidence retained, no ACK", () => {
  const bundleBody = J({
    schema: "vislineage.bundle/1",
    actions: [{ id: "act-1", kind: "write_file" }],
  });
  const nativeBundleHash = `sha256:${H(`VL-BUNDLE/1${bundleBody}`)}`;
  const bundleBytes = Buffer.from(
    J({ schema: "vislineage.bundle/1", hash: nativeBundleHash, body: bundleBody }),
  );
  const rawDigest = `sha256:${H(bundleBytes)}`;
  // The two commitment domains are distinct by construction.
  expect(nativeBundleHash).not.toBe(rawDigest);

  const handoff = {
    v: 1 as const,
    kind: "action-lineage" as const,
    format: VISLINEAGE_BUNDLE_FORMAT,
    bundle: nativeBundleHash,
    action: "sha256:" + "a".repeat(64),
    trace: "sha256:" + "b".repeat(64),
    graph: "sha256:" + "c".repeat(64),
    disclosure: "sha256:" + "d".repeat(64),
    semantics: "sha256:" + "e".repeat(64),
  };

  // Correct handoff: source_commitment keeps the NATIVE hash while the
  // artifact digest binds the raw bytes.
  const evidence = checkSunlightHandoff({
    handoff,
    bundleHash: nativeBundleHash,
    bundleBytes,
  });
  expect(evidence.source_commitment).toBe(nativeBundleHash);
  expect(evidence.artifact.digest).toBe(rawDigest);
  expect(evidence.artifact.digest).not.toBe(evidence.source_commitment);
  expect(evidence.format).toBe("vislineage-bundle/1");
  expect(evidence.assessment).toBe("OPAQUE");

  // The attack: handoff.bundle carries the raw complete-bundle digest.
  const retained: HandoffMismatch[] = [];
  let acked = false;
  try {
    checkSunlightHandoff(
      { handoff: { ...handoff, bundle: rawDigest }, bundleHash: nativeBundleHash, bundleBytes },
      (m) => retained.push(m),
    );
    acked = true; // no Sunlight success ACK may be emitted
  } catch (e) {
    expect(e).toBeInstanceOf(RpcError);
    expect((e as RpcError).code).toBe("PROVENANCE_INVALID");
  }
  expect(acked).toBe(false);
  // Forbidden side effect: the mismatch is silently dropped — evidence is
  // retained carrying both digests.
  expect(retained).toHaveLength(1);
  expect(retained[0]!.claimed_commitment).toBe(rawDigest);
  expect(retained[0]!.native_commitment).toBe(nativeBundleHash);
  expect(retained[0]!.raw_digest).toBe(rawDigest);

  // A wrong-format handoff also rejects with no ACK.
  retained.length = 0;
  expect(() =>
    checkSunlightHandoff(
      { handoff: { ...handoff, format: "vislineage-bundle/9" }, bundleHash: nativeBundleHash, bundleBytes },
      (m) => retained.push(m),
    ),
  ).toThrowError(expect.objectContaining({ code: "PROVENANCE_INVALID" }));
  expect(retained[0]!.format).toBe("vislineage-bundle/9");
});

test("TV-GW-56: frozen runs-on-latticeag fixture — belief→verdict→approval→receipt ordering preserved; no cloud/production authority implied", () => {
  const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
  const EXAMPLE = join(ROOT, "examples", "runs-on-latticeag");

  const cfg = JSON.parse(
    readFileSync(join(EXAMPLE, "latticeag.json"), "utf8"),
  ) as {
    $schema: string;
    schema_version: number;
    adapters: Record<string, unknown>;
    sync: { enabled: boolean };
  };
  expect(cfg["$schema"]).toBe(
    "https://latticeag.dev/schemas/latticeag-config/v1.json",
  );
  expect(cfg.schema_version).toBe(1);
  expect(Object.keys(cfg.adapters).sort()).toEqual([
    "axion",
    "lexshield",
    "lexverdict",
    "polymesh",
    "vekinbox",
    "viscompile",
    "visreplay",
  ]);
  expect(cfg.sync.enabled).toBe(false); // offline fixture: sync denied

  const beliefs = JSON.parse(
    readFileSync(join(EXAMPLE, "fixtures", "beliefs.json"), "utf8"),
  ) as { spec: string; beliefs: { id: string }[] };
  expect(beliefs.spec).toBe("axion.belief_batch.v1");
  expect(beliefs.beliefs.map((b) => b.id)).toEqual(["belief-assumption-1"]);

  const approvals = JSON.parse(
    readFileSync(join(EXAMPLE, "fixtures", "approvals.json"), "utf8"),
  ) as Array<{
    request_id: string;
    resolved_by: string;
    receipt: { request_id: string; tier: string; source?: string };
  }>;
  expect(approvals).toHaveLength(1);
  expect(approvals[0]!.request_id).toBe("req-approval-1");
  expect(approvals[0]!.receipt.request_id).toBe("req-approval-1");
  // Forbidden side effect: the fixture approver is the offline
  // auto-approve test identity — never a production authority.
  expect(approvals[0]!.resolved_by).toBe("auto-approve-test");
  expect(approvals[0]!.receipt.tier).toBe("agent_asserted");

  const transcript = JSON.parse(
    readFileSync(join(EXAMPLE, "fixtures", "golden-transcript.v2.json"), "utf8"),
  ) as { kind: string; schema_version: number };
  expect(transcript.kind).toBe("latticeag.viscompile.transcript");
  expect(transcript.schema_version).toBe(2);

  // The frozen golden-chain contract, re-derived from the fixture's own
  // checked-in assertion source.
  const assertSrc = readFileSync(
    join(EXAMPLE, "src", "assert-chain.ts"),
    "utf8",
  );
  for (const name of [
    "belief_extracted",
    "verdict",
    "approval_granted",
    "receipt_issued",
  ]) {
    expect(assertSrc).toContain(`"${name}"`);
  }
  expect(assertSrc).toContain(
    "belief < verdict && verdict < approval && approval < receipt",
  );

  // The recorded golden chain satisfies the ordering when present.
  const eventsPath = join(EXAMPLE, ".latticeag", "events.jsonl");
  if (existsSync(eventsPath)) {
    const events = readFileSync(eventsPath, "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map(
        (l) =>
          JSON.parse(l) as {
            name: string;
            seq: number;
            producer?: { adapter?: string };
            payload?: { source?: string; resolved_by?: string };
          },
      );
    const first = (name: string) => events.find((e) => e.name === name)?.seq;
    const belief = first("belief_extracted");
    const verdict = first("verdict");
    const approval = first("approval_granted");
    const receipt = first("receipt_issued");
    expect(belief).toBeDefined();
    expect(verdict).toBeDefined();
    expect(approval).toBeDefined();
    expect(receipt).toBeDefined();
    expect(belief!).toBeLessThan(verdict!);
    expect(verdict!).toBeLessThan(approval!);
    expect(approval!).toBeLessThan(receipt!);
    // No cloud request or production approval authority: fixture-sourced
    // receipt, offline approver, no cloud/sync producer lane.
    const receiptEvent = events.find((e) => e.name === "receipt_issued")!;
    expect(receiptEvent.payload?.source).toBe("fixture");
    const approvalEvent = events.find((e) => e.name === "approval_granted")!;
    expect(approvalEvent.payload?.resolved_by).toBe("auto-approve-test");
    for (const e of events) {
      expect(e.producer?.adapter ?? "").not.toMatch(/cloud|sync/i);
    }
  }
});

// ═════════════════════════════════════════════════════════════════════════
// §4.4 CONNECTOR-FAMILY TRANSCRIPT vectors (TV-GW-57..62)
// ═════════════════════════════════════════════════════════════════════════

/**
 * Shared family-vector core: generate the spec's peerTranscript output,
 * validate it end-to-end with real REQUEST/1 proof verification, and
 * assert the family table's forbidden-effect rules plus a negative probe
 * (a transcript claiming a native CONNECTED mesh state fails validation).
 */
async function expectFamilyTranscript(
  vector: string,
  family: ConnectorFamilyName,
  transport: string,
  session: string,
  familyChecks: readonly string[],
  neverRules: readonly string[],
): Promise<string[]> {
  const lines = collectPeerTranscript(family, transport, session);
  const out = peerTranscriptValidation(family, lines, {
    verifyKey: origin.material.public,
    gateway: "gw1",
  });
  expect(out.exchanges).toBe(10);
  for (const c of out.checks) {
    expect(c.ok, `${vector} ${family} check ${c.name}: ${c.detail ?? ""}`).toBe(true);
  }
  expect(out.ok).toBe(true);

  // The family row names this vector and declares its forbidden rules.
  const row = CONNECTOR_FAMILIES[family];
  expect(row.vectors).toContain(vector);
  expect(row.resume.transport).toBe(transport);
  expect(row.identity.providerKeyIsIdentity).toBe(false);
  expect(row.approval.fixtureApprovalIsHypothetical).toBe(true);
  for (const rule of neverRules) {
    expect(row.resume.never).toContain(rule);
  }
  const assertionIds = familyAssertions(family).map((a) => a.id);
  for (const id of ["ten-exchanges", "exchange-order", "native-boundary", "adapter-required", "peer-proofs", ...familyChecks]) {
    expect(assertionIds).toContain(id);
  }
  // Every family assertion is bound to this vector id.
  expect(familyAssertions(family).every((a) => a.vector === vector)).toBe(true);

  // The transcript header marks the native boundary honestly: zero
  // fixture routes, no interoperability claim.
  const header = JSON.parse(lines[0]!) as {
    native_boundary: { fixture_routes: number; interoperability_claim: boolean };
  };
  expect(header.native_boundary.fixture_routes).toBe(0);
  expect(header.native_boundary.interoperability_claim).toBe(false);

  // Negative probe: claiming CONNECTED mesh without a native adapter ACK
  // must fail the adapter-required check — the validator is not a stamp.
  const forged = [...lines];
  const reg = JSON.parse(forged[4]!) as {
    response: { result: { mesh: string } };
  };
  reg.response.result.mesh = "CONNECTED";
  forged[4] = JSON.stringify(reg);
  const bad = peerTranscriptValidation(family, forged, {
    verifyKey: origin.material.public,
    gateway: "gw1",
  });
  expect(bad.ok).toBe(false);
  expect(bad.checks.find((c) => c.name === "adapter-required")?.ok).toBe(false);

  // The disconnect exchange is terminal — no exchange follows it.
  const last = JSON.parse(lines[10]!) as {
    request: { method: string };
    response: { result: { state: string } };
  };
  expect(last.request.method).toBe("agent.disconnect");
  expect(last.response.result.state).toBe("DISCONNECTED");
  return lines;
}

test("TV-GW-57: openai-completions transcript validates — completion ids retained, no respawn/re-execute, no mesh claim without adapter", async () => {
  const row = CONNECTOR_FAMILIES["openai-completions"];
  expect(row.identity.retainedIds).toEqual(
    expect.arrayContaining(["completion_id", "request_id", "tool_call_id"]),
  );
  await expectFamilyTranscript(
    "TV-GW-57",
    "openai-completions",
    "loopback-http-sse",
    "completion1",
    ["completion-id-retained", "no-mesh-claim"],
    ["re-execute a completion", "respawn the process", "fabricate SDK events"],
  );
});

test("TV-GW-58: openai-agents transcript validates — native run/handoff ids retained as text; reconnect never re-executes a tool or exports traces unconsented", async () => {
  const row = CONNECTOR_FAMILIES["openai-agents"];
  expect(row.identity.retainedIds).toEqual(
    expect.arrayContaining(["run_id", "trace_id", "tool_call_id", "handoff_id"]),
  );
  await expectFamilyTranscript(
    "TV-GW-58",
    "openai-agents",
    "loopback-http-sse",
    "agent-run1",
    ["native-ids-retained", "no-tool-reexecution"],
    ["reexecute a tool on reconnect", "export traces without consent"],
  );
});

test("TV-GW-59: hermes transcript validates with no CLI spawn; a missing real interceptor prevents enforcement-capability advertisement", async () => {
  const row = CONNECTOR_FAMILIES.hermes;
  expect(row.identity.retainedIds).toEqual(
    expect.arrayContaining(["session_id", "tool_call_id"]),
  );
  const lines = await expectFamilyTranscript(
    "TV-GW-59",
    "hermes",
    "loopback-http-sse",
    "hermes-session1",
    ["no-cli-spawn", "interceptor-required"],
    ["advertise enforcement without a real interceptor"],
  );
  // Forbidden side effect: nothing in the transcript spawned a Hermes CLI
  // (`latticeag run --cmd` is never required for the sidecar path).
  expect(lines.join("\n")).not.toContain("--cmd");
});

test("TV-GW-60: langgraph transcript validates — checkpoint binding intact; a moved checkpoint yields REVISION_CONFLICT with zero resume/dispatch", async () => {
  const row = CONNECTOR_FAMILIES.langgraph;
  expect(row.identity.retainedIds).toEqual(
    expect.arrayContaining(["thread_id", "checkpoint_ns", "checkpoint_id", "node", "attempt"]),
  );
  const lines = await expectFamilyTranscript(
    "TV-GW-60",
    "langgraph",
    "loopback-http-sse",
    "thread1",
    ["checkpoint-conflict"],
    ["resume a moved checkpoint", "dispatch after REVISION_CONFLICT"],
  );
  // A checkpoint-moved transcript (exchange order swapped) must not
  // validate — order is a binding, not a suggestion.
  const swapped = [...lines];
  [swapped[7], swapped[8]] = [swapped[8]!, swapped[7]!];
  const out = peerTranscriptValidation("langgraph", swapped);
  expect(out.ok).toBe(false);
  expect(out.checks.find((c) => c.name === "exchange-order")?.ok).toBe(false);
});

test("TV-GW-61: custom-http transcript validates — control enrollment inside scopes while routing stays CAP_ADAPTER_UNAVAILABLE; no guessed mesh endpoint", async () => {
  const row = CONNECTOR_FAMILIES["custom-http"];
  expect(row.identity.retainedIds).toEqual(
    expect.arrayContaining(["session_id", "request_id"]),
  );
  const lines = await expectFamilyTranscript(
    "TV-GW-61",
    "custom-http",
    "paired-native-http",
    "custom-session1",
    ["control-without-mesh"],
    ["fetch an endpoint URL carried inside a product event", "guess a mesh HTTP endpoint"],
  );
  // Forbidden side effect: no exchange fabricates an http(s) mesh route.
  const joined = lines.join("\n");
  expect(joined).not.toMatch(/"endpoint"\s*:\s*"https?:/);
});

test("TV-GW-62: custom-wss transcript validates — grant revocation during reconnect yields TOKEN_REVOKED; no WSS route or approval replay", async () => {
  const row = CONNECTOR_FAMILIES["custom-wss"];
  expect(row.identity.retainedIds).toEqual(
    expect.arrayContaining(["session_id", "connection_id"]),
  );
  await expectFamilyTranscript(
    "TV-GW-62",
    "custom-wss",
    "paired-native-wss",
    "custom-session2",
    ["revoked-reconnect"],
    ["replay an already dispatched operation on resume", "route after grant revocation"],
  );
});

// ═════════════════════════════════════════════════════════════════════════
// SYNC SERVICE + PERSONAL RECEIPT vectors
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-63: sync.configure requires a review bound to this exact method+params; failOnSyncStatus reports empty/unknown honestly", async () => {
  const ports = createMemorySyncPorts() as MemorySyncPorts &
    Partial<SyncServicePorts>;
  let revision = "0";
  let paused = false;
  let applied: JsonObject | null = null;
  ports.syncPaused = () => paused || ports.paused.size > 0;
  ports.syncRevision = () => revision as Count;
  ports.applySync = (document, next) => {
    applied = document;
    revision = next;
    paused = document.paused === true;
  };
  ports.cloud = () => null;
  ports.validateReview = makeReviewValidator("operator1", now + 300_000);
  const service = createSyncService(ports as SyncServicePorts);

  const doc = (): JsonObject => ({
    enabled: true,
    paused: false,
    cloud: null,
    streams: Object.fromEntries(
      STREAMS.map((s) => [
        s,
        {
          enabled: s === "runs",
          paused: false,
          profile: "metadata",
          include_objects: false,
          cohort: "private",
          from: "now",
        },
      ]),
    ) as JsonObject["streams"],
  });

  const sansReview = { expected_revision: "0" as Count, sync: doc() };
  const review = reviewBindingHash(
    "sync.configure",
    sansReview,
    "operator1",
    now + 300_000,
  ) as unknown as NativeRef;
  expect(
    await service.configure({
      expected_revision: "0",
      sync: doc(),
      review,
    }),
  ).toEqual({ revision: "1" });
  expect(applied).not.toBeNull();

  // Forbidden side effect: a review minted for ANOTHER method does not
  // unlock configure; a stale revision does not silently apply.
  const wrongMethod = reviewBindingHash(
    "config.apply",
    sansReview,
    "operator1",
    now + 300_000,
  ) as unknown as NativeRef;
  await expectCode(
    () =>
      service.configure({ expected_revision: "1", sync: doc(), review: wrongMethod }),
    "POLICY_DENIED",
  );
  await expectCode(
    () => service.configure({ expected_revision: "0", sync: doc(), review }),
    "REVISION_CONFLICT",
  );
  expect(revision).toBe("1"); // nothing applied twice

  // fail-on-sync-status (exit-5 gate): empty until work is admitted,
  // nonempty while admitted work is unsent, unknown when the daemon's
  // admitted cut is unknowable.
  const engine = new OutboxEngine(ports);
  expect(engine.failOnSyncStatus("run1")).toEqual({ empty: true, unknown: false });
  ports.consents.set("runs", streamConsent({}));
  const item = engine.enqueue(args({ stream: "runs", run: "run1" }))!;
  expect(engine.failOnSyncStatus("run1")).toEqual({ empty: false, unknown: false });
  ports.sinks.set("dest1", createMemorySink());
  await engine.flush(["runs"], 60_000);
  expect(item.state).toBe("ACKED");
  expect(engine.failOnSyncStatus("run1")).toEqual({ empty: true, unknown: false });
  // Unknowable daemon cut + admitted work is never success. A distinct
  // source/cut avoids the deterministic-intent dedup of the run1 item.
  engine.enqueue(
    args({
      stream: "runs",
      run: "run9",
      source: srcRef("evt9"),
      through: "c0000000000000001:8",
    }),
  );
  ports.daemon = "unknown";
  expect(engine.failOnSyncStatus("run9")).toEqual({ empty: false, unknown: true });
});

test("TV-GW-64: personal/CIS receipt without explicit consent AND a deletion-capable retention contract is denied before any object or digest export", async () => {
  // Projection level: both flags absent → denial before export.
  const denied = projectForStream(
    "receipts",
    {
      source: srcRef("cis1"),
      envelope: { kind: "receipt", receipt_class: "cis", person: "p1" },
      personal: true,
      objects: { [H("obj1")]: { body: "x" } },
      consent: { existence: true, hashes: true, ids: true },
    },
    "metadata",
  );
  expect(denied.ok).toBe(false);
  if (!denied.ok) expect(denied.code).toBe("POLICY_DENIED");
  // One flag without the other still denies.
  const half = projectForStream(
    "receipts",
    {
      source: srcRef("cis1"),
      envelope: { kind: "receipt", receipt_class: "cis" },
      personal: true,
      consent: { personalData: true },
    },
    "metadata",
  );
  expect(half.ok).toBe(false);

  // Engine level: enqueue throws POLICY_DENIED before persisting an item,
  // a payload object, or a digest — and no sink ever sees the receipt.
  const ports = createMemorySyncPorts();
  const sink = createMemorySink();
  ports.sinks.set("proof-native-import", sink);
  ports.consents.set(
    "receipts",
    streamConsent({ destination: "proof-native-import" }),
  );
  const engine = new OutboxEngine(ports);
  await expectCode(
    () =>
      engine.enqueue(
        args({
          stream: "receipts",
          envelope: { kind: "receipt", receipt_class: "cis", person: "p1" },
          personal: true,
        }),
      ),
    "POLICY_DENIED",
  );
  // Forbidden side effects: zero items, zero objects, zero digests, zero
  // sink attempts.
  expect(ports.items.size).toBe(0);
  expect(ports.objects.size).toBe(0);
  expect(sink.attempts).toHaveLength(0);

  // With BOTH E48 flags the same export is admitted (control: the denial
  // is consent-scoped, not a blanket ban on personal receipts).
  const ports2 = createMemorySyncPorts();
  const sink2 = createMemorySink();
  ports2.sinks.set("proof-native-import", sink2);
  ports2.consents.set(
    "receipts",
    streamConsent({
      destination: "proof-native-import",
      personalData: true,
      deletionContract: true,
    }),
  );
  const engine2 = new OutboxEngine(ports2);
  const item = engine2.enqueue(
    args({ stream: "receipts", personal: true }),
  )!;
  await engine2.flush(["receipts"], 60_000);
  expect(item.state).toBe("ACKED");
  expect(sink2.sent).toHaveLength(1);
});
