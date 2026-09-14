/**
 * TV-GW CONFIG + LIFECYCLE conformance vectors (spec §13.2 matrix).
 *
 * One named test per vector. Each test drives the real implementation —
 * config migration, the catalog/release verifiers, the §5.4 lifecycle
 * engine behind its injected ports, the §5.3 resolver edge table, the
 * E35 handoff seam, and the frozen runs-on-latticeag fixture — and
 * asserts both the required outcome and every forbidden side effect the
 * vector names (zero spawns, zero fetches, no pointer moves, no
 * projection duplication, no synthesized authority, no cloud calls).
 *
 * Adapter-method invocation counts are observed by wrapping each spawned
 * child's stdin: every `gateway-adapter/1` request line carries
 * "method", so describe/configure/start/health/drain/stop counts are
 * exact. Registry/port calls (casActive, removeStage, catalog.fetch,
 * putObject) are counted by the memory ports or by thin wrappers.
 */
import { spawn } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";

import { describe, expect, test, vi } from "vitest";

import {
  F,
  H,
  J,
  adapterSource,
  artifact,
  auditor,
  blob,
  native,
  now,
  origin,
  release as mkRelease,
  schema,
  sunlight,
  tar,
} from "@latticeag/testkit";
import { migrateConfig, migrateConfigFile } from "@latticeag/config";

import { RpcError } from "../protocol/errors.js";
import type { Count, Hash } from "../protocol/refs.js";
import type { Dependency, ProductManifest, Release } from "../protocol/product.js";

import type { AdapterChild } from "../lifecycle/adapter-client.js";
import { LifecycleEngine } from "../lifecycle/engine.js";
import {
  DependencyConflictError,
  resolvePlan,
} from "../lifecycle/resolve.js";
import type { PlanSummary } from "../lifecycle/resolve.js";
import { createProductService } from "../lifecycle/service.js";
import type { ProductServiceBundle } from "../lifecycle/service.js";
import {
  StubAdapterChild,
} from "../lifecycle/testing.js";
import type { MemoryPorts, StubScript } from "../lifecycle/testing.js";
import {
  checkSunlightHandoff,
  VISLINEAGE_BUNDLE_FORMAT,
} from "../lifecycle/handoff.js";
import type { HandoffMismatch } from "../lifecycle/handoff.js";
import {
  dep,
  fixturePorts,
  fixtureTrust,
  manifestOf,
  retainedRow,
  REVIEW,
} from "../lifecycle/testbed.js";

// ── §8.2 literal v1 input (spec-verbatim; must equal F.config1) ─────────

const V1_LITERAL = JSON.parse(
  `{"schema_version":1,"project":{"name":"demo","run_id_prefix":"run"},"bus":{},"ingest":{"bind":"127.0.0.1","port":9847,"path":"/v1/ingest"},"adapters":{"axion":{"enabled":false,"base_url":"http://127.0.0.1:9001","webhook_path":"/v1/ingest/axion"},"visreplay":{"enabled":false,"session_dir":".latticeag/sessions"},"lexverdict":{"enabled":true,"base_url_env":"LEXVERDICT_URL"},"vekinbox":{"enabled":false,"base_url_env":"VEKINBOX_URL","api_key_env":"VEKINBOX_API_KEY","workspace_id_env":"VEKINBOX_WORKSPACE_ID","agent_id_env":"VEKINBOX_AGENT_ID"},"viscompile":{"enabled":false,"bin":"lattice","baseline":"baseline.json"},"lexshield":{"enabled":false,"bin":"lexshield"},"polymesh":{"enabled":false,"gateway_url_env":"POLYMESH_GATEWAY_URL","mesh_id_env":"POLYMESH_MESH_ID","capability":"latticeag.events.relay"}},"redaction":{"keys":["authorization","api_key"],"include_raw_text":false},"sync":{"enabled":false,"gateway_url_env":"LEXGATEWAY_URL","token_env":"LEXGATEWAY_TOKEN","mode":"replicate","local_port":8788,"polymesh":{"enabled":false}},"doctor":{}}`,
) as Record<string, unknown>;

const INSTALL_EVENTS = [
  "ProductPlanCreated",
  "ProductFetchStarted",
  "ProductVerified",
  "ProductStaged",
  "ProductStartRequested",
  "ProductStarted",
  "ProductActivated",
];

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

// ── adapter-method call counting ─────────────────────────────────────────

/** Per-child adapter-method invocation counters. */
type AdapterCalls = Map<string, number>;

/**
 * Wrap a child's stdin so every `gateway-adapter/1` request line is
 * counted by method before being forwarded verbatim.
 */
function tapChild(child: AdapterChild, calls: AdapterCalls): void {
  const inner = child.stdin;
  if (inner === null) return;
  (child as { stdin: Writable }).stdin = new Writable({
    write(chunk, _enc, cb) {
      for (const line of String(chunk).split("\n")) {
        const t = line.trim();
        if (!t.startsWith("{")) continue;
        const m = /"method"\s*:\s*"([a-z]+)"/.exec(t);
        if (m !== null) calls.set(m[1]!, (calls.get(m[1]!) ?? 0) + 1);
      }
      inner.write(chunk, cb);
    },
  });
}

/** Spawn the real fixture adapter (node adapter.mjs) like the daemon. */
function realChild(
  cmd: readonly string[],
  dir: string,
  env: Record<string, string>,
): AdapterChild {
  return spawn(cmd[0]!, [...cmd.slice(1)], {
    cwd: dir,
    env: { ...process.env, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  }) as unknown as AdapterChild;
}

const stubChild =
  (methods: StubScript["methods"]) =>
  (): AdapterChild =>
    new StubAdapterChild({ methods });

/**
 * A spawn port that selects the i-th factory per spawn and returns
 * per-child adapter-method call counters (calls[i] counts requests the
 * engine actually wrote to child i).
 */
function spawnTap(
  factories: ReadonlyArray<
    (cmd: readonly string[], dir: string, env: Record<string, string>) => AdapterChild
  >,
): { spawnAdapter: (cmd: readonly string[], dir: string, env: Record<string, string>) => AdapterChild; calls: AdapterCalls[] } {
  const calls: AdapterCalls[] = [];
  let n = 0;
  return {
    calls,
    spawnAdapter: (cmd, dir, env) => {
      const f = factories[Math.min(n, factories.length - 1)]!;
      n += 1;
      const child = f(cmd, dir, env);
      const m: AdapterCalls = new Map();
      calls.push(m);
      tapChild(child, m);
      return child;
    },
  };
}

// ── fixture release rebuilds (signed, spec-shaped) ──────────────────────

/**
 * Rebuild a complete, validly signed fixture release with knobs the
 * vectors require (slug, version, builder identity, dependency edges,
 * emitted capabilities, appended signature statements). Mirrors the
 * §13.1 prelude `release()` construction exactly.
 */
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
    package: { ...base.package, name: `@latticeag/fixture-${slug}`, archive: ar },
    provenance: {
      ...base.provenance,
      descriptor: provenance.ref,
      statements: ps.map(native),
      builder,
      lockfile,
      sbom: sbom.ref,
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

// ── lifecycle drivers ────────────────────────────────────────────────────

type Op = Awaited<ReturnType<ProductServiceBundle["waitOperation"]>>;

function newService(ports: MemoryPorts): ProductServiceBundle {
  return createProductService(ports, { engine: { liveProbes: false } });
}

async function runInstall(
  svc: ProductServiceBundle,
  source = "lexverdict",
  version = "0.1.0",
  pinned = false,
): Promise<Op> {
  const { plan } = await svc.product.plan({
    kind: "install",
    source,
    version,
    ...(pinned ? { pinned: true } : {}),
  } as Parameters<ProductServiceBundle["product"]["plan"]>[0]);
  const acc = await svc.product.install({ plan, review: REVIEW });
  return svc.waitOperation(acc.operation);
}

async function runUpdate(svc: ProductServiceBundle, version: string): Promise<Op> {
  const { plan } = await svc.product.plan({
    kind: "update",
    source: "lexverdict",
    version,
  });
  const acc = await svc.product.update({ plan, review: REVIEW });
  return svc.waitOperation(acc.operation);
}

async function runRollback(svc: ProductServiceBundle, version: string): Promise<Op> {
  const { plan } = await svc.product.plan({
    kind: "rollback",
    source: "lexverdict",
    version,
  });
  const acc = await svc.product.rollback({ plan, review: REVIEW });
  return svc.waitOperation(acc.operation);
}

async function runUninstall(svc: ProductServiceBundle): Promise<Op> {
  const { plan } = await svc.product.plan({ kind: "uninstall", source: "lexverdict" });
  const acc = await svc.product.uninstall({ plan, review: REVIEW });
  return svc.waitOperation(acc.operation);
}

async function installLex(
  ports: MemoryPorts,
): Promise<{ svc: ProductServiceBundle; op: Op }> {
  const svc = newService(ports);
  const op = await runInstall(svc);
  return { svc, op };
}

function planOf(
  summary: Partial<PlanSummary> & { kind: PlanSummary["kind"] },
): PlanSummary {
  return {
    slug: "lexverdict",
    from: null,
    to: "0.1.0",
    manifest: "0".repeat(64) as Hash,
    archive: "",
    dependencies: [],
    grants: null,
    revisions: { config: "1" as Count, catalog: "1" as Count, registry: "1" as Count },
    trust: "0".repeat(64) as Hash,
    keep_data: true,
    cascade: false,
    ...summary,
  };
}

/** Count casActive invocations (the config-unwire / pointer move). */
function countCas(ports: MemoryPorts): { calls: Array<{ expected: Count | null; next: Count | null }> } {
  const calls: Array<{ expected: Count | null; next: Count | null }> = [];
  const registry = ports.productRegistry;
  const orig = registry.casActive.bind(registry);
  registry.casActive = (slug, expected, next) => {
    calls.push({ expected, next });
    return orig(slug, expected, next);
  };
  return { calls };
}

/** Count removeStage invocations (package-link removal). */
function countRemoveStage(ports: MemoryPorts): { calls: string[] } {
  const calls: string[] = [];
  const orig = ports.paths.removeStage?.bind(ports.paths);
  ports.paths.removeStage = (dir: string) => {
    calls.push(dir);
    orig?.(dir);
  };
  return { calls };
}

const journalFor = (ports: MemoryPorts, type: string, generation?: Count) =>
  ports.journalLog.filter(
    (j) => j.type === type && (generation === undefined || j.generation === generation),
  );

// ── TV-GW-01 config migration ────────────────────────────────────────────

describe("TV-GW-01: v1→v2 config migration", () => {
  test("§8.2 literal migrates to exactly F.config2; no outbound request; legacy preserved", async () => {
    // The fixture constant IS the §8.2 literal.
    expect(F.config1).toEqual(V1_LITERAL);

    // Forbid every outbound channel the implementation could plausibly use.
    const httpReq = vi
      .spyOn(http, "request")
      .mockImplementation(() => {
        throw new Error("outbound http.request forbidden in migration");
      });
    const httpGet = vi.spyOn(http, "get").mockImplementation(() => {
      throw new Error("outbound http.get forbidden in migration");
    });
    const httpsReq = vi.spyOn(https, "request").mockImplementation(() => {
      throw new Error("outbound https.request forbidden in migration");
    });
    const netConnect = vi.spyOn(net, "connect").mockImplementation(() => {
      throw new Error("outbound net.connect forbidden in migration");
    });
    const fetchSpy = vi.fn(() => {
      throw new Error("outbound fetch forbidden in migration");
    });
    vi.stubGlobal("fetch", fetchSpy);
    const prevEnv = process.env.LEXVERDICT_URL;
    try {
      // In-memory migration (spec function + shipped implementation).
      const before = structuredClone(V1_LITERAL);
      process.env.LEXVERDICT_URL = "http://sentinel.invalid/never-copied";
      const out = migrateConfig(V1_LITERAL as never, "ws1", "gw1") as Record<
        string,
        unknown
      >;
      expect(out).toEqual(F.config2);
      expect(out.schema_version).toBe(2);

      // All seven adapter objects and env variable names unchanged.
      const adapters = out.adapters as Record<string, Record<string, unknown>>;
      expect(Object.keys(adapters).sort()).toEqual([
        "axion",
        "lexshield",
        "lexverdict",
        "polymesh",
        "vekinbox",
        "viscompile",
        "visreplay",
      ]);
      expect(adapters).toEqual(V1_LITERAL.adapters);
      expect(adapters.lexverdict!.base_url_env).toBe("LEXVERDICT_URL");

      // No environment *values* are copied into the migrated config.
      expect(JSON.stringify(out)).not.toContain("sentinel.invalid");

      // The v1 input is never mutated.
      expect(V1_LITERAL).toEqual(before);

      // Legacy sync preserved under sync.legacy; all six new streams
      // disabled and paused pending review.
      const sync = out.sync as {
        enabled: boolean;
        paused: boolean;
        legacy: unknown;
        streams: Record<string, { enabled: boolean; paused: boolean }>;
      };
      expect(sync.legacy).toEqual(V1_LITERAL.sync);
      expect(sync.enabled).toBe(false);
      const streamNames = Object.keys(sync.streams).sort();
      expect(streamNames).toEqual([
        "approvals",
        "lineage",
        "mesh",
        "receipts",
        "runs",
        "watch",
      ]);
      for (const name of streamNames) {
        expect(sync.streams[name]!.enabled).toBe(false);
      }

      // File-level crash-safe migration of the same literal.
      const dir = mkdtempSync(join(tmpdir(), "gw-migrate-"));
      try {
        const cfgPath = join(dir, "latticeag.json");
        const raw = Buffer.from(`${JSON.stringify(V1_LITERAL, null, 2)}\n`, "utf8");
        writeFileSync(cfgPath, raw);
        const sha = createHash("sha256").update(raw).digest("hex");
        // Historical v1 lane present before migration.
        const laneDir = join(dir, ".latticeag");
        const lane = join(laneDir, "events.jsonl");
        const laneBytes = Buffer.from(
          '{"seq":1,"name":"v1_historical"}\n{"seq":2,"name":"v1_historical"}\n',
        );
        mkdirSync(laneDir, { recursive: true });
        writeFileSync(lane, laneBytes);

        const result = migrateConfigFile(cfgPath, {
          workspace: "ws1",
          instance: "gw1",
        });
        expect(result.receipt).toEqual({
          workspace_id: "ws1",
          instance_id: "gw1",
          legacy_log_path: ".latticeag/events.jsonl",
          consent_reset: true,
        });
        expect(result.old_sha256).toBe(sha);

        // Migrated file is exactly F.config2.
        const migrated = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<
          string,
          unknown
        >;
        expect(migrated).toEqual(F.config2);

        // Exclusive backup: v1 bytes preserved verbatim for old binaries.
        expect(result.backup_path).toBe(`${cfgPath}.v1.${sha}.bak`);
        expect(readFileSync(result.backup_path)).toEqual(raw);
        const backupDoc = JSON.parse(readFileSync(result.backup_path, "utf8")) as {
          schema_version: number;
        };
        expect(backupDoc.schema_version).toBe(1);

        // Historical v1 events remain mounted read-only — bytes unchanged.
        expect(readFileSync(lane)).toEqual(laneBytes);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }

      // No outbound request of any kind was attempted.
      for (const spy of [httpReq, httpGet, httpsReq, netConnect, fetchSpy]) {
        expect(spy).not.toHaveBeenCalled();
      }
    } finally {
      if (prevEnv === undefined) {
        delete process.env.LEXVERDICT_URL;
      } else {
        process.env.LEXVERDICT_URL = prevEnv;
      }
      vi.unstubAllGlobals();
      vi.restoreAllMocks();
    }
  });
});

// ── install path (TV-GW-04 … TV-GW-08) ──────────────────────────────────

describe("TV-GW-04: normal install through READY", () => {
  test("exact transition sequence, three health passes, one activation, config bound once", async () => {
    const tap = spawnTap([realChild]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    const cas = countCas(ports);
    const { svc, op } = await installLex(ports);
    try {
      expect(op.state).toBe("READY");
      // PLANNED→FETCHING→VERIFIED→STAGED→STARTING→HEALTHCHECKING→READY
      expect(op.events.map((e) => e.event)).toEqual(INSTALL_EVENTS);
      expect(op.events.map((e) => e.to)).toEqual([
        "PLANNED",
        "FETCHING",
        "VERIFIED",
        "STAGED",
        "STARTING",
        "HEALTHCHECKING",
        "READY",
      ]);
      // Every named event also reached the receipt sink.
      expect(ports.events).toEqual(op.events);

      // One adapter process; exact §5.2 method counts.
      expect(ports.spawned).toHaveLength(1);
      expect(ports.spawned[0]!.cmd).toEqual([process.execPath, "adapter.mjs"]);
      const calls = tap.calls[0]!;
      expect(calls.get("describe")).toBe(1);
      // The config binding (instance+config+generation) written once.
      expect(calls.get("configure")).toBe(1);
      expect(calls.get("start")).toBe(1);
      // Three readiness passes gate activation (§5.2 default).
      expect(calls.get("health")).toBe(3);
      expect(calls.get("drain") ?? 0).toBe(0);
      expect(calls.get("stop") ?? 0).toBe(0);

      // Exactly one activation: one pointer CAS, one projection, one
      // ProductActivated receipt.
      expect(cas.calls).toEqual([{ expected: null, next: "1" }]);
      expect(journalFor(ports, "active_pointer")).toHaveLength(1);
      expect(journalFor(ports, "projection")).toHaveLength(1);
      expect(journalFor(ports, "start_intent")).toHaveLength(1);
      expect(op.events.filter((e) => e.event === "ProductActivated")).toHaveLength(1);

      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.0");
      expect(active.state).toBe("READY");
      expect(active.activation_indexed).toBe(true);
      expect(active.projected).toBe(true);
      expect(existsSync(join(active.staged_dir!, "package", "adapter.mjs"))).toBe(true);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);
});

describe("TV-GW-05: flipped signature bit", () => {
  test("SIGNATURE_INVALID before extraction/start; zero adapter invocations", async () => {
    const wire = structuredClone(F.release1.wire) as Release;
    // Flip bit 0 of the first signature_hex, body/hash unchanged.
    const sig = wire.signatures[0]!.signature_hex;
    const last = parseInt(sig.slice(-1), 16);
    wire.signatures[0]!.signature_hex = sig.slice(0, -1) + (last ^ 1).toString(16);
    const unchanged = structuredClone(wire.signatures[0]) as Record<string, unknown>;
    delete unchanged.signature_hex;
    const orig = structuredClone(F.release1.wire.signatures[0]) as Record<
      string,
      unknown
    >;
    delete orig.signature_hex;
    expect(unchanged).toEqual(orig); // body/hash left alone

    const tap = spawnTap([realChild]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    ports.putRelease(wire, F.release1.archive);
    const cas = countCas(ports);
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
      // Rejected at VERIFIED boundary: fetched, then refused — never
      // extracted, staged, or started.
      expect(op.events.map((e) => e.event)).toEqual([
        "ProductPlanCreated",
        "ProductFetchStarted",
        "ProductRejected",
      ]);
      expect(ports.spawned).toHaveLength(0); // zero adapter invocations
      expect(tap.calls).toHaveLength(0);
      expect(cas.calls).toHaveLength(0); // active pointer never touched
      expect(journalFor(ports, "start_intent")).toHaveLength(0);
      const gen = ports.productRegistry.generations("lexverdict")[0]!;
      expect(gen.state).toBe("REJECTED");
      expect(gen.staged_dir).toBeNull();
      expect(gen.active).toBe(false);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-06: unapproved builder", () => {
  test("signed descriptor/manifest naming unapproved-builder → PROVENANCE_INVALID", async () => {
    const rel = buildRelease({ builder: "unapproved-builder" });
    const tap = spawnTap([stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    ports.putRelease(rel.wire as Release, rel.archive);
    const cas = countCas(ports);
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      const { plan } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      const acc = await svc.product.install({ plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.error?.code).toBe("PROVENANCE_INVALID");
      // Zero sandbox starts; active pointer unchanged.
      expect(ports.spawned).toHaveLength(0);
      expect(tap.calls).toHaveLength(0);
      expect(cas.calls).toHaveLength(0);
      expect(journalFor(ports, "active_pointer")).toHaveLength(0);
      expect(journalFor(ports, "start_intent")).toHaveLength(0);
      const gen = ports.productRegistry.generations("lexverdict")[0]!;
      expect(gen.state).toBe("REJECTED");
      expect(ports.productRegistry.active("lexverdict")).toBeUndefined();
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-07: unsafe archive path", () => {
  test('release("0.1.0",{"package/../../escape":"x"}) → POLICY_DENIED; nothing escapes staging', async () => {
    const rel = mkRelease("0.1.0", { "package/../../escape": "x" });
    const tap = spawnTap([stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    ports.putRelease(rel.wire as Release, rel.archive);
    const cas = countCas(ports);
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      const { plan } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      const acc = await svc.product.install({ plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.error?.code).toBe("POLICY_DENIED");
      // No file outside staging was written.
      expect(existsSync(join(ports.stageRoot, "escape"))).toBe(false);
      expect(existsSync(join(ports.stageRoot, "..", "escape"))).toBe(false);
      expect(existsSync(join(ports.dataRoot, "escape"))).toBe(false);
      // No activation, no spawn.
      expect(ports.spawned).toHaveLength(0);
      expect(cas.calls).toHaveLength(0);
      const gen = ports.productRegistry.generations("lexverdict")[0]!;
      expect(gen.state).toBe("REJECTED");
      expect(gen.active).toBe(false);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-08: lifecycle scripts never run", () => {
  test("scripts.postinstall=`exit 77` is never invoked; inert adapter reaches READY", async () => {
    const pkg = JSON.parse(
      Buffer.from(F.release1.files["package/package.json"] as string).toString("utf8"),
    ) as Record<string, unknown>;
    pkg.scripts = { postinstall: "exit 77" };
    const rel = mkRelease("0.1.0", {
      "package/package.json": JSON.stringify(pkg),
    });
    const tap = spawnTap([realChild]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    ports.putRelease(rel.wire as Release, rel.archive);
    const { svc, op } = await installLex(ports);
    try {
      expect(op.state).toBe("READY");
      // Exactly one spawn — the adapter itself — and its argv is the
      // manifest entry, not a package-manager lifecycle invocation.
      expect(ports.spawned).toHaveLength(1);
      expect(ports.spawned[0]!.cmd).toEqual([process.execPath, "adapter.mjs"]);
      // Hook invocation count is exactly zero: no npm/install runner ever
      // spawned and no adapter method other than the §5.2 handshake ran.
      const calls = tap.calls[0]!;
      expect(calls.get("describe")).toBe(1);
      expect(calls.get("configure")).toBe(1);
      expect(calls.get("start")).toBe(1);
      expect(calls.get("health")).toBe(3);
      expect([...calls.keys()].sort()).toEqual([
        "configure",
        "describe",
        "health",
        "start",
      ]);
      const gen = ports.productRegistry.active("lexverdict")!;
      // The staged package.json carries the hook verbatim (inert data).
      const stagedPkg = JSON.parse(
        readFileSync(join(gen.staged_dir!, "package", "package.json"), "utf8"),
      ) as { scripts?: { postinstall?: string } };
      expect(stagedPkg.scripts?.postinstall).toBe("exit 77");
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);
});

// ── resolver/edge vectors (TV-GW-09, TV-GW-10, TV-GW-53, TV-GW-54) ──────

describe("TV-GW-09: required dependency cycle", () => {
  test("a→b and b→a at exact 1.0.0 → DEPENDENCY_CONFLICT cycle [a,b,a]; nothing fetched/started", async () => {
    const relA = buildRelease({
      slug: "a",
      version: "1.0.0",
      dependencies: [dep("b", "1.0.0", "required")],
    });
    const relB = buildRelease({
      slug: "b",
      version: "1.0.0",
      dependencies: [dep("a", "1.0.0", "required")],
    });
    const manifestA = manifestOf(relA);
    const manifestB = manifestOf(relB);

    // Pure resolver: the exact cycle path, with zero catalog access.
    let cycle: string[] | null = null;
    try {
      resolvePlan({
        kind: "install",
        source: "a",
        version: "1.0.0",
        target: { manifest: manifestA, manifestDigest: H(J(manifestA)) as Hash },
        manifests: new Map<string, ProductManifest[]>([
          ["a", [manifestA]],
          ["b", [manifestB]],
        ]),
        index: null,
        installed: [],
        opts: { now },
      });
      expect.unreachable("cycle must throw");
    } catch (e) {
      expect(e).toBeInstanceOf(DependencyConflictError);
      expect((e as DependencyConflictError).code).toBe("DEPENDENCY_CONFLICT");
      cycle = (e as DependencyConflictError).cycle;
    }
    expect(cycle).toEqual(["a", "b", "a"]);

    // Service level: plan() refuses and nothing is allocated/fetched/started.
    const tap = spawnTap([stubChild(okAdapter)]);
    const ports = fixturePorts({ index: null, spawnAdapter: tap.spawnAdapter });
    ports.putRelease(relA.wire as Release, relA.archive);
    ports.putRelease(relB.wire as Release, relB.archive);
    const fetchCalls: string[] = [];
    const origFetch = ports.catalog.fetch.bind(ports.catalog);
    ports.catalog.fetch = (sref) => {
      fetchCalls.push(`${sref.slug}@${sref.version}`);
      return origFetch(sref);
    };
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await expect(
        svc.product.plan({ kind: "install", source: "a", version: "1.0.0" }),
      ).rejects.toMatchObject({
        code: "DEPENDENCY_CONFLICT",
        cycle: ["a", "b", "a"],
      });
      // Zero archives fetched by the engine: the FETCHING stage never ran
      // (the only fetches were plan-time manifest reads, no journal entry).
      expect(ports.journalLog).toHaveLength(0);
      expect(ports.events).toHaveLength(0);
      expect(ports.spawned).toHaveLength(0); // zero processes started
      expect(ports.productRegistry.all()).toHaveLength(0);
      expect(fetchCalls.every((c) => c === "a@1.0.0" || c === "b@1.0.0")).toBe(true);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-10: E28 uncertified composition", () => {
  test("required E28 LexWatt edge → CAP_ADAPTER_UNAVAILABLE before allocation", async () => {
    expect(resolvePlanEdgeCode("E28")).toBe("CAP_ADAPTER_UNAVAILABLE");
    const rel = buildRelease({
      dependencies: [{ ...dep("lexwatt", "1.0.0", "required", "E28") }],
    });
    const tap = spawnTap([stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    ports.putRelease(rel.wire as Release, rel.archive);
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await expect(
        svc.product.plan({ kind: "install", source: "lexverdict", version: "0.1.0" }),
      ).rejects.toMatchObject({ code: "CAP_ADAPTER_UNAVAILABLE" });
      // Before allocation: no generation row, no journal, no spawn, no
      // adapter/native run allocated.
      expect(ports.productRegistry.all()).toHaveLength(0);
      expect(ports.journalLog).toHaveLength(0);
      expect(ports.events).toHaveLength(0);
      expect(ports.spawned).toHaveLength(0);
      expect(tap.calls).toHaveLength(0);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-53: E17 Charter→Mint authority", () => {
  test("required E17 edge → UNSUPPORTED_COMPOSITION; no synthesized precedent_root", async () => {
    const rel = buildRelease({
      dependencies: [
        { ...dep("charter", "1.0.0", "required", "E17"), capability: "precedent" },
      ],
    });
    const tap = spawnTap([stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    ports.putRelease(rel.wire as Release, rel.archive);
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await expect(
        svc.product.plan({ kind: "install", source: "lexverdict", version: "0.1.0" }),
      ).rejects.toMatchObject({ code: "UNSUPPORTED_COMPOSITION" });
      // Real-money/native authority disabled: nothing ran, nothing
      // allocated, and no precedent_root was synthesized anywhere.
      expect(ports.spawned).toHaveLength(0);
      expect(ports.productRegistry.all()).toHaveLength(0);
      expect(ports.journalLog).toHaveLength(0);
      const observable = JSON.stringify({
        events: ports.events,
        journal: ports.journalLog,
        plans: [...svc.plans.values()],
      });
      expect(observable).not.toContain("precedent_root");
      expect(observable).not.toContain("constitution");
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-54: E38 Mint→Bond exclusive hold", () => {
  test("Mint-only task.fund/settlement.execute cannot satisfy Bond hold → MINT_EXCLUSIVE_HOLD_UNAVAILABLE", async () => {
    const rel = buildRelease({
      emit: ["task.fund", "settlement.execute"],
      dependencies: [
        {
          ...dep("bond", "1.0.0", "required", "E38"),
          capability: "bond.exclusive_hold",
        },
      ],
    });
    const tap = spawnTap([stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    ports.putRelease(rel.wire as Release, rel.archive);
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await expect(
        svc.product.plan({ kind: "install", source: "lexverdict", version: "0.1.0" }),
      ).rejects.toMatchObject({ code: "MINT_EXCLUSIVE_HOLD_UNAVAILABLE" });
      // No Bond reserve/create was performed and no collateral was reused:
      // the edge rejects at plan time before any allocation or native run.
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
});

// ── update / crash / rollback / uninstall (TV-GW-11 … TV-GW-17) ─────────

describe("TV-GW-11: unhealthy update candidate", () => {
  test("readiness=false three times → HEALTH_FAILED; 0.1.0 active+data unchanged; no candidate capability", async () => {
    const tap = spawnTap([
      stubChild(okAdapter),
      stubChild({
        ...okAdapter,
        health: () => ({
          liveness: true,
          readiness: false,
          dependencies: [],
          native: {},
        }),
      }),
    ]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    const cas = countCas(ports);
    const { svc } = await installLex(ports);
    try {
      const gen1 = ports.productRegistry.active("lexverdict")!;
      const sentinel = join(gen1.data_dir!, "sentinel.bin");
      writeFileSync(sentinel, "v1-data");

      const op = await runUpdate(svc, "0.1.1");
      expect(op.state).toBe("HEALTH_FAILED");
      expect(op.error?.code).toBe("HEALTH_FAILED");

      // Candidate polled exactly three readiness=false probes.
      const candidate = tap.calls[1]!;
      expect(candidate.get("health")).toBe(3);
      expect(candidate.get("describe")).toBe(1);
      expect(candidate.get("configure")).toBe(1);
      expect(candidate.get("start")).toBe(1);
      // …then drained and stopped exactly once.
      expect(candidate.get("drain")).toBe(1);
      expect(candidate.get("stop")).toBe(1);
      expect(op.events.map((e) => e.event)).toContain("ProductCandidateAbortRequested");
      expect(op.events.map((e) => e.event)).not.toContain("ProductActivated");

      // No candidate capability was ever advertised: no pointer CAS for
      // the candidate, no activation index, nothing to withdraw.
      const gen2 = ports.productRegistry
        .generations("lexverdict")
        .find((g) => g.version === "0.1.1")!;
      expect(gen2.state).toBe("STOPPED_RETAINED");
      expect(gen2.active).toBe(false);
      expect(gen2.activation_indexed).toBe(false);
      expect(gen2.projected).toBe(false);
      expect(gen2.capabilities_withdrawn).toBe(false);
      expect(journalFor(ports, "active_pointer", gen2.generation)).toHaveLength(0);
      expect(journalFor(ports, "projection", gen2.generation)).toHaveLength(0);
      expect(cas.calls.filter((c) => c.next === gen2.generation)).toHaveLength(0);

      // Active version and its data bytes are untouched.
      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.0");
      expect(active.state).toBe("READY");
      expect(readFileSync(sentinel, "utf8")).toBe("v1-data");
      // The old adapter was never asked to drain/stop.
      expect(tap.calls[0]!.get("drain") ?? 0).toBe(0);
      expect(tap.calls[0]!.get("stop") ?? 0).toBe(0);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-12: crash between pointer fsync and projection", () => {
  test("update crash → recovery indexes one 0.1.1 activation, preserves pointer, probes before readiness", async () => {
    const tap = spawnTap([stubChild(okAdapter), stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    const { svc } = await installLex(ports);
    try {
      // Arm the crash at the first projection journal of the update —
      // after the active-pointer marker fsync.
      ports.crashOn("projection");
      const op = await runUpdate(svc, "0.1.1");
      // The update op never completed its transition list.
      expect(op.events.map((e) => e.event)).not.toContain("ProductActivated");

      const gens = ports.productRegistry.generations("lexverdict");
      const gen2 = gens.find((g) => g.version === "0.1.1")!;
      // Committed pointer preserved; projection torn.
      expect(gen2.state).toBe("HEALTHCHECKING");
      expect(gen2.active).toBe(true);
      expect(gen2.projected).toBe(false);
      expect(gen2.activation_indexed).toBe(true);
      expect(journalFor(ports, "active_pointer", gen2.generation)).toHaveLength(1);
      expect(journalFor(ports, "projection", gen2.generation)).toHaveLength(1);
      expect(ports.events.filter(
        (e) => e.event === "ProductActivated" && e.generation === gen2.generation,
      )).toHaveLength(0);

      // Daemon restart: a fresh engine over the same durable ports probes
      // the generation before marking it ready.
      let activatedAtProbe: number | undefined;
      let probes = 0;
      ports.probeGeneration = () => {
        probes += 1;
        activatedAtProbe = ports.events.filter(
          (e) => e.event === "ProductActivated" && e.generation === gen2.generation,
        ).length;
        return Promise.resolve(true);
      };
      await svc.engine.close(); // daemon teardown; children detached
      const engine2 = new LifecycleEngine(ports, { liveProbes: false });
      await engine2.recoverAfterCrash("active_pointer");

      const after = ports.productRegistry.generations("lexverdict").find(
        (g) => g.version === "0.1.1",
      )!;
      expect(after.state).toBe("READY");
      expect(after.projected).toBe(true);
      expect(after.active).toBe(true);
      expect(probes).toBe(1);
      // The probe ran strictly before the activation receipt.
      expect(activatedAtProbe).toBe(0);
      // Exactly one 0.1.1 activation was ever indexed/projected/emitted.
      expect(journalFor(ports, "projection", gen2.generation)).toHaveLength(1);
      expect(journalFor(ports, "active_pointer", gen2.generation)).toHaveLength(1);
      expect(ports.events.filter(
        (e) => e.event === "ProductActivated" && e.generation === gen2.generation,
      )).toHaveLength(1);
      // No repeated native effect: no new spawn, no re-handshake.
      expect(ports.spawned).toHaveLength(2);
      expect(tap.calls[1]!.get("describe") ?? 0).toBe(1);
      expect(tap.calls[1]!.get("configure") ?? 0).toBe(1);
      expect(tap.calls[1]!.get("start") ?? 0).toBe(1);
      // The committed pointer points at 0.1.1.
      expect(ports.productRegistry.active("lexverdict")!.version).toBe("0.1.1");
      await engine2.close();
    } finally {
      ports.cleanup();
    }
  });
});

describe("TV-GW-13: reviewed rollback to a retained trusted generation", () => {
  test("re-verify + same start/health path; atomic pointer; rollback receipts; history retained", async () => {
    const tap = spawnTap([stubChild(okAdapter), stubChild(okAdapter), stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    const { svc } = await installLex(ports);
    try {
      const up = await runUpdate(svc, "0.1.1");
      expect(up.state).toBe("READY");
      const receiptCountAfterUpdate = ports.events.length;

      const rb = await svc.product.plan({
        kind: "rollback",
        source: "lexverdict",
        version: "0.1.0",
      });
      const acc = await svc.product.rollback({ plan: rb.plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.state).toBe("READY");
      // Same verification/start/health path as a forward operation, plus
      // the named rollback receipts.
      expect(op.events.map((e) => e.event)).toEqual([
        "ProductRollbackPlanned",
        "ProductFetchStarted",
        "ProductVerified",
        "ProductStaged",
        "ProductStartRequested",
        "ProductStarted",
        "ProductActivated",
        "ProductDrainRequested",
        "ProductStopped",
      ]);
      // Atomic pointer move to the retained-compatible generation.
      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.0");
      expect(active.state).toBe("READY");
      const target = ports.productRegistry
        .generations("lexverdict")
        .find((g) => g.version === "0.1.0")!;
      expect(target.generation).toBe(active.generation); // same retained row reactivated
      const rolled = ports.productRegistry
        .generations("lexverdict")
        .find((g) => g.version === "0.1.1")!;
      expect(rolled.state).toBe("STOPPED_RETAINED");
      expect(rolled.active).toBe(false);
      // The rolled-back generation re-ran the full adapter handshake.
      expect(tap.calls[2]!.get("describe")).toBe(1);
      expect(tap.calls[2]!.get("configure")).toBe(1);
      expect(tap.calls[2]!.get("start")).toBe(1);
      expect(tap.calls[2]!.get("health")).toBe(3);
      // History is not erased: every prior receipt survives and no
      // tombstone was written.
      expect(ports.events.length).toBe(receiptCountAfterUpdate + 9);
      expect(ports.events.some((e) => e.generation === "1")).toBe(true);
      expect(journalFor(ports, "tombstone")).toHaveLength(0);
      expect(ports.productRegistry.generations("lexverdict")).toHaveLength(2);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-14: revoked rollback target", () => {
  test("independently signed revocation set → POLICY_DENIED; no start or pointer change", async () => {
    const tap = spawnTap([stubChild(okAdapter), stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    const cas = countCas(ports);
    const { svc } = await installLex(ports);
    try {
      await runUpdate(svc, "0.1.1");
      const spawnCount = ports.spawned.length;
      const casCount = cas.calls.length;
      const journalCount = ports.journalLog.length;
      const pointerCount = journalFor(ports, "active_pointer").length;

      // The retained 0.1.0 digest lands in the revocation set.
      ports.trust = fixtureTrust({
        revocations: new Set([F.release1.manifest.package.archive.digest]),
      });
      const op = await runRollback(svc, "0.1.0");
      expect(op.error?.code).toBe("POLICY_DENIED");
      expect(op.events.map((e) => e.event)).not.toContain("ProductActivated");

      // No rollback start and no pointer change.
      expect(ports.spawned).toHaveLength(spawnCount);
      expect(cas.calls).toHaveLength(casCount);
      expect(journalFor(ports, "active_pointer")).toHaveLength(pointerCount);
      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.1");
      expect(active.state).toBe("READY");
      // Retained generation set unchanged: both rows remain, target digest intact.
      const gens = ports.productRegistry.generations("lexverdict");
      expect(gens).toHaveLength(2);
      const target = gens.find((g) => g.version === "0.1.0")!;
      expect(target.archive_digest).toBe(F.release1.manifest.package.archive.digest);
      expect(target.active).toBe(false);
      // The revocation check ran before any fetch/stage work.
      expect(ports.journalLog.length - journalCount).toBeLessThanOrEqual(2); // PLANNED+REJECTED only
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-15: irreversible data without verified snapshot", () => {
  test("rollback → UNSUPPORTED_COMPOSITION before pointer change; data retained", async () => {
    const tap = spawnTap([stubChild(okAdapter), stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    const cas = countCas(ports);
    const { svc } = await installLex(ports);
    try {
      await runUpdate(svc, "0.1.1");
      const gens = ports.productRegistry.generations("lexverdict");
      const cur = gens.find((g) => g.version === "0.1.1")!;
      const target = gens.find((g) => g.version === "0.1.0")!;
      // Sentinel data bytes in both generation data dirs.
      writeFileSync(join(cur.data_dir!, "sentinel.bin"), "v2-data");
      writeFileSync(join(target.data_dir!, "sentinel.bin"), "v1-data");
      // Current generation migrated irreversibly; the target has no
      // verified snapshot/inverse.
      ports.productRegistry.update(cur.slug, cur.generation, {
        irreversible_data: true,
      });
      expect(target.snapshot_verified).toBe(false);
      const spawnCount = ports.spawned.length;
      const casCount = cas.calls.length;
      const journalCount = ports.journalLog.length;

      const op = await runRollback(svc, "0.1.0");
      expect(op.error?.code).toBe("UNSUPPORTED_COMPOSITION");
      // Refused before any transition/receipt on the rollback target.
      expect(op.events).toHaveLength(0);
      expect(ports.journalLog.length).toBe(journalCount);
      expect(ports.spawned).toHaveLength(spawnCount);
      expect(cas.calls).toHaveLength(casCount);
      // Pointer, data bytes, and retained rows unchanged.
      expect(ports.productRegistry.active("lexverdict")!.version).toBe("0.1.1");
      expect(target.state).toBe("STOPPED_RETAINED");
      expect(readFileSync(join(cur.data_dir!, "sentinel.bin"), "utf8")).toBe("v2-data");
      expect(readFileSync(join(target.data_dir!, "sentinel.bin"), "utf8")).toBe("v1-data");
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-16: live required dependent", () => {
  test("uninstall a while b requires it → DEPENDENTS_PRESENT; both stay active; zero stops", async () => {
    const tap = spawnTap([stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    const { svc } = await installLex(ports);
    try {
      // Active product "b" whose signed manifest requires lexverdict.
      ports.putGeneration(
        retainedRow("b", "1.0.0", "1" as Count, "0".repeat(64), "", {
          state: "READY",
          active: true,
          dependencies: [dep("lexverdict", ">=0.1.0 <0.2.0", "required")],
        }),
      );
      // plan() refuses with cascade=false before any commit.
      await expect(
        svc.product.plan({ kind: "uninstall", source: "lexverdict" }),
      ).rejects.toMatchObject({ code: "DEPENDENTS_PRESENT" });
      // And a forged plan at engine level refuses before any drain/stop.
      await expect(
        svc.engine.uninstall({
          plan: planOf({ kind: "uninstall", from: "0.1.0", to: null }),
        }),
      ).rejects.toMatchObject({ code: "DEPENDENTS_PRESENT" });
      // Zero stop/drain calls anywhere; both products remain active.
      expect(tap.calls[0]!.get("drain") ?? 0).toBe(0);
      expect(tap.calls[0]!.get("stop") ?? 0).toBe(0);
      expect(ports.events.map((e) => e.event)).not.toContain("ProductStopped");
      expect(ports.events.map((e) => e.event)).not.toContain("ProductDrainRequested");
      expect(ports.productRegistry.active("lexverdict")!.state).toBe("READY");
      expect(ports.productRegistry.active("b")!.state).toBe("READY");
      expect(journalFor(ports, "tombstone")).toHaveLength(0);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

describe("TV-GW-17: reviewed uninstall", () => {
  test("drain→stop→unwire once→remove; data/receipts/tombstones preserved", async () => {
    const tap = spawnTap([stubChild(okAdapter)]);
    const ports = fixturePorts({ spawnAdapter: tap.spawnAdapter });
    const cas = countCas(ports);
    const rm = countRemoveStage(ports);
    const { svc } = await installLex(ports);
    try {
      const gen = ports.productRegistry.active("lexverdict")!;
      const stagedDir = gen.staged_dir!;
      const dataDir = gen.data_dir!;
      writeFileSync(join(dataDir, "sentinel.bin"), "retained-data");
      const receiptsBefore = ports.events.length;
      const installReceipts = [...ports.events];

      const { plan } = await svc.product.plan({ kind: "uninstall", source: "lexverdict" });
      const acc = await svc.product.uninstall({ plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.state).toBe("REMOVED");
      expect(op.events.map((e) => e.event)).toEqual([
        "ProductDrainRequested",
        "ProductStopped",
        "ProductUninstallStarted",
        "ProductUninstalled",
      ]);
      expect(op.events.map((e) => e.to)).toEqual([
        "DRAINING",
        "STOPPED_RETAINED",
        "UNINSTALLING",
        "REMOVED",
      ]);
      // Adapter drained/stopped exactly once each.
      expect(tap.calls[0]!.get("drain")).toBe(1);
      expect(tap.calls[0]!.get("stop")).toBe(1);
      // Config/registry unwired exactly once: one active-pointer CAS to
      // null, one package-link removal, one tombstone journal.
      expect(cas.calls.filter((c) => c.next === null)).toHaveLength(1);
      expect(rm.calls).toEqual([stagedDir]);
      expect(journalFor(ports, "tombstone")).toHaveLength(1);
      expect(ports.productRegistry.active("lexverdict")).toBeUndefined();
      expect(gen.state).toBe("REMOVED");
      // keep_data default: data bytes retained; package links removed;
      // every prior receipt preserved.
      expect(existsSync(dataDir)).toBe(true);
      expect(readFileSync(join(dataDir, "sentinel.bin"), "utf8")).toBe("retained-data");
      expect(existsSync(stagedDir)).toBe(false);
      expect(ports.events.slice(0, receiptsBefore)).toEqual(installReceipts);
      expect(ports.events.length).toBe(receiptsBefore + 4);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});

// ── E35 handoff + frozen fixture (TV-GW-55, TV-GW-56) ───────────────────

describe("TV-GW-55: E35 VisLineage→Sunlight handoff", () => {
  const bundleBody = J({
    schema: "vislineage.bundle/1",
    actions: [{ id: "act-1", kind: "write_file" }],
  });
  const nativeBundleHash = `sha256:${H(`VL-BUNDLE/1${bundleBody}`)}`;
  const bundleBytes = Buffer.from(
    J({ schema: "vislineage.bundle/1", hash: nativeBundleHash, body: bundleBody }),
  );
  const rawDigest = `sha256:${H(bundleBytes)}`;
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

  test("native commitment accepted; raw-bundle-hash substitution → PROVENANCE_INVALID, mismatch retained, no ACK", () => {
    // The two commitment domains must be distinct by construction.
    expect(nativeBundleHash).not.toBe(rawDigest);

    // Correct handoff → OPAQUE evidence; source_commitment preserves the
    // NATIVE bundle hash while the artifact digest binds the raw bytes.
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
        {
          handoff: { ...handoff, bundle: rawDigest },
          bundleHash: nativeBundleHash,
          bundleBytes,
        },
        (m) => retained.push(m),
      );
      acked = true; // no Sunlight success ACK may be emitted
    } catch (e) {
      expect(e).toBeInstanceOf(RpcError);
      expect((e as RpcError).code).toBe("PROVENANCE_INVALID");
    }
    expect(acked).toBe(false);
    // The native mismatch result is retained with both digests.
    expect(retained).toHaveLength(1);
    expect(retained[0]!.claimed_commitment).toBe(rawDigest);
    expect(retained[0]!.native_commitment).toBe(nativeBundleHash);
    expect(retained[0]!.raw_digest).toBe(rawDigest);

    // A wrong-format handoff also rejects with no ACK.
    retained.length = 0;
    expect(() =>
      checkSunlightHandoff(
        {
          handoff: { ...handoff, format: "vislineage-bundle/9" },
          bundleHash: nativeBundleHash,
          bundleBytes,
        },
        (m) => retained.push(m),
      ),
    ).toThrowError(expect.objectContaining({ code: "PROVENANCE_INVALID" }));
    expect(retained[0]!.format).toBe("vislineage-bundle/9");
  });
});

describe("TV-GW-56: frozen runs-on-latticeag fixture", () => {
  const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
  const EXAMPLE = join(ROOT, "examples", "runs-on-latticeag");

  test("frozen fixture, golden chain belief<verdict<approval<receipt, no cloud/production authority", () => {
    // The fixture exists: v1 legacy config with the exact schema + the
    // seven legacy adapter ids, plus the offline fixture switches.
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
    expect(cfg.sync.enabled).toBe(false); // network/sync denied offline

    // Frozen evidence inputs.
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
    // Fixture approvals carry test authority only — never a production
    // approver identity.
    expect(approvals[0]!.resolved_by).toBe("auto-approve-test");
    expect(approvals[0]!.receipt.tier).toBe("agent_asserted");
    const transcript = JSON.parse(
      readFileSync(join(EXAMPLE, "fixtures", "golden-transcript.v2.json"), "utf8"),
    ) as { kind: string; schema_version: number };
    expect(transcript.kind).toBe("latticeag.viscompile.transcript");
    expect(transcript.schema_version).toBe(2);

    // The frozen golden-chain contract, re-derived from the fixture's own
    // checked-in assertion source (not imported, per the vector's "no
    // production approval authority" constraint).
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
    expect(assertSrc).toContain('PRODUCTION_CONFIG = "env: production\\nreplicas: 3\\n"');

    // The recorded golden chain (frozen run output) satisfies the
    // contract when present in this workspace.
    const eventsPath = join(EXAMPLE, ".latticeag", "events.jsonl");
    if (existsSync(eventsPath)) {
      const events = readFileSync(eventsPath, "utf8")
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l) as {
          name: string;
          seq: number;
          producer?: { adapter?: string };
          payload?: { source?: string; resolved_by?: string };
        });
      const first = (name: string) =>
        events.find((e) => e.name === name)?.seq;
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
      // No cloud request or production approval authority: the recorded
      // receipt is fixture-sourced, the approver is the offline
      // auto-approve fixture, and no producer is a cloud/sync lane.
      const receiptEvent = events.find((e) => e.name === "receipt_issued")!;
      expect(receiptEvent.payload?.source).toBe("fixture");
      const approvalEvent = events.find((e) => e.name === "approval_granted")!;
      expect(approvalEvent.payload?.resolved_by).toBe("auto-approve-test");
      for (const e of events) {
        expect(e.producer?.adapter ?? "").not.toMatch(/cloud|sync/i);
      }
      // The exact corrected production output the chain asserts.
      const outPath = join(EXAMPLE, "out", "config.yaml");
      if (existsSync(outPath)) {
        expect(readFileSync(outPath, "utf8")).toBe("env: production\nreplicas: 3\n");
      }
    }
  });
});

/** Edge-table lookup used by the E-edge vectors. */
function resolvePlanEdgeCode(edge: string): string | null {
  const rel = buildRelease({
    dependencies: [dep("producer-x", "1.0.0", "required", edge)],
  });
  try {
    resolvePlan({
      kind: "install",
      source: "lexverdict",
      version: "0.1.0",
      target: {
        manifest: rel.manifest as ProductManifest,
        manifestDigest: H(J(rel.manifest)) as Hash,
      },
      manifests: new Map<string, ProductManifest[]>([
        ["lexverdict", [rel.manifest as ProductManifest]],
      ]),
      index: null,
      installed: [],
      opts: { now },
    });
    return null;
  } catch (e) {
    return e instanceof RpcError ? e.code : "unexpected";
  }
}
