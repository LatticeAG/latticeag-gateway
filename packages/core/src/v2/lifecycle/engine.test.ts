import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { F, release as mkRelease, schema } from "@latticeag/testkit";

import type { Release } from "../protocol/product.js";
import { LifecycleEngine } from "./engine.js";
import { createProductService } from "./service.js";
import { StubAdapterChild } from "./testing.js";
import type { MemoryPorts, StubScript } from "./testing.js";
import type { PlanSummary } from "./resolve.js";
import type { GenerationRow } from "./ports.js";
import {
  dep,
  fixturePorts,
  fixtureTrust,
  INDEX2,
  manifestOf,
  REVIEW,
  retainedRow,
} from "./testbed.js";

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
  health: () => ({ liveness: true, readiness: true, dependencies: [], native: { status: "ok" } }),
  drain: () => ({ in_flight: 0, uncertain: [] }),
  snapshot: () => ({ supported: false, objects: [] }),
  stop: () => ({ state: "STOPPED", uncertain: [] }),
};

/** Real spawned adapter via node; later calls return the given stub. */
function realThenStub(stub: () => StubAdapterChild) {
  let n = 0;
  return (cmd: readonly string[], dir: string, env: Record<string, string>) => {
    n += 1;
    if (n === 1) {
      return spawn(cmd[0]!, [...cmd.slice(1)], {
        cwd: dir,
        env: { ...process.env, ...env },
        stdio: ["pipe", "pipe", "pipe"],
      }) as never;
    }
    return stub();
  };
}

function planOf(summary: Partial<PlanSummary> & { kind: PlanSummary["kind"] }): PlanSummary {
  return {
    slug: "lexverdict",
    from: null,
    to: "0.1.0",
    manifest: "0".repeat(64) as PlanSummary["manifest"],
    archive: "",
    dependencies: [],
    grants: null,
    revisions: { config: "1", catalog: "1", registry: "1" },
    trust: "0".repeat(64) as PlanSummary["trust"],
    keep_data: true,
    cascade: false,
    ...summary,
  };
}

async function installLex(ports: MemoryPorts) {
  const svc = createProductService(ports, { engine: { liveProbes: false } });
  const { plan } = await svc.product.plan({
    kind: "install",
    source: "lexverdict",
    version: "0.1.0",
  });
  const acc = await svc.product.install({ plan, review: REVIEW });
  const op = await svc.waitOperation(acc.operation);
  return { svc, op };
}

describe("LifecycleEngine — TV-GW-04 normal install (real spawned adapter)", () => {
  test("install walks PLANNED→…→READY, emits the exact event sequence, one activation", async () => {
    const ports = fixturePorts();
    const { svc, op } = await installLex(ports);
    try {
      expect(op.state).toBe("READY");
      expect(op.events.map((e) => e.event)).toEqual(INSTALL_EVENTS);
      expect(op.events.filter((e) => e.event === "ProductActivated")).toHaveLength(1);
      expect(ports.spawned).toHaveLength(1); // exactly one adapter process
      expect(String(ports.spawned[0]!.cmd[1])).toBe("adapter.mjs");
      const active = ports.productRegistry.active("lexverdict");
      expect(active?.version).toBe("0.1.0");
      expect(active?.state).toBe("READY");
      expect(existsSync(join(active!.staged_dir!, "package", "adapter.mjs"))).toBe(true);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);
});

describe("LifecycleEngine — negative vectors", () => {
  test("TV-GW-05: corrupted signature → SIGNATURE_INVALID, zero spawns", async () => {
    const wire = structuredClone(F.release1.wire) as Release;
    wire.signatures[0]!.signature_hex = wire.signatures[0]!.signature_hex.slice(0, -2) + "00";
    const ports = fixturePorts();
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
      expect(op.state).toBe("SIGNATURE_INVALID");
      expect(ports.spawned).toHaveLength(0);
      const gen = ports.productRegistry.generations("lexverdict")[0]!;
      expect(gen.state).toBe("REJECTED");
      expect(gen.active).toBe(false);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });

  test("TV-GW-06: unapproved builder → PROVENANCE_INVALID, no spawn", async () => {
    const ports = fixturePorts({ trust: { builders: new Set(["rogue-builder"]) } });
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
      expect(ports.spawned).toHaveLength(0);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });

  test("TV-GW-07: path-traversal tar → POLICY_DENIED, nothing outside staging", async () => {
    const rel = mkRelease("0.1.0", { "../evil-traversal.txt": "owned" });
    const ports = fixturePorts();
    ports.putRelease(rel.wire as Release, rel.archive);
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
      expect(ports.spawned).toHaveLength(0);
      expect(existsSync(join(ports.stageRoot, "..", "evil-traversal.txt"))).toBe(false);
      expect(existsSync(join(ports.dataRoot, "evil-traversal.txt"))).toBe(false);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });

  test("TV-GW-08: postinstall script is never executed, product reaches READY", async () => {
    const pkg = JSON.parse(
      Buffer.from(F.release1.files["package/package.json"]).toString("utf8"),
    ) as Record<string, unknown>;
    pkg.scripts = { postinstall: `node -e "require('fs').writeFileSync('postinstall.ran','x')"` };
    const rel = mkRelease("0.1.0", { "package/package.json": JSON.stringify(pkg) });
    const ports = fixturePorts();
    ports.putRelease(rel.wire as Release, rel.archive);
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
      // Exactly one process spawn: the adapter. No npm/lifecycle script ran.
      expect(ports.spawned).toHaveLength(1);
      expect(existsSync(join(ports.stageRoot, "postinstall.ran"))).toBe(false);
      const gen = ports.productRegistry.active("lexverdict")!;
      expect(existsSync(join(gen.staged_dir!, "postinstall.ran"))).toBe(false);
      expect(existsSync(join(gen.staged_dir!, "package", "postinstall.ran"))).toBe(false);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);
});

describe("LifecycleEngine — update / rollback / uninstall", () => {
  test("TV-GW-11: failed candidate health leaves the old version active", async () => {
    let stops = 0;
    const ports = fixturePorts({
      spawnAdapter: realThenStub(
        () =>
          new StubAdapterChild({
            methods: {
              ...okAdapter,
              health: () => ({
                liveness: true,
                readiness: false, // candidate never becomes ready
                dependencies: [],
                native: {},
              }),
              stop: () => {
                stops += 1;
                return { state: "STOPPED", uncertain: [] };
              },
            },
          }),
      ),
    });
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await installLex(ports);
      const { plan } = await svc.product.plan({
        kind: "update",
        source: "lexverdict",
        version: "0.1.1",
      });
      const acc = await svc.product.update({ plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.error?.code).toBe("HEALTH_FAILED");
      expect(op.state).toBe("HEALTH_FAILED");
      // Old version is still active; candidate aborted and stopped.
      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.0");
      expect(active.state).toBe("READY");
      const events = op.events.map((e) => e.event);
      expect(events).toContain("ProductCandidateAbortRequested");
      expect(events).toContain("ProductStopped");
      expect(events).not.toContain("ProductActivated");
      expect(stops).toBe(1); // the failed candidate was stopped, not the old one
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);

  test("update success: pointer moves only after health; old drains", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await installLex(ports);
      const { plan } = await svc.product.plan({
        kind: "update",
        source: "lexverdict",
        version: "0.1.1",
      });
      const acc = await svc.product.update({ plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.state).toBe("READY");
      const events = op.events.map((e) => e.event);
      expect(events).toEqual([
        ...INSTALL_EVENTS, // candidate path, then the old generation drains
        "ProductDrainRequested",
        "ProductStopped",
      ]);
      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.1");
      const old = ports.productRegistry.generations("lexverdict")[0]!;
      expect(old.version).toBe("0.1.0");
      expect(old.state).toBe("STOPPED_RETAINED");
      expect(old.active).toBe(false);
      expect(ports.spawned).toHaveLength(2);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);

  test("TV-GW-13: rollback to a retained generation re-verifies and activates", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await installLex(ports);
      const up = await svc.product.plan({ kind: "update", source: "lexverdict", version: "0.1.1" });
      const upAcc = await svc.product.update({ plan: up.plan, review: REVIEW });
      await svc.waitOperation(upAcc.operation);
      const rb = await svc.product.plan({
        kind: "rollback",
        source: "lexverdict",
        version: "0.1.0",
      });
      const acc = await svc.product.rollback({ plan: rb.plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.state).toBe("READY");
      const events = op.events.map((e) => e.event);
      expect(events).toEqual([
        "ProductRollbackPlanned",
        "ProductFetchStarted",
        "ProductVerified",
        "ProductStaged",
        "ProductStartRequested",
        "ProductStarted",
        "ProductActivated",
        "ProductDrainRequested", // the superseded 0.1.1 drains
        "ProductStopped",
      ]);
      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.0");
      expect(ports.spawned).toHaveLength(3);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 45_000);

  test("TV-GW-14: revoked rollback target → POLICY_DENIED, pointer unchanged", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await installLex(ports);
      const up = await svc.product.plan({ kind: "update", source: "lexverdict", version: "0.1.1" });
      const upAcc = await svc.product.update({ plan: up.plan, review: REVIEW });
      await svc.waitOperation(upAcc.operation);
      // Revoke the retained target's archive digest.
      ports.trust = fixtureTrust({
        revocations: new Set([F.release1.manifest.package.archive.digest]),
      });
      const rb = await svc.product.plan({ kind: "rollback", source: "lexverdict", version: "0.1.0" });
      const acc = await svc.product.rollback({ plan: rb.plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.error?.code).toBe("POLICY_DENIED");
      const active = ports.productRegistry.active("lexverdict")!;
      expect(active.version).toBe("0.1.1");
      expect(ports.spawned).toHaveLength(2); // no rollback spawn
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 45_000);

  test("TV-GW-15: irreversible data without verified snapshot → UNSUPPORTED_COMPOSITION", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await installLex(ports);
      const up = await svc.product.plan({ kind: "update", source: "lexverdict", version: "0.1.1" });
      const upAcc = await svc.product.update({ plan: up.plan, review: REVIEW });
      await svc.waitOperation(upAcc.operation);
      // Current generation migrated data irreversibly; the rollback target
      // has no verified snapshot/inverse.
      const cur = ports.productRegistry.active("lexverdict")!;
      ports.productRegistry.update(cur.slug, cur.generation, { irreversible_data: true });
      const target = ports.productRegistry
        .generations("lexverdict")
        .find((g) => g.version === "0.1.0")!;
      expect(target.snapshot_verified).toBe(false);
      const rb = await svc.product.plan({ kind: "rollback", source: "lexverdict", version: "0.1.0" });
      const acc = await svc.product.rollback({ plan: rb.plan, review: REVIEW });
      const op = await svc.waitOperation(acc.operation);
      expect(op.error?.code).toBe("UNSUPPORTED_COMPOSITION");
      expect(ports.productRegistry.active("lexverdict")!.version).toBe("0.1.1");
      expect(ports.spawned).toHaveLength(2);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 45_000);

  test("TV-GW-16: live dependent blocks uninstall → DEPENDENTS_PRESENT, zero stops", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await installLex(ports);
      // A live product that requires lexverdict.
      ports.putGeneration(
        retainedRow("dep1", "1.0.0", "1" as GenerationRow["generation"], "0".repeat(64), "", {
          state: "READY",
          active: true,
          dependencies: [dep("lexverdict", ">=0.1.0 <0.2.0")],
        }),
      );
      // plan() itself must refuse — resolvePlan enforces it pre-commit.
      await expect(
        svc.product.plan({ kind: "uninstall", source: "lexverdict" }),
      ).rejects.toMatchObject({ code: "DEPENDENTS_PRESENT" });
      // And a forged plan at engine level refuses before any stop.
      const engine = svc.engine;
      await expect(
        engine.uninstall({ plan: planOf({ kind: "uninstall", from: "0.1.0", to: null }) }),
      ).rejects.toMatchObject({ code: "DEPENDENTS_PRESENT" });
      const events = ports.events.map((e) => e.event);
      expect(events).not.toContain("ProductStopped");
      expect(events).not.toContain("ProductDrainRequested");
      expect(ports.productRegistry.active("lexverdict")?.state).toBe("READY");
      expect(ports.productRegistry.active("dep1")?.state).toBe("READY");
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);

  test("TV-GW-17: clean uninstall — DRAINING→STOPPED_RETAINED→UNINSTALLING→REMOVED, data retained", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await installLex(ports);
      const gen = ports.productRegistry.active("lexverdict")!;
      const dataDir = gen.data_dir!;
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
      expect(gen.state).toBe("REMOVED");
      expect(ports.productRegistry.active("lexverdict")).toBeUndefined();
      // keep_data default: data dir retained, package links removed.
      expect(existsSync(dataDir)).toBe(true);
      expect(existsSync(gen.staged_dir!)).toBe(false);
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);
});

describe("LifecycleEngine — crash recovery (TV-GW-12)", () => {
  test("marker-fsync/pre-projection crash: pointer preserved, one indexed activation, probe before readiness", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    let probes = 0;
    (ports as { probeGeneration?: (r: GenerationRow) => Promise<boolean> }).probeGeneration =
      () => {
        probes += 1;
        return Promise.resolve(true);
      };
    try {
      const { plan } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      // Crash right at the projection journal — after the active-pointer
      // marker fsync but before the projection lands.
      ports.crashOn("projection");
      const acc = await svc.product.install({ plan, review: REVIEW });
      await svc.waitOperation(acc.operation).catch(() => undefined);
      const gen = ports.productRegistry.generations("lexverdict")[0]!;
      expect(gen.state).toBe("HEALTHCHECKING");
      expect(gen.active).toBe(true); // committed pointer preserved
      const projectionsBefore = ports.journalLog.filter((j) => j.type === "projection").length;
      expect(projectionsBefore).toBe(1); // indexed once, pre-crash
      const activatedBefore = ports.events.filter((e) => e.event === "ProductActivated").length;
      expect(activatedBefore).toBe(0);

      // Daemon restart: fresh engine over the same durable ports.
      const engine2 = new LifecycleEngine(ports, { liveProbes: false });
      await engine2.recoverAfterCrash("active_pointer");
      const after = ports.productRegistry.generations("lexverdict")[0]!;
      expect(after.state).toBe("READY");
      expect(after.activation_indexed).toBe(true);
      expect(after.projected).toBe(true);
      expect(probes).toBe(1); // probed before readiness
      const projections = ports.journalLog.filter((j) => j.type === "projection").length;
      expect(projections).toBe(1); // still exactly one activation index
      const activated = ports.events.filter((e) => e.event === "ProductActivated").length;
      expect(activated).toBe(1); // exactly one activation event overall
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);
});
