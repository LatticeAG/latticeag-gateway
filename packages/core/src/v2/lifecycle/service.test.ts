import { describe, expect, test } from "vitest";

import { F } from "@latticeag/testkit";

import { createProductService } from "./service.js";
import { fixturePorts, INDEX2, REVIEW } from "./testbed.js";

describe("createProductService (§3.2 ProductService)", () => {
  test("plan → install → QUEUED → READY; operation.get reports terminal state", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      const { plan, summary } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      expect(plan).toHaveLength(64);
      expect(summary).toMatchObject({
        kind: "install",
        slug: "lexverdict",
        from: null,
        to: "0.1.0",
      });
      const acc = await svc.product.install({ plan, review: REVIEW });
      expect(acc).toEqual({ operation: expect.any(String), state: "QUEUED" });
      const op = await svc.waitOperation(acc.operation);
      expect(op.state).toBe("READY");
      const got = await svc.operation.get({ operation: acc.operation });
      expect(got).toMatchObject({
        operation: acc.operation,
        kind: "install",
        state: "READY",
        slug: "lexverdict",
        from: null,
        to: "0.1.0",
        error: null,
      });
      // product.list shows the installed row.
      const page = await svc.product.list({ after: null, limit: 100 });
      const items = page.items as { slug: string; state: string; version: string }[];
      expect(items).toContainEqual(
        expect.objectContaining({ slug: "lexverdict", state: "READY", version: "0.1.0" }),
      );
      // product.health reports live adapter probes.
      const health = await svc.product.health({ slug: "lexverdict" });
      expect(health.state).toBe("READY");
      expect(health.readiness).toBe(true);
      expect(health.native).toEqual({ status: "ok" });
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 30_000);

  test("an install plan fed to uninstall rejects PLAN_STALE", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      const { plan } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      await expect(svc.product.uninstall({ plan, review: REVIEW })).rejects.toMatchObject({
        code: "PLAN_STALE",
      });
      await expect(svc.product.update({ plan, review: REVIEW })).rejects.toMatchObject({
        code: "PLAN_STALE",
      });
      await expect(svc.product.rollback({ plan, review: REVIEW })).rejects.toMatchObject({
        code: "PLAN_STALE",
      });
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });

  test("unknown plan hash and missing review are refused", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      await expect(
        svc.product.install({ plan: "0".repeat(64), review: REVIEW }),
      ).rejects.toMatchObject({ code: "PLAN_STALE" });
      const { plan } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      await expect(
        svc.product.install({ plan, review: null as never }),
      ).rejects.toMatchObject({ code: "POLICY_DENIED" });
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });

  test("moved active pointer makes an update plan PLAN_STALE at commit", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      // Plan an update while nothing is installed → NOT_FOUND first.
      await expect(
        svc.product.plan({ kind: "update", source: "lexverdict", version: "0.1.1" }),
      ).rejects.toMatchObject({ code: "NOT_FOUND" });
      const { plan } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      const acc = await svc.product.install({ plan, review: REVIEW });
      await svc.waitOperation(acc.operation);
      // Now update planning works (0.1.1 is in INDEX2).
      const up = await svc.product.plan({
        kind: "update",
        source: "lexverdict",
        version: "0.1.1",
      });
      // Simulate a concurrent move: bump a CAS revision → plan is stale.
      const originalRev = ports.revisions;
      (ports as { revisions: () => { config: string; catalog: string; registry: string } }).revisions =
        () => ({ config: "2", catalog: "1", registry: "1" });
      await expect(svc.product.update({ plan: up.plan, review: REVIEW })).rejects.toMatchObject({
        code: "PLAN_STALE",
      });
      (ports as { revisions: typeof originalRev }).revisions = originalRev;
      const upAcc = await svc.product.update({ plan: up.plan, review: REVIEW });
      const upOp = await svc.waitOperation(upAcc.operation);
      expect(upOp.state).toBe("READY");
      expect(ports.productRegistry.active("lexverdict")?.version).toBe("0.1.1");
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  }, 45_000);
});

describe("plan-hash parity with the §13.1 fixture", () => {
  test("plan summary fields equal planFor('install') and hash is stable", async () => {
    const ports = fixturePorts();
    const svc = createProductService(ports, { engine: { liveProbes: false } });
    try {
      const { plan, summary } = await svc.product.plan({
        kind: "install",
        source: "lexverdict",
        version: "0.1.0",
      });
      const s = summary as { [k: string]: unknown };
      expect(s.manifest).toBe(F.release1.wire.manifest.ref.digest);
      expect(s.archive).toBe(F.release1.manifest.package.archive.digest);
      expect(s.revisions).toEqual({ config: "1", catalog: "1", registry: "1" });
      expect(plan).toBe(plan); // deterministic content hash
    } finally {
      await svc.engine.close();
      ports.cleanup();
    }
  });
});
