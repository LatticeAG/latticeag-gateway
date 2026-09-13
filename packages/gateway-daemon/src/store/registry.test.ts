import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { CommitMarker } from "./journal.js";
import { Registry } from "./registry.js";
import { GENESIS_HASH, pathExists, sha256hex, type Json } from "./util.js";

const roots: string[] = [];

async function tmpRoot(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "gw-registry-"));
  roots.push(dir);
  return dir;
}

afterEach(async () => {
  while (roots.length > 0) {
    await rm(roots.pop()!, { recursive: true, force: true });
  }
});

function marker(tx: string, mutation: Json, records: CommitMarker["records"] = []): CommitMarker {
  return {
    v: 1,
    tx,
    previous: GENESIS_HASH,
    records,
    objects: [],
    mutation,
    result_sha256: sha256hex(`result-${tx}`),
  };
}

const h = (s: string) => sha256hex(s);

describe("registry", () => {
  it("applies event mutations and preserves slot conflict candidates", async () => {
    const reg = Registry.open(join(await tmpRoot(), "registry.sqlite"), {
      instance: "inst-a",
    });
    reg.applyCommit(
      marker("1", {
        v: 1,
        kind: "events",
        events: [
          { workspace: "w", source: "s", stream: "st", seq: "1", hash: h("cand-a") },
        ],
      }),
    );
    reg.applyCommit(
      marker("2", {
        v: 1,
        kind: "events",
        events: [
          { workspace: "w", source: "s", stream: "st", seq: "1", hash: h("cand-b") },
        ],
      }),
    );
    const rows = reg.eventSlotCandidates("w", "s", "st", "1");
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.hash))).toEqual(
      new Set([h("cand-a"), h("cand-b")]),
    );
    expect(rows.every((r) => r.conflict === 1)).toBe(true);
    expect(reg.lastIndexedTx()).toBe("2");
    reg.close();
  });

  it("indexes cursors, operations, runs, products, grants, approvals", async () => {
    const reg = Registry.open(join(await tmpRoot(), "registry.sqlite"), {
      instance: "inst-a",
    });
    reg.applyCommit(
      marker("1", {
        v: 1,
        kind: "batch",
        mutations: [
          {
            v: 1,
            kind: "cursors",
            cursors: [
              {
                instance: "inst-a",
                cursor: "c0000000000000001:1",
                lane: "legacy",
                segment: "s0000000000000001.jsonl",
                offset: 0,
                length: 8,
                raw_sha256: h("line1"),
              },
            ],
          },
          {
            v: 1,
            kind: "operations",
            operations: [
              {
                principal: "op",
                id: "op-1",
                request_hash: h("req"),
                result_json: "{\"ok\":true}",
                state: "COMPLETED",
              },
            ],
          },
          {
            v: 1,
            kind: "runs",
            runs: [{ legacy_namespace: "v1", ulid: "01JABC", owner: "cli" }],
          },
          {
            v: 1,
            kind: "products",
            products: [
              { slug: "proof", instance: "p0", generation: 1, state: "ENABLED", active: true },
            ],
          },
          {
            v: 1,
            kind: "grants",
            grants: [
              { peer: "cloud", key: "k1", revision: "3", scopes: ["read"], state: "ACTIVE" },
            ],
          },
          {
            v: 1,
            kind: "approvals",
            approvals: [
              { home: "local", request: "req-1", revision: "1", state: "PENDING" },
            ],
          },
        ],
      }),
    );
    expect(reg.cursorLookup("inst-a", "c0000000000000001:1")?.lane).toBe("legacy");
    expect(reg.operationLookup("op", "op-1")?.state).toBe("COMPLETED");
    expect(reg.operationByRequestHash(h("req"))?.id).toBe("op-1");
    expect(reg.runLookup("v1", "01JABC")?.owner).toBe("cli");
    expect(reg.activeProduct("proof", "p0")?.generation).toBe(1);
    expect(reg.grantLookup("cloud", "k1")[0]!.revision).toBe("3");
    expect(reg.approvalLookup("local", "req-1")[0]!.state).toBe("PENDING");
    reg.close();
  });

  it("rebuilds the derived index exactly once after the file is dropped", async () => {
    const root = await tmpRoot();
    const path = join(root, "registry.sqlite");
    const markers = [
      marker("1", {
        v: 1,
        kind: "events",
        events: [
          { workspace: "w", source: "s", stream: "st", seq: "1", hash: h("a") },
          { workspace: "w", source: "s", stream: "st", seq: "1", hash: h("b") },
        ],
      }),
      marker("2", {
        v: 1,
        kind: "operations",
        operations: [
          { principal: "op", id: "o1", request_hash: h("rq"), state: "COMPLETED" },
        ],
      }),
    ];
    let reg = Registry.open(path, { instance: "inst-a" });
    for (const m of markers) reg.applyCommit(m);
    reg.close();

    // Kill-simulate: drop the sqlite file (and WAL sidecars) entirely.
    for (const suffix of ["", "-wal", "-shm"]) {
      await rm(`${path}${suffix}`, { force: true });
    }
    expect(await pathExists(path)).toBe(false);

    reg = Registry.open(path, { instance: "inst-a" });
    expect(reg.lastIndexedTx()).toBeNull();
    reg.rebuildFromJournal(markers);
    expect(reg.lastIndexedTx()).toBe("2");
    // Exactly-once: one operation row, both conflict candidates retained.
    expect(reg.operationLookup("op", "o1")).not.toBeNull();
    const rows = reg.eventSlotCandidates("w", "s", "st", "1");
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.conflict === 1)).toBe(true);
    reg.close();
  });

  it("auto-indexes transport cursors from marker records via resolver", async () => {
    const reg = Registry.open(join(await tmpRoot(), "registry.sqlite"), {
      instance: "inst-a",
      resolveCursor: (loc) => `c0000000000000001:${loc.offset + 1}`,
    });
    reg.applyCommit(
      marker("1", { v: 1, kind: "noop" }, [
        {
          lane: "legacy",
          segment: "s0000000000000001.jsonl",
          offset: 0,
          length: 9,
          raw_sha256: h("x"),
        },
      ]),
    );
    const row = reg.cursorLookup("inst-a", "c0000000000000001:1");
    expect(row).not.toBeNull();
    expect(row!.segment).toBe("s0000000000000001.jsonl");
    reg.close();
  });

  it("rejects a mismatched persisted instance identity", async () => {
    const path = join(await tmpRoot(), "registry.sqlite");
    const reg = Registry.open(path, { instance: "inst-a" });
    reg.close();
    expect(() => Registry.open(path, { instance: "inst-b" })).toThrowError(
      expect.objectContaining({ code: "IDENTITY_MISMATCH" }),
    );
  });
});
