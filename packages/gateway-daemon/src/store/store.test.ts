import {
  appendFile,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { CommitMarker } from "./journal.js";
import { layout } from "./layout.js";
import { GatewayStore } from "./store.js";
import { GENESIS_HASH, sha256hex } from "./util.js";

const roots: string[] = [];

async function tmpRoot(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "gw-store-"));
  roots.push(dir);
  return dir;
}

afterEach(async () => {
  while (roots.length > 0) {
    await rm(roots.pop()!, { recursive: true, force: true });
  }
});

const noopMutation = { v: 1, kind: "noop" } as const;

async function readMarkers(root: string): Promise<CommitMarker[]> {
  const lay = layout(root);
  const raw = await readFile(lay.commitsPath);
  return raw
    .toString("utf8")
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as CommitMarker);
}

describe("store", () => {
  it("runs the full §2.3 commit pipeline and returns tx+cursors", async () => {
    const root = await tmpRoot();
    const store = await GatewayStore.open(root, {
      instance: "test",
      segmentBytes: 1 << 20,
    });
    expect(store.status()).toBe("READY");

    const res = await store.commit({
      records: [
        { lane: "legacy", data: '{"e":1}' },
        { lane: "proof", partition: "p1", data: '{"p":1}' },
      ],
      objects: [Buffer.from("obj-bytes")],
      mutation: {
        v: 1,
        kind: "events",
        events: [
          {
            workspace: "w",
            source: "s",
            stream: "st",
            seq: "1",
            hash: sha256hex("ev"),
          },
        ],
      },
      result_sha256: sha256hex("result"),
    });
    expect(res.tx).toBe("1");
    expect(res.cursors).toEqual([
      "c0000000000000001:1",
      "c0000000000000002:1",
    ]);
    expect(res.objects[0]!.digest).toBe(sha256hex("obj-bytes"));

    // Marker shape: closed, previous=genesis, records locate lines.
    const markers = await readMarkers(root);
    expect(markers).toHaveLength(1);
    const m = markers[0]!;
    expect(Object.keys(m).sort()).toEqual(
      ["v", "tx", "previous", "records", "objects", "mutation", "result_sha256"].sort(),
    );
    expect(m.previous).toBe(GENESIS_HASH);
    expect(m.records).toHaveLength(2);
    expect(m.objects).toEqual([
      { digest: sha256hex("obj-bytes"), bytes: "9" },
    ]);

    // Second commit chains on the first marker's raw line.
    const res2 = await store.commit({
      records: [{ lane: "legacy", data: '{"e":2}' }],
      mutation: noopMutation,
      result_sha256: sha256hex("result2"),
    });
    expect(res2.tx).toBe("2");
    const markers2 = await readMarkers(root);
    const raw = await readFile(layout(root).commitsPath);
    const nl1 = raw.indexOf(0x0a);
    expect(markers2[1]!.previous).toBe(sha256hex(raw.subarray(0, nl1 + 1)));

    // Registry projections + auto cursor index.
    expect(
      store.registry.eventSlotCandidates("w", "s", "st", "1"),
    ).toHaveLength(1);
    const crow = store.registry.cursorLookup("test", "c0000000000000001:1");
    expect(crow).not.toBeNull();
    expect(crow!.lane).toBe("legacy");
    expect(store.registry.lastIndexedTx()).toBe("2");

    // Reads return exact committed bytes.
    const read = await store.readCursor("c0000000000000001:1");
    expect(read!.data.toString("utf8")).toBe('{"e":1}');
    const scanned: string[] = [];
    for await (const r of store.laneScan("legacy")) scanned.push(r.data.toString("utf8"));
    expect(scanned).toEqual(['{"e":1}', '{"e":2}']);
    const scannedFrom: string[] = [];
    for await (const r of store.laneScan("legacy", { from: "c0000000000000001:1" })) {
      scannedFrom.push(r.data.toString("utf8"));
    }
    expect(scannedFrom).toEqual(['{"e":2}']);

    // kv meta
    store.kv.set("boot_identity", "boot-1");
    expect(store.kv.get("boot_identity")).toBe("boot-1");
    await store.close();
  });

  it("reports orphans for lane bytes without a marker and never serves them", async () => {
    const root = await tmpRoot();
    const store = await GatewayStore.open(root, { instance: "test" });
    await store.commit({
      records: [{ lane: "legacy", data: '{"e":1}' }],
      mutation: noopMutation,
      result_sha256: sha256hex("r1"),
    });
    await store.close();

    // Orphan injection: complete line appended with no commit marker.
    const lay = layout(root);
    const seg = join(lay.legacyLaneDir, "s0000000000000001.jsonl");
    await appendFile(seg, Buffer.from('{"ghost":true}\n'));

    const store2 = await GatewayStore.open(root, { instance: "test" });
    expect(store2.status()).toBe("READY");
    expect(store2.recovery.orphans.length).toBeGreaterThan(0);
    expect(store2.recovery.torn_bytes_moved).toBeGreaterThan(0);
    const scanned: string[] = [];
    for await (const r of store2.laneScan("legacy")) scanned.push(r.data.toString("utf8"));
    expect(scanned).toEqual(['{"e":1}']);
    // Orphan bytes preserved in quarantine.
    const q = await store2.quarantineList();
    expect(q.length).toBeGreaterThan(0);
    const preserved = await readFile(q[0]!.path);
    expect(preserved.toString("utf8")).toContain("ghost");
    // Appends resume on the truncated committed tail.
    const res = await store2.commit({
      records: [{ lane: "legacy", data: '{"e":2}' }],
      mutation: noopMutation,
      result_sha256: sha256hex("r2"),
    });
    expect(res.cursors).toEqual(["c0000000000000001:2"]);
    await store2.close();
  });

  it("opens READ_ONLY on committed journal corruption and refuses commits", async () => {
    const root = await tmpRoot();
    const store = await GatewayStore.open(root, { instance: "test" });
    await store.commit({
      records: [{ lane: "legacy", data: '{"e":1}' }],
      mutation: noopMutation,
      result_sha256: sha256hex("r1"),
    });
    await store.commit({
      records: [{ lane: "legacy", data: '{"e":2}' }],
      mutation: noopMutation,
      result_sha256: sha256hex("r2"),
    });
    await store.commit({
      records: [{ lane: "legacy", data: '{"e":3}' }],
      mutation: noopMutation,
      result_sha256: sha256hex("r3"),
    });
    await store.close();

    // Flip a hex char inside committed line 2's result_sha256. Marker 3's
    // previous-link then fails → the unverifiable region starts at tx 2.
    const lay = layout(root);
    const buf = await readFile(lay.commitsPath);
    const nl1 = buf.indexOf(0x0a);
    const nl2 = buf.indexOf(0x0a, nl1 + 1);
    const m2 = JSON.parse(buf.subarray(nl1 + 1, nl2).toString()) as CommitMarker;
    m2.result_sha256 = (m2.result_sha256[0] === "a" ? "b" : "a") + m2.result_sha256.slice(1);
    await writeFile(
      lay.commitsPath,
      Buffer.concat([
        buf.subarray(0, nl1 + 1),
        Buffer.from(JSON.stringify(m2)),
        buf.subarray(nl2),
      ]),
    );

    const store2 = await GatewayStore.open(root, { instance: "test" });
    expect(store2.status()).toBe("READ_ONLY");
    expect(store2.recovery.at).toBe("2");
    await expect(
      store2.commit({
        records: [{ lane: "legacy", data: '{"e":3}' }],
        mutation: noopMutation,
        result_sha256: sha256hex("r3"),
      }),
    ).rejects.toMatchObject({ code: "READ_ONLY" });
    // Reads still serve the verified prefix.
    const scanned: string[] = [];
    for await (const r of store2.laneScan("legacy")) scanned.push(r.data.toString("utf8"));
    expect(scanned).toEqual(['{"e":1}']);
    await store2.close();
  });

  it("rebuilds the registry exactly once when registry.sqlite is dropped", async () => {
    const root = await tmpRoot();
    const store = await GatewayStore.open(root, { instance: "test" });
    await store.commit({
      records: [{ lane: "legacy", data: '{"e":1}' }],
      mutation: {
        v: 1,
        kind: "events",
        events: [
          { workspace: "w", source: "s", stream: "st", seq: "1", hash: sha256hex("a") },
          { workspace: "w", source: "s", stream: "st", seq: "1", hash: sha256hex("b") },
        ],
      },
      result_sha256: sha256hex("r1"),
    });
    await store.commit({
      records: [{ lane: "legacy", data: '{"e":2}' }],
      mutation: {
        v: 1,
        kind: "operations",
        operations: [
          { principal: "op", id: "o1", request_hash: sha256hex("rq"), state: "COMPLETED" },
        ],
      },
      result_sha256: sha256hex("r2"),
    });
    await store.close();

    const lay = layout(root);
    for (const suffix of ["", "-wal", "-shm"]) {
      await rm(`${lay.registryPath}${suffix}`, { force: true });
    }

    const store2 = await GatewayStore.open(root, { instance: "test" });
    expect(store2.status()).toBe("READY");
    expect(store2.recovery.replayed_tx).toBe(2);
    expect(store2.registry.lastIndexedTx()).toBe("2");
    const rows = store2.registry.eventSlotCandidates("w", "s", "st", "1");
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.conflict === 1)).toBe(true);
    expect(store2.registry.operationLookup("op", "o1")?.state).toBe("COMPLETED");
    // Cursor index rebuilt too.
    expect(store2.registry.cursorLookup("test", "c0000000000000001:2")).not.toBeNull();
    const read = await store2.readCursor("c0000000000000001:2");
    expect(read!.data.toString("utf8")).toBe('{"e":2}');
    await store2.close();
  });
});
