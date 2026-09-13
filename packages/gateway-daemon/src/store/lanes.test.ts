import {
  appendFile,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  LaneWriter,
  manifestName,
  parseCursor,
  recoverLane,
  type ActivePointer,
  type SealManifest,
} from "./lanes.js";
import { sha256hex } from "./util.js";

const roots: string[] = [];

async function tmpRoot(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "gw-lanes-"));
  roots.push(dir);
  return dir;
}

afterEach(async () => {
  while (roots.length > 0) {
    await rm(roots.pop()!, { recursive: true, force: true });
  }
});

function rec(n: number): Buffer {
  return Buffer.from(JSON.stringify({ n }), "utf8");
}

describe("lanes", () => {
  it("assigns cursors c<16hex lane-ordinal>:<decimal ordinal>", async () => {
    const dir = join(await tmpRoot(), "bus", "legacy");
    const w = await LaneWriter.create(dir, { lane: "legacy", ordinal: 1n });
    const a1 = await w.append(rec(1));
    const a2 = await w.append(rec(2));
    const a3 = await w.append(rec(3));
    expect(a1.cursor).toBe("c0000000000000001:1");
    expect(a2.cursor).toBe("c0000000000000001:2");
    expect(a3.cursor).toBe("c0000000000000001:3");
    expect(a1.segment).toBe("s0000000000000001.jsonl");
    expect(a1.offset).toBe(0);
    expect(a2.offset).toBe(a1.length);
    expect(a1.raw_sha256).toBe(
      sha256hex(Buffer.concat([rec(1), Buffer.from([0x0a])])),
    );
    expect(parseCursor(a3.cursor)).toEqual({ laneOrdinal: 1n, recordOrdinal: 3n });
    await w.close();
  });

  it("rotates at segment_bytes, seals manifest, swaps active.json atomically", async () => {
    const dir = join(await tmpRoot(), "bus", "legacy");
    const w = await LaneWriter.create(dir, {
      lane: "legacy",
      ordinal: 1n,
      segmentBytes: 24, // each record line is 8 bytes ("{\"n\":N}\n")
    });
    for (let i = 1; i <= 4; i++) await w.append(rec(i));
    await w.close();

    const seg1 = join(dir, "s0000000000000001.jsonl");
    const manRaw = await readFile(join(dir, manifestName("s0000000000000001.jsonl")), "utf8");
    const man = JSON.parse(manRaw) as SealManifest;
    const segBytes = await readFile(seg1);
    expect(man.v).toBe(1);
    expect(man.segment).toBe("s0000000000000001.jsonl");
    expect(man.length).toBe(24);
    expect(man.record_count).toBe(3);
    expect(man.first_cursor).toBe("c0000000000000001:1");
    expect(man.last_cursor).toBe("c0000000000000001:3");
    expect(man.raw_sha256).toBe(sha256hex(segBytes));
    expect((await stat(seg1)).size).toBe(24);

    const active = JSON.parse(
      await readFile(join(dir, "active.json"), "utf8"),
    ) as ActivePointer;
    expect(active.segment).toBe("s0000000000000002.jsonl");
    expect(active.next_record_ordinal).toBe("4");

    // Atomic swap leaves no tmp files behind.
    const names = await readdir(dir);
    expect(names.filter((n) => n.includes(".tmp-"))).toHaveLength(0);
    expect((await stat(join(dir, "s0000000000000002.jsonl"))).size).toBe(8);
  });

  it("rotates on segment age (maxAgeMs) too", async () => {
    const dir = join(await tmpRoot(), "bus", "proof", "p1");
    const w = await LaneWriter.create(dir, {
      lane: "proof/p1",
      ordinal: 7n,
      segmentBytes: 1 << 20,
      maxAgeMs: -1, // every append on a non-empty segment rotates
    });
    await w.append(rec(1));
    await w.append(rec(2));
    await w.close();
    const names = (await readdir(dir)).sort();
    expect(names).toContain("s0000000000000001.jsonl");
    expect(names).toContain("s0000000000000001.manifest.json");
    expect(names).toContain("s0000000000000002.jsonl");
  });

  it("quarantines a torn tail on recover and resumes ordinals", async () => {
    const root = await tmpRoot();
    const dir = join(root, "bus", "legacy");
    const quarantineDir = join(root, "journal", "quarantine");
    const w = await LaneWriter.create(dir, { lane: "legacy", ordinal: 1n });
    await w.append(rec(1));
    await w.append(rec(2));
    await w.fsync();
    const committed = await stat(join(dir, "s0000000000000001.jsonl"));
    const tail = Buffer.from('{"torn":true,"x"');
    await appendFile(join(dir, "s0000000000000001.jsonl"), tail);
    await w.close();

    const rep = await recoverLane(dir, { quarantineDir });
    expect(rep.corrupt).toHaveLength(0);
    expect(rep.torn_bytes_moved).toBe(tail.length);
    expect(rep.orphans).toHaveLength(1);
    const preserved = await readFile(rep.orphans[0]!);
    expect(preserved.equals(tail)).toBe(true);
    expect((await stat(join(dir, "s0000000000000001.jsonl"))).size).toBe(
      committed.size,
    );
    expect(rep.next_record_ordinal).toBe(3);

    const { writer } = await LaneWriter.open(dir, {
      lane: "legacy",
      ordinal: 1n,
      quarantineDir,
    });
    const a3 = await writer.append(rec(3));
    expect(a3.cursor).toBe("c0000000000000001:3");
    await writer.close();
  });

  it("rejects records over the profile cap before materializing", async () => {
    const dir = join(await tmpRoot(), "bus", "legacy");
    const w = await LaneWriter.create(dir, {
      lane: "legacy",
      ordinal: 1n,
      maxRecordBytes: 16,
    });
    await expect(w.append(Buffer.alloc(17, 0x41))).rejects.toMatchObject({
      code: "OBJECT_LIMIT",
    });
    await expect(w.append(Buffer.from('{"a":1}\nx'))).rejects.toMatchObject({
      code: "BAD_RECORD",
    });
    await expect(w.append(Buffer.alloc(0))).rejects.toMatchObject({
      code: "BAD_RECORD",
    });
    // Nothing was written.
    expect((await stat(join(dir, "s0000000000000001.jsonl"))).size).toBe(0);
    await w.close();
  });
});
