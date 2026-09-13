import { appendFile, mkdtemp, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { rm } from "node:fs/promises";
import { Journal, type CommitMarker } from "./journal.js";
import { ensureLayout } from "./layout.js";
import { GENESIS_HASH, sha256hex } from "./util.js";

const roots: string[] = [];

async function tmpRoot(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "gw-journal-"));
  roots.push(dir);
  return dir;
}

afterEach(async () => {
  while (roots.length > 0) {
    await rm(roots.pop()!, { recursive: true, force: true });
  }
});

function fields(i: number) {
  return {
    records: [
      {
        lane: "legacy",
        segment: "s0000000000000001.jsonl",
        offset: (i - 1) * 8,
        length: 8,
        raw_sha256: sha256hex(`rec-${i}`),
      },
    ],
    objects: [],
    mutation: { v: 1, kind: "noop" },
    result_sha256: sha256hex(`result-${i}`),
  };
}

async function appendN(j: Journal, n: number): Promise<CommitMarker[]> {
  const out: CommitMarker[] = [];
  for (let i = 1; i <= n; i++) {
    const m = j.nextMarker(fields(i));
    await j.append(m);
    out.push(m);
  }
  return out;
}

describe("journal", () => {
  it("appends 3 markers and verifies the chain", async () => {
    const lay = await ensureLayout(await tmpRoot());
    const j = await Journal.open(lay);
    await j.verify();
    const markers = await appendN(j, 3);

    expect(markers[0]!.tx).toBe("1");
    expect(markers[0]!.previous).toBe(GENESIS_HASH);
    expect(markers[2]!.tx).toBe("3");

    // previous === sha256 of the prior raw line (including LF)
    const raw = await readFile(lay.commitsPath);
    const nl1 = raw.indexOf(0x0a);
    expect(markers[1]!.previous).toBe(sha256hex(raw.subarray(0, nl1 + 1)));

    const v = await j.verify();
    expect(v.status).toBe("OK");
    if (v.status === "OK") {
      expect(v.markers).toHaveLength(3);
      expect(v.headTx).toBe("3");
      expect(v.torn).toBeNull();
    }
    const lastNl = raw.lastIndexOf(0x0a);
    const prevNl = raw.lastIndexOf(0x0a, lastNl - 1);
    expect(j.head()).toEqual({
      tx: "3",
      hash: sha256hex(raw.subarray(prevNl + 1, lastNl + 1)),
    });
  });

  it("flags committed-byte corruption READ_ONLY at the corrupt tx", async () => {
    const lay = await ensureLayout(await tmpRoot());
    const j1 = await Journal.open(lay);
    await j1.verify();
    const markers = await appendN(j1, 3);

    // Flip one hex char inside line 1's result_sha256 (stays valid JSON).
    const buf = await readFile(lay.commitsPath);
    const nl = buf.indexOf(0x0a);
    const m1 = JSON.parse(buf.subarray(0, nl).toString()) as CommitMarker;
    const first = m1.result_sha256[0]!;
    m1.result_sha256 = (first === "a" ? "b" : "a") + m1.result_sha256.slice(1);
    const corrupted = Buffer.concat([
      Buffer.from(JSON.stringify(m1)),
      Buffer.from([0x0a]),
      buf.subarray(nl + 1),
    ]);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(lay.commitsPath, corrupted);

    const j2 = await Journal.open(lay);
    const v = await j2.verify();
    expect(v.status).toBe("READ_ONLY");
    if (v.status === "READ_ONLY") {
      expect(v.at).toBe(markers[0]!.tx);
      expect(v.reason).toContain("previous");
      expect(v.markers).toHaveLength(0);
    }
    // Committed bytes were not silently repaired: corrupted file intact.
    const after = await readFile(lay.commitsPath);
    expect(after.length).toBe(corrupted.length);
    // And appends are refused.
    await expect(j2.append(j2.nextMarker(fields(9)))).rejects.toMatchObject({
      code: "READ_ONLY",
    });
  });

  it("moves a torn uncommitted tail to quarantine and keeps the chain", async () => {
    const lay = await ensureLayout(await tmpRoot());
    const j = await Journal.open(lay);
    await j.verify();
    const markers = await appendN(j, 3);
    const sizeBefore = (await stat(lay.commitsPath)).size;

    const tornBytes = Buffer.from('{"v":1,"tx":"4","previous":"never-committed');
    await appendFile(lay.commitsPath, tornBytes);

    const v = await j.verify();
    expect(v.status).toBe("OK");
    if (v.status === "OK") {
      expect(v.headTx).toBe("3");
      expect(v.torn).not.toBeNull();
      expect(v.torn!.bytes).toBe(tornBytes.length);
      const q = await readFile(v.torn!.quarantine);
      expect(q.equals(tornBytes)).toBe(true);
    }
    // Journal truncated back to the committed end.
    expect((await stat(lay.commitsPath)).size).toBe(sizeBefore);
    // Quarantine listing shows the evidence.
    const names = await readdir(lay.quarantineDir);
    expect(names.length).toBeGreaterThan(0);
    // The chain continues cleanly at tx 4 — last committed head unchanged.
    const headBefore = j.head().hash;
    const m4 = j.nextMarker(fields(4));
    await j.append(m4);
    expect(m4.tx).toBe("4");
    expect(m4.previous).toBe(headBefore);
    const v2 = await j.verify();
    expect(v2.status).toBe("OK");
    if (v2.status === "OK") expect(v2.headTx).toBe("4");
  });
});
