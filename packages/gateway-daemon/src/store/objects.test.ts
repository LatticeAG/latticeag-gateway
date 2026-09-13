import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ObjectStore } from "./objects.js";
import { sha256hex } from "./util.js";

const roots: string[] = [];

async function tmpRoot(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "gw-objects-"));
  roots.push(dir);
  return dir;
}

afterEach(async () => {
  while (roots.length > 0) {
    await rm(roots.pop()!, { recursive: true, force: true });
  }
});

describe("objects", () => {
  it("put/get round-trips exact bytes at objects/sha256/<first2>/<hex>", async () => {
    const dir = join(await tmpRoot(), "objects", "sha256");
    const os = new ObjectStore(dir);
    const payload = Buffer.from('{"opaque":"native-bytes"}', "utf8");
    const put = await os.put(payload);
    expect(put.digest).toBe(sha256hex(payload));
    expect(put.bytes).toBe(payload.length);
    expect(put.created).toBe(true);

    const path = os.pathFor(put.digest);
    expect(path).toBe(join(dir, put.digest.slice(0, 2), put.digest));
    expect((await stat(path)).mode & 0o777).toBe(0o600);

    const got = await os.get(put.digest);
    expect(got.equals(payload)).toBe(true);
    expect(await os.has(put.digest)).toBe(true);
    // Idempotent put.
    const again = await os.put(payload);
    expect(again.created).toBe(false);
    // Missing object.
    const missing = sha256hex("absent");
    expect(await os.has(missing)).toBe(false);
    await expect(os.get(missing)).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(os.has("zzzz")).rejects.toMatchObject({ code: "BAD_DIGEST" });
  });

  it("enforces the ≤1MiB proof-bound via maxBytes", async () => {
    const dir = join(await tmpRoot(), "objects", "sha256");
    const os = new ObjectStore(dir, { maxBytes: 1048576 });
    await expect(os.put(Buffer.alloc(1048577, 0x41))).rejects.toMatchObject({
      code: "OBJECT_LIMIT",
    });
    const ok = await os.put(Buffer.alloc(1048576, 0x42));
    expect(ok.bytes).toBe(1048576);
  });

  it("detects corrupt committed object bytes on first read (no repair)", async () => {
    const dir = join(await tmpRoot(), "objects", "sha256");
    const os = new ObjectStore(dir);
    const put = await os.put(Buffer.from("evidence"));
    const path = os.pathFor(put.digest);
    const original = await readFile(path);
    const damaged = Buffer.from(original);
    damaged[0] = damaged[0]! ^ 0xff;
    await writeFile(path, damaged);

    const fresh = new ObjectStore(dir);
    await expect(fresh.get(put.digest)).rejects.toMatchObject({ code: "CORRUPT" });
    expect(await fresh.has(put.digest)).toBe(false);
    // File left in place — never silently repaired or deleted.
    expect((await readFile(path)).equals(damaged)).toBe(true);
  });
});
