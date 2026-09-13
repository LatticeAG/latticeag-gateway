import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { F, tar } from "@latticeag/testkit";

import { extractArchive, scanArchive } from "./extract.js";

const denied = (fn: () => unknown): void => {
  expect(fn).toThrowError(expect.objectContaining({ code: "POLICY_DENIED" }));
};

describe("extractArchive (§5.2)", () => {
  test("fixture archive extracts with digests", () => {
    const dir = mkdtempSync(join(tmpdir(), "gw-extract-"));
    try {
      const entries = extractArchive(F.release1.archive, dir);
      const adapter = entries.find((e) => e.path === "package/adapter.mjs");
      expect(adapter?.kind).toBe("file");
      expect(adapter!.digest).toHaveLength(64);
      expect(readFileSync(join(dir, "package", "adapter.mjs"), "utf8")).toContain(
        "createInterface",
      );
      expect(readFileSync(join(dir, "package", "gateway-adapter.json"), "utf8")).toContain(
        "gateway-adapter/1",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("TV-GW-07: traversal entry → POLICY_DENIED, nothing written outside", () => {
    const dir = mkdtempSync(join(tmpdir(), "gw-extract-"));
    const evil = join(dir, "..", "evil-traversal.txt");
    try {
      const archive = tar({ "../evil-traversal.txt": "owned", "package/ok.txt": "ok" });
      denied(() => extractArchive(archive, dir));
      expect(existsSync(evil)).toBe(false);
      expect(existsSync(join(dir, "package", "ok.txt"))).toBe(false); // all-or-nothing: scan first
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("absolute paths, backslashes, dot-dot and special types are denied", () => {
    const dir = mkdtempSync(join(tmpdir(), "gw-extract-"));
    try {
      denied(() => extractArchive(tar({ "/abs.txt": "x" }), dir));
      denied(() => extractArchive(tar({ "a/../b.txt": "x" }), dir));
      denied(() => extractArchive(tar({ "a\\b.txt": "x" }), dir));
      denied(() => extractArchive(tar({ "a/./b.txt": "x" }), dir));

      // symlink entry (typeflag '2')
      const symlink = tar({ "package/ok.txt": "ok" });
      const block = Buffer.alloc(512);
      block.write("package/link", 0, 100); // name
      block.write("0000644\0", 100); // mode
      block.write("0000000\0", 108); // uid
      block.write("0000000\0", 116); // gid
      block.write("00000000000\0", 124); // size
      block.write("00000000000\0", 136); // mtime
      block.fill(32, 148, 156); // checksum field = spaces while summing
      block[156] = 0x32; // '2' symlink
      block.write("package/ok.txt", 157, 100); // linkname
      block.write("ustar\0", 257); // magic
      block.write("00", 263); // version
      // tar checksum: all 512 bytes, checksum field treated as 8 spaces.
      const sum = Array.from(block).reduce(
        (a, b, i) => a + (i >= 148 && i < 156 ? 0x20 : b),
        0,
      );
      block.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
      const withLink = Buffer.concat([symlink.subarray(0, symlink.length - 1024), block, Buffer.alloc(1024)]);
      denied(() => extractArchive(withLink, dir));
      expect(existsSync(join(dir, "package", "link"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("case-colliding names are denied", () => {
    const dir = mkdtempSync(join(tmpdir(), "gw-extract-"));
    try {
      denied(() => extractArchive(tar({ "a.txt": "1", "A.txt": "2" }), dir));
      denied(() => extractArchive(tar({ "Dir/x.txt": "1", "dir/y.txt": "2" }), dir));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("planted symlink inside root is caught by the containment walk", () => {
    const dir = mkdtempSync(join(tmpdir(), "gw-extract-"));
    try {
      // Pre-plant a symlink inside the root that the archive would traverse.
      symlinkSync("/tmp", join(dir, "escape"));
      denied(() => extractArchive(tar({ "escape/pwn.txt": "x" }), dir));
      expect(existsSync("/tmp/pwn.txt")).toBe(false);
    } finally {
      rmSync(join(dir, "escape"), { force: true });
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("scanArchive parses the fixture tar into entries", () => {
    const entries = scanArchive(F.release1.archive);
    const paths = entries.map((e) => e.path);
    expect(paths).toContain("package/adapter.mjs");
    expect(paths).toContain("package/gateway-adapter.json");
    expect(paths).toContain("package/config.schema.json");
  });
});
