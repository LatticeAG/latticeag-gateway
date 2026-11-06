/**
 * Regression tests for the §1.2 socket ancestor walk.
 *
 * The walk must terminate at the filesystem root. A previous implementation
 * derived the parent with `new URL("file://<dir>/..").pathname`, which keeps
 * the literal `..` segment, so every step appended `/..` and the loop only
 * ended with ENAMETOOLONG once the path outgrew PATH_MAX.
 */
import { describe, expect, test } from "vitest";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UnsafeSocketPathError, assertSafeSocketAncestors } from "./socket-server.js";

describe("assertSafeSocketAncestors", () => {
  test("terminates at the filesystem root", async () => {
    await expect(assertSafeSocketAncestors("/")).resolves.toBeUndefined();
  });

  test("terminates for a nested directory below the temporary root", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-nested-"));
    try {
      const nested = join(dir, "nest", "deeper");
      await mkdir(nested, { recursive: true, mode: 0o700 });
      await expect(assertSafeSocketAncestors(nested)).resolves.toBeUndefined();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects a group/world writable ancestor without the sticky bit",
    async () => {
      const dir = await mkdtemp(join(tmpdir(), "gw-unsafe-"));
      try {
        await chmod(dir, 0o777);
        const child = join(dir, "child");
        await mkdir(child, { recursive: true, mode: 0o700 });
        await expect(
          assertSafeSocketAncestors(child),
        ).rejects.toBeInstanceOf(UnsafeSocketPathError);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
  );
});
