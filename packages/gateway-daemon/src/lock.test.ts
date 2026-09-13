/**
 * Lock acquisition tests (spec §1.2): exclusive instance lock, contender
 * endpoint handoff, stale dead-PID recovery. Uses real temp directories and
 * the real flock helper when available.
 */
import { describe, expect, test } from "vitest";
import { mkdtemp, rm, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  acquireLock,
  processAlive,
  readBootId,
  readProcessStart,
  type LockRecord,
} from "./lock.js";

async function tempStateRoot(): Promise<string> {
  return mkdtemp(join(tmpdir(), "gw-lock-test-"));
}

async function writeEndpoints(runtimeDir: string): Promise<void> {
  const { mkdir } = await import("node:fs/promises");
  await mkdir(runtimeDir, { recursive: true });
  await writeFile(
    join(runtimeDir, "endpoints.json"),
    JSON.stringify({
      pid: 4242,
      instance: "gw1",
      boot_id: "boot",
      control_sock: "/tmp/holder.sock",
      ui_url: "http://127.0.0.1:9848/",
    }),
  );
}

describe("acquireLock", () => {
  test("first acquisition holds; second reports contended + endpoint", async () => {
    const root = await tempStateRoot();
    try {
      const runtimeDir = join(root, "runtime");
      await writeEndpoints(runtimeDir);
      const first = await acquireLock(root, "gw1");
      expect(first.held).toBe(true);
      if (!first.held) return;
      try {
        const second = await acquireLock(root, "gw1");
        expect(second.held).toBe(false);
        if (second.held) return;
        expect(second.endpoint).not.toBeNull();
        expect(second.endpoint?.control_sock).toBe("/tmp/holder.sock");
        expect(second.endpoint?.ui_url).toBe("http://127.0.0.1:9848/");
        // Lock path lives under runtime/ with owner-only dirs.
        const st = await stat(join(root, "runtime"));
        expect(st.mode & 0o777).toBe(0o700);
      } finally {
        await first.release();
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("release frees the lock for a later acquirer", async () => {
    const root = await tempStateRoot();
    try {
      const first = await acquireLock(root, "gw1");
      expect(first.held).toBe(true);
      if (!first.held) return;
      await first.release();
      const second = await acquireLock(root, "gw1");
      expect(second.held).toBe(true);
      if (second.held) await second.release();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("stale dead-PID lock record recovers (O_EXCL fallback)", async () => {
    const root = await tempStateRoot();
    try {
      const runtimeDir = join(root, "runtime");
      const { mkdir } = await import("node:fs/promises");
      await mkdir(runtimeDir, { recursive: true });
      // A lock record for a provably dead PID. Use PID 2^22+ (never
      // allocated as a pid_max-exceeding value on Linux pid_max ≤ 4194304).
      const deadPid = 4194304;
      expect(processAlive(deadPid)).toBe(false);
      const stale: LockRecord = {
        v: 1,
        pid: deadPid,
        process_start: "999",
        boot_id: await readBootId(),
        instance: "gw1",
        acquired_ms: Date.now() - 60_000,
      };
      await writeFile(join(runtimeDir, "daemon.lock"), JSON.stringify(stale));
      const r = await acquireLock(root, "gw1", { flock: false });
      expect(r.held).toBe(true);
      if (r.held) await r.release();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("live-PID lock record reports contention (O_EXCL fallback)", async () => {
    const root = await tempStateRoot();
    try {
      const runtimeDir = join(root, "runtime");
      const { mkdir } = await import("node:fs/promises");
      await mkdir(runtimeDir, { recursive: true });
      await writeEndpoints(runtimeDir);
      const live: LockRecord = {
        v: 1,
        pid: process.pid, // this very test process is provably alive
        process_start: await readProcessStart(process.pid),
        boot_id: await readBootId(),
        instance: "gw1",
        acquired_ms: Date.now(),
      };
      await writeFile(join(runtimeDir, "daemon.lock"), JSON.stringify(live));
      const r = await acquireLock(root, "gw1", { flock: false });
      expect(r.held).toBe(false);
      if (r.held) return;
      expect(r.endpoint?.control_sock).toBe("/tmp/holder.sock");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
