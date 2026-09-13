/**
 * Exclusive daemon instance lock (spec §1.2).
 *
 * One daemon per (OS user, realpath of selected config file). The writer is
 * elected by an OS-held exclusive lock on `<stateRoot>/runtime/daemon.lock`,
 * never by PID-file existence.
 *
 * Two mechanisms:
 *
 *  - Primary (Linux): a `flock(1)` subprocess helper takes
 *    `LOCK_EX | LOCK_NB` on `daemon.lock` and holds it for the daemon
 *    lifetime ("small audited helper", spec §1.2). Acquisition is proven by
 *    a marker byte the helper emits only after `flock` execs it — `flock`
 *    runs the command only once the lock is held — and contention is
 *    proven by the helper exiting status 1.
 *
 *  - Portable fallback: `O_EXCL` creation of `daemon.lock` plus a liveness
 *    probe of the stored record `{pid, process_start, boot_id, instance}`.
 *    A record whose process is provably dead — dead PID, PID-start-time
 *    mismatch (PID reuse guard), or different boot identity — is stale and
 *    replaced. When liveness cannot be proven either way we fail safe and
 *    report the existing endpoint.
 *
 * Invariants:
 *  - A contender is told the existing authenticated endpoint, never a
 *    second writer.
 *  - Nothing is ever killed by PID. The only termination this module
 *    performs is our own flock helper during `release()`.
 *  - The lock record is rewritten in place (same inode) — rename-replacing
 *    a flock'd path would hand the next opener a different, unlocked inode.
 *  - The parent directory is created/kept 0700.
 */
import { spawn, spawnSync, execFileSync, type ChildProcess } from "node:child_process";
import { open, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import {
  ensureDir,
  fsyncDir,
  pathExists,
  readFileOrNull,
} from "./store/util.js";

/** Contents of `runtime/daemon.lock` — liveness metadata (§1.2). */
export interface LockRecord {
  v: 1;
  pid: number;
  /** `/proc/<pid>/stat` start-time token; guards PID reuse. */
  process_start: string | null;
  /** `/proc/sys/kernel/random/boot_id`; distinguishes boots. */
  boot_id: string | null;
  instance: string;
  acquired_ms: number;
}

/** The endpoint a contender should use (from `runtime/endpoints.json`). */
export interface LockEndpoint {
  control_sock: string;
  ui_url: string | null;
  pid: number;
  instance: string;
  boot_id: string | null;
}

export type LockAcquireResult =
  | {
      held: true;
      path: string;
      record: LockRecord;
      release: () => Promise<void>;
    }
  | {
      held: false;
      path: string;
      /** Existing authenticated endpoint when one is advertised. */
      endpoint: LockEndpoint | null;
      reason: string;
    };

const LOCK_FILE = "daemon.lock";
const ENDPOINTS_FILE = "endpoints.json";

/** Current boot identity, or null on platforms without /proc. */
export async function readBootId(): Promise<string | null> {
  const raw = await readFileOrNull("/proc/sys/kernel/random/boot_id");
  if (raw === null) return null;
  const id = raw.toString("utf8").trim();
  return id.length > 0 ? id : null;
}

/**
 * Process start identity: on Linux the `/proc/<pid>/stat` starttime field
 * (jiffies since boot — unique per (pid,boot)); elsewhere a `ps` snapshot.
 * Null means "unverifiable" — callers must fail safe.
 */
export async function readProcessStart(pid: number): Promise<string | null> {
  const raw = await readFileOrNull(`/proc/${pid}/stat`);
  if (raw !== null) {
    const text = raw.toString("utf8");
    // Field 2 (comm) may contain spaces/parens; fields after the last ')'
    // begin at field 3 (state). starttime is field 22 → index 19.
    const close = text.lastIndexOf(")");
    if (close >= 0) {
      const parts = text.slice(close + 2).split(" ");
      if (parts.length > 19 && parts[19] !== undefined && parts[19] !== "") {
        return parts[19];
      }
    }
    return null;
  }
  try {
    const out = execFileSync("ps", ["-o", "lstart=", "-p", String(pid)], {
      encoding: "utf8",
      timeout: 5000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out.length > 0 ? out : null;
  } catch {
    return null;
  }
}

/** PID exists (same-user or EPERM-visible). Never signals the process. */
export function processAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Read the advertised endpoint a lock contender should use. */
export async function readEndpoint(runtimeDir: string): Promise<LockEndpoint | null> {
  const raw = await readFileOrNull(join(runtimeDir, ENDPOINTS_FILE));
  if (raw === null) return null;
  try {
    const u = JSON.parse(raw.toString("utf8")) as Partial<LockEndpoint>;
    if (typeof u.control_sock !== "string") return null;
    return {
      control_sock: u.control_sock,
      ui_url: typeof u.ui_url === "string" ? u.ui_url : null,
      pid: typeof u.pid === "number" ? u.pid : 0,
      instance: typeof u.instance === "string" ? u.instance : "",
      boot_id: typeof u.boot_id === "string" ? u.boot_id : null,
    };
  } catch {
    return null;
  }
}

async function readLockRecord(path: string): Promise<LockRecord | null> {
  const raw = await readFileOrNull(path);
  if (raw === null || raw.length === 0) return null;
  try {
    const u = JSON.parse(raw.toString("utf8")) as Partial<LockRecord>;
    if (typeof u.pid !== "number" || !Number.isSafeInteger(u.pid)) return null;
    return {
      v: 1,
      pid: u.pid,
      process_start: typeof u.process_start === "string" ? u.process_start : null,
      boot_id: typeof u.boot_id === "string" ? u.boot_id : null,
      instance: typeof u.instance === "string" ? u.instance : "",
      acquired_ms: typeof u.acquired_ms === "number" ? u.acquired_ms : 0,
    };
  } catch {
    return null;
  }
}

/** Rewrite the lock record in place — never rename a flock'd inode. */
async function writeLockRecordInPlace(path: string, record: LockRecord): Promise<void> {
  const fh = await open(path, "r+");
  try {
    await fh.writeFile(JSON.stringify(record));
    await fh.truncate();
    await fh.sync();
  } finally {
    await fh.close();
  }
}

function flockAvailable(): boolean {
  if (process.platform === "win32") return false;
  try {
    const r = spawnSync("flock", ["--version"], { stdio: "ignore", timeout: 5000 });
    return r.status === 0;
  } catch {
    return false;
  }
}

/**
 * Try the `flock(1)` mechanism. Returns:
 *  - {mode:"held", child} once the helper proves it holds LOCK_EX,
 *  - {mode:"contended"} when the helper exits 1 before the marker,
 *  - {mode:"unavailable"} when flock cannot run at all.
 */
function tryFlock(
  lockPath: string,
  timeoutMs: number,
): Promise<
  | { mode: "held"; child: ChildProcess }
  | { mode: "contended" }
  | { mode: "unavailable"; error?: unknown }
> {
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      // The marker byte is written only after flock has acquired the lock
      // and exec'd the helper — deterministic proof of acquisition.
      child = spawn(
        "flock",
        [
          "-n",
          lockPath,
          process.execPath,
          "-e",
          'process.stdout.write("L");setInterval(()=>{},1<<30);',
        ],
        { stdio: ["ignore", "pipe", "ignore"] },
      );
    } catch (error) {
      resolve({ mode: "unavailable", error });
      return;
    }
    let settled = false;
    const done = (
      r:
        | { mode: "held"; child: ChildProcess }
        | { mode: "contended" }
        | { mode: "unavailable"; error?: unknown },
    ): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(r);
    };
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* gone */
      }
      done({ mode: "unavailable", error: new Error("flock helper timed out") });
    }, timeoutMs);
    child.once("error", (error) => done({ mode: "unavailable", error }));
    child.stdout?.once("data", (chunk: Buffer) => {
      if (chunk.includes(0x4c /* "L" */)) done({ mode: "held", child });
    });
    child.once("exit", (code) => {
      // flock exits 1 on lock contention (with -n).
      done(code === 1 ? { mode: "contended" } : { mode: "unavailable", error: new Error(`flock exited ${code}`) });
    });
  });
}

async function stopHelper(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  const deadline = Date.now() + 2000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await Promise.race([exited, new Promise((r) => setTimeout(r, 25))]);
  }
  try {
    child.kill("SIGKILL");
  } catch {
    /* gone */
  }
  await exited;
}

/**
 * Acquire the instance lock under `stateRoot` (its `runtime/` directory is
 * created 0700). On contention, returns `{held:false, endpoint}` where
 * `endpoint` is the holder's advertised authenticated endpoint — the caller
 * connects to it rather than spawning a second daemon.
 */
export async function acquireLock(
  stateRoot: string,
  instance: string,
  opts: { timeoutMs?: number; flock?: boolean } = {},
): Promise<LockAcquireResult> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const runtimeDir = join(stateRoot, "runtime");
  await ensureDir(stateRoot);
  await ensureDir(runtimeDir);
  const lockPath = join(runtimeDir, LOCK_FILE);

  const record: LockRecord = {
    v: 1,
    pid: process.pid,
    process_start: await readProcessStart(process.pid),
    boot_id: await readBootId(),
    instance,
    acquired_ms: Date.now(),
  };

  if (opts.flock !== false && flockAvailable()) {
    // Ensure the path exists (flock opens it O_RDWR; create ahead so the
    // mode is ours: 0600).
    if (!(await pathExists(lockPath))) {
      const fh = await open(lockPath, "a", 0o600);
      await fh.close();
      await fsyncDir(runtimeDir);
    }
    const r = await tryFlock(lockPath, timeoutMs);
    if (r.mode === "held") {
      await writeLockRecordInPlace(lockPath, record);
      let released = false;
      return {
        held: true,
        path: lockPath,
        record,
        release: async () => {
          if (released) return;
          released = true;
          await stopHelper(r.child);
          // Only the holder ever removes the record.
          await unlink(lockPath).catch(() => {});
        },
      };
    }
    if (r.mode === "contended") {
      return {
        held: false,
        path: lockPath,
        endpoint: await readEndpoint(runtimeDir),
        reason: "daemon.lock is held by another process",
      };
    }
    // Unavailable → fall through to the portable path.
  }

  // ── Portable fallback: O_EXCL create + liveness probe. ──────────────────
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const fh = await open(lockPath, "wx", 0o600).catch((e: unknown) => {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") return null;
      throw e;
    });
    if (fh !== null) {
      try {
        await fh.writeFile(JSON.stringify(record));
        await fh.sync();
      } finally {
        await fh.close();
      }
      await fsyncDir(runtimeDir);
      let released = false;
      return {
        held: true,
        path: lockPath,
        record,
        release: async () => {
          if (released) return;
          released = true;
          await unlink(lockPath).catch(() => {});
        },
      };
    }
    // EEXIST — probe the recorded holder before treating it as live.
    const prior = await readLockRecord(lockPath);
    if (prior === null) {
      // Unreadable/empty record: if nobody holds a flock on it and it has
      // no usable identity, treat as stale only when it is also not newly
      // created. Conservative choice: report contention on first pass, then
      // remove on retry if it still yields no record.
      if (attempt < 2) {
        await new Promise((r) => setTimeout(r, 50));
        continue;
      }
      await unlink(lockPath).catch(() => {});
      continue;
    }
    const bootMismatch =
      prior.boot_id !== null &&
      record.boot_id !== null &&
      prior.boot_id !== record.boot_id;
    const dead = !processAlive(prior.pid);
    const priorStart = dead ? null : await readProcessStart(prior.pid);
    const startMismatch =
      !dead &&
      prior.process_start !== null &&
      priorStart !== null &&
      priorStart !== prior.process_start;
    if (bootMismatch || dead || startMismatch) {
      // Stale record — provably not a live daemon. Never kill anything;
      // just remove the stale file and retry the exclusive create.
      await unlink(lockPath).catch(() => {});
      continue;
    }
    return {
      held: false,
      path: lockPath,
      endpoint: await readEndpoint(runtimeDir),
      reason:
        prior.process_start !== null && priorStart === null
          ? "holder liveness unverifiable; refusing to steal lock"
          : "daemon.lock is held by another process",
    };
  }
  return {
    held: false,
    path: lockPath,
    endpoint: await readEndpoint(runtimeDir),
    reason: "lock acquisition races did not settle",
  };
}
