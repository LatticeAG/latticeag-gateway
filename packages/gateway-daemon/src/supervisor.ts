/**
 * `supervisor.ts` — daemon-owned product process supervision (spec §1.3,
 * §5.4).
 *
 * The lifecycle engine spawns adapter children through the injected
 * `LifecyclePorts.spawnAdapter` port; this supervisor is that port. Every
 * child it spawns is daemon-owned and tracked by pid so shutdown can
 * escalate SIGTERM → SIGKILL. Processes it did not spawn (CLI-owned runs,
 * foreign daemons' products) are never touched: `pidAlive`/`probeGeneration`
 * only inspect, and `shutdownAll` iterates its own table only.
 *
 * Reconciliation: the engine's `onChildExit`/stop paths kill children
 * itself; the supervisor's exit listener simply forgets them, so the
 * tracked set is always "live daemon-owned children".
 */
import { spawn, type ChildProcess } from "node:child_process";
import type { AdapterChild, GenerationRow } from "../../core/dist/v2/lifecycle/index.js";

/** Spawn primitive — injectable for tests. */
export type SpawnFn = (
  cmd: readonly string[],
  dir: string,
  env: Record<string, string>,
) => ChildProcess;

export interface SupervisedProcess {
  readonly child: AdapterChild;
  readonly pid: number;
  readonly argv: readonly string[];
  readonly started_ms: number;
  exited: boolean;
  /** Filled on exit for post-mortem diagnostics. */
  exitCode: number | null;
  exitSignal: string | null;
}

export interface SupervisorOptions {
  /** Process spawn primitive (default: node:child_process spawn). */
  spawn?: SpawnFn;
  /** Clock for started_ms stamps. */
  now?: () => number;
}

const defaultSpawn: SpawnFn = (cmd, dir, env) =>
  spawn(cmd[0]!, cmd.slice(1), {
    cwd: dir,
    env: { ...env },
    // stdin/stdout: the adapter protocol's LF-delimited pipe pair;
    // stderr is piped so AdapterClient can capture bounded diagnostics.
    stdio: ["pipe", "pipe", "pipe"],
  });

export class ProductProcessSupervisor {
  private readonly spawnFn: SpawnFn;
  private readonly now: () => number;
  private readonly procs = new Map<number, SupervisedProcess>();
  private shuttingDown = false;

  constructor(opts: SupervisorOptions = {}) {
    this.spawnFn = opts.spawn ?? defaultSpawn;
    this.now = opts.now ?? Date.now;
  }

  /**
   * `LifecyclePorts.spawnAdapter`: spawn a daemon-owned adapter child and
   * begin tracking it. Secrets are never placed on argv/env by this layer
   * (the engine supplies env verbatim); the adapter protocol speaks on
   * the inherited stdin/stdout pipe pair.
   */
  spawnAdapter(
    cmd: readonly string[],
    dir: string,
    env: Record<string, string>,
  ): AdapterChild {
    if (this.shuttingDown) {
      throw new Error("supervisor is shutting down");
    }
    const child = this.spawnFn(cmd, dir, env);
    const pid = child.pid;
    if (pid !== undefined) {
      const rec: SupervisedProcess = {
        child,
        pid,
        argv: cmd,
        started_ms: this.now(),
        exited: false,
        exitCode: null,
        exitSignal: null,
      };
      this.procs.set(pid, rec);
      child.once("exit", (code, signal) => {
        rec.exited = true;
        rec.exitCode = code;
        rec.exitSignal = signal;
        this.procs.delete(pid);
      });
    }
    return child as AdapterChild;
  }

  /** `LifecyclePorts.pidAlive`: non-destructive liveness (signal 0). */
  pidAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * `LifecyclePorts.probeGeneration`: a retained pid that is still alive
   * means the generation's adapter outlived a daemon restart. Truthful —
   * a dead pid reports false; the engine then re-spawns through us.
   */
  async probeGeneration(row: GenerationRow): Promise<boolean> {
    if (row.pid === null || row.pid === undefined) return false;
    return this.pidAlive(row.pid);
  }

  /** Live daemon-owned children count (daemon.status products field). */
  count(): number {
    return this.procs.size;
  }

  /** Snapshot of tracked processes (tests/diagnostics). */
  list(): readonly SupervisedProcess[] {
    return [...this.procs.values()];
  }

  /**
   * §1.3 shutdown: SIGTERM every daemon-owned child, wait up to
   * `graceMs`, then SIGKILL survivors. Never throws — teardown continues.
   */
  async shutdownAll(graceMs: number): Promise<void> {
    this.shuttingDown = true;
    const live = [...this.procs.values()];
    if (live.length === 0) return;
    for (const rec of live) {
      try {
        rec.child.kill("SIGTERM");
      } catch {
        /* already gone */
      }
    }
    const deadline = this.now() + Math.max(0, graceMs);
    while (this.procs.size > 0 && this.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    for (const rec of [...this.procs.values()]) {
      try {
        rec.child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    }
    // Bound the final reap: a wedged uninterruptible child must not hang
    // daemon teardown.
    const killDeadline = this.now() + 2_000;
    while (this.procs.size > 0 && this.now() < killDeadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    this.procs.clear();
  }
}
