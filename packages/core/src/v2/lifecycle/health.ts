/**
 * §5.2 health gate: activation requires `readinessSuccesses` (3) readiness
 * successes `readinessIntervalMs` (1 s) apart within `startup_timeout_ms`
 * (default 30 000, max 120 000); ≥3 consecutive probe failures fail the
 * candidate immediately. Live probes run every `probeIntervalMs` (10 s);
 * three consecutive failures degrade the instance.
 *
 * Clock and sleep are injectable for deterministic tests (TV-GW-11 uses a
 * poller returning readiness=false to fail the candidate fast).
 */
import { RpcError } from "../protocol/errors.js";
import { ADAPTER_LIMITS } from "../protocol/product.js";
import type { Json } from "../protocol/refs.js";

export interface ClockOps {
  now(): number;
  sleep(ms: number): Promise<void>;
}

export const systemClock: ClockOps = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

export interface ProbeOutcome {
  liveness: boolean;
  readiness: boolean;
  dependencies?: Json[];
  native?: Json;
}

export type Probe = () => Promise<ProbeOutcome>;

export interface ReadinessGateOptions {
  readonly clock?: ClockOps;
  /** Successes required (default 3). */
  readonly successes?: number;
  /** Spacing between checks, ms (default 1000). */
  readonly intervalMs?: number;
  /** Overall startup timeout, ms (default 30000, hard max 120000). */
  readonly startupTimeoutMs?: number;
  /** Consecutive failures that fail the candidate early (default 3). */
  readonly failureLimit?: number;
}

export interface ReadinessResult {
  readonly ok: true;
  readonly checks: number;
  readonly elapsedMs: number;
  readonly last: ProbeOutcome;
}

/**
 * Activation gate. Polls `probe`; each readiness=true advances the
 * success counter (reset on failure). Resolves after `successes`
 * consecutive successes spaced `intervalMs` apart. Throws HEALTH_FAILED
 * when `failureLimit` consecutive probes fail or `startupTimeoutMs`
 * elapses.
 */
export async function awaitReadiness(
  probe: Probe,
  opts: ReadinessGateOptions = {},
): Promise<ReadinessResult> {
  const clock = opts.clock ?? systemClock;
  const need = opts.successes ?? ADAPTER_LIMITS.readinessSuccesses;
  const interval = opts.intervalMs ?? ADAPTER_LIMITS.readinessIntervalMs;
  const timeout = Math.min(
    opts.startupTimeoutMs ?? ADAPTER_LIMITS.startupTimeoutDefaultMs,
    ADAPTER_LIMITS.startupTimeoutMaxMs,
  );
  const failLimit = opts.failureLimit ?? ADAPTER_LIMITS.probeFailureLimit;
  const start = clock.now();
  let ok = 0;
  let consecutiveFails = 0;
  let checks = 0;
  let last: ProbeOutcome = { liveness: false, readiness: false };
  for (;;) {
    checks += 1;
    try {
      last = await probe();
    } catch {
      last = { liveness: false, readiness: false };
    }
    if (last.readiness === true) {
      ok += 1;
      consecutiveFails = 0;
      if (ok >= need) {
        return { ok: true, checks, elapsedMs: clock.now() - start, last };
      }
    } else {
      ok = 0;
      consecutiveFails += 1;
      if (consecutiveFails >= failLimit) {
        throw new RpcError(
          "HEALTH_FAILED",
          `readiness failed ${consecutiveFails} consecutive probes`,
        );
      }
    }
    if (clock.now() - start >= timeout) {
      throw new RpcError(
        "HEALTH_FAILED",
        `readiness not achieved within startup_timeout_ms=${timeout}`,
      );
    }
    await clock.sleep(interval);
  }
}

export interface LiveProbeOptions {
  readonly clock?: ClockOps;
  /** Probe interval, ms (default 10 000). */
  readonly intervalMs?: number;
  /** Consecutive failures before DEGRADED (default 3). */
  readonly failureLimit?: number;
}

export interface LiveProbeHandle {
  /** Stop the loop; idempotent. */
  stop(): void;
  /** Current consecutive-failure count. */
  failures(): number;
  /** Resolves when the loop ends (stop or degrade). */
  done: Promise<void>;
}

/**
 * Live-probe loop: every `intervalMs` the probe runs; `failureLimit`
 * consecutive failures invoke `onDegraded` exactly once and end the loop.
 * Successes reset the counter. `stop()` ends the loop without degrading.
 */
export function startLiveProbes(
  probe: Probe,
  opts: LiveProbeOptions,
  onDegraded: (last: ProbeOutcome) => void,
): LiveProbeHandle {
  const clock = opts.clock ?? systemClock;
  const interval = opts.intervalMs ?? ADAPTER_LIMITS.probeIntervalMs;
  const failLimit = opts.failureLimit ?? ADAPTER_LIMITS.probeFailureLimit;
  let stopped = false;
  let fails = 0;
  let finish: () => void = () => undefined;
  const done = new Promise<void>((r) => {
    finish = r;
  });
  void (async () => {
    let last: ProbeOutcome = { liveness: true, readiness: true };
    while (!stopped) {
      await clock.sleep(interval);
      if (stopped) break;
      try {
        last = await probe();
      } catch {
        last = { liveness: false, readiness: false };
      }
      if (last.liveness === true && last.readiness === true) {
        fails = 0;
        continue;
      }
      fails += 1;
      if (fails >= failLimit) {
        stopped = true;
        onDegraded(last);
        break;
      }
    }
    finish();
  })();
  return {
    stop: () => {
      stopped = true;
      finish();
    },
    failures: () => fails,
    done,
  };
}
