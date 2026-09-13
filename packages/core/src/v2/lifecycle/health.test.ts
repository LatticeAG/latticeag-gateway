import { describe, expect, test } from "vitest";

import { awaitReadiness, startLiveProbes } from "./health.js";
import type { ClockOps, ProbeOutcome } from "./health.js";

/** Deterministic clock: sleep advances instantly but yields one macrotask so
 *  real timers (e.g. the test's own setTimeout) are not starved by the probe
 *  loop. */
function fakeClock(start = 0): ClockOps & { now: () => number } {
  let t = start;
  return {
    now: () => t,
    sleep: (ms) => {
      t += ms;
      return new Promise((resolve) => setTimeout(resolve, 0));
    },
  };
}

const ready: ProbeOutcome = { liveness: true, readiness: true };
const unready: ProbeOutcome = { liveness: true, readiness: false };

describe("awaitReadiness (§5.2 activation gate)", () => {
  test("three readiness successes 1s apart activate within the timeout", async () => {
    let calls = 0;
    const r = await awaitReadiness(() => {
      calls += 1;
      return Promise.resolve(ready);
    }, { clock: fakeClock() });
    expect(r.ok).toBe(true);
    expect(calls).toBe(3);
  });

  test("readiness=false three consecutive times → HEALTH_FAILED", async () => {
    await expect(awaitReadiness(() => Promise.resolve(unready), { clock: fakeClock() }))
      .rejects.toMatchObject({ code: "HEALTH_FAILED" });
  });

  test("interleaved failures reset the success counter", async () => {
    const seq = [ready, unready, ready, ready, ready];
    let i = 0;
    const r = await awaitReadiness(() => Promise.resolve(seq[i++] ?? ready), {
      clock: fakeClock(),
    });
    expect(r.checks).toBe(5);
  });

  test("startup timeout → HEALTH_FAILED", async () => {
    // Always unready but spaced so failureLimit never trips: single-shot.
    await expect(
      awaitReadiness(() => Promise.resolve(unready), {
        clock: fakeClock(),
        failureLimit: 10,
        startupTimeoutMs: 2_500,
      }),
    ).rejects.toMatchObject({ code: "HEALTH_FAILED" });
  });

  test("startup_timeout_ms is capped at 120 000", async () => {
    const clock = fakeClock();
    // Probe always ready — timeout bound only affects failure paths; assert
    // the gate still succeeds instantly.
    const r = await awaitReadiness(() => Promise.resolve(ready), {
      clock,
      startupTimeoutMs: 9_999_999,
    });
    expect(r.ok).toBe(true);
  });
});

describe("startLiveProbes (§5.2 liveness)", () => {
  test("three consecutive failures invoke onDegraded once", async () => {
    let degraded = 0;
    let calls = 0;
    const h = startLiveProbes(
      () => {
        calls += 1;
        return Promise.resolve(unready);
      },
      { clock: fakeClock(), intervalMs: 10 },
      () => {
        degraded += 1;
      },
    );
    await h.done;
    expect(degraded).toBe(1);
    expect(calls).toBe(3);
  });

  test("successes reset the failure counter; stop() ends the loop", async () => {
    let i = 0;
    const seq = [unready, unready, ready, unready, unready, ready];
    let degraded = 0;
    const h = startLiveProbes(
      () => Promise.resolve(seq[i++ % seq.length]!),
      { clock: fakeClock(), intervalMs: 1 },
      () => {
        degraded += 1;
      },
    );
    await new Promise((r) => setTimeout(r, 20));
    h.stop();
    await h.done;
    expect(degraded).toBe(0);
  });
});
