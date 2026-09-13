import { describe, expect, it } from "vitest";
import { ADMISSION_LIMITS, TOPICS, TOPIC_POLICY, isTopic } from "./topics.js";

describe("v2 topic registry (§3.4)", () => {
  it("is a closed 11-topic registry", () => {
    expect(TOPICS).toEqual([
      "telemetry",
      "belief",
      "tool.observation",
      "verdict",
      "approval.request",
      "approval.decision",
      "receipt",
      "lineage",
      "watch.alert",
      "gateway.action",
      "mesh.opaque",
    ]);
    expect(isTopic("gateway.action")).toBe(true);
    expect(isTopic("gateway")).toBe(false);
    expect(isTopic("*")).toBe(false);
  });

  it("carries a policy for every topic", () => {
    for (const t of TOPICS) {
      const p = TOPIC_POLICY[t];
      expect(typeof p.failOpen).toBe("boolean");
      expect(["collection", "consumer", "admission", "never"]).toContain(p.gating);
    }
    expect(TOPIC_POLICY.telemetry.failOpen).toBe(true);
    expect(TOPIC_POLICY["gateway.action"].failOpen).toBe(false);
    expect(TOPIC_POLICY["gateway.action"].gating).toBe("admission");
    expect(TOPIC_POLICY.verdict.failOpen).toBe(false);
    expect(TOPIC_POLICY.verdict.gating).toBe("consumer");
  });

  it("declares §3.4 admission limits", () => {
    expect(ADMISSION_LIMITS.ringCapacity).toBe(10000);
    expect(ADMISSION_LIMITS.principalEventsPerSecond).toBe(100);
    expect(ADMISSION_LIMITS.principalBurst).toBe(1000);
    expect(ADMISSION_LIMITS.maxOutstandingRpcs).toBe(16);
    expect(ADMISSION_LIMITS.maxUnackedStreamBytes).toBe(256 * 1024);
    expect(ADMISSION_LIMITS.controlQueueItems).toBe(1024);
    expect(ADMISSION_LIMITS.controlQueueBytes).toBe(16 * 1024 * 1024);
    expect(ADMISSION_LIMITS.failClosedWaitMs).toBe(5000);
    expect(ADMISSION_LIMITS.subscriberCreditDisconnectMs).toBe(5000);
  });
});
