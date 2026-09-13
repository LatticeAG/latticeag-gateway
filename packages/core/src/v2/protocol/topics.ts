/**
 * Gateway v2 — closed bus topic registry and admission limits (spec §3.4).
 *
 * Topics are a closed Gateway routing registry; each carries an explicit
 * imported profile and a capability-filtered scope. An adapter cannot
 * downgrade a control message by naming it telemetry. gateway.action is
 * reserved to the core writer.
 */

/** The closed topic registry (§3.4 table order). */
export const TOPICS = [
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
] as const;

export type Topic = (typeof TOPICS)[number];

export function isTopic(name: string): name is Topic {
  return (TOPICS as readonly string[]).includes(name);
}

/**
 * Where a topic's fail-closed behavior applies:
 *  - "consumer": a missing/unavailable event blocks its dependent
 *    computation or policy consumer (belief, verdict).
 *  - "admission": the durable-admission barrier itself is fail-closed —
 *    unpersisted evidence never authorizes downstream effects
 *    (approval.*, receipt, watch.alert monitor admission, gateway.action,
 *    mesh.opaque durable capability).
 *  - "never": never serves as a required gate; losses are counted with a
 *    visible gap (telemetry, tool.observation, lineage).
 */
export type TopicGating = "collection" | "consumer" | "admission" | "never";

export interface TopicPolicy {
  /** Producer-side writes may drop/spill under pressure. */
  readonly failOpen: boolean;
  /** Where the fail-closed requirement bites, or "never". */
  readonly gating: TopicGating;
}

/**
 * Failure policy per topic (§3.4 table).
 *
 * Notes:
 *  - receipt is fail-open only for already-completed workload reporting;
 *    evidence-bearing actions stay fail-closed, so the map records the
 *    strict default.
 *  - watch.alert is fail-open for alert collection but fail-closed for
 *    required monitor admission; both halves are represented.
 *  - mesh.opaque follows native policy with a fail-closed default; a
 *    telemetry capability may explicitly drop.
 */
export const TOPIC_POLICY: Readonly<Record<Topic, TopicPolicy>> = {
  telemetry: { failOpen: true, gating: "never" },
  belief: { failOpen: true, gating: "consumer" },
  "tool.observation": { failOpen: true, gating: "never" },
  verdict: { failOpen: false, gating: "consumer" },
  "approval.request": { failOpen: false, gating: "admission" },
  "approval.decision": { failOpen: false, gating: "admission" },
  receipt: { failOpen: false, gating: "admission" },
  lineage: { failOpen: true, gating: "never" },
  "watch.alert": { failOpen: true, gating: "admission" },
  "gateway.action": { failOpen: false, gating: "admission" },
  "mesh.opaque": { failOpen: false, gating: "admission" },
};

/**
 * Bus admission constants (§3.4):
 *  - v1 ring_capacity default 10000.
 *  - Per-principal ingress 100 events/s with burst 1000.
 *  - Max 16 outstanding RPCs per principal.
 *  - Max 256 KiB unacknowledged stream data.
 *  - Control queue reserved at 1024 items / 16 MiB (telemetry never uses it).
 *  - Fail-closed topics wait at most 5000 ms, then BACKPRESSURE with no ACK.
 *  - Subscribers are disconnected after 5000 ms over their credit.
 */
export const ADMISSION_LIMITS = {
  /** Default ring capacity (v1 ring_capacity). */
  ringCapacity: 10000,
  /** Per-principal ingress rate, events per second. */
  principalEventsPerSecond: 100,
  /** Per-principal ingress burst allowance. */
  principalBurst: 1000,
  /** Max outstanding RPCs per principal. */
  maxOutstandingRpcs: 16,
  /** Max unacknowledged stream data per subscriber, bytes. */
  maxUnackedStreamBytes: 256 * 1024,
  /** Reserved control queue capacity, items. */
  controlQueueItems: 1024,
  /** Reserved control queue capacity, bytes. */
  controlQueueBytes: 16 * 1024 * 1024,
  /** Fail-closed admission wait before BACKPRESSURE (no ACK), ms. */
  failClosedWaitMs: 5000,
  /** Subscriber credit overrun before disconnect (cursor retained), ms. */
  subscriberCreditDisconnectMs: 5000,
} as const;
