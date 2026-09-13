/**
 * Gateway v2 — sync outbox types, streams, destinations, state machine,
 * and retry backoff (spec §9.1–§9.2).
 *
 * All six streams default disabled. Journal an outbox intent in the same
 * transaction as its source event and consent snapshot; create immutable
 * redacted payload bytes before making the item sendable.
 */

import type { Count, Hash, Id, NativeRef, ObjectRef } from "./refs.js";

// ── §9.1 verbatim types ──────────────────────────────────────────────────

export const STREAMS = [
  "runs",
  "receipts",
  "lineage",
  "approvals",
  "watch",
  "mesh",
] as const;

export type StreamName = (typeof STREAMS)[number];

export function isStreamName(name: string): name is StreamName {
  return (STREAMS as readonly string[]).includes(name);
}

export const OUTBOX_STATES = [
  "PENDING",
  "IN_FLIGHT",
  "RETRY",
  "BLOCKED",
  "ACKED",
] as const;

export type OutboxState = (typeof OUTBOX_STATES)[number];

export type OutboxItem = {
  v: 1;
  id: Id;
  destination: Id;
  cohort: string;
  stream: StreamName;
  source: NativeRef;
  payload: ObjectRef;
  consent_revision: Count;
  redaction_sha256: Hash;
  from: string;
  through: string;
  state: OutboxState;
  attempts: number;
  next_attempt_ms: number;
  remote_stage: Id | null;
};

/**
 * Consumer-owned adapter result, not a new native receipt or mesh packet;
 * native ACK bytes are retained and validated under the pinned destination
 * binding before stored=true is trusted.
 */
export type SinkAck = {
  stored: boolean;
  batch: Hash;
  through: string;
  conflicts: NativeRef[];
  native: NativeRef;
};

// ── §9.1 destinations ────────────────────────────────────────────────────

/** Disclosure profile per stream config (`metadata`|`masked`|`full`). */
export type StreamProfile = "metadata" | "masked" | "full";

export interface StreamDestination {
  /** Destination adapter/binding named by the §9.1 table. */
  readonly destination: string;
  /** Default disclosure profile. */
  readonly profile: StreamProfile;
}

/**
 * Per-stream destination and default profile (§9.1 table). What may leave
 * is further constrained by consent/cohort/redaction policy; arbitrary
 * event traffic is never implicitly federated.
 */
export const STREAM_DESTINATIONS: Readonly<Record<StreamName, StreamDestination>> = {
  /** Proof-style hosted collector; metadata. */
  runs: { destination: "proof-hosted-collector", profile: "metadata" },
  /** Proof native import adapter; metadata. */
  receipts: { destination: "proof-native-import", profile: "metadata" },
  /** Proof collector/VisLineage adapter; metadata. */
  lineage: { destination: "proof-collector-vislineage", profile: "metadata" },
  /** VekInbox compatible adapter; metadata. */
  approvals: { destination: "vekinbox-compatible", profile: "metadata" },
  /** Paired Watch alert-archive adapter; metadata. */
  watch: { destination: "watch-alert-archive", profile: "metadata" },
  /** Existing polymesh-gateway; metadata. */
  mesh: { destination: "polymesh-gateway", profile: "metadata" },
};

// ── §9.2 queue/retry/conflict semantics ──────────────────────────────────

/**
 * Outbox state machine (§9.2):
 *  - PENDING → IN_FLIGHT journals the batch and remote-stage before send.
 *  - IN_FLIGHT → ACKED requires authenticated durable native ACK for the
 *    exact batch/cut; ACKED is terminal and never reenters PENDING.
 *  - IN_FLIGHT → RETRY covers timeout/lost ACK/transient transport;
 *    RETRY → IN_FLIGHT resends identical bytes/IDs.
 *  - PENDING/RETRY/IN_FLIGHT → BLOCKED on auth revocation, unsupported
 *    schema, changed consent, permanent rejection, unresolved conflict.
 *  - BLOCKED → PENDING requires the relevant explicit repair/review.
 * Pause is an orthogonal durable per-stream flag.
 */
export const OUTBOX_TRANSITIONS: Readonly<
  Record<OutboxState, readonly OutboxState[]>
> = {
  PENDING: ["IN_FLIGHT", "BLOCKED"],
  IN_FLIGHT: ["ACKED", "RETRY", "BLOCKED"],
  RETRY: ["IN_FLIGHT", "BLOCKED"],
  BLOCKED: ["PENDING"],
  ACKED: [],
};

export function canOutboxTransition(from: OutboxState, to: OutboxState): boolean {
  return OUTBOX_TRANSITIONS[from].includes(to);
}

/** Sync bounds (§9.1–§9.2, §3.3 sync.flush). */
export const SYNC_LIMITS = {
  /** Per-payload cap, bytes (§9.1). */
  payloadBytes: 1024 * 1024,
  /** Proof adapter batch event cap. */
  batchEvents: 1000,
  /** Proof adapter batch blob cap. */
  batchBlobs: 64,
  /** Batch byte cap including framing (strictly under 8 MiB). */
  batchBytes: 8 * 1024 * 1024,
  /** Global concurrent send operations. */
  globalSenders: 2,
  /** Concurrent send operations per stream. */
  perStreamSenders: 1,
  /** sync.flush timeout_ms range maximum (§3.2). */
  flushTimeoutMaxMs: 300_000,
  /** Backoff ceiling, ms. */
  backoffCapMs: 300_000,
  /** Backoff base, ms. */
  backoffBaseMs: 1_000,
} as const;

/** Upper bound of the backoff window for an attempt: min(300000, 1000*2^a). */
export function backoffCap(attempt: number): number {
  const exp = Math.max(0, Math.floor(attempt));
  return Math.min(SYNC_LIMITS.backoffCapMs, SYNC_LIMITS.backoffBaseMs * 2 ** exp);
}

/**
 * Full-jitter backoff sampler (§9.2): uniform sample from
 * `[0, min(300000, 1000*2^attempt)]` ms, honoring a bounded authenticated
 * Retry-After. Retries are never exhausted to discard an item; auth
 * failures pause the destination and show SYNC_BLOCKED instead.
 */
export function backoff(attempt: number): number {
  const cap = backoffCap(attempt);
  return Math.floor(Math.random() * (cap + 1));
}
