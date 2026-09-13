import { storeError } from "./errors.js";
import type { Registry, OutboxRow } from "./registry.js";
import type { Json } from "./util.js";

/**
 * Persistent outbox items per §9.1/§9.2. Rows live in the derived
 * `outbox` table; durable intent is journaled through `mutation` kind
 * `"outbox"`, so a registry rebuild replays every state transition.
 */

export const OUTBOX_STREAMS = [
  "runs",
  "receipts",
  "lineage",
  "approvals",
  "watch",
  "mesh",
] as const;
export type OutboxStream = (typeof OUTBOX_STREAMS)[number];

export type OutboxState = "PENDING" | "IN_FLIGHT" | "RETRY" | "BLOCKED" | "ACKED";

export interface OutboxItem {
  v: 1;
  id: string;
  destination: string;
  cohort: string;
  stream: OutboxStream;
  source: Json;
  payload: Json;
  consent_revision: string;
  redaction_sha256: string;
  from: string;
  through: string;
  state: OutboxState;
  attempts: number;
  next_attempt_ms: number;
  remote_stage: string | null;
}

/** §9.2 transition graph. ACKED is terminal and never reenters PENDING. */
const TRANSITIONS: Record<OutboxState, readonly OutboxState[]> = {
  PENDING: ["IN_FLIGHT", "BLOCKED"],
  IN_FLIGHT: ["ACKED", "RETRY", "BLOCKED"],
  RETRY: ["IN_FLIGHT", "BLOCKED"],
  // BLOCKED → PENDING only through an explicit repair/review path.
  BLOCKED: ["PENDING"],
  ACKED: [],
};

/** Full-jitter backoff per §9.2: [0, min(300000, 1000*2^attempt)) ms. */
export function backoffMs(attempt: number, rand: () => number = Math.random): number {
  const cap = Math.min(300000, 1000 * 2 ** Math.max(0, attempt));
  return Math.floor(rand() * cap);
}

export interface OutboxPatch {
  batch_hash?: string | null;
  next_attempt_ms?: number;
  attempts?: number;
  remote_stage?: string | null;
  through?: string;
}

function rowToItem(row: OutboxRow): OutboxItem {
  return JSON.parse(row.item_json) as OutboxItem;
}

export class OutboxStore {
  private readonly registry: Registry;

  constructor(registry: Registry) {
    this.registry = registry;
  }

  /**
   * Persist a new item (dedup by id). New items must enter as PENDING —
   * later states move only through `transition`/`markAcked`.
   */
  enqueue(item: OutboxItem): { enqueued: boolean; item: OutboxItem } {
    if (item.v !== 1 || item.state !== "PENDING") {
      throw storeError(
        "INVALID_TRANSITION",
        "outbox items must be enqueued in PENDING state",
        { id: item.id, state: item.state },
      );
    }
    const existing = this.registry.outboxGet(item.id);
    if (existing !== null) {
      return { enqueued: false, item: rowToItem(existing) };
    }
    this.registry.outboxUpsert(item, {
      state: item.state,
      item_json: JSON.stringify(item),
      tx: this.registry.lastIndexedTx() ?? "0",
    });
    return { enqueued: true, item };
  }

  get(id: string): OutboxItem | null {
    const row = this.registry.outboxGet(id);
    return row === null ? null : rowToItem(row);
  }

  /** Apply a §9.2 state transition; rejects edges outside the graph. */
  transition(id: string, to: OutboxState, patch: OutboxPatch = {}): OutboxItem {
    const row = this.registry.outboxGet(id);
    if (row === null) {
      throw storeError("NOT_FOUND", `outbox item ${id} not found`);
    }
    const item = rowToItem(row);
    if (item.state === to && to !== "IN_FLIGHT") {
      return item; // idempotent hold (except re-send, which must journal)
    }
    const allowed = TRANSITIONS[item.state];
    if (!allowed.includes(to)) {
      throw storeError(
        "INVALID_TRANSITION",
        `outbox ${id}: ${item.state} -> ${to} not permitted`,
        { id, from: item.state, to },
      );
    }
    const next: OutboxItem = {
      ...item,
      state: to,
      attempts: patch.attempts ?? item.attempts,
      next_attempt_ms: patch.next_attempt_ms ?? item.next_attempt_ms,
      remote_stage:
        patch.remote_stage !== undefined ? patch.remote_stage : item.remote_stage,
      through: patch.through ?? item.through,
    };
    this.registry.outboxUpsert(item, {
      batch_hash: patch.batch_hash !== undefined ? patch.batch_hash : row.batch_hash,
      state: to,
      item_json: JSON.stringify(next),
      tx: this.registry.lastIndexedTx() ?? "0",
    });
    return next;
  }

  /** IN_FLIGHT → ACKED only; records the durable native ACK cut. */
  markAcked(id: string, patch: OutboxPatch = {}): OutboxItem {
    return this.transition(id, "ACKED", patch);
  }

  /** Items eligible to send: PENDING or RETRY whose backoff has expired. */
  listPending(opts: {
    destination?: string;
    cohort?: string;
    stream?: string;
    due_ms?: number;
  } = {}): OutboxItem[] {
    const clauses: string[] = ["state IN ('PENDING','RETRY')"];
    const params: (string | number)[] = [];
    if (opts.destination !== undefined) {
      clauses.push("destination = ?");
      params.push(opts.destination);
    }
    if (opts.cohort !== undefined) {
      clauses.push("cohort = ?");
      params.push(opts.cohort);
    }
    if (opts.stream !== undefined) {
      clauses.push("stream = ?");
      params.push(opts.stream);
    }
    const rows = this.registry.outboxWhere(clauses.join(" AND "), ...params);
    const due = opts.due_ms;
    return rows
      .map(rowToItem)
      .filter((i) => due === undefined || i.next_attempt_ms <= due);
  }

  listByState(state: OutboxState): OutboxItem[] {
    return this.registry
      .outboxWhere("state = ?", state)
      .map(rowToItem);
  }

  count(state?: OutboxState): number {
    const rows =
      state === undefined
        ? this.registry.outboxWhere("1 = 1")
        : this.registry.outboxWhere("state = ?", state);
    return rows.length;
  }
}
