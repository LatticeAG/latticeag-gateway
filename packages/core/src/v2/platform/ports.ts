/**
 * Gateway v2 — platform ports (dependency seams for the core services).
 *
 * The service implementations in this directory depend only on these
 * narrow structural interfaces plus the v2 crypto/protocol libraries.
 * `packages/gateway-daemon`'s durable `GatewayStore` satisfies the store
 * side through a thin adapter (its `commit`/`laneScan`/`putObject` line up
 * field-for-field); `testing.ts` ships an in-memory implementation.
 *
 * Evidence flow (spec §2.3): services never mutate projections directly —
 * every durable state change goes through `store.commit({records, objects,
 * mutation, result_sha256})`, which persists objects, appends lane records,
 * writes the journal marker, then applies `mutation` to the derived
 * registry in one atomic step. `registry.*` methods are read-only; the
 * only exception is `kvSet`, which mirrors the real store's `kv_meta`
 * (identity/boot/daemon runtime state, never evidence).
 */
import type { KeyObject } from "node:crypto";
import type {
  Count,
  Hash,
  Id,
  Json,
  Media,
  NativeRef,
  ObjectRef,
  PublicKey,
} from "../protocol/refs.js";
import type { ReceiptPointer } from "../protocol/envelope.js";
import type { Topic } from "../protocol/topics.js";
import type { Principal } from "../protocol/services.js";

/** Millisecond clock — injectable everywhere (tests pin now=1789257600000). */
export type PlatformClock = () => number;

// ── lane records and commits ─────────────────────────────────────────────

/** One LF-free JSON lane record (data is UTF-8 text or raw bytes). */
export interface PlatformCommitRecord {
  /** `"legacy"` or `"proof"`. */
  lane: string;
  /** Proof partition name (required when lane is `"proof"`). */
  partition?: string;
  data: Uint8Array | string;
}

/** Commit input — mirrors the daemon store's CommitInput field-for-field. */
export interface PlatformCommitInput {
  records?: PlatformCommitRecord[];
  /** Raw object bytes admitted before lane appends (§2.3 order). */
  objects?: Uint8Array[];
  /** Versioned local reducer input (PlatformMutation). */
  mutation: Json;
  /** 64-hex SHA-256 of the operation result payload. */
  result_sha256: Hash;
}

export interface PlatformCommitResult {
  /** Canonical decimal transaction id, strictly increasing. */
  tx: Count;
  /** One transport cursor per committed record, in record order. */
  cursors: string[];
}

/** A committed lane record as yielded by `laneScan`. */
export interface PlatformLaneRecord {
  /** Full lane key, e.g. `"legacy"` or `"proof/ws1"`. */
  lane: string;
  /** `c<16 lowercase hex lane ordinal>:<decimal record ordinal>`. */
  cursor: string;
  /** Record payload bytes (terminating LF stripped). */
  data: Uint8Array;
  /** Global monotone commit order across all lanes of this store. */
  order: number;
}

export interface PlatformLaneHead {
  /** 16-hex lane ordinal. */
  laneOrdinal: string;
  /** Ordinal the next record in this lane will receive (1-based). */
  nextRecordOrdinal: number;
  /** Global order of the lane's head record, or 0 when empty. */
  headOrder: number;
  /** Head record's cursor, or null for an empty lane. */
  headCursor: string | null;
  /** First retained record ordinal (1 = full retention). */
  floorOrdinal: number;
}

/** Result of resolving a transport cursor against committed lanes. */
export interface PlatformCursorResolution {
  lane: string;
  /** Record ordinal inside the lane. */
  ordinal: number;
  /** Global commit order. */
  order: number;
  /** False when the ordinal fell under the lane's retention floor. */
  retained: boolean;
}

// ── registry projection entries ──────────────────────────────────────────

/** One admitted event candidate under its Proof slot (§2.1 P06). */
export interface PlatformEventEntry {
  workspace: Id;
  source: Id;
  stream: Id;
  seq: Count;
  /** Event hash for proof-evidence/1, raw_sha256 for legacy candidates. */
  hash: Hash;
  /** SHA-256 of the exact committed record bytes. */
  raw_sha256: Hash;
  topic: Topic;
  profile: string;
  media: Media;
  /** Decimal length of the committed record bytes (record_ref.bytes). */
  record_bytes: Count;
  lane: string;
  cursor: string;
  /** Global commit order of the backing record. */
  order: number;
  /** TV-GW-32: more than one distinct candidate occupies this slot. */
  conflict: boolean;
}

export type PlatformRunState = "RUNNING" | "FINISHED";

export interface PlatformRunEntry {
  run_id: string;
  owner: Id;
  kit: string;
  state: PlatformRunState;
  /** Highest spool sequence durably reported. */
  spool_seq: Count;
  exit_code: number | null;
  signal: string | null;
  /** Unacknowledged sync intents attributed to this run. */
  pending_sync: number;
}

export interface PlatformSubscriptionEntry {
  id: Id;
  owner: Id;
  topics: Topic[];
  /** Durable ACK frontier (global commit order). */
  position: number;
  /** Cursor string of the frontier record (the subscribe/last-ack cursor). */
  cursor: string;
  /** Highest order handed to the SSE consumer; ACK cannot pass it. */
  delivered: number;
  /** Finite lease: expires at equality `now >= expires_ms` (P10). */
  expires_ms: number;
  state: "OPEN" | "CLOSED";
}

export interface PlatformOperationEntry {
  id: Id;
  principal: Id;
  kind: string;
  state: string;
  slug: string;
  from: string | null;
  to: string | null;
  /** Transition cursor of the last state change. */
  cursor: string | null;
  error: { code: string; retryable: boolean; field: string | null } | null;
}

/** Enrolled producer source ↔ key/owner mapping (spec §3.4). */
export interface PlatformSourceEntry {
  source: Id;
  /** Proof body `key` id — SHA-256 of the raw public key. */
  key_id: Hash;
  /** Canonical base64url raw Ed25519 public key. */
  public: PublicKey;
  /** Principal enrolled to publish as this source (peer or local id). */
  owner: Id;
}

/**
 * A committed gateway.action/1 observation, indexed for objects.put
 * authorization, receipt.get, and lineage walking. `previous` links the
 * action graph (spec §2.1 `previous_action` field).
 */
export interface PlatformActionEntry {
  /** `sha256(J(pointer))` — canonical lookup key. */
  key: Hash;
  pointer: ReceiptPointer;
  /** NativeRef form of this action for previous_action resolution. */
  nativeRef: NativeRef;
  previous: NativeRef | null;
  principal: Id;
  method: string;
}

// ── registry reads (projections are commit-applied, never direct writes) ─

export interface PlatformRegistry {
  kvGet(key: string): Promise<string | null>;
  /**
   * Runtime meta write (instance identity, daemon state). Never used for
   * evidence-bearing state — that goes through commit mutations only.
   */
  kvSet(key: string, value: string): Promise<void>;

  /** All retained candidates occupying one Proof slot. */
  eventSlot(
    workspace: Id,
    source: Id,
    stream: Id,
    seq: Count,
  ): Promise<PlatformEventEntry[]>;
  /** Resolve a transport cursor to its indexed event entry, if any. */
  eventByCursor(cursor: string): Promise<PlatformEventEntry | null>;
  /** All entries of one `(workspace,source,stream)` lane, seq ascending. */
  eventLane(
    workspace: Id,
    source: Id,
    stream: Id,
  ): Promise<PlatformEventEntry[]>;
  /** All entries carrying a topic, in commit order. */
  eventsByTopic(topic: Topic): Promise<PlatformEventEntry[]>;

  runGet(runId: string): Promise<PlatformRunEntry | null>;
  operationGet(id: Id): Promise<PlatformOperationEntry | null>;
  subscriptionGet(id: Id): Promise<PlatformSubscriptionEntry | null>;
  /** Open/closed leases owned by a principal (session revoke closes them). */
  subscriptionsByOwner(owner: Id): Promise<PlatformSubscriptionEntry[]>;
  sourceGet(source: Id): Promise<PlatformSourceEntry | null>;
  actionGet(key: Hash): Promise<PlatformActionEntry | null>;
  /** Resolve an action by its NativeRef `object_id`. */
  actionByNativeId(objectId: string): Promise<PlatformActionEntry | null>;

  countProducts(): Promise<number>;
  countPeers(): Promise<number>;
}

// ── store port ───────────────────────────────────────────────────────────

export interface PlatformStore {
  /**
   * §2.3 commit protocol: objects → lane appends → journal marker →
   * registry projection apply → `{tx, cursors}`. Single-writer; services
   * serialize calls.
   */
  commit(input: PlatformCommitInput): Promise<PlatformCommitResult>;

  /**
   * Read committed records of one lane in ordinal order. `after` is an
   * exclusive lower-bound cursor; `limit` caps yielded records.
   */
  laneScan(
    lane: string,
    after?: string | null,
    limit?: number,
  ): AsyncIterable<PlatformLaneRecord>;

  /** Head metadata of a lane (created on demand). */
  laneHead(lane: string): Promise<PlatformLaneHead>;

  /**
   * Resolve a transport cursor to lane/ordinal/order. Returns null when
   * the lane or ordinal was never committed; `retained:false` marks
   * cursors below the retention floor (CURSOR_GONE territory).
   */
  resolveCursor(cursor: string): Promise<PlatformCursorResolution | null>;

  /** The cursor the next record of `lane` would receive, if knowable. */
  peekNextCursor?(lane: string): Promise<string | null>;

  /**
   * Global commit frontier: the highest committed record order across all
   * lanes and its cursor (null cursor when nothing is committed). Used as
   * the atomic snapshot point for subscriptions ("from now").
   */
  globalHead(): Promise<{ order: number; cursor: string | null }>;

  /**
   * Read one retained committed record by its cursor; null when the cursor
   * is unknown or the record fell under the retention floor. Bytes are the
   * record payload without the framing LF.
   */
  getRecord(cursor: string): Promise<Uint8Array | null>;

  /** Content-addressed read; throws (NOT_FOUND) when the digest is absent. */
  getObject(digest: Hash): Promise<Uint8Array>;
  /** Idempotent content-addressed write; rejects beyond `maxBytes`. */
  putObject(
    bytes: Uint8Array,
    maxBytes: number,
  ): Promise<{ digest: Hash; bytes: number }>;

  registry: PlatformRegistry;
}

// ── session/bootstrap store ──────────────────────────────────────────────

/**
 * Browser bootstrap + session records keyed by TOKEN HASH only — bearer
 * material (bootstrap/session/CSRF) is never stored in plaintext
 * (spec §4.3/§7.2).
 */
export interface PlatformBootstrapRecord {
  /** `sha256` of the bootstrap token. */
  hash: Hash;
  role: "viewer" | "operator";
  /** One-use, 60 s; expiry at equality. */
  expires_ms: number;
}

export interface PlatformSessionRecord {
  /** `sha256` of the session token. */
  hash: Hash;
  role: "viewer" | "operator";
  /** `sha256` of the session's memory-only CSRF secret. */
  csrf_sha256: Hash;
  /** Session owner principal (the L principal that minted it). */
  owner: Id;
  /** Absolute expiry (viewer 8 h, operator 10 min). */
  expires_ms: number;
  /** Idle deadline (viewer 30 min, operator 5 min). */
  idle_expires_ms: number;
  created_ms: number;
  state: "ACTIVE" | "REVOKED";
}

export interface PlatformSessionStore {
  /** Insert a one-use bootstrap. */
  bootstrapPut(record: PlatformBootstrapRecord): Promise<void>;
  /**
   * Atomically consume a bootstrap by token hash: returns the record and
   * marks it used exactly once; null when unknown or already consumed.
   */
  bootstrapTake(hash: Hash): Promise<PlatformBootstrapRecord | null>;
  sessionPut(record: PlatformSessionRecord): Promise<void>;
  sessionGet(hash: Hash): Promise<PlatformSessionRecord | null>;
  /** Mark a session revoked by token hash. */
  sessionRevoke(hash: Hash): Promise<void>;
}

// ── the full port bundle ─────────────────────────────────────────────────

/** Evidence-bearing profile a publisher may select. */
export const EVIDENCE_PROFILES = [
  "@latticeag/events@0.1.0",
  "proof-evidence/1",
  "proof-bundle/1",
] as const;

export interface PlatformPorts {
  store: PlatformStore;
  sessionStore: PlatformSessionStore;

  /** Directory containing the v2 `latticeag.json` (config.get fallback). */
  configDir: string;
  clock: PlatformClock;

  /** Authenticated workspace binding (never caller-selected). */
  workspace: Id;
  /** Daemon instance id (audience/cookie scoping). */
  instance: Id;

  /** Audit partition workspace (spec §2.2/§3.3): `"audit1"`. */
  receiptWorkspace: Id;
  /** Audit Proof source id (spec §3.3): `"gateway1"`. */
  auditSource: Id;
  /** Ed25519 secret key sealing audit Proof events (the daemon's auditor). */
  auditKey: KeyObject;

  /** UI origin for daemon.status/session URLs, e.g. `http://127.0.0.1:9848`. */
  uiEndpoint: string | null;
  /** Explicitly advertised evidence profiles (§2.2 hello). */
  profiles: readonly string[];
  /** Mesh availability advertised by hello (native adapter absent → false). */
  mesh: { available: boolean; code?: string };

  /** Bound native Proof collector (receipt bundle export) — Phase 0: false. */
  nativeCollectorBound: boolean;
  /** Bound native lineage adapter — absent: NOT_EVALUATED + gap. */
  nativeLineageBound: boolean;

  /** 128-bit control-id mint (Proof Id grammar); injectable for tests. */
  newId(): Id;
  /** 32-byte bearer-token mint, canonical base64url; injectable for tests. */
  newToken(): string;
  /** Scheduled by daemon.stop after the DRAINING response is durable. */
  onStop?(graceMs: number): void;
}

/** Per-call binding: the authenticated principal and request id. */
export interface ServiceContext {
  readonly principal: Principal;
  readonly requestId?: Id;
}

/** Default local-operator context (socket-authenticated, spec §3.2 L). */
export const LOCAL_OPERATOR_CONTEXT: ServiceContext = {
  principal: { id: "operator1", role: "local_operator" },
};

/** Canonical lookup key of a ReceiptPointer in the actions index. */
export function actionKeyOf(
  pointer: ReceiptPointer,
  hashJson: (value: unknown) => Hash,
): Hash {
  return hashJson(pointer);
}

/** Portable service-side alias: an action is addressed by pointer or ref. */
export type ActionAddress = ReceiptPointer | NativeRef;
