import { chmod } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { storeError } from "./errors.js";
import type { CommitMarker, RecordLocator } from "./journal.js";
import { FILE_MODE, isDecimalString, isHex64, sha256hex, type Json } from "./util.js";
import { canonicalJson } from "../core-v2.js";

/**
 * `registry.sqlite` — the derived index per §2.3/§8.3. WAL, synchronous
 * FULL, foreign keys on, one writer. It may be dropped at any time and
 * rebuilt exactly from committed journal markers; committed bytes are never
 * stored here.
 */

export type CursorResolver = (locator: RecordLocator) => string | null;

// ---------- typed row shapes ----------

export interface EventRow {
  workspace: string;
  source: string;
  stream: string;
  seq: string;
  hash: string;
  conflict: number;
  lane: string | null;
  segment: string | null;
  offset: number | null;
  length: number | null;
  tx: string;
}

export interface NativeObjectRow {
  profile: string;
  namespace: string;
  type: string;
  object_id: string;
  commitment: string;
  raw_sha256: string | null;
  bytes: string | null;
  tx: string;
}

export interface CursorRow {
  instance: string;
  cursor: string;
  lane: string;
  segment: string;
  offset: number;
  length: number;
  raw_sha256: string;
  tx: string;
}

export interface RunRow {
  legacy_namespace: string;
  ulid: string;
  owner: string;
  tx: string;
}

export interface ProductRow {
  slug: string;
  instance: string;
  generation: number;
  state: string;
  active: number;
  tx: string;
}

export interface OperationRow {
  principal: string;
  id: string;
  request_hash: string;
  result_json: string | null;
  state: string;
  tx: string;
}

export interface ApprovalRow {
  home: string;
  request: string;
  revision: string;
  state: string;
  tx: string;
}

export interface GrantRow {
  peer: string;
  key: string;
  revision: string;
  scopes_json: string;
  state: string;
  tx: string;
}

export interface OutboxRow {
  id: string;
  destination: string;
  cohort: string;
  stream: string;
  batch_hash: string | null;
  state: string;
  item_json: string;
  tx: string;
}

export interface PairRow {
  peer: string;
  key: string;
  meta_json: string;
  state: string;
  tx: string;
}

export interface SubscriptionRow {
  id: string;
  owner: string;
  cursor: string;
  filter_json: string;
  state: string;
  tx: string;
}

export interface CatalogMeta {
  highest_revision: string | null;
  hash: string | null;
}

// ---------- v2 core projection rows (platform/ports.ts shapes) ----------

/**
 * Core event index entry: extends the legacy slot row with the fields
 * the v2 event service needs (topic/profile/cursor/global order).
 */
export interface EventRowV2 extends EventRow {
  raw_sha256: string | null;
  topic: string | null;
  profile: string | null;
  media: string | null;
  record_bytes: string | null;
  cursor: string | null;
  record_order: number | null;
}

export interface RunRowV2 {
  run_id: string;
  owner: string;
  kit: string;
  state: string;
  spool_seq: string;
  exit_code: number | null;
  signal: string | null;
  pending_sync: number;
  tx: string;
}

export interface OperationRowV2 {
  id: string;
  principal: string;
  kind: string;
  state: string;
  slug: string;
  from_v: string | null;
  to_v: string | null;
  cursor: string | null;
  error_json: string | null;
  tx: string;
}

export interface SubscriptionRowV2 extends SubscriptionRow {
  topics_json: string | null;
  position: number;
  delivered: number;
  expires_ms: number | null;
}

export interface SourceRow {
  source: string;
  key_id: string;
  public: string;
  owner: string;
  tx: string;
}

export interface ActionRow {
  key: string;
  object_id: string;
  pointer_json: string;
  native_json: string;
  previous_json: string;
  principal: string;
  method: string;
  tx: string;
}

export interface PeerRow {
  id: string;
  state: string;
  tx: string;
}

export interface DocRow {
  kind: string;
  id: string;
  doc_json: string;
  tx: string;
}

export interface BootstrapRow {
  hash: string;
  role: string;
  expires_ms: number;
  consumed: number;
  epoch: string;
  tx: string;
}

// ---------- versioned mutation union (marker.mutation) ----------

export interface EventIndexEntry {
  workspace: string;
  source: string;
  stream: string;
  seq: string;
  hash: string;
  lane?: string;
  segment?: string;
  offset?: number;
  length?: number;
}

export interface NativeObjectEntry {
  profile: string;
  namespace: string;
  type: string;
  object_id: string;
  commitment?: string | null;
  raw_sha256?: string;
  bytes?: string;
}

export interface CursorEntry {
  instance: string;
  cursor: string;
  lane: string;
  segment: string;
  offset: number;
  length: number;
  raw_sha256: string;
}

export interface RunEntry {
  legacy_namespace: string;
  ulid: string;
  owner: string;
}

export interface ProductEntry {
  slug: string;
  instance: string;
  generation: number;
  state: string;
  active?: boolean;
}

export interface OperationEntry {
  principal: string;
  id: string;
  request_hash: string;
  result_json?: string | null;
  state: string;
}

export interface ApprovalEntry {
  home: string;
  request: string;
  revision: string;
  state: string;
}

export interface GrantEntry {
  peer: string;
  key: string;
  revision: string;
  scopes: Json;
  state: string;
}

export interface OutboxEntry {
  id: string;
  destination: string;
  cohort: string;
  stream: string;
  batch_hash?: string | null;
  state: string;
  item: Json;
}

export interface PairEntry {
  peer: string;
  key: string;
  meta?: Json;
  state: string;
}

export interface SubscriptionEntry {
  id: string;
  owner: string;
  cursor: string;
  filter?: Json;
  state: string;
}

// ---------- core (platform-layer) mutation entries ----------

/**
 * Core event index entry (platform `events` mutation). The `record` field
 * indexes into the commit marker's `records` array; the reducer resolves
 * it to the cursor/lane/global order through the configured record
 * resolver. Explicit `cursor`/`order`/`lane` override the resolution
 * (used when replaying or projecting externally computed positions).
 */
export interface EventIndexEntryV2 {
  workspace: string;
  source: string;
  stream: string;
  seq: string;
  hash: string;
  raw_sha256: string;
  topic: string;
  profile: string;
  media: string;
  record_bytes: string;
  record?: number;
  cursor?: string;
  order?: number;
  lane?: string;
  conflict?: boolean;
}

export interface RunEntryV2 {
  run_id: string;
  owner: string;
  kit: string;
  state: string;
  spool_seq: string;
  exit_code: number | null;
  signal: string | null;
  pending_sync: number;
}

export interface OperationEntryV2 {
  id: string;
  principal: string;
  kind: string;
  state: string;
  slug: string;
  from: string | null;
  to: string | null;
  cursor: string | null;
  error: { code: string; retryable: boolean; field: string | null } | null;
}

export interface SubscriptionEntryV2 {
  id: string;
  owner: string;
  topics: string[];
  position: number;
  cursor: string;
  delivered: number;
  expires_ms: number;
  state: string;
}

export interface SourceEntry {
  source: string;
  key_id: string;
  public: string;
  owner: string;
}

export interface ActionEntry {
  pointer: Json;
  nativeRef: Json;
  previous: Json;
  principal: string;
  method: string;
}

export interface PeerStateEntry {
  id: string;
  state: string;
}

/** Generic durable document row (peer/pair/grant/lifecycle/cloud state). */
export interface DocEntry {
  kind: string;
  id: string;
  /** Full replacement document; null deletes the row. */
  doc: Json;
}

export interface BootstrapEntry {
  hash: string;
  role: string;
  expires_ms: number;
  consumed?: boolean;
  epoch?: string;
}

export interface KvEntry {
  key: string;
  /** null deletes the key. */
  value: string | null;
}

export type RegistryMutation =
  | { v: 1; kind: "noop" }
  | { v: 1; kind: "batch"; mutations: RegistryMutation[] }
  | { v: 1; kind: "events"; events: (EventIndexEntry | EventIndexEntryV2)[] }
  | { v: 1; kind: "native_objects"; objects: NativeObjectEntry[] }
  | { v: 1; kind: "cursors"; cursors: CursorEntry[] }
  | { v: 1; kind: "runs"; runs: (RunEntry | RunEntryV2)[] }
  | { v: 1; kind: "products"; products: ProductEntry[] }
  | { v: 1; kind: "operations"; operations: (OperationEntry | OperationEntryV2)[] }
  | { v: 1; kind: "approvals"; approvals: ApprovalEntry[] }
  | { v: 1; kind: "grants"; grants: GrantEntry[] }
  | { v: 1; kind: "outbox"; items: OutboxEntry[] }
  | { v: 1; kind: "pairs"; pairs: PairEntry[] }
  | { v: 1; kind: "subscriptions"; subscriptions: (SubscriptionEntry | SubscriptionEntryV2)[] }
  | { v: 1; kind: "sources"; sources: SourceEntry[] }
  | { v: 1; kind: "actions"; actions: ActionEntry[] }
  | { v: 1; kind: "peers"; peers: PeerStateEntry[] }
  | { v: 1; kind: "kv"; entries: KvEntry[] }
  | { v: 1; kind: "docs"; docs: DocEntry[] }
  | { v: 1; kind: "bootstraps"; bootstraps: BootstrapEntry[] }
  | { v: 1; kind: "bootstrap_take"; hash: string; epoch?: string }
  | {
      v: 1;
      kind: "lifecycle";
      /** Generation-row upserts (row = the full GenerationRow document). */
      upserts?: LifecycleGenerationEntry[];
      /**
       * Atomic active-pointer CAS: succeeds only when the currently active
       * generation equals `expected` (null = none). The outcome is recorded
       * under `kv_meta["lifecycle:cas:<tx>"]` = "1" | "0" so the commitSync
       * caller can read it; the mutation itself never throws on mismatch —
       * journal replay must stay deterministic.
       */
      cas?: { slug: string; expected: string | null; next: string | null };
    }
  | {
      v: 1;
      kind: "catalog";
      highest_revision?: string | null;
      hash?: string | null;
    };

/** One lifecycle generation upsert inside a `"lifecycle"` mutation. */
export interface LifecycleGenerationEntry {
  slug: string;
  /** Decimal generation (Count). */
  generation: string;
  /** Full GenerationRow document (its `active` flag is kept in sync). */
  row: Json;
}

/** Lifecycle generation row as read back. */
export interface LifecycleGenerationRow {
  slug: string;
  generation: string;
  active: number;
  row_json: string;
  tx: string;
}

const SCHEMA = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS kv_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  workspace TEXT NOT NULL,
  source TEXT NOT NULL,
  stream TEXT NOT NULL,
  seq TEXT NOT NULL,
  hash TEXT NOT NULL,
  conflict INTEGER NOT NULL DEFAULT 0,
  lane TEXT,
  segment TEXT,
  offset INTEGER,
  length INTEGER,
  tx TEXT NOT NULL,
  PRIMARY KEY (workspace, source, stream, seq, hash)
);
CREATE INDEX IF NOT EXISTS events_slot ON events(workspace, source, stream, seq);

CREATE TABLE IF NOT EXISTS native_objects (
  profile TEXT NOT NULL,
  namespace TEXT NOT NULL,
  type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  commitment TEXT NOT NULL DEFAULT '',
  raw_sha256 TEXT,
  bytes TEXT,
  tx TEXT NOT NULL,
  PRIMARY KEY (profile, namespace, type, object_id, commitment)
);
CREATE INDEX IF NOT EXISTS native_objects_id
  ON native_objects(profile, namespace, type, object_id);

CREATE TABLE IF NOT EXISTS transport_cursors (
  instance TEXT NOT NULL,
  cursor TEXT NOT NULL,
  lane TEXT NOT NULL,
  segment TEXT NOT NULL,
  offset INTEGER NOT NULL,
  length INTEGER NOT NULL,
  raw_sha256 TEXT NOT NULL,
  tx TEXT NOT NULL,
  PRIMARY KEY (instance, cursor)
);

CREATE TABLE IF NOT EXISTS runs (
  legacy_namespace TEXT NOT NULL,
  ulid TEXT NOT NULL,
  owner TEXT NOT NULL,
  tx TEXT NOT NULL,
  PRIMARY KEY (legacy_namespace, ulid)
);

CREATE TABLE IF NOT EXISTS products (
  slug TEXT NOT NULL,
  instance TEXT NOT NULL,
  generation INTEGER NOT NULL,
  state TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0,
  tx TEXT NOT NULL,
  PRIMARY KEY (slug, instance, generation)
);
CREATE INDEX IF NOT EXISTS products_active ON products(slug, instance, active);

CREATE TABLE IF NOT EXISTS operations (
  principal TEXT NOT NULL,
  id TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  result_json TEXT,
  state TEXT NOT NULL,
  tx TEXT NOT NULL,
  PRIMARY KEY (principal, id)
);
CREATE INDEX IF NOT EXISTS operations_request ON operations(request_hash);

CREATE TABLE IF NOT EXISTS approvals (
  home TEXT NOT NULL,
  request TEXT NOT NULL,
  revision TEXT NOT NULL,
  state TEXT NOT NULL,
  tx TEXT NOT NULL,
  PRIMARY KEY (home, request, revision)
);

CREATE TABLE IF NOT EXISTS grants (
  peer TEXT NOT NULL,
  key TEXT NOT NULL,
  revision TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  state TEXT NOT NULL,
  tx TEXT NOT NULL,
  PRIMARY KEY (peer, key, revision)
);

CREATE TABLE IF NOT EXISTS outbox (
  id TEXT PRIMARY KEY,
  destination TEXT NOT NULL,
  cohort TEXT NOT NULL,
  stream TEXT NOT NULL,
  batch_hash TEXT,
  state TEXT NOT NULL,
  item_json TEXT NOT NULL,
  tx TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS outbox_batch
  ON outbox(destination, cohort, stream, batch_hash);
CREATE INDEX IF NOT EXISTS outbox_state
  ON outbox(destination, cohort, stream, state);

CREATE TABLE IF NOT EXISTS pairs (
  peer TEXT NOT NULL,
  key TEXT NOT NULL,
  meta_json TEXT NOT NULL,
  state TEXT NOT NULL,
  tx TEXT NOT NULL,
  PRIMARY KEY (peer, key)
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  cursor TEXT NOT NULL,
  filter_json TEXT NOT NULL,
  state TEXT NOT NULL,
  tx TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS catalog_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  highest_revision TEXT,
  hash TEXT
);

-- ── v2 core projections ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS runs_v2 (
  run_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  kit TEXT NOT NULL,
  state TEXT NOT NULL,
  spool_seq TEXT NOT NULL,
  exit_code INTEGER,
  signal TEXT,
  pending_sync INTEGER NOT NULL DEFAULT 0,
  tx TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operations_v2 (
  id TEXT PRIMARY KEY,
  principal TEXT NOT NULL,
  kind TEXT NOT NULL,
  state TEXT NOT NULL,
  slug TEXT NOT NULL,
  from_v TEXT,
  to_v TEXT,
  cursor TEXT,
  error_json TEXT,
  tx TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
  source TEXT PRIMARY KEY,
  key_id TEXT NOT NULL,
  public TEXT NOT NULL,
  owner TEXT NOT NULL,
  tx TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
  key TEXT PRIMARY KEY,
  object_id TEXT NOT NULL,
  pointer_json TEXT NOT NULL,
  native_json TEXT NOT NULL,
  previous_json TEXT NOT NULL,
  principal TEXT NOT NULL,
  method TEXT NOT NULL,
  tx TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS actions_object ON actions(object_id);

CREATE TABLE IF NOT EXISTS peers (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  tx TEXT NOT NULL
);

-- Generic durable documents: pair/challenge/grant/session/lifecycle/cloud
-- records whose full JSON state rides the journal. kind namespaces rows.
CREATE TABLE IF NOT EXISTS docs (
  kind TEXT NOT NULL,
  id TEXT NOT NULL,
  doc_json TEXT NOT NULL,
  tx TEXT NOT NULL,
  PRIMARY KEY (kind, id)
);

-- One-use session bootstrap tokens (hash-keyed; never plaintext).
CREATE TABLE IF NOT EXISTS bootstraps (
  hash TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  expires_ms INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  epoch TEXT NOT NULL DEFAULT '',
  tx TEXT NOT NULL
);

-- Product-lifecycle generation rows (row_json carries the full
-- GenerationRow); active is the registry's atomic active pointer.
CREATE TABLE IF NOT EXISTS lifecycle_generations (
  slug TEXT NOT NULL,
  generation TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0,
  row_json TEXT NOT NULL,
  tx TEXT NOT NULL,
  PRIMARY KEY (slug, generation)
);
`;

/**
 * Columns added after the initial schema; applied to pre-existing
 * databases via ALTER TABLE (the CREATE TABLE statements above describe
 * the fresh-database shape only for brand-new tables).
 */
const COLUMN_MIGRATIONS: Readonly<Record<string, readonly string[]>> = {
  events: [
    "raw_sha256 TEXT",
    "topic TEXT",
    "profile TEXT",
    "media TEXT",
    "record_bytes TEXT",
    "cursor TEXT",
    "record_order INTEGER",
  ],
  subscriptions: [
    "topics_json TEXT",
    "position INTEGER NOT NULL DEFAULT 0",
    "delivered INTEGER NOT NULL DEFAULT 0",
    "expires_ms INTEGER",
  ],
};

const DATA_TABLES = [
  "events",
  "native_objects",
  "transport_cursors",
  "runs",
  "runs_v2",
  "products",
  "operations",
  "operations_v2",
  "approvals",
  "grants",
  "outbox",
  "pairs",
  "subscriptions",
  "sources",
  "actions",
  "peers",
  "docs",
  "bootstraps",
  "lifecycle_generations",
] as const;

/** Full committed-record resolution: locator → derived index entry. */
export interface ResolvedRecord {
  cursor: string;
  ordinal: number;
  order: number;
}

export type RecordResolver = (locator: RecordLocator) => ResolvedRecord | null;

export interface RegistryOptions {
  /** Persisted instance identity; must match a previously stored one. */
  instance?: string;
  /** Derives cursor strings for marker records (transport_cursors index). */
  resolveCursor?: CursorResolver;
  /**
   * Full record resolution (cursor + global order) for marker records;
   * preferred over `resolveCursor` when both are present.
   */
  resolveRecord?: RecordResolver;
}

export class Registry {
  readonly path: string;
  private db: DatabaseSync;
  private readonly resolveCursor: CursorResolver | undefined;
  private readonly resolveRecord: RecordResolver | undefined;
  private closed = false;

  private constructor(
    path: string,
    db: DatabaseSync,
    resolveCursor?: CursorResolver,
    resolveRecord?: RecordResolver,
  ) {
    this.path = path;
    this.db = db;
    this.resolveCursor = resolveCursor;
    this.resolveRecord = resolveRecord;
  }

  static open(path: string, opts: RegistryOptions = {}): Registry {
    const db = new DatabaseSync(path);
    db.exec(SCHEMA);
    reg0MigrateColumns(db);
    const reg = new Registry(path, db, opts.resolveCursor, opts.resolveRecord);
    reg.fixModes();
    if (opts.instance !== undefined) {
      const existing = reg.kvGet("instance_id");
      if (existing === null) {
        reg.kvSet("instance_id", opts.instance);
      } else if (existing !== opts.instance) {
        db.close();
        throw storeError("IDENTITY_MISMATCH", "registry instance mismatch", {
          stored: existing,
          requested: opts.instance,
        });
      }
    }
    return reg;
  }

  close(): void {
    if (!this.closed) {
      this.db.close();
      this.closed = true;
    }
  }

  /** Run `fn` inside one IMMEDIATE sqlite transaction. */
  inTx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      this.db.exec("COMMIT");
      this.fixModes();
      return out;
    } catch (e) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* already rolled back */
      }
      throw e;
    }
  }

  /** §8.3: private state files are 0600; sqlite creates under umask. */
  private fixModes(): void {
    for (const suffix of ["", "-wal", "-shm"]) {
      chmod(`${this.path}${suffix}`, FILE_MODE).catch(() => {});
    }
  }

  // ---------- kv meta ----------

  kvGet(key: string): string | null {
    const row = this.db
      .prepare("SELECT value FROM kv_meta WHERE key = ?")
      .get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  kvSet(key: string, value: string): void {
    this.db
      .prepare("INSERT OR REPLACE INTO kv_meta(key, value) VALUES(?, ?)")
      .run(key, value);
  }

  lastIndexedTx(): string | null {
    return this.kvGet("last_indexed_tx");
  }

  // ---------- commit application ----------

  /**
   * Apply one committed marker: auto-index transport cursors from its
   * records (via the configured resolver), run the mutation reducer, and
   * advance `last_indexed_tx` — all in a single sqlite transaction.
   */
  applyCommit(marker: CommitMarker): void {
    this.inTx(() => {
      this.indexMarkerCursors(marker);
      this.applyMutation(marker.mutation, marker.tx, marker);
      this.kvSet("last_indexed_tx", marker.tx);
    });
  }

  private indexMarkerCursors(marker: CommitMarker): void {
    for (const rec of marker.records) {
      const resolved = this.resolveRecord?.(rec);
      const cursor = resolved?.cursor ?? this.resolveCursor?.(rec);
      if (cursor !== null && cursor !== undefined && cursor !== "") {
        this.db
          .prepare(
            `INSERT OR REPLACE INTO transport_cursors
             (instance, cursor, lane, segment, offset, length, raw_sha256, tx)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            this.kvGet("instance_id") ?? "",
            cursor,
            rec.lane,
            rec.segment,
            rec.offset,
            rec.length,
            rec.raw_sha256,
            marker.tx,
          );
      }
    }
  }

  /**
   * Full derived-index rebuild: wipe every data table and replay all
   * markers in one atomic sqlite transaction. `kv_meta` survives (it holds
   * identity, not projection state); `last_indexed_tx` ends at the head.
   */
  rebuildFromJournal(markers: CommitMarker[]): void {
    this.inTx(() => {
      for (const t of DATA_TABLES) this.db.exec(`DELETE FROM ${t}`);
      for (const marker of markers) {
        this.indexMarkerCursors(marker);
        this.applyMutation(marker.mutation, marker.tx, marker);
        this.kvSet("last_indexed_tx", marker.tx);
      }
      if (markers.length === 0) this.kvSet("last_indexed_tx", "0");
    });
  }

  /** Dispatch the versioned mutation union into projection writes. */
  private applyMutation(
    mutation: unknown,
    tx: string,
    marker: CommitMarker,
  ): void {
    const m = mutation as RegistryMutation;
    if (
      typeof m !== "object" ||
      m === null ||
      (m as { v?: unknown }).v !== 1 ||
      typeof (m as { kind?: unknown }).kind !== "string"
    ) {
      throw storeError("MUTATION_UNKNOWN", "mutation is not a v1 reducer input");
    }
    switch (m.kind) {
      case "noop":
        return;
      case "batch":
        for (const sub of m.mutations) this.applyMutation(sub, tx, marker);
        return;
      case "events":
        for (const e of m.events) {
          if (isEventEntryV2(e)) this.upsertEventV2(e, tx, marker);
          else this.upsertEvent(e, tx);
        }
        return;
      case "native_objects":
        for (const o of m.objects) {
          this.db
            .prepare(
              `INSERT OR REPLACE INTO native_objects
               (profile, namespace, type, object_id, commitment, raw_sha256, bytes, tx)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              o.profile,
              o.namespace,
              o.type,
              o.object_id,
              o.commitment ?? "",
              o.raw_sha256 ?? null,
              o.bytes ?? null,
              tx,
            );
        }
        return;
      case "cursors":
        for (const c of m.cursors) {
          this.db
            .prepare(
              `INSERT OR REPLACE INTO transport_cursors
               (instance, cursor, lane, segment, offset, length, raw_sha256, tx)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              c.instance,
              c.cursor,
              c.lane,
              c.segment,
              c.offset,
              c.length,
              c.raw_sha256,
              tx,
            );
        }
        return;
      case "runs":
        for (const r of m.runs) {
          if (isRunEntryV2(r)) {
            this.db
              .prepare(
                `INSERT OR REPLACE INTO runs_v2
                 (run_id, owner, kit, state, spool_seq, exit_code, signal,
                  pending_sync, tx)
                 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              )
              .run(
                r.run_id,
                r.owner,
                r.kit,
                r.state,
                r.spool_seq,
                r.exit_code,
                r.signal,
                r.pending_sync,
                tx,
              );
          } else {
            this.db
              .prepare(
                `INSERT OR REPLACE INTO runs(legacy_namespace, ulid, owner, tx)
                 VALUES(?, ?, ?, ?)`,
              )
              .run(r.legacy_namespace, r.ulid, r.owner, tx);
          }
        }
        return;
      case "products":
        for (const p of m.products) {
          if (p.active === true) {
            this.db
              .prepare("UPDATE products SET active = 0 WHERE slug = ? AND instance = ?")
              .run(p.slug, p.instance);
          }
          this.db
            .prepare(
              `INSERT OR REPLACE INTO products(slug, instance, generation, state, active, tx)
               VALUES(?, ?, ?, ?, ?, ?)`,
            )
            .run(p.slug, p.instance, p.generation, p.state, p.active === true ? 1 : 0, tx);
        }
        return;
      case "operations":
        for (const o of m.operations) {
          if (isOperationEntryV2(o)) {
            this.db
              .prepare(
                `INSERT OR REPLACE INTO operations_v2
                 (id, principal, kind, state, slug, from_v, to_v, cursor,
                  error_json, tx)
                 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              )
              .run(
                o.id,
                o.principal,
                o.kind,
                o.state,
                o.slug,
                o.from,
                o.to,
                o.cursor,
                o.error === null ? null : JSON.stringify(o.error),
                tx,
              );
          } else {
            this.db
              .prepare(
                `INSERT OR REPLACE INTO operations
                 (principal, id, request_hash, result_json, state, tx)
                 VALUES(?, ?, ?, ?, ?, ?)`,
              )
              .run(o.principal, o.id, o.request_hash, o.result_json ?? null, o.state, tx);
          }
        }
        return;
      case "approvals":
        for (const a of m.approvals) {
          this.db
            .prepare(
              `INSERT OR REPLACE INTO approvals(home, request, revision, state, tx)
               VALUES(?, ?, ?, ?, ?)`,
            )
            .run(a.home, a.request, a.revision, a.state, tx);
        }
        return;
      case "grants":
        for (const g of m.grants) {
          this.db
            .prepare(
              `INSERT OR REPLACE INTO grants(peer, key, revision, scopes_json, state, tx)
               VALUES(?, ?, ?, ?, ?, ?)`,
            )
            .run(g.peer, g.key, g.revision, JSON.stringify(g.scopes), g.state, tx);
        }
        return;
      case "outbox":
        for (const item of m.items) {
          this.upsertOutboxRow(item, tx);
        }
        return;
      case "pairs":
        for (const p of m.pairs) {
          this.db
            .prepare(
              `INSERT OR REPLACE INTO pairs(peer, key, meta_json, state, tx)
               VALUES(?, ?, ?, ?, ?)`,
            )
            .run(p.peer, p.key, JSON.stringify(p.meta ?? null), p.state, tx);
        }
        return;
      case "subscriptions":
        for (const s of m.subscriptions) {
          if (isSubscriptionEntryV2(s)) {
            this.db
              .prepare(
                `INSERT OR REPLACE INTO subscriptions
                 (id, owner, cursor, filter_json, state, topics_json,
                  position, delivered, expires_ms, tx)
                 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              )
              .run(
                s.id,
                s.owner,
                s.cursor,
                JSON.stringify({ topics: s.topics }),
                s.state,
                JSON.stringify(s.topics),
                s.position,
                s.delivered,
                s.expires_ms,
                tx,
              );
          } else {
            this.db
              .prepare(
                `INSERT OR REPLACE INTO subscriptions
                 (id, owner, cursor, filter_json, state, tx)
                 VALUES(?, ?, ?, ?, ?, ?)`,
              )
              .run(s.id, s.owner, s.cursor, JSON.stringify(s.filter ?? null), s.state, tx);
          }
        }
        return;
      case "sources":
        for (const s of m.sources) {
          this.db
            .prepare(
              `INSERT OR REPLACE INTO sources(source, key_id, public, owner, tx)
               VALUES(?, ?, ?, ?, ?)`,
            )
            .run(s.source, s.key_id, s.public, s.owner, tx);
        }
        return;
      case "actions":
        for (const a of m.actions) {
          // Lookup key contract (platform actionKeyOf):
          // sha256(canonical JSON of the ReceiptPointer).
          const key = sha256hex(canonicalJson(a.pointer));
          const objectId =
            typeof (a.nativeRef as { object_id?: unknown }).object_id ===
            "string"
              ? ((a.nativeRef as { object_id: string }).object_id)
              : "";
          this.db
            .prepare(
              `INSERT OR REPLACE INTO actions
               (key, object_id, pointer_json, native_json, previous_json,
                principal, method, tx)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              key,
              objectId,
              JSON.stringify(a.pointer),
              JSON.stringify(a.nativeRef),
              JSON.stringify(a.previous ?? null),
              a.principal,
              a.method,
              tx,
            );
        }
        return;
      case "peers":
        for (const p of m.peers) {
          this.db
            .prepare("INSERT OR REPLACE INTO peers(id, state, tx) VALUES(?, ?, ?)")
            .run(p.id, p.state, tx);
        }
        return;
      case "kv":
        for (const e of m.entries) {
          if (e.key === "last_indexed_tx") continue; // internal
          if (e.value === null) {
            this.db.prepare("DELETE FROM kv_meta WHERE key = ?").run(e.key);
          } else {
            this.kvSet(e.key, e.value);
          }
        }
        return;
      case "docs":
        for (const d of m.docs) {
          if (d.doc === null) {
            this.db
              .prepare("DELETE FROM docs WHERE kind = ? AND id = ?")
              .run(d.kind, d.id);
          } else {
            this.db
              .prepare(
                `INSERT OR REPLACE INTO docs(kind, id, doc_json, tx)
                 VALUES(?, ?, ?, ?)`,
              )
              .run(d.kind, d.id, JSON.stringify(d.doc), tx);
          }
        }
        return;
      case "bootstraps":
        for (const b of m.bootstraps) {
          this.db
            .prepare(
              `INSERT OR REPLACE INTO bootstraps
               (hash, role, expires_ms, consumed, epoch, tx)
               VALUES(?, ?, ?, ?, ?, ?)`,
            )
            .run(
              b.hash,
              b.role,
              b.expires_ms,
              b.consumed === true ? 1 : 0,
              b.epoch ?? "",
              tx,
            );
        }
        return;
      case "bootstrap_take": {
        // Atomic one-use consume; outcome recorded for the commitSync
        // caller (never thrown — replay must stay deterministic). An
        // `epoch` clause binds the consume to the boot that minted it.
        const r =
          m.epoch === undefined
            ? this.db
                .prepare(
                  "UPDATE bootstraps SET consumed = 1, tx = ? WHERE hash = ? AND consumed = 0",
                )
                .run(tx, m.hash)
            : this.db
                .prepare(
                  "UPDATE bootstraps SET consumed = 1, tx = ? WHERE hash = ? AND consumed = 0 AND epoch = ?",
                )
                .run(tx, m.hash, m.epoch);
        this.kvSet(`bootstrap:took:${tx}`, Number(r.changes) > 0 ? "1" : "0");
        return;
      }
      case "lifecycle": {
        for (const u of m.upserts ?? []) {
          const row = u.row as { active?: unknown };
          const active =
            row.active === true ||
            (u.row as { active?: unknown }).active === 1
              ? 1
              : 0;
          this.db
            .prepare(
              `INSERT OR REPLACE INTO lifecycle_generations
               (slug, generation, active, row_json, tx) VALUES(?, ?, ?, ?, ?)`,
            )
            .run(u.slug, u.generation, active, JSON.stringify(u.row), tx);
        }
        if (m.cas !== undefined) {
          const cur = this.db
            .prepare(
              `SELECT generation, row_json FROM lifecycle_generations
               WHERE slug = ? AND active = 1`,
            )
            .get(m.cas.slug) as
            | { generation: string; row_json: string }
            | undefined;
          const current = cur?.generation ?? null;
          let ok = false;
          if (current === m.cas.expected) {
            // Resolve the next row BEFORE deactivating so a missing target
            // leaves the prior active pointer intact.
            const next =
              m.cas.next === null
                ? undefined
                : (this.db
                    .prepare(
                      `SELECT row_json FROM lifecycle_generations
                       WHERE slug = ? AND generation = ?`,
                    )
                    .get(m.cas.slug, m.cas.next) as
                    | { row_json: string }
                    | undefined);
            if (m.cas.next === null || next !== undefined) {
              if (cur !== undefined) {
                const row = JSON.parse(cur.row_json) as Record<
                  string,
                  unknown
                >;
                row.active = false;
                this.db
                  .prepare(
                    `UPDATE lifecycle_generations SET active = 0, row_json = ?, tx = ?
                     WHERE slug = ? AND generation = ?`,
                  )
                  .run(JSON.stringify(row), tx, m.cas.slug, cur.generation);
              }
              if (next !== undefined && m.cas.next !== null) {
                const row = JSON.parse(next.row_json) as Record<
                  string,
                  unknown
                >;
                row.active = true;
                this.db
                  .prepare(
                    `UPDATE lifecycle_generations SET active = 1, row_json = ?, tx = ?
                     WHERE slug = ? AND generation = ?`,
                  )
                  .run(JSON.stringify(row), tx, m.cas.slug, m.cas.next);
              }
              ok = true;
            }
          }
          this.kvSet(`lifecycle:cas:${tx}`, ok ? "1" : "0");
        }
        if ((m.upserts?.length ?? 0) > 0 || m.cas !== undefined) {
          const rev = BigInt(this.kvGet("lifecycle:revision") ?? "0") + 1n;
          this.kvSet("lifecycle:revision", rev.toString());
        }
        return;
      }
      case "catalog": {
        const cur = this.catalogMeta();
        const highest = m.highest_revision !== undefined ? m.highest_revision : cur.highest_revision;
        const hash = m.hash !== undefined ? m.hash : cur.hash;
        this.db
          .prepare(
            `INSERT OR REPLACE INTO catalog_meta(id, highest_revision, hash)
             VALUES(1, ?, ?)`,
          )
          .run(highest, hash);
        return;
      }
      default:
        throw storeError("MUTATION_UNKNOWN", `unknown mutation kind ${String((m as { kind?: unknown }).kind)}`);
    }
  }

  private upsertEvent(e: EventIndexEntry, tx: string): void {
    if (!isHex64(e.hash) || !isDecimalString(e.seq)) {
      throw storeError("MUTATION_UNKNOWN", "event entry fails hash/seq shape");
    }
    this.db
      .prepare(
        `INSERT OR IGNORE INTO events
         (workspace, source, stream, seq, hash, conflict, lane, segment, offset, length, tx)
         VALUES(?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
      )
      .run(
        e.workspace,
        e.source,
        e.stream,
        e.seq,
        e.hash,
        e.lane ?? null,
        e.segment ?? null,
        e.offset ?? null,
        e.length ?? null,
        tx,
      );
    // Conflict flag: >1 distinct hash candidate under one slot.
    this.db
      .prepare(
        `UPDATE events SET conflict =
           (SELECT CASE WHEN COUNT(*) > 1 THEN 1 ELSE 0 END FROM events e2
            WHERE e2.workspace = events.workspace AND e2.source = events.source
              AND e2.stream = events.stream AND e2.seq = events.seq)
         WHERE workspace = ? AND source = ? AND stream = ? AND seq = ?`,
      )
      .run(e.workspace, e.source, e.stream, e.seq);
  }

  /**
   * Core (platform-layer) event entry: resolves `record` (index into the
   * marker's committed record list) through the configured record resolver
   * to the cursor/lane/global order, or takes explicit cursor/order/lane
   * fields when present.
   */
  private upsertEventV2(
    e: EventIndexEntryV2,
    tx: string,
    marker: CommitMarker,
  ): void {
    if (!isHex64(e.hash) || !isDecimalString(e.seq)) {
      throw storeError("MUTATION_UNKNOWN", "event entry fails hash/seq shape");
    }
    let cursor = e.cursor ?? null;
    let order = e.order ?? 0;
    let lane = e.lane ?? null;
    if (e.record !== undefined) {
      const locator = marker.records[e.record];
      const resolved =
        locator !== undefined ? this.resolveRecord?.(locator) : undefined;
      if (resolved !== null && resolved !== undefined) {
        cursor = resolved.cursor;
        order = resolved.order;
        lane = locator!.lane;
      }
    }
    const existing = this.db
      .prepare(
        `SELECT raw_sha256 FROM events
         WHERE workspace = ? AND source = ? AND stream = ? AND seq = ?
           AND hash = ?`,
      )
      .all(e.workspace, e.source, e.stream, e.seq, e.hash) as unknown as {
      raw_sha256: string | null;
    }[];
    // Candidates are distinct by raw bytes: the same (hash,raw_sha256)
    // pair is a re-played commit, not a new conflict candidate.
    if (!existing.some((r) => r.raw_sha256 === e.raw_sha256)) {
      this.db
        .prepare(
          `INSERT OR IGNORE INTO events
           (workspace, source, stream, seq, hash, conflict, lane, segment,
            offset, length, raw_sha256, topic, profile, media, record_bytes,
            cursor, record_order, tx)
           VALUES(?, ?, ?, ?, ?, 0, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          e.workspace,
          e.source,
          e.stream,
          e.seq,
          e.hash,
          lane,
          e.raw_sha256,
          e.topic,
          e.profile,
          e.media,
          e.record_bytes,
          cursor,
          order,
          tx,
        );
    }
    // TV-GW-32/P06: >1 distinct raw candidate under one slot → conflict.
    this.db
      .prepare(
        `UPDATE events SET conflict =
           (SELECT CASE WHEN COUNT(DISTINCT COALESCE(raw_sha256, hash)) > 1
             THEN 1 ELSE 0 END FROM events e2
            WHERE e2.workspace = events.workspace AND e2.source = events.source
              AND e2.stream = events.stream AND e2.seq = events.seq)
         WHERE workspace = ? AND source = ? AND stream = ? AND seq = ?`,
      )
      .run(e.workspace, e.source, e.stream, e.seq);
    if (e.conflict === true) {
      this.db
        .prepare(
          `UPDATE events SET conflict = 1
           WHERE workspace = ? AND source = ? AND stream = ? AND seq = ?`,
        )
        .run(e.workspace, e.source, e.stream, e.seq);
    }
  }

  private upsertOutboxRow(item: OutboxEntry, tx: string): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO outbox
         (id, destination, cohort, stream, batch_hash, state, item_json, tx)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        item.id,
        item.destination,
        item.cohort,
        item.stream,
        item.batch_hash ?? null,
        item.state,
        JSON.stringify(item.item),
        tx,
      );
  }

  // ---------- typed query helpers ----------

  /** Every conflicting candidate retained under one native slot (§8.3). */
  eventSlotCandidates(
    workspace: string,
    source: string,
    stream: string,
    seq: string,
  ): EventRow[] {
    return this.db
      .prepare(
        `SELECT * FROM events
         WHERE workspace = ? AND source = ? AND stream = ? AND seq = ?
         ORDER BY hash`,
      )
      .all(workspace, source, stream, seq) as unknown as EventRow[];
  }

  nativeObjectCandidates(
    profile: string,
    namespace: string,
    type: string,
    object_id: string,
  ): NativeObjectRow[] {
    return this.db
      .prepare(
        `SELECT * FROM native_objects
         WHERE profile = ? AND namespace = ? AND type = ? AND object_id = ?
         ORDER BY commitment`,
      )
      .all(profile, namespace, type, object_id) as unknown as NativeObjectRow[];
  }

  cursorLookup(instance: string, cursor: string): CursorRow | null {
    const row = this.db
      .prepare("SELECT * FROM transport_cursors WHERE instance = ? AND cursor = ?")
      .get(instance, cursor) as unknown as CursorRow | undefined;
    return row ?? null;
  }

  runLookup(legacy_namespace: string, ulid: string): RunRow | null {
    const row = this.db
      .prepare("SELECT * FROM runs WHERE legacy_namespace = ? AND ulid = ?")
      .get(legacy_namespace, ulid) as unknown as RunRow | undefined;
    return row ?? null;
  }

  operationLookup(principal: string, id: string): OperationRow | null {
    const row = this.db
      .prepare("SELECT * FROM operations WHERE principal = ? AND id = ?")
      .get(principal, id) as unknown as OperationRow | undefined;
    return row ?? null;
  }

  operationByRequestHash(request_hash: string): OperationRow | null {
    const row = this.db
      .prepare("SELECT * FROM operations WHERE request_hash = ? ORDER BY tx DESC LIMIT 1")
      .get(request_hash) as unknown as OperationRow | undefined;
    return row ?? null;
  }

  activeProduct(slug: string, instance: string): ProductRow | null {
    const row = this.db
      .prepare(
        "SELECT * FROM products WHERE slug = ? AND instance = ? AND active = 1 LIMIT 1",
      )
      .get(slug, instance) as unknown as ProductRow | undefined;
    return row ?? null;
  }

  approvalLookup(home: string, request: string): ApprovalRow[] {
    return this.db
      .prepare(
        "SELECT * FROM approvals WHERE home = ? AND request = ? ORDER BY revision DESC",
      )
      .all(home, request) as unknown as ApprovalRow[];
  }

  grantLookup(peer: string, key: string): GrantRow[] {
    return this.db
      .prepare("SELECT * FROM grants WHERE peer = ? AND key = ? ORDER BY revision DESC")
      .all(peer, key) as unknown as GrantRow[];
  }

  catalogMeta(): CatalogMeta {
    const row = this.db
      .prepare("SELECT highest_revision, hash FROM catalog_meta WHERE id = 1")
      .get() as { highest_revision: string | null; hash: string | null } | undefined;
    return { highest_revision: row?.highest_revision ?? null, hash: row?.hash ?? null };
  }

  // ---------- outbox rows (used by outbox.ts) ----------

  outboxGet(id: string): OutboxRow | null {
    const row = this.db
      .prepare("SELECT * FROM outbox WHERE id = ?")
      .get(id) as unknown as OutboxRow | undefined;
    return row ?? null;
  }

  outboxUpsert(
    item: { id: string; destination: string; cohort: string; stream: string },
    fields: {
      batch_hash?: string | null;
      state: string;
      item_json: string;
      tx: string;
    },
  ): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO outbox
         (id, destination, cohort, stream, batch_hash, state, item_json, tx)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        item.id,
        item.destination,
        item.cohort,
        item.stream,
        fields.batch_hash ?? null,
        fields.state,
        fields.item_json,
        fields.tx,
      );
  }

  outboxWhere(where: string, ...params: (string | number)[]): OutboxRow[] {
    return this.db
      .prepare(`SELECT * FROM outbox WHERE ${where} ORDER BY rowid`)
      .all(...params) as unknown as OutboxRow[];
  }

  // ---------- v2 core readers ----------

  /** Resolve a transport cursor to its indexed v2 event entry, if any. */
  eventByCursor(cursor: string): EventRowV2 | null {
    const row = this.db
      .prepare("SELECT * FROM events WHERE cursor = ?")
      .get(cursor) as unknown as EventRowV2 | undefined;
    return row ?? null;
  }

  /** All entries of one `(workspace,source,stream)` lane, seq ascending. */
  eventLane(workspace: string, source: string, stream: string): EventRowV2[] {
    return this.db
      .prepare(
        `SELECT * FROM events
         WHERE workspace = ? AND source = ? AND stream = ?
         ORDER BY LENGTH(seq), seq`,
      )
      .all(workspace, source, stream) as unknown as EventRowV2[];
  }

  /** Event entries in global commit order after `order` (bounded). */
  eventsAfter(order: number, limit: number): EventRowV2[] {
    return this.db
      .prepare(
        `SELECT * FROM events WHERE record_order > ?
         ORDER BY record_order LIMIT ?`,
      )
      .all(order, limit) as unknown as EventRowV2[];
  }

  /** All entries carrying a topic, in global commit order. */
  eventsByTopic(topic: string): EventRowV2[] {
    return this.db
      .prepare(
        `SELECT * FROM events WHERE topic = ? ORDER BY record_order`,
      )
      .all(topic) as unknown as EventRowV2[];
  }

  /** All v2 slot candidates (same row source as eventSlotCandidates). */
  eventSlotV2(
    workspace: string,
    source: string,
    stream: string,
    seq: string,
  ): EventRowV2[] {
    return this.db
      .prepare(
        `SELECT * FROM events
         WHERE workspace = ? AND source = ? AND stream = ? AND seq = ?
         ORDER BY hash`,
      )
      .all(workspace, source, stream, seq) as unknown as EventRowV2[];
  }

  runV2Get(runId: string): RunRowV2 | null {
    const row = this.db
      .prepare("SELECT * FROM runs_v2 WHERE run_id = ?")
      .get(runId) as unknown as RunRowV2 | undefined;
    return row ?? null;
  }

  operationV2Get(id: string): OperationRowV2 | null {
    const row = this.db
      .prepare("SELECT * FROM operations_v2 WHERE id = ?")
      .get(id) as unknown as OperationRowV2 | undefined;
    return row ?? null;
  }

  subscriptionV2Get(id: string): SubscriptionRowV2 | null {
    const row = this.db
      .prepare("SELECT * FROM subscriptions WHERE id = ?")
      .get(id) as unknown as SubscriptionRowV2 | undefined;
    return row ?? null;
  }

  subscriptionsV2ByOwner(owner: string): SubscriptionRowV2[] {
    return this.db
      .prepare("SELECT * FROM subscriptions WHERE owner = ? ORDER BY rowid")
      .all(owner) as unknown as SubscriptionRowV2[];
  }

  sourceGet(source: string): SourceRow | null {
    const row = this.db
      .prepare("SELECT * FROM sources WHERE source = ?")
      .get(source) as unknown as SourceRow | undefined;
    return row ?? null;
  }

  actionGet(key: string): ActionRow | null {
    const row = this.db
      .prepare("SELECT * FROM actions WHERE key = ?")
      .get(key) as unknown as ActionRow | undefined;
    return row ?? null;
  }

  actionByObjectId(objectId: string): ActionRow | null {
    const row = this.db
      .prepare("SELECT * FROM actions WHERE object_id = ? ORDER BY tx DESC LIMIT 1")
      .get(objectId) as unknown as ActionRow | undefined;
    return row ?? null;
  }

  /** Installed-product count: slugs with a live (non-tombstoned) active generation. */
  countProductsInstalled(): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(DISTINCT g.slug) AS n
         FROM lifecycle_generations g
         WHERE g.active = 1
           AND json_extract(g.row_json, '$.state') NOT IN ('REMOVED','FAILED')`,
      )
      .get() as { n: number };
    return row.n;
  }

  countPeers(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS n FROM docs WHERE kind = 'peer'")
      .get() as { n: number };
    return row.n;
  }

  // ---------- lifecycle generations ----------

  lifecycleGenerations(slug: string): LifecycleGenerationRow[] {
    return this.db
      .prepare(
        `SELECT * FROM lifecycle_generations WHERE slug = ?
         ORDER BY LENGTH(generation), generation`,
      )
      .all(slug) as unknown as LifecycleGenerationRow[];
  }

  lifecycleGenerationsAll(): LifecycleGenerationRow[] {
    return this.db
      .prepare(
        `SELECT * FROM lifecycle_generations
         ORDER BY slug, LENGTH(generation), generation`,
      )
      .all() as unknown as LifecycleGenerationRow[];
  }

  lifecycleGenerationGet(
    slug: string,
    generation: string,
  ): LifecycleGenerationRow | null {
    const row = this.db
      .prepare(
        `SELECT * FROM lifecycle_generations
         WHERE slug = ? AND generation = ?`,
      )
      .get(slug, generation) as unknown as
      | LifecycleGenerationRow
      | undefined;
    return row ?? null;
  }

  lifecycleRevision(): string {
    return this.kvGet("lifecycle:revision") ?? "0";
  }

  // ---------- durable documents ----------

  docGet(kind: string, id: string): DocRow | null {
    const row = this.db
      .prepare("SELECT * FROM docs WHERE kind = ? AND id = ?")
      .get(kind, id) as unknown as DocRow | undefined;
    return row ?? null;
  }

  docsList(kind: string): DocRow[] {
    return this.db
      .prepare("SELECT * FROM docs WHERE kind = ? ORDER BY rowid")
      .all(kind) as unknown as DocRow[];
  }

  /**
   * Atomic one-use bootstrap consume: flips `consumed` inside one
   * statement and returns the row it locked, or null when absent/already
   * consumed. The durable marker is appended by the caller (commitSync)
   * so the journal remains the evidence trail.
   */
  bootstrapConsume(hash: string, tx: string): BootstrapRow | null {
    const r = this.db
      .prepare(
        "UPDATE bootstraps SET consumed = 1, tx = ? WHERE hash = ? AND consumed = 0",
      )
      .run(tx, hash);
    if (Number(r.changes) === 0) return null;
    return this.db
      .prepare("SELECT * FROM bootstraps WHERE hash = ?")
      .get(hash) as unknown as BootstrapRow;
  }

  bootstrapGet(hash: string): BootstrapRow | null {
    const row = this.db
      .prepare("SELECT * FROM bootstraps WHERE hash = ?")
      .get(hash) as unknown as BootstrapRow | undefined;
    return row ?? null;
  }
}

// ---------- entry-shape guards (dual legacy/core mutation payloads) -----

function isEventEntryV2(
  e: EventIndexEntry | EventIndexEntryV2,
): e is EventIndexEntryV2 {
  return typeof (e as EventIndexEntryV2).raw_sha256 === "string";
}

function isRunEntryV2(r: RunEntry | RunEntryV2): r is RunEntryV2 {
  return typeof (r as RunEntryV2).run_id === "string";
}

function isOperationEntryV2(
  o: OperationEntry | OperationEntryV2,
): o is OperationEntryV2 {
  return typeof (o as OperationEntryV2).slug === "string";
}

function isSubscriptionEntryV2(
  s: SubscriptionEntry | SubscriptionEntryV2,
): s is SubscriptionEntryV2 {
  return Array.isArray((s as SubscriptionEntryV2).topics);
}

/** Apply additive column migrations to databases created by older builds. */
function reg0MigrateColumns(db: DatabaseSync): void {
  for (const [table, columns] of Object.entries(COLUMN_MIGRATIONS)) {
    const existing = new Set(
      (db.prepare(`PRAGMA table_info(${table})`).all() as unknown as {
        name: string;
      }[]).map((c) => c.name),
    );
    for (const decl of columns) {
      const name = decl.split(" ")[0]!;
      if (!existing.has(name)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${decl}`);
      }
    }
  }
}
