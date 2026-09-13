import { chmod } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { storeError } from "./errors.js";
import type { CommitMarker, RecordLocator } from "./journal.js";
import { FILE_MODE, isDecimalString, isHex64, type Json } from "./util.js";

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

export type RegistryMutation =
  | { v: 1; kind: "noop" }
  | { v: 1; kind: "batch"; mutations: RegistryMutation[] }
  | { v: 1; kind: "events"; events: EventIndexEntry[] }
  | { v: 1; kind: "native_objects"; objects: NativeObjectEntry[] }
  | { v: 1; kind: "cursors"; cursors: CursorEntry[] }
  | { v: 1; kind: "runs"; runs: RunEntry[] }
  | { v: 1; kind: "products"; products: ProductEntry[] }
  | { v: 1; kind: "operations"; operations: OperationEntry[] }
  | { v: 1; kind: "approvals"; approvals: ApprovalEntry[] }
  | { v: 1; kind: "grants"; grants: GrantEntry[] }
  | { v: 1; kind: "outbox"; items: OutboxEntry[] }
  | { v: 1; kind: "pairs"; pairs: PairEntry[] }
  | { v: 1; kind: "subscriptions"; subscriptions: SubscriptionEntry[] }
  | {
      v: 1;
      kind: "catalog";
      highest_revision?: string | null;
      hash?: string | null;
    };

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
`;

const DATA_TABLES = [
  "events",
  "native_objects",
  "transport_cursors",
  "runs",
  "products",
  "operations",
  "approvals",
  "grants",
  "outbox",
  "pairs",
  "subscriptions",
] as const;

export interface RegistryOptions {
  /** Persisted instance identity; must match a previously stored one. */
  instance?: string;
  /** Derives cursor strings for marker records (transport_cursors index). */
  resolveCursor?: CursorResolver;
}

export class Registry {
  readonly path: string;
  private db: DatabaseSync;
  private readonly resolveCursor: CursorResolver | undefined;
  private closed = false;

  private constructor(path: string, db: DatabaseSync, resolveCursor?: CursorResolver) {
    this.path = path;
    this.db = db;
    this.resolveCursor = resolveCursor;
  }

  static open(path: string, opts: RegistryOptions = {}): Registry {
    const db = new DatabaseSync(path);
    db.exec(SCHEMA);
    const reg = new Registry(path, db, opts.resolveCursor);
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
      for (const rec of marker.records) {
        const cursor = this.resolveCursor?.(rec);
        if (cursor !== null && cursor !== undefined) {
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
      this.applyMutation(marker.mutation, marker.tx);
      this.kvSet("last_indexed_tx", marker.tx);
    });
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
        for (const rec of marker.records) {
          const cursor = this.resolveCursor?.(rec);
          if (cursor !== null && cursor !== undefined) {
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
        this.applyMutation(marker.mutation, marker.tx);
        this.kvSet("last_indexed_tx", marker.tx);
      }
      if (markers.length === 0) this.kvSet("last_indexed_tx", "0");
    });
  }

  /** Dispatch the versioned mutation union into projection writes. */
  private applyMutation(mutation: unknown, tx: string): void {
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
        for (const sub of m.mutations) this.applyMutation(sub, tx);
        return;
      case "events":
        for (const e of m.events) this.upsertEvent(e, tx);
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
          this.db
            .prepare(
              `INSERT OR REPLACE INTO runs(legacy_namespace, ulid, owner, tx)
               VALUES(?, ?, ?, ?)`,
            )
            .run(r.legacy_namespace, r.ulid, r.owner, tx);
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
          this.db
            .prepare(
              `INSERT OR REPLACE INTO operations
               (principal, id, request_hash, result_json, state, tx)
               VALUES(?, ?, ?, ?, ?, ?)`,
            )
            .run(o.principal, o.id, o.request_hash, o.result_json ?? null, o.state, tx);
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
          this.db
            .prepare(
              `INSERT OR REPLACE INTO subscriptions
               (id, owner, cursor, filter_json, state, tx)
               VALUES(?, ?, ?, ?, ?, ?)`,
            )
            .run(s.id, s.owner, s.cursor, JSON.stringify(s.filter ?? null), s.state, tx);
        }
        return;
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
}
