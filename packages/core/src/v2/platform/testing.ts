/**
 * In-memory `PlatformPorts` for tests: simple Maps + in-memory lane arrays
 * implementing the §2.3 commit contract (objects → records → marker →
 * projection) without sqlite or filesystem IO.
 *
 * Determinism: the clock is pinned (default 1789257600000), lane ordinals
 * are assigned in first-commit order starting at 1, and `newId`/`newToken`
 * are injectable so tests can reproduce fixture tokens.
 */
import { generateKeyPairSync } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { Buffer } from "node:buffer";
import type { Hash, Id, Json } from "../protocol/refs.js";
import { canonicalJson, isCanonicalDomainValue } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import { formatCursor, newControlId, newToken, parseCursor } from "../crypto/ids.js";
import { CryptoError } from "../crypto/errors.js";
import type { Topic } from "../protocol/topics.js";
import type { ReceiptPointer } from "../protocol/envelope.js";
import type { NativeRef } from "../protocol/refs.js";
import type {
  PlatformActionEntry,
  PlatformBootstrapRecord,
  PlatformCommitInput,
  PlatformCommitResult,
  PlatformCursorResolution,
  PlatformEventEntry,
  PlatformLaneHead,
  PlatformLaneRecord,
  PlatformOperationEntry,
  PlatformPorts,
  PlatformRegistry,
  PlatformRunEntry,
  PlatformSessionRecord,
  PlatformSessionStore,
  PlatformSourceEntry,
  PlatformStore,
  PlatformSubscriptionEntry,
} from "./ports.js";
import { EVIDENCE_PROFILES } from "./ports.js";

const LANE_PART = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const PROOF_LANE_CAP = 65536;
const LEGACY_LANE_CAP = 1048576;

export class MemoryStoreError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "MemoryStoreError";
    this.code = code;
  }
}

interface MemoryLane {
  key: string;
  ordinal: bigint;
  records: {
    ordinal: number;
    cursor: string;
    data: Uint8Array;
    order: number;
    raw_sha256: string;
  }[];
  /** First retained record ordinal; records below it are pruned. */
  floor: number;
}

interface MemoryMarker {
  v: 1;
  tx: string;
  previous: string;
  records: {
    lane: string;
    segment: string;
    offset: number;
    length: number;
    raw_sha256: string;
  }[];
  objects: { digest: string; bytes: string }[];
  mutation: Json;
  result_sha256: string;
}

// ── mutation payload shapes (the versioned local reducer input) ──────────

type Mutation =
  | { v: 1; kind: "noop" }
  | { v: 1; kind: "batch"; mutations: Mutation[] }
  | { v: 1; kind: "kv"; entries: { key: string; value: string | null }[] }
  | {
      v: 1;
      kind: "events";
      events: (Omit<
        PlatformEventEntry,
        "cursor" | "order" | "lane" | "conflict"
      > & {
        /** Index into commit.records supplying cursor/lane/order. */
        record?: number;
        cursor?: string;
        order?: number;
        lane?: string;
        conflict?: boolean;
      })[];
    }
  | { v: 1; kind: "runs"; runs: PlatformRunEntry[] }
  | { v: 1; kind: "operations"; operations: PlatformOperationEntry[] }
  | { v: 1; kind: "subscriptions"; subscriptions: PlatformSubscriptionEntry[] }
  | { v: 1; kind: "sources"; sources: PlatformSourceEntry[] }
  | { v: 1; kind: "actions"; actions: Omit<PlatformActionEntry, "key">[] }
  | {
      v: 1;
      kind: "products";
      products: {
        slug: string;
        instance: string;
        generation: number;
        state: string;
        active?: boolean;
      }[];
    }
  | {
      v: 1;
      kind: "peers";
      peers: { id: string; state: string }[];
    };

/**
 * The in-memory store. Lanes hold committed record arrays; a global
 * `order` counter gives every record a monotone commit position used by
 * the subscription frontier/ack logic.
 */
export class MemoryPlatformStore implements PlatformStore {
  readonly registry: PlatformRegistry;

  /** lane key → lane state. */
  private readonly lanes = new Map<string, MemoryLane>();
  private nextLaneOrdinal = 1n;
  private order = 0;
  private txCounter = 0;
  private headHash = "0".repeat(64);
  /** All committed markers, in order (journal chain). */
  readonly markers: MemoryMarker[] = [];
  /** digest → raw object bytes. */
  readonly objects = new Map<string, Uint8Array>();
  /** cursor → {lane, ordinal}. */
  private readonly cursorIndex = new Map<string, { lane: string; ordinal: number; order: number }>();

  // projection tables
  private readonly kv = new Map<string, string>();
  private readonly events = new Map<string, PlatformEventEntry[]>(); // slot key
  private readonly eventByCursorIdx = new Map<string, PlatformEventEntry>();
  private readonly runs = new Map<string, PlatformRunEntry>();
  private readonly operations = new Map<string, PlatformOperationEntry>();
  private readonly subscriptions = new Map<string, PlatformSubscriptionEntry>();
  private readonly sources = new Map<string, PlatformSourceEntry>();
  private readonly actions = new Map<string, PlatformActionEntry>();
  private readonly actionsByNativeId = new Map<string, PlatformActionEntry>();
  private readonly products = new Map<string, { state: string; active: boolean }>();
  private readonly peers = new Map<string, { state: string }>();

  constructor() {
    const self = this;
    this.registry = {
      kvGet: (key) => Promise.resolve(self.kv.get(key) ?? null),
      kvSet: (key, value) => {
        self.kv.set(key, value);
        return Promise.resolve();
      },
      eventSlot: (workspace, source, stream, seq) =>
        Promise.resolve([
          ...(self.events.get(`${workspace}/${source}/${stream}/${seq}`) ?? []),
        ]),
      eventByCursor: (cursor) =>
        Promise.resolve(self.eventByCursorIdx.get(cursor) ?? null),
      eventLane: (workspace, source, stream) => {
        const prefix = `${workspace}/${source}/${stream}/`;
        const out: PlatformEventEntry[] = [];
        for (const [key, list] of self.events) {
          if (key.startsWith(prefix)) out.push(...list);
        }
        out.sort((a, b) => {
          const d = BigInt(a.seq) - BigInt(b.seq);
          return d < 0n ? -1 : d > 0n ? 1 : 0;
        });
        return Promise.resolve(out);
      },
      eventsByTopic: (topic) => {
        const out: PlatformEventEntry[] = [];
        for (const list of self.events.values()) {
          for (const e of list) if (e.topic === topic) out.push(e);
        }
        out.sort((a, b) => a.order - b.order);
        return Promise.resolve(out);
      },
      runGet: (runId) => Promise.resolve(self.runs.get(runId) ?? null),
      operationGet: (id) => Promise.resolve(self.operations.get(id) ?? null),
      subscriptionGet: (id) =>
        Promise.resolve(self.subscriptions.get(id) ?? null),
      subscriptionsByOwner: (owner) => {
        const out: PlatformSubscriptionEntry[] = [];
        for (const s of self.subscriptions.values()) {
          if (s.owner === owner) out.push({ ...s });
        }
        return Promise.resolve(out);
      },
      sourceGet: (source) => Promise.resolve(self.sources.get(source) ?? null),
      actionGet: (key) => Promise.resolve(self.actions.get(key) ?? null),
      actionByNativeId: (objectId) =>
        Promise.resolve(self.actionsByNativeId.get(objectId) ?? null),
      countProducts: () => {
        const inst = new Set<string>();
        for (const key of self.products.keys()) {
          inst.add(key.split("/").slice(0, 2).join("/"));
        }
        return Promise.resolve(inst.size);
      },
      countPeers: () => Promise.resolve(self.peers.size),
    };
  }

  // ── test-side seeding helpers (fixture setup, not evidence) ────────────

  /** Enroll a producer source directly (pairing/registration fixture). */
  seedSource(entry: PlatformSourceEntry): void {
    this.sources.set(entry.source, entry);
  }

  /** Directly place a registry run row. */
  seedRun(entry: PlatformRunEntry): void {
    this.runs.set(entry.run_id, entry);
  }

  /** Directly place a registry operation row. */
  seedOperation(entry: PlatformOperationEntry): void {
    this.operations.set(entry.id, entry);
  }

  /** Directly place a committed action entry. */
  seedAction(entry: Omit<PlatformActionEntry, "key">): void {
    const key = sha256Hex(canonicalJson(entry.pointer));
    const full = { ...entry, key };
    this.actions.set(key, full);
    this.actionsByNativeId.set(entry.nativeRef.object_id, full);
  }

  /** Seed config kv state (document stored as its raw JSON text). */
  seedConfig(document: unknown, revision: string): void {
    this.kv.set("config:document", JSON.stringify(document));
    this.kv.set("config:revision", revision);
  }

  /**
   * Retention: drop committed records below `beforeOrdinal` in `lane`.
   * Their cursors still resolve (`retained:false`) so the service layer can
   * answer CURSOR_GONE instead of NOT_FOUND.
   */
  pruneBefore(lane: string, beforeOrdinal: number): void {
    const l = this.lanes.get(lane);
    if (l === undefined) return;
    l.floor = Math.max(l.floor, beforeOrdinal);
    l.records = l.records.filter((r) => r.ordinal >= l.floor);
  }

  /** All entries currently occupying a Proof slot (test assertions). */
  slotEntries(
    workspace: string,
    source: string,
    stream: string,
    seq: string,
  ): PlatformEventEntry[] {
    return [...(this.events.get(`${workspace}/${source}/${stream}/${seq}`) ?? [])];
  }

  /** Read a committed lane record's bytes by cursor (test assertions). */
  recordAt(cursor: string): Uint8Array | null {
    const at = this.cursorIndex.get(cursor);
    if (at === undefined) return null;
    const lane = this.lanes.get(at.lane);
    const rec = lane?.records.find((r) => r.ordinal === at.ordinal);
    return rec?.data ?? null;
  }

  // ── PlatformStore ──────────────────────────────────────────────────────

  private laneFor(key: string): MemoryLane {
    let lane = this.lanes.get(key);
    if (lane === undefined) {
      lane = {
        key,
        ordinal: this.nextLaneOrdinal,
        records: [],
        floor: 1,
      };
      this.nextLaneOrdinal += 1n;
      this.lanes.set(key, lane);
    }
    return lane;
  }

  private static checkRecord(laneKey: string, data: Uint8Array): void {
    if (data.length === 0) {
      throw new MemoryStoreError("BAD_RECORD", "empty record");
    }
    const cap = laneKey.startsWith("proof/") ? PROOF_LANE_CAP : LEGACY_LANE_CAP;
    if (data.length > cap) {
      throw new MemoryStoreError(
        "OBJECT_LIMIT",
        `record exceeds lane cap ${cap}`,
      );
    }
    if (data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) {
      throw new MemoryStoreError("BAD_RECORD", "record carries a UTF-8 BOM");
    }
    for (const b of data) {
      if (b === 0x0a) {
        throw new MemoryStoreError("BAD_RECORD", "record contains raw LF");
      }
    }
  }

  async commit(input: PlatformCommitInput): Promise<PlatformCommitResult> {
    if (!/^[0-9a-f]{64}$/.test(input.result_sha256)) {
      throw new MemoryStoreError("BAD_RECORD", "result_sha256 must be 64 hex");
    }
    const objectDescs: { digest: string; bytes: string }[] = [];
    for (const bytes of input.objects ?? []) {
      const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const digest = sha256Hex(data);
      this.objects.set(digest, data);
      objectDescs.push({ digest, bytes: String(data.length) });
    }

    const locators: MemoryMarker["records"] = [];
    const cursors: string[] = [];
    const committed: MemoryLane["records"] = [];
    for (const rec of input.records ?? []) {
      const laneKey =
        rec.partition !== undefined ? `${rec.lane}/${rec.partition}` : rec.lane;
      const parts = laneKey.split("/");
      if (
        parts.length > 2 ||
        !parts.every((p) => LANE_PART.test(p)) ||
        (parts.length === 2 && parts[0] !== "proof") ||
        (parts.length === 1 && parts[0] !== "legacy")
      ) {
        throw new MemoryStoreError("BAD_LANE", `invalid lane key ${laneKey}`);
      }
      const data =
        typeof rec.data === "string"
          ? Buffer.from(rec.data, "utf8")
          : Buffer.from(rec.data);
      MemoryPlatformStore.checkRecord(laneKey, data);
      const lane = this.laneFor(laneKey);
      const last = lane.records[lane.records.length - 1];
      const nextOrdinal =
        last === undefined ? Math.max(lane.floor, 1) : last.ordinal + 1;
      const order = ++this.order;
      const cursor = formatCursor(lane.ordinal.toString(16).padStart(16, "0"), nextOrdinal);
      const raw_sha256 = sha256Hex(new Uint8Array([...data, 0x0a]));
      const committedRec = {
        ordinal: nextOrdinal,
        cursor,
        data,
        order,
        raw_sha256,
      };
      lane.records.push(committedRec);
      committed.push(committedRec);
      this.cursorIndex.set(cursor, { lane: laneKey, ordinal: nextOrdinal, order });
      cursors.push(cursor);
      locators.push({
        lane: laneKey,
        segment: "s0000000000000001.jsonl",
        offset: 0,
        length: data.length + 1,
        raw_sha256,
      });
    }

    const tx = String(++this.txCounter);
    const marker: MemoryMarker = {
      v: 1,
      tx,
      previous: this.headHash,
      records: locators,
      objects: objectDescs,
      mutation: input.mutation,
      result_sha256: input.result_sha256,
    };
    const line = `${JSON.stringify(marker)}\n`;
    this.headHash = sha256Hex(line);
    this.markers.push(marker);

    this.applyMutation(
      input.mutation as unknown as Mutation,
      committed,
      cursors,
      tx,
    );
    return { tx, cursors };
  }

  private applyMutation(
    mutation: Mutation,
    committed: MemoryLane["records"],
    cursors: string[],
    tx: string,
  ): void {
    const m = mutation;
    if (typeof m !== "object" || m === null || m.v !== 1) {
      throw new MemoryStoreError("MUTATION_UNKNOWN", "mutation must be v:1");
    }
    switch (m.kind) {
      case "noop":
        return;
      case "batch":
        for (const sub of m.mutations) {
          this.applyMutation(sub, committed, cursors, tx);
        }
        return;
      case "kv":
        for (const e of m.entries) {
          if (e.value === null) this.kv.delete(e.key);
          else this.kv.set(e.key, e.value);
        }
        return;
      case "events":
        for (const e of m.events) {
          const recIdx = e.record ?? (m.events.length === 1 ? 0 : undefined);
          const rec = recIdx !== undefined ? committed[recIdx] : undefined;
          const entry: PlatformEventEntry = {
            workspace: e.workspace,
            source: e.source,
            stream: e.stream,
            seq: e.seq,
            hash: e.hash,
            raw_sha256: e.raw_sha256,
            topic: e.topic,
            profile: e.profile,
            media: e.media,
            record_bytes: e.record_bytes,
            lane:
              e.lane ?? (rec !== undefined ? this.laneOfOrder(rec.order) : ""),
            cursor: e.cursor ?? cursors[recIdx ?? -1] ?? "",
            order: e.order ?? rec?.order ?? 0,
            conflict: e.conflict ?? false,
          };
          const slotKey = `${entry.workspace}/${entry.source}/${entry.stream}/${entry.seq}`;
          const list = this.events.get(slotKey) ?? [];
          // Candidates are distinct by raw bytes; (hash,raw_sha256) pairs
          // already present are the same committed record (re-replay).
          if (
            !list.some(
              (x) => x.hash === entry.hash && x.raw_sha256 === entry.raw_sha256,
            )
          ) {
            list.push(entry);
            this.events.set(slotKey, list);
          }
          if (entry.cursor !== "") this.eventByCursorIdx.set(entry.cursor, entry);
          // TV-GW-32/P06: >1 distinct candidate under one slot → all
          // conflicted, zero authority, no timestamp winner.
          const conflicted =
            new Set(list.map((x) => x.raw_sha256)).size > 1;
          for (const x of list) x.conflict = conflicted;
        }
        return;
      case "runs":
        for (const r of m.runs) this.runs.set(r.run_id, { ...r });
        return;
      case "operations":
        for (const o of m.operations) this.operations.set(o.id, { ...o });
        return;
      case "subscriptions":
        for (const s of m.subscriptions) this.subscriptions.set(s.id, { ...s });
        return;
      case "sources":
        for (const s of m.sources) this.sources.set(s.source, { ...s });
        return;
      case "actions":
        for (const a of m.actions) this.seedAction(a);
        return;
      case "products":
        for (const p of m.products) {
          if (p.active === true) {
            for (const [key, row] of this.products) {
              if (key.startsWith(`${p.slug}/${p.instance}/`)) row.active = false;
            }
          }
          this.products.set(`${p.slug}/${p.instance}/${p.generation}`, {
            state: p.state,
            active: p.active === true,
          });
        }
        return;
      case "peers":
        for (const p of m.peers) this.peers.set(p.id, { state: p.state });
        return;
      default:
        throw new MemoryStoreError(
          "MUTATION_UNKNOWN",
          `unknown mutation kind ${String((m as { kind?: unknown }).kind)}`,
        );
    }
  }

  private laneOfOrder(order: number): string {
    for (const lane of this.lanes.values()) {
      if (lane.records.some((r) => r.order === order)) return lane.key;
    }
    return "";
  }

  async *laneScan(
    lane: string,
    after?: string | null,
    limit?: number,
  ): AsyncIterable<PlatformLaneRecord> {
    const l = this.lanes.get(lane);
    if (l === undefined) return;
    let fromOrdinal = 0;
    if (after !== undefined && after !== null) {
      const parsed = parseCursor(after);
      if (parsed === null) {
        throw new MemoryStoreError("BAD_CURSOR", `unparseable cursor ${after}`);
      }
      fromOrdinal = Number(parsed.ordinal);
    }
    let yielded = 0;
    for (const rec of l.records) {
      if (rec.ordinal <= fromOrdinal) continue;
      if (limit !== undefined && yielded >= limit) return;
      yielded += 1;
      yield { lane, cursor: rec.cursor, data: rec.data, order: rec.order };
    }
  }

  laneHead(lane: string): Promise<PlatformLaneHead> {
    const l = this.lanes.get(lane);
    if (l === undefined) {
      return Promise.resolve({
        laneOrdinal: "0".repeat(16),
        nextRecordOrdinal: 1,
        headOrder: 0,
        headCursor: null,
        floorOrdinal: 1,
      });
    }
    const head = l.records[l.records.length - 1];
    return Promise.resolve({
      laneOrdinal: l.ordinal.toString(16).padStart(16, "0"),
      nextRecordOrdinal:
        head === undefined ? l.floor : head.ordinal + 1,
      headOrder: head?.order ?? 0,
      headCursor: head?.cursor ?? null,
      floorOrdinal: l.floor,
    });
  }

  resolveCursor(cursor: string): Promise<PlatformCursorResolution | null> {
    const parsed = parseCursor(cursor);
    if (parsed === null) return Promise.resolve(null);
    const laneHex = parsed.lane;
    for (const lane of this.lanes.values()) {
      if (lane.ordinal.toString(16).padStart(16, "0") !== laneHex) continue;
      const ordinal = Number(parsed.ordinal);
      if (ordinal === 0) {
        return Promise.resolve({ lane: lane.key, ordinal: 0, order: 0, retained: true });
      }
      const rec = lane.records.find((r) => r.ordinal === ordinal);
      if (rec !== undefined) {
        return Promise.resolve({
          lane: lane.key,
          ordinal,
          order: rec.order,
          retained: true,
        });
      }
      if (ordinal < lane.floor) {
        return Promise.resolve({
          lane: lane.key,
          ordinal,
          order: -1,
          retained: false,
        });
      }
      const head = lane.records[lane.records.length - 1];
      if (head !== undefined && ordinal > head.ordinal) {
        return Promise.resolve(null); // beyond head: never committed
      }
      // Inside floor..head but missing → pruned interior (holes) or unknown.
      return Promise.resolve({ lane: lane.key, ordinal, order: -1, retained: false });
    }
    return Promise.resolve(null);
  }

  async peekNextCursor(lane: string): Promise<string | null> {
    const head = await this.laneHead(lane);
    if (head.laneOrdinal === "0".repeat(16)) return null;
    return formatCursor(head.laneOrdinal, head.nextRecordOrdinal);
  }

  /** Highest committed record order across all lanes, and its cursor. */
  globalHead(): Promise<{ order: number; cursor: string | null }> {
    let best: { order: number; cursor: string } | null = null;
    for (const lane of this.lanes.values()) {
      const head = lane.records[lane.records.length - 1];
      if (head !== undefined && (best === null || head.order > best.order)) {
        best = { order: head.order, cursor: head.cursor };
      }
    }
    return Promise.resolve(
      best === null ? { order: 0, cursor: null } : best,
    );
  }

  getRecord(cursor: string): Promise<Uint8Array | null> {
    const at = this.cursorIndex.get(cursor);
    if (at === undefined) return Promise.resolve(null);
    const lane = this.lanes.get(at.lane);
    const rec = lane?.records.find((r) => r.ordinal === at.ordinal);
    return Promise.resolve(rec?.data ?? null);
  }

  getObject(digest: Hash): Promise<Uint8Array> {
    const data = this.objects.get(digest);
    if (data === undefined) {
      return Promise.reject(
        new MemoryStoreError("NOT_FOUND", `object ${digest} absent`),
      );
    }
    return Promise.resolve(data);
  }

  putObject(
    bytes: Uint8Array,
    maxBytes: number,
  ): Promise<{ digest: Hash; bytes: number }> {
    if (bytes.length > maxBytes) {
      return Promise.reject(
        new MemoryStoreError("OBJECT_LIMIT", "object exceeds bound"),
      );
    }
    const digest = sha256Hex(bytes);
    this.objects.set(digest, bytes);
    return Promise.resolve({ digest, bytes: bytes.length });
  }
}

// ── in-memory session store ──────────────────────────────────────────────

export class MemorySessionStore implements PlatformSessionStore {
  readonly bootstraps = new Map<string, PlatformBootstrapRecord>();
  readonly sessions = new Map<string, PlatformSessionRecord>();
  private readonly consumed = new Set<string>();

  bootstrapPut(record: PlatformBootstrapRecord): Promise<void> {
    this.bootstraps.set(record.hash, record);
    return Promise.resolve();
  }

  /** Atomic consume-once take. */
  bootstrapTake(hash: Hash): Promise<PlatformBootstrapRecord | null> {
    if (this.consumed.has(hash)) return Promise.resolve(null);
    const rec = this.bootstraps.get(hash);
    if (rec === undefined) return Promise.resolve(null);
    this.consumed.add(hash);
    this.bootstraps.delete(hash);
    return Promise.resolve(rec);
  }

  sessionPut(record: PlatformSessionRecord): Promise<void> {
    this.sessions.set(record.hash, record);
    return Promise.resolve();
  }

  sessionGet(hash: Hash): Promise<PlatformSessionRecord | null> {
    return Promise.resolve(this.sessions.get(hash) ?? null);
  }

  sessionRevoke(hash: Hash): Promise<void> {
    const rec = this.sessions.get(hash);
    if (rec !== undefined) rec.state = "REVOKED";
    return Promise.resolve();
  }
}

// ── createMemoryPlatformPorts ────────────────────────────────────────────

export interface MemoryPortsOptions {
  now?: number;
  workspace?: Id;
  instance?: Id;
  configDir?: string;
  auditKey?: KeyObject;
  uiEndpoint?: string | null;
  profiles?: readonly string[];
  mesh?: { available: boolean; code?: string };
  nativeCollectorBound?: boolean;
  nativeLineageBound?: boolean;
  newId?: () => Id;
  newToken?: () => string;
  onStop?: (graceMs: number) => void;
}

export interface MemoryPlatformPorts extends PlatformPorts {
  readonly store: MemoryPlatformStore;
  readonly sessionStore: MemorySessionStore;
  /** Move the injectable clock forward / pin it (ms since epoch). */
  setNow(ms: number): void;
  advance(ms: number): void;
}

export function createMemoryPlatformPorts(
  opts: MemoryPortsOptions = {},
): MemoryPlatformPorts {
  let now = opts.now ?? 1789257600000;
  const auditKey =
    opts.auditKey ?? generateKeyPairSync("ed25519").privateKey;
  const ports: MemoryPlatformPorts = {
    store: new MemoryPlatformStore(),
    sessionStore: new MemorySessionStore(),
    configDir: opts.configDir ?? "",
    clock: () => now,
    workspace: opts.workspace ?? "ws1",
    instance: opts.instance ?? "gw1",
    receiptWorkspace: "audit1",
    auditSource: "gateway1",
    auditKey,
    uiEndpoint: opts.uiEndpoint === undefined ? "http://127.0.0.1:9848" : opts.uiEndpoint,
    profiles: opts.profiles ?? EVIDENCE_PROFILES,
    mesh: opts.mesh ?? { available: false, code: "CAP_ADAPTER_UNAVAILABLE" },
    nativeCollectorBound: opts.nativeCollectorBound ?? false,
    nativeLineageBound: opts.nativeLineageBound ?? false,
    newId: opts.newId ?? (() => newControlId()),
    newToken: opts.newToken ?? (() => newToken()),
    onStop: opts.onStop,
    setNow(ms: number) {
      now = ms;
    },
    advance(ms: number) {
      now += ms;
    },
  };
  return ports;
}

/** Convenience: ReceiptPointer for an indexed event entry. */
export function pointerFor(entry: {
  workspace: Id;
  source: Id;
  stream: Id;
  seq: string;
  hash: Hash;
}): ReceiptPointer {
  return {
    workspace: entry.workspace,
    event: {
      source: entry.source,
      stream: entry.stream,
      seq: entry.seq,
      hash: entry.hash,
    },
  };
}

export { CryptoError, isCanonicalDomainValue };
export type { NativeRef, Topic };
