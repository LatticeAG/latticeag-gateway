import { join } from "node:path";
import { readdir } from "node:fs/promises";
import { storeError } from "./errors.js";
import {
  Journal,
  type JournalHead,
  type ObjectDescriptor,
  type RecordLocator,
} from "./journal.js";
import type { StateLayout } from "./layout.js";
import {
  LaneWriter,
  formatCursor,
  parseCursor,
  readSegmentSlice,
  segmentOrdinalOf,
  type CommittedSegment,
} from "./lanes.js";
import { ObjectStore } from "./objects.js";
import { OutboxStore } from "./outbox.js";
import {
  recoverStoreContext,
  type IndexedLocator,
  type LaneIndex,
  type RecoveryReport,
} from "./recovery.js";
import { Registry } from "./registry.js";
import {
  ensureDir,
  isHex64,
  pathExists,
  sha256hex,
  type Json,
} from "./util.js";

const LANE_PART = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const LANE_KEY = /^legacy$|^proof\/[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
/** Proof events are natively capped at 64 KiB (§2.2). */
const PROOF_LANE_CAP = 65536;
const LEGACY_LANE_CAP = 1048576;

export interface CommitRecordInput {
  /** `"legacy"` or `"proof"`. */
  lane: string;
  /** Proof partition name; required for `lane:"proof"`. */
  partition?: string;
  /** One LF-free UTF-8 JSON value. */
  data: Uint8Array | string;
}

export interface CommitInput {
  records?: CommitRecordInput[];
  /** Raw object bytes admitted before lane appends (§2.3 order). */
  objects?: Uint8Array[];
  /** Versioned local reducer input (see registry.ts RegistryMutation). */
  mutation: Json;
  /** 64-hex SHA-256 of the operation result payload. */
  result_sha256: string;
}

export interface CommitResult {
  tx: string;
  cursors: string[];
  records: RecordLocator[];
  objects: ObjectDescriptor[];
}

export interface ScannedRecord {
  cursor: string;
  /** Record payload bytes (LF stripped). */
  data: Buffer;
  locator: IndexedLocator;
  /** Global monotone commit order across all lanes (1-based). */
  order: number;
}

/** Head metadata of one lane (created lanes that never committed stay empty). */
export interface LaneHeadInfo {
  /** 16-hex lane ordinal. */
  laneOrdinal: string;
  /** Ordinal the next record in this lane will receive (1-based). */
  nextRecordOrdinal: number;
  /** Global commit order of the lane's head record, or 0 when empty. */
  headOrder: number;
  /** Head record's cursor, or null for an empty lane. */
  headCursor: string | null;
  /** First retained record ordinal (1 = full retention). */
  floorOrdinal: number;
}

/** Result of resolving a transport cursor against committed lanes. */
export interface CursorResolution {
  lane: string;
  /** Record ordinal inside the lane. */
  ordinal: number;
  /** Global commit order (-1 for pruned interior positions). */
  order: number;
  /** False when the ordinal fell under the lane's retention floor. */
  retained: boolean;
}

export interface OpenOptions {
  instance?: string;
  segmentBytes?: number;
  maxSegmentAgeMs?: number;
  /** Override per-line caps; default: proof lanes 64 KiB, others 1 MiB. */
  maxRecordBytes?: number;
  maxObjectBytes?: number;
}

export type StoreStatus = "READY" | "READ_ONLY" | "RECOVERING";

async function readdirSafe(dir: string): Promise<string[]> {
  try {
    return await readdir(dir);
  } catch {
    return [];
  }
}

export function laneDirFor(lay: StateLayout, laneKey: string): string {
  const parts = laneKey.split("/");
  if (
    parts.length === 0 ||
    parts.length > 2 ||
    !parts.every((p) => LANE_PART.test(p))
  ) {
    throw storeError("BAD_LANE", `invalid lane key ${laneKey}`);
  }
  return join(lay.busDir, ...parts);
}

/**
 * The durable Gateway store facade. `open` runs full §2.3 recovery
 * (journal chain verify, per-lane orphan/torn recovery, registry replay),
 * then `commit` executes the exact commit order:
 * objects → lane appends → lane fsync → journal marker fdatasync →
 * sqlite apply → acknowledge.
 */
export class GatewayStore {
  readonly root: string;
  readonly layout: StateLayout;
  readonly registry: Registry;
  readonly outbox: OutboxStore;
  readonly objects: ObjectStore;
  readonly recovery: RecoveryReport;

  private readonly journal: Journal;
  private readonly laneIndex: Map<string, LaneIndex>;
  private readonly laneOrdinals: Map<string, bigint>;
  private readonly laneCommitted: Map<string, Map<string, CommittedSegment>>;
  private readonly writers = new Map<string, LaneWriter>();
  private nextLaneOrdinal: bigint;
  private recordOrder: number;
  private state: StoreStatus;
  private readOnly: { at: string; reason: string } | null;
  private readonly opts: Required<Omit<OpenOptions, "instance">>;
  private readonly instance: string;
  private closedFlag = false;

  private constructor(
    root: string,
    lay: StateLayout,
    journal: Journal,
    registry: Registry,
    objects: ObjectStore,
    ctx: {
      report: RecoveryReport;
      laneIndex: Map<string, LaneIndex>;
      laneOrdinals: Map<string, bigint>;
      laneCommitted: Map<string, Map<string, CommittedSegment>>;
      nextLaneOrdinal: bigint;
      readOnly: { at: string; reason: string } | null;
    },
    opts: Required<Omit<OpenOptions, "instance">>,
    instance: string,
  ) {
    this.root = root;
    this.layout = lay;
    this.journal = journal;
    this.registry = registry;
    this.objects = objects;
    this.outbox = new OutboxStore(registry);
    this.recovery = ctx.report;
    this.laneIndex = ctx.laneIndex;
    this.laneOrdinals = ctx.laneOrdinals;
    this.laneCommitted = ctx.laneCommitted;
    this.nextLaneOrdinal = ctx.nextLaneOrdinal;
    this.readOnly = ctx.readOnly;
    this.state = this.readOnly === null ? "READY" : "READ_ONLY";
    // The global record-order counter resumes where the recovered index
    // ended — buildLaneIndex assigns order 1..N across committed markers.
    let order = 0;
    for (const li of ctx.laneIndex.values()) {
      for (const seg of li.segments.values()) {
        for (const loc of seg.locators) {
          if (loc.order > order) order = loc.order;
        }
      }
    }
    this.recordOrder = order;
    this.opts = opts;
    this.instance = instance;
  }

  static async open(
    root: string,
    opts: OpenOptions = {},
  ): Promise<GatewayStore> {
    const resolved = {
      segmentBytes: opts.segmentBytes ?? 67108864,
      maxSegmentAgeMs: opts.maxSegmentAgeMs ?? 86400000,
      maxRecordBytes: opts.maxRecordBytes ?? 0,
      maxObjectBytes: opts.maxObjectBytes ?? 1048576,
    };
    const ctx = await recoverStoreContext(root, { instance: opts.instance });
    const instance =
      opts.instance ?? ctx.registry.kvGet("instance_id") ?? "default";
    if (ctx.registry.kvGet("instance_id") === null) {
      ctx.registry.kvSet("instance_id", instance);
    }
    const store = new GatewayStore(
      root,
      ctx.layout,
      ctx.journal,
      ctx.registry,
      new ObjectStore(ctx.layout.objectsDir, { maxBytes: resolved.maxObjectBytes }),
      ctx,
      resolved,
      instance,
    );
    if (store.state === "READY") {
      // Reopen lane writers on the recovered heads.
      for (const [lane, rep] of ctx.laneReports) {
        if (rep.corrupt.length > 0) continue;
        const dir = laneDirFor(ctx.layout, lane);
        let ordinal = ctx.laneOrdinals.get(lane);
        if (ordinal === undefined) {
          ordinal = store.nextLaneOrdinal;
          store.nextLaneOrdinal += 1n;
          store.laneOrdinals.set(lane, ordinal);
        }
        const { writer } = await LaneWriter.open(dir, {
          lane,
          ordinal,
          segmentBytes: resolved.segmentBytes,
          maxAgeMs: resolved.maxSegmentAgeMs,
          maxRecordBytes: store.capFor(lane),
          quarantineDir: ctx.layout.quarantineDir,
          committed: ctx.laneCommitted.get(lane),
          report: rep,
        });
        store.writers.set(lane, writer);
      }
    }
    return store;
  }

  status(): StoreStatus {
    return this.state;
  }

  get instanceId(): string {
    return this.instance;
  }

  head(): JournalHead {
    return this.journal.head();
  }

  private capFor(lane: string): number {
    if (this.opts.maxRecordBytes > 0) return this.opts.maxRecordBytes;
    return lane.startsWith("proof/") ? PROOF_LANE_CAP : LEGACY_LANE_CAP;
  }

  /**
   * Execute the §2.3 commit protocol:
   * persist immutable objects → append complete lane records → fsync lanes
   * → append+fdatasync the commit marker → apply the sqlite transaction →
   * acknowledge with `{tx, cursors}`.
   */
  async commit(input: CommitInput): Promise<CommitResult> {
    if (this.closedFlag) throw storeError("CORRUPT", "store is closed");
    if (this.readOnly !== null) {
      throw storeError("READ_ONLY", "store is read-only", this.readOnly);
    }
    if (!isHex64(input.result_sha256)) {
      throw storeError("BAD_RECORD", "result_sha256 must be 64 lowercase hex");
    }
    if (typeof input.mutation !== "object" || input.mutation === null) {
      throw storeError("MUTATION_UNKNOWN", "mutation must be a reducer input object");
    }

    // 1. Immutable objects first.
    const objects: ObjectDescriptor[] = [];
    for (const bytes of input.objects ?? []) {
      const put = await this.objects.put(bytes);
      objects.push({ digest: put.digest, bytes: put.bytes.toString() });
    }

    // 2. Append complete lane records.
    const records: RecordLocator[] = [];
    const cursors: string[] = [];
    const touched = new Set<LaneWriter>();
    for (const rec of input.records ?? []) {
      const laneKey =
        rec.partition !== undefined ? `${rec.lane}/${rec.partition}` : rec.lane;
      if (!LANE_KEY.test(laneKey)) {
        throw storeError("BAD_LANE", `invalid lane key ${laneKey}`);
      }
      const writer = await this.writerFor(laneKey);
      const data =
        typeof rec.data === "string" ? Buffer.from(rec.data, "utf8") : rec.data;
      const app = await writer.append(data);
      records.push({
        lane: laneKey,
        segment: app.segment,
        offset: app.offset,
        length: app.length,
        raw_sha256: app.raw_sha256,
      });
      cursors.push(app.cursor);
      touched.add(writer);
    }

    // 3. fsync every touched lane before the marker.
    for (const w of touched) await w.fsync();

    // 4. Append + fdatasync the commit marker.
    const marker = this.journal.nextMarker({
      records,
      objects,
      mutation: input.mutation,
      result_sha256: input.result_sha256,
    });
    await this.journal.append(marker);

    // 5. Index the commit in memory (cursor resolution feeds the sqlite
    //    reducer), then apply the registry transaction.
    for (let i = 0; i < records.length; i++) {
      this.indexRecord(records[i]!, cursors[i]!);
    }
    this.registry.applyCommit(marker);

    return { tx: marker.tx, cursors, records, objects };
  }

  /**
   * Synchronous mutation-only commit: no lane records, no objects — just
   * the journal marker (fdatasync) + the registry apply, in §2.3 order.
   * Backs synchronous port contracts (peer/session/approval stores) whose
   * callers cannot await; never used for evidence-carrying lane writes.
   */
  commitSync(input: { mutation: Json; result_sha256: string }): { tx: string } {
    if (this.closedFlag) throw storeError("CORRUPT", "store is closed");
    if (this.readOnly !== null) {
      throw storeError("READ_ONLY", "store is read-only", this.readOnly);
    }
    if (!isHex64(input.result_sha256)) {
      throw storeError("BAD_RECORD", "result_sha256 must be 64 lowercase hex");
    }
    if (typeof input.mutation !== "object" || input.mutation === null) {
      throw storeError("MUTATION_UNKNOWN", "mutation must be a reducer input object");
    }
    const marker = this.journal.nextMarker({
      records: [],
      objects: [],
      mutation: input.mutation,
      result_sha256: input.result_sha256,
    });
    this.journal.appendSync(marker);
    this.registry.applyCommit(marker);
    return { tx: marker.tx };
  }

  /** Append a locator to the in-memory committed index. */
  private indexRecord(rec: RecordLocator, cursor: string): void {
    let li = this.laneIndex.get(rec.lane);
    if (li === undefined) {
      li = {
        lane: rec.lane,
        ordinal: this.laneOrdinals.get(rec.lane) ?? 0n,
        segments: new Map(),
        totalRecords: 0,
      };
      this.laneIndex.set(rec.lane, li);
    }
    let seg = li.segments.get(rec.segment);
    if (seg === undefined) {
      seg = {
        segment: rec.segment,
        ordinal: segmentOrdinalOf(rec.segment) ?? 0,
        locators: [],
        end: 0,
      };
      li.segments.set(rec.segment, seg);
    }
    li.totalRecords += 1;
    this.recordOrder += 1;
    const ord = Number(parseCursor(cursor)?.recordOrdinal ?? li.totalRecords);
    seg.locators.push({ ...rec, cursor, ordinal: ord, order: this.recordOrder });
    seg.locators.sort((a, b) => a.offset - b.offset);
    seg.end = Math.max(seg.end, rec.offset + rec.length);
    const comm =
      this.laneCommitted.get(rec.lane) ?? new Map<string, CommittedSegment>();
    const cl: CommittedSegment = comm.get(rec.segment) ?? { locators: [] };
    cl.locators.push({
      offset: rec.offset,
      length: rec.length,
      raw_sha256: rec.raw_sha256,
    });
    cl.locators.sort((a, b) => a.offset - b.offset);
    comm.set(rec.segment, cl);
    this.laneCommitted.set(rec.lane, comm);
  }

  private async writerFor(laneKey: string): Promise<LaneWriter> {
    const existing = this.writers.get(laneKey);
    if (existing !== undefined) return existing;
    const dir = laneDirFor(this.layout, laneKey);
    const ordinal = this.laneOrdinals.get(laneKey) ?? this.nextLaneOrdinal;
    let writer: LaneWriter;
    const hasSegments =
      (await pathExists(join(dir, "lane.json"))) ||
      (await readdirSafe(dir)).some((n) => /^s[0-9a-f]{16}\.jsonl$/.test(n));
    if (hasSegments) {
      const opened = await LaneWriter.open(dir, {
        lane: laneKey,
        ordinal,
        segmentBytes: this.opts.segmentBytes,
        maxAgeMs: this.opts.maxSegmentAgeMs,
        maxRecordBytes: this.capFor(laneKey),
        quarantineDir: this.layout.quarantineDir,
        committed: this.laneCommitted.get(laneKey),
      });
      writer = opened.writer;
    } else {
      await ensureDir(dir);
      writer = await LaneWriter.create(dir, {
        lane: laneKey,
        ordinal,
        segmentBytes: this.opts.segmentBytes,
        maxAgeMs: this.opts.maxSegmentAgeMs,
        maxRecordBytes: this.capFor(laneKey),
      });
    }
    if (!this.laneOrdinals.has(laneKey)) {
      this.laneOrdinals.set(laneKey, writer.laneOrdinal);
    }
    const floor = writer.laneOrdinal + 1n;
    if (this.nextLaneOrdinal < floor) this.nextLaneOrdinal = floor;
    this.writers.set(laneKey, writer);
    return writer;
  }

  /**
   * Read committed records of one lane in commit order. Only journaled
   * extents are served — orphan/torn bytes are never returned — and each
   * slice is re-hashed against its marker locator.
   */
  async *laneScan(
    laneKey: string,
    opts: { from?: string; limit?: number } = {},
  ): AsyncIterable<ScannedRecord> {
    const li = this.laneIndex.get(laneKey);
    if (li === undefined) return;
    let fromOrdinal = 0n;
    if (opts.from !== undefined) {
      const parsed = parseCursor(opts.from);
      if (parsed === null) {
        throw storeError("BAD_CURSOR", `unparseable cursor ${opts.from}`);
      }
      if (parsed.laneOrdinal !== li.ordinal) {
        throw storeError("BAD_CURSOR", "cursor belongs to another lane", {
          cursor: opts.from,
        });
      }
      fromOrdinal = parsed.recordOrdinal;
    }
    const dir = laneDirFor(this.layout, laneKey);
    const segs = [...li.segments.values()].sort((a, b) => a.ordinal - b.ordinal);
    let yielded = 0;
    for (const seg of segs) {
      for (const loc of seg.locators) {
        if (BigInt(loc.ordinal) <= fromOrdinal) continue;
        if (opts.limit !== undefined && yielded >= opts.limit) return;
        const raw = await readSegmentSlice(join(dir, seg.segment), loc.offset, loc.length);
        if (sha256hex(raw) !== loc.raw_sha256) {
          throw storeError("CORRUPT", "lane record fails digest check", {
            lane: laneKey,
            segment: seg.segment,
            offset: loc.offset,
          });
        }
        yielded += 1;
        yield {
          cursor: loc.cursor,
          data: raw.subarray(0, raw.length - 1),
          locator: loc,
          order: loc.order,
        };
      }
    }
  }

  /** Head metadata of one lane; unknown lanes report an empty head. */
  async laneHead(laneKey: string): Promise<LaneHeadInfo> {
    const li = this.laneIndex.get(laneKey);
    const ordinal = li?.ordinal ?? this.laneOrdinals.get(laneKey) ?? 0n;
    let head: IndexedLocator | null = null;
    let floor = 1;
    if (li !== undefined) {
      for (const seg of li.segments.values()) {
        for (const loc of seg.locators) {
          if (head === null || loc.ordinal > head.ordinal) head = loc;
        }
        if (seg.locators.length > 0) {
          const min = seg.locators.reduce(
            (a, b) => (a.ordinal < b.ordinal ? a : b),
            seg.locators[0]!,
          );
          if (min.ordinal > 0) floor = Math.min(floor, min.ordinal);
        }
      }
    }
    return {
      laneOrdinal: ordinal.toString(16).padStart(16, "0"),
      nextRecordOrdinal: head === null ? floor : head.ordinal + 1,
      headOrder: head?.order ?? 0,
      headCursor: head === null || head.cursor === "" ? null : head.cursor,
      floorOrdinal: floor,
    };
  }

  /**
   * Resolve a transport cursor to lane/ordinal/global-order. Null when the
   * lane or ordinal was never committed; `retained:false` marks positions
   * below the retention floor or inside a pruned interior hole.
   */
  async resolveCursor(cursor: string): Promise<CursorResolution | null> {
    const parsed = parseCursor(cursor);
    if (parsed === null) return null;
    for (const li of this.laneIndex.values()) {
      if (li.ordinal !== parsed.laneOrdinal) continue;
      const ordinal = Number(parsed.recordOrdinal);
      if (ordinal === 0) {
        return { lane: li.lane, ordinal: 0, order: 0, retained: true };
      }
      let head: IndexedLocator | null = null;
      let floor = Number.MAX_SAFE_INTEGER;
      for (const seg of li.segments.values()) {
        for (const loc of seg.locators) {
          if (BigInt(loc.ordinal) === parsed.recordOrdinal) {
            return {
              lane: li.lane,
              ordinal,
              order: loc.order,
              retained: true,
            };
          }
          if (head === null || loc.ordinal > head.ordinal) head = loc;
          if (loc.ordinal > 0 && loc.ordinal < floor) floor = loc.ordinal;
        }
      }
      const floorOrdinal = floor === Number.MAX_SAFE_INTEGER ? 1 : floor;
      if (head !== null && ordinal > head.ordinal) return null;
      if (ordinal < floorOrdinal || head !== null) {
        return { lane: li.lane, ordinal, order: -1, retained: false };
      }
      return null;
    }
    return null;
  }

  /** The cursor the next record of `lane` would receive, if knowable. */
  async peekNextCursor(laneKey: string): Promise<string | null> {
    const li = this.laneIndex.get(laneKey);
    if (li === undefined) return null;
    const head = await this.laneHead(laneKey);
    return formatCursor(li.ordinal, head.nextRecordOrdinal);
  }

  /**
   * Global commit frontier: highest committed record order across lanes
   * and its cursor (null cursor when nothing is committed).
   */
  async globalHead(): Promise<{ order: number; cursor: string | null }> {
    let best: { order: number; cursor: string } | null = null;
    for (const li of this.laneIndex.values()) {
      for (const seg of li.segments.values()) {
        for (const loc of seg.locators) {
          if (
            loc.cursor !== "" &&
            (best === null || loc.order > best.order)
          ) {
            best = { order: loc.order, cursor: loc.cursor };
          }
        }
      }
    }
    return best === null ? { order: 0, cursor: null } : best;
  }

  /** Read one retained committed record's bytes by its cursor. */
  async getRecord(cursor: string): Promise<Uint8Array | null> {
    const rec = await this.readCursor(cursor);
    return rec === null ? null : rec.data;
  }

  /** Resolve one cursor to its committed record; null when unknown. */
  async readCursor(cursor: string): Promise<ScannedRecord | null> {
    const parsed = parseCursor(cursor);
    if (parsed === null) {
      throw storeError("BAD_CURSOR", `unparseable cursor ${cursor}`);
    }
    for (const li of this.laneIndex.values()) {
      if (li.ordinal !== parsed.laneOrdinal) continue;
      for (const seg of li.segments.values()) {
        const loc = seg.locators.find((l) => BigInt(l.ordinal) === parsed.recordOrdinal);
        if (loc === undefined) continue;
        const dir = laneDirFor(this.layout, li.lane);
        const raw = await readSegmentSlice(join(dir, seg.segment), loc.offset, loc.length);
        if (sha256hex(raw) !== loc.raw_sha256) {
          throw storeError("CORRUPT", "lane record fails digest check", {
            lane: li.lane,
            segment: seg.segment,
            offset: loc.offset,
          });
        }
        return {
          cursor: loc.cursor,
          data: raw.subarray(0, raw.length - 1),
          locator: loc,
          order: loc.order,
        };
      }
      return null;
    }
    return null;
  }

  async putObject(bytes: Uint8Array): Promise<{ digest: string; bytes: number }> {
    const r = await this.objects.put(bytes);
    return { digest: r.digest, bytes: r.bytes };
  }

  async getObject(digest: string): Promise<Buffer> {
    return this.objects.get(digest);
  }

  async hasObject(digest: string): Promise<boolean> {
    return this.objects.has(digest);
  }

  /** Daemon-local kv meta (identity, boot); last_indexed_tx is internal. */
  readonly kv = {
    get: (key: string): string | null => this.registry.kvGet(key),
    set: (key: string, value: string): void => {
      if (key === "last_indexed_tx") {
        throw storeError("BAD_RECORD", "last_indexed_tx is managed internally");
      }
      this.registry.kvSet(key, value);
    },
  };

  async quarantineList(): Promise<
    { name: string; path: string; bytes: number; mtime_ms: number }[]
  > {
    return this.journal.quarantineList();
  }

  async close(): Promise<void> {
    if (this.closedFlag) return;
    this.closedFlag = true;
    for (const w of this.writers.values()) await w.close();
    this.registry.close();
  }
}
