import { createHash, type Hash } from "node:crypto";
import {
  open,
  readdir,
  readFile,
  stat,
  type FileHandle,
} from "node:fs/promises";
import { join } from "node:path";
import { storeError } from "./errors.js";
import {
  ensureDir,
  FILE_MODE,
  fsyncDir,
  hex16,
  isErrno,
  isHex64,
  nowMs,
  quarantineBytes,
  quarantineTail,
  readFileOrNull,
  sha256hex,
  writeFileAtomic,
  writeFileExclusive,
} from "./util.js";

/** Default rotation bound per §2.3 (`storage.segment_bytes`). */
export const DEFAULT_SEGMENT_BYTES = 67108864;
/** Default rotation age per §2.3 (24 hours). */
export const DEFAULT_SEGMENT_AGE_MS = 86400000;
/** Default per-line cap; proof lanes should pass 65536 (native event cap). */
export const DEFAULT_MAX_RECORD_BYTES = 1048576;

export const LANE_META_FILE = "lane.json";
export const ACTIVE_FILE = "active.json";

const SEGMENT_RE = /^s([0-9a-f]{16})\.jsonl$/;
const CURSOR_RE = /^c([0-9a-f]{16}):([0-9]+)$/;

/** Cursor: `c<16 lowercase hex lane-ordinal>:<decimal record ordinal>`. */
export function formatCursor(laneOrdinal: bigint, recordOrdinal: bigint | number): string {
  return `c${hex16(laneOrdinal)}:${BigInt(recordOrdinal).toString()}`;
}

export function parseCursor(cursor: string): { laneOrdinal: bigint; recordOrdinal: bigint } | null {
  const m = CURSOR_RE.exec(cursor);
  if (m === null || m[1] === undefined || m[2] === undefined) return null;
  try {
    return { laneOrdinal: BigInt(`0x${m[1]}`), recordOrdinal: BigInt(m[2]) };
  } catch {
    return null;
  }
}

/** Result of one committed lane append. */
export interface LaneAppend {
  cursor: string;
  /** Segment file name. */
  segment: string;
  /** Byte offset of the LF-terminated line. */
  offset: number;
  /** Byte length including the LF. */
  length: number;
  /** SHA-256 of the exact slice [offset, offset+length). */
  raw_sha256: string;
}

/** Immutable identity file written once per lane directory. */
export interface LaneMeta {
  v: 1;
  lane: string;
  /** 16 lowercase hex. */
  ordinal: string;
  created_ms: number;
}

/** Sealed-segment manifest written beside `<seg>.jsonl` at rotation. */
export interface SealManifest {
  v: 1;
  segment: string;
  first_cursor: string | null;
  last_cursor: string | null;
  /** Complete lines in the sealed file. */
  record_count: number;
  /**
   * Ordinal space this segment consumed (== record_count for a writer
   * seal; larger for a recovery seal of a segment whose uncommitted tail
   * was truncated — later segments' ordinals already counted it).
   */
  consumed_ordinals?: number;
  length: number;
  raw_sha256: string;
  sealed_ms: number;
}

/** Hint pointer file; recovery never trusts it over committed records. */
export interface ActivePointer {
  v: 1;
  lane: string;
  lane_ordinal: string;
  segment: string;
  next_record_ordinal: string;
  opened_ms: number;
}

export function segmentName(ordinal: number | bigint): string {
  return `s${hex16(ordinal)}.jsonl`;
}

export function manifestName(segment: string): string {
  return segment.replace(/\.jsonl$/, ".manifest.json");
}

export function segmentOrdinalOf(segment: string): number | null {
  const m = SEGMENT_RE.exec(segment);
  return m === null || m[1] === undefined ? null : Number(BigInt(`0x${m[1]}`));
}

export interface LaneWriterOptions {
  /** Lane key relative to `bus/` (identity metadata only). */
  lane: string;
  /** Lane ordinal; ignored if `lane.json` already persists one. */
  ordinal: bigint | number;
  segmentBytes?: number;
  maxAgeMs?: number;
  /** Per-line profile cap; records beyond it are rejected before append. */
  maxRecordBytes?: number;
}

/**
 * Append-only writer for one lane directory (`bus/legacy` or
 * `bus/proof/<partition>`).
 *
 * Rotation per §2.3: when the active segment would exceed `segment_bytes`
 * or outlive `maxAgeMs`, the writer fsyncs+seals a manifest carrying
 * first/last cursor, length and raw SHA-256, creates+fsyncs the next
 * segment, then atomically replaces `active.json` (tmp+rename+dir fsync).
 */
export class LaneWriter {
  readonly dir: string;
  readonly lane: string;
  readonly laneOrdinal: bigint;
  readonly segmentBytes: number;
  readonly maxAgeMs: number;
  readonly maxRecordBytes: number;

  private fh: FileHandle | null = null;
  private segment = "";
  private segOrdinal = 0;
  private offset = 0;
  private openedMs = 0;
  private recordsInSegment = 0;
  private firstCursor: string | null = null;
  private lastCursor: string | null = null;
  private recordOrdinal = 1;
  private hash: Hash = createHash("sha256");
  private closed = false;

  private constructor(dir: string, lane: string, laneOrdinal: bigint, opts: LaneWriterOptions) {
    this.dir = dir;
    this.lane = lane;
    this.laneOrdinal = laneOrdinal;
    this.segmentBytes = opts.segmentBytes ?? DEFAULT_SEGMENT_BYTES;
    this.maxAgeMs = opts.maxAgeMs ?? DEFAULT_SEGMENT_AGE_MS;
    this.maxRecordBytes = opts.maxRecordBytes ?? DEFAULT_MAX_RECORD_BYTES;
  }

  /** Current active segment file name. */
  get activeSegment(): string {
    return this.segment;
  }

  /** Next record ordinal (1-based, monotonic across rotations). */
  get nextRecordOrdinal(): number {
    return this.recordOrdinal;
  }

  /** Create a brand-new lane directory. Fails if `lane.json` exists. */
  static async create(dir: string, opts: LaneWriterOptions): Promise<LaneWriter> {
    await ensureDir(dir);
    const ordinal = BigInt(opts.ordinal);
    const meta: LaneMeta = {
      v: 1,
      lane: opts.lane,
      ordinal: hex16(ordinal),
      created_ms: nowMs(),
    };
    await writeFileExclusive(join(dir, LANE_META_FILE), JSON.stringify(meta));
    const w = new LaneWriter(dir, opts.lane, ordinal, opts);
    await w.startSegment(1);
    await w.writeActive();
    await fsyncDir(dir);
    return w;
  }

  /**
   * Open an existing lane directory for appending after `recoverLane`.
   * Throws CORRUPT when the recovery report contains corrupt entries.
   */
  static async open(
    dir: string,
    opts: LaneWriterOptions & {
      quarantineDir?: string;
      committed?: Map<string, CommittedSegment>;
      /** Precomputed recovery report (skips a second recoverLane pass). */
      report?: LaneRecoverReport;
    },
  ): Promise<{ writer: LaneWriter; report: LaneRecoverReport }> {
    const report =
      opts.report ??
      (await recoverLane(dir, {
        quarantineDir: opts.quarantineDir,
        committed: opts.committed,
      }));
    if (report.corrupt.length > 0) {
      throw storeError("CORRUPT", `lane ${opts.lane} failed recovery`, {
        corrupt: report.corrupt,
      });
    }
    const meta = await readLaneMeta(dir);
    const ordinal = meta !== null ? BigInt(`0x${meta.ordinal}`) : BigInt(opts.ordinal);
    if (meta === null) {
      const m: LaneMeta = {
        v: 1,
        lane: opts.lane,
        ordinal: hex16(ordinal),
        created_ms: nowMs(),
      };
      await writeFileExclusive(join(dir, LANE_META_FILE), JSON.stringify(m));
    }
    const w = new LaneWriter(dir, opts.lane, ordinal, opts);
    if (report.active_segment === null) {
      const nextSeg =
        report.segments.length === 0
          ? 1
          : report.segments[report.segments.length - 1]!.ordinal + 1;
      await w.startSegment(nextSeg);
      w.recordOrdinal = report.next_record_ordinal;
    } else {
      const active = report.segments.find(
        (s) => s.segment === report.active_segment,
      );
      if (active === undefined) {
        throw storeError("CORRUPT", `lane ${opts.lane} active head unrecoverable`);
      }
      w.segment = active.segment;
      w.segOrdinal = active.ordinal;
      w.offset = active.length;
      w.openedMs = report.active_opened_ms;
      w.recordsInSegment = active.records;
      w.firstCursor =
        active.records > 0
          ? formatCursor(ordinal, active.written_base + 1)
          : null;
      w.lastCursor =
        active.records > 0
          ? formatCursor(ordinal, active.written_base + active.records)
          : null;
      const existing = await readFileOrNull(join(dir, active.segment));
      w.hash = createHash("sha256");
      if (existing !== null) w.hash.update(existing);
      w.fh = await open(join(dir, active.segment), "a", FILE_MODE);
      w.recordOrdinal = report.next_record_ordinal;
    }
    await w.writeActive();
    return { writer: w, report };
  }

  /**
   * Append one record. The record must be a single UTF-8 JSON line without
   * BOM or embedded raw LF; the profile cap is enforced before any byte is
   * materialized.
   */
  async append(record: Uint8Array): Promise<LaneAppend> {
    if (this.closed || this.fh === null) {
      throw storeError("CORRUPT", `lane ${this.lane} is closed`);
    }
    if (record.length === 0) {
      throw storeError("BAD_RECORD", "empty record");
    }
    if (record.length > this.maxRecordBytes) {
      throw storeError("OBJECT_LIMIT", "record exceeds lane cap", {
        lane: this.lane,
        limit: this.maxRecordBytes,
        actual: record.length,
      });
    }
    if (record.length >= 3 && record[0] === 0xef && record[1] === 0xbb && record[2] === 0xbf) {
      throw storeError("BAD_RECORD", "record carries a UTF-8 BOM");
    }
    for (let i = 0; i < record.length; i++) {
      if (record[i] === 0x0a) {
        throw storeError("BAD_RECORD", "record contains an embedded raw LF");
      }
    }
    const line = Buffer.concat([Buffer.from(record), Buffer.from([0x0a])]);
    const now = nowMs();
    if (
      this.recordsInSegment > 0 &&
      (this.offset + line.length > this.segmentBytes ||
        now - this.openedMs > this.maxAgeMs)
    ) {
      await this.rotate();
    }
    const offset = this.offset;
    await this.fh.write(line);
    this.hash.update(line);
    this.offset += line.length;
    const cursor = formatCursor(this.laneOrdinal, this.recordOrdinal);
    if (this.recordsInSegment === 0) this.firstCursor = cursor;
    this.lastCursor = cursor;
    this.recordsInSegment += 1;
    this.recordOrdinal += 1;
    return {
      cursor,
      segment: this.segment,
      offset,
      length: line.length,
      raw_sha256: sha256hex(line),
    };
  }

  /** fsync the active segment (commit protocol step before the marker). */
  async fsync(): Promise<void> {
    if (this.fh !== null) await this.fh.sync();
  }

  async close(): Promise<void> {
    if (this.fh !== null) {
      await this.fh.sync();
      await this.fh.close();
      this.fh = null;
    }
    this.closed = true;
  }

  private async startSegment(ordinal: number): Promise<void> {
    this.segOrdinal = ordinal;
    this.segment = segmentName(ordinal);
    const path = join(this.dir, this.segment);
    if ((await stat(path).then(() => true).catch(() => false))) {
      throw storeError("CORRUPT", `segment ${this.segment} already exists`, {
        lane: this.lane,
      });
    }
    this.fh = await open(path, "a", FILE_MODE);
    this.offset = 0;
    this.openedMs = nowMs();
    this.recordsInSegment = 0;
    this.firstCursor = null;
    this.lastCursor = null;
    this.hash = createHash("sha256");
    await fsyncDir(this.dir);
  }

  private async rotate(): Promise<void> {
    // 1. Seal: fsync the segment, then write/fsync its manifest.
    if (this.fh !== null) {
      await this.fh.sync();
      await this.fh.close();
      this.fh = null;
    }
    const manifest: SealManifest = {
      v: 1,
      segment: this.segment,
      first_cursor: this.firstCursor,
      last_cursor: this.lastCursor,
      record_count: this.recordsInSegment,
      consumed_ordinals: this.recordsInSegment,
      length: this.offset,
      raw_sha256: this.hash.copy().digest("hex"),
      sealed_ms: nowMs(),
    };
    await writeFileAtomic(
      join(this.dir, manifestName(this.segment)),
      JSON.stringify(manifest),
    );
    // 2. Create/fsync the next segment (immutable id from creation).
    await this.startSegment(this.segOrdinal + 1);
    // 3. Atomically replace the active pointer (tmp+rename+dir fsync).
    await this.writeActive();
  }

  private async writeActive(): Promise<void> {
    const pointer: ActivePointer = {
      v: 1,
      lane: this.lane,
      lane_ordinal: hex16(this.laneOrdinal),
      segment: this.segment,
      next_record_ordinal: this.recordOrdinal.toString(),
      opened_ms: this.openedMs,
    };
    await writeFileAtomic(join(this.dir, ACTIVE_FILE), JSON.stringify(pointer));
  }
}

/** Committed extents of one segment, derived from journal markers. */
export interface CommittedSegment {
  /** Marker-committed record extents, sorted by offset. May contain holes:
   *  records appended by a commit that died before its marker are orphans
   *  and can sit between committed records — their bytes must stay in
   *  place because committed (segment, offset) references are immutable. */
  locators: { offset: number; length: number; raw_sha256: string }[];
}

export interface SegmentInfo {
  segment: string;
  ordinal: number;
  sealed: boolean;
  /** Post-recovery byte length. */
  length: number;
  /**
   * Retained complete-line count (what the file holds post-recovery,
   * orphan holes included).
   */
  records: number;
  /**
   * Ordinal space consumed by this segment (>= records when a dead
   * uncommitted tail was truncated from a non-final segment).
   */
  consumed: number;
  /**
   * Total consumed ordinals of all earlier segments of the lane; a record
   * at line index i of this segment has ordinal `written_base + i + 1`.
   */
  written_base: number;
  /** Start offset of every retained complete line (sorted). */
  line_offsets: number[];
  first_cursor: string | null;
  last_cursor: string | null;
  raw_sha256: string | null;
}

export interface LaneCorrupt {
  segment: string | null;
  reason: string;
}

export interface LaneRecoverReport {
  dir: string;
  lane_ordinal: string | null;
  segments: SegmentInfo[];
  active_segment: string | null;
  active_opened_ms: number;
  next_record_ordinal: number;
  torn_bytes_moved: number;
  /** Quarantine paths (or `path@off..end` references in dry-run) of orphans. */
  orphans: string[];
  corrupt: LaneCorrupt[];
}

export interface LaneRecoverOptions {
  quarantineDir?: string;
  /**
   * Committed extents per segment name, derived from journal markers.
   * Each locator is checked to sit exactly on one LF-terminated line and
   * to hash-match its slice; complete lines no marker commits are orphans
   * — copied to quarantine (mid-segment holes stay in place to keep
   * committed offsets stable; the tail beyond the last committed record
   * is truncated). When omitted, every complete line counts as present and
   * only a trailing partial line is torn.
   */
  committed?: Map<string, CommittedSegment>;
  /** Report without mutating (READ_ONLY detection pass). */
  dryRun?: boolean;
}

async function readLaneMeta(dir: string): Promise<LaneMeta | null> {
  const buf = await readFileOrNull(join(dir, LANE_META_FILE));
  if (buf === null) return null;
  try {
    const u: unknown = JSON.parse(buf.toString("utf8"));
    if (
      typeof u === "object" &&
      u !== null &&
      (u as LaneMeta).v === 1 &&
      typeof (u as LaneMeta).ordinal === "string" &&
      /^[0-9a-f]{16}$/.test((u as LaneMeta).ordinal)
    ) {
      return u as LaneMeta;
    }
  } catch {
    /* fall through */
  }
  return null;
}

async function readManifest(path: string): Promise<SealManifest | null> {
  const buf = await readFileOrNull(path);
  if (buf === null) return null;
  try {
    const u: unknown = JSON.parse(buf.toString("utf8"));
    if (typeof u !== "object" || u === null) return null;
    const m = u as SealManifest;
    if (
      m.v !== 1 ||
      typeof m.segment !== "string" ||
      !isHex64(m.raw_sha256) ||
      typeof m.length !== "number" ||
      !Number.isSafeInteger(m.length) ||
      typeof m.record_count !== "number" ||
      !Number.isSafeInteger(m.record_count) ||
      (m.consumed_ordinals !== undefined &&
        (typeof m.consumed_ordinals !== "number" ||
          !Number.isSafeInteger(m.consumed_ordinals)))
    ) {
      return null;
    }
    return m;
  } catch {
    return null;
  }
}

/** Line-start index of `offset` within `lineStarts`, or -1. */
export function lineIndexOf(lineStarts: number[], offset: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const v = lineStarts[mid]!;
    if (v === offset) return mid;
    if (v < offset) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

interface LineScan {
  /** Start offset of every complete LF-terminated line. */
  starts: number[];
  /** Byte offset just past the final LF (== size when not torn). */
  completeEnd: number;
}

function scanLines(data: Buffer): LineScan {
  const starts: number[] = [];
  let pos = 0;
  for (let i = 0; i < data.length; i++) {
    if (data[i] === 0x0a) {
      starts.push(pos);
      pos = i + 1;
    }
  }
  return { starts, completeEnd: pos };
}

/**
 * Recover one lane directory after a crash.
 *
 * - Sealed segments are verified against their manifests (record count,
 *   length, raw SHA-256). A mismatch is committed corruption → `corrupt`,
 *   never repair.
 * - Every committed locator is checked to sit exactly on an LF-terminated
 *   line and to hash-match its slice; committed bytes missing or altered
 *   are `corrupt`.
 * - Complete lines no marker commits are orphans: mid-segment holes are
 *   copied to quarantine but left in place (committed offsets are
 *   immutable); the tail past the last committed record is quarantined and
 *   truncated. Orphan bytes are never ACKed.
 * - `written_base`/`line_offsets` preserve the writer's ordinal space so
 *   derived cursors match the ones returned at commit time, even across
 *   orphan holes.
 * - The active head derives from sealed manifests + committed records,
 *   never from `active.json` (an untrusted pointer, §2.3).
 */
export async function recoverLane(
  dir: string,
  opts: LaneRecoverOptions = {},
): Promise<LaneRecoverReport> {
  const report: LaneRecoverReport = {
    dir,
    lane_ordinal: null,
    segments: [],
    active_segment: null,
    active_opened_ms: nowMs(),
    next_record_ordinal: 1,
    torn_bytes_moved: 0,
    orphans: [],
    corrupt: [],
  };
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (e) {
    if (isErrno(e, "ENOENT")) return report;
    throw e;
  }
  const meta = await readLaneMeta(dir);
  report.lane_ordinal = meta?.ordinal ?? null;
  const ordBig = meta !== null ? BigInt(`0x${meta.ordinal}`) : 0n;

  const segFiles = entries
    .filter((n) => SEGMENT_RE.test(n))
    .sort((a, b) => a.localeCompare(b));
  const cursorOf = (ordinal: number): string => formatCursor(ordBig, ordinal);

  const verifyCommitted = (
    name: string,
    data: Buffer,
    scan: LineScan,
    locators: { offset: number; length: number; raw_sha256: string }[],
    retainedEnd: number,
  ): boolean => {
    for (const loc of locators) {
      const idx = lineIndexOf(scan.starts, loc.offset);
      if (idx < 0) {
        report.corrupt.push({
          segment: name,
          reason: `committed record at offset ${loc.offset} is not a line boundary`,
        });
        return false;
      }
      if (loc.offset + loc.length > retainedEnd) {
        report.corrupt.push({
          segment: name,
          reason: `committed record at offset ${loc.offset} exceeds retained end`,
        });
        return false;
      }
      if (data[loc.offset + loc.length - 1] !== 0x0a) {
        report.corrupt.push({
          segment: name,
          reason: `committed record at offset ${loc.offset} is not LF-terminated`,
        });
        return false;
      }
      const slice = data.subarray(loc.offset, loc.offset + loc.length);
      if (sha256hex(slice) !== loc.raw_sha256) {
        report.corrupt.push({
          segment: name,
          reason: `committed record at offset ${loc.offset} fails digest check`,
        });
        return false;
      }
    }
    return true;
  };

  /** Preserve retained-but-uncommitted lines in quarantine (no removal). */
  const preserveOrphanHoles = async (
    name: string,
    segPath: string,
    data: Buffer,
    scan: LineScan,
    coveredOffsets: Set<number>,
    retainedEnd: number,
  ): Promise<void> => {
    const chunks: Buffer[] = [];
    for (const start of scan.starts) {
      if (start >= retainedEnd) break;
      if (coveredOffsets.has(start)) continue;
      const idx = lineIndexOf(scan.starts, start);
      const next =
        idx + 1 < scan.starts.length ? scan.starts[idx + 1]! : retainedEnd;
      chunks.push(data.subarray(start, next));
      if (opts.dryRun) report.orphans.push(`${segPath}@${start}..${next}`);
    }
    if (chunks.length === 0 || opts.dryRun) return;
    if (opts.quarantineDir === undefined) {
      report.corrupt.push({
        segment: name,
        reason: "orphan lines present but no quarantine dir configured",
      });
      return;
    }
    // Content-addressed evidence name: re-recovery is idempotent.
    const blob = Buffer.concat(chunks);
    const qp = join(
      opts.quarantineDir,
      `lane-orphan-${name}-${sha256hex(blob).slice(0, 16)}.bin`,
    );
    try {
      await writeFileExclusive(qp, blob);
    } catch (e) {
      if (!isErrno(e, "EEXIST")) throw e;
    }
    report.orphans.push(qp);
  };

  let writtenBase = 0;
  for (let idx = 0; idx < segFiles.length; idx++) {
    const name = segFiles[idx]!;
    const segPath = join(dir, name);
    const isLast = idx === segFiles.length - 1;
    const comm = opts.committed?.get(name) ?? null;
    const mPath = join(dir, manifestName(name));
    const manifest = await readManifest(mPath);
    const data = await readFile(segPath);
    const scan = scanLines(data);
    const covered = new Set((comm?.locators ?? []).map((l) => l.offset));
    const committedEnd = (comm?.locators ?? []).reduce(
      (m, l) => Math.max(m, l.offset + l.length),
      0,
    );

    if (manifest !== null) {
      // ---- sealed segment: verify immutable bytes against the manifest.
      if (
        manifest.segment !== name ||
        data.length !== manifest.length ||
        scan.starts.length !== manifest.record_count ||
        sha256hex(data) !== manifest.raw_sha256
      ) {
        report.corrupt.push({
          segment: name,
          reason: "sealed segment fails manifest verification",
        });
        continue;
      }
      if (
        opts.committed !== undefined &&
        !verifyCommitted(name, data, scan, comm?.locators ?? [], manifest.length)
      ) {
        continue;
      }
      if (opts.committed !== undefined) {
        await preserveOrphanHoles(name, segPath, data, scan, covered, manifest.length);
      }
      const consumed = manifest.consumed_ordinals ?? manifest.record_count;
      if (consumed < manifest.record_count) {
        report.corrupt.push({
          segment: name,
          reason: "manifest consumed_ordinals below record_count",
        });
        continue;
      }
      report.segments.push({
        segment: name,
        ordinal: segmentOrdinalOf(name) ?? 0,
        sealed: true,
        length: manifest.length,
        records: manifest.record_count,
        consumed,
        written_base: writtenBase,
        line_offsets: scan.starts,
        first_cursor: manifest.first_cursor,
        last_cursor: manifest.last_cursor,
        raw_sha256: manifest.raw_sha256,
      });
      writtenBase += consumed;
      continue;
    }

    if (!isLast) {
      // ---- non-final segment without a manifest (mid-rotation crash).
      if (opts.committed === undefined) {
        report.corrupt.push({ segment: name, reason: "unsealed non-final segment" });
        continue;
      }
      const end = committedEnd;
      if (data.length < end) {
        report.corrupt.push({
          segment: name,
          reason: "committed bytes missing from unsealed segment",
        });
        continue;
      }
      if (!verifyCommitted(name, data, scan, comm?.locators ?? [], end)) {
        continue;
      }
      if (meta === null && end > 0) {
        report.corrupt.push({ segment: name, reason: "lane identity missing" });
        continue;
      }
      // Orphan evidence: retained holes copied out, tail moved+truncated.
      await preserveOrphanHoles(name, segPath, data, scan, covered, end);
      const moved = await moveTail(segPath, end, opts, report, name);
      if (moved === "corrupt") continue;
      const retained = scan.starts.filter((s) => s < end);
      // Seal the retained bytes (they match committed markers exactly).
      const seal: SealManifest = {
        v: 1,
        segment: name,
        first_cursor: retained.length > 0 ? cursorOf(writtenBase + 1) : null,
        last_cursor:
          retained.length > 0 ? cursorOf(writtenBase + retained.length) : null,
        record_count: retained.length,
        consumed_ordinals: scan.starts.length,
        length: end,
        raw_sha256: sha256hex(data.subarray(0, end)),
        sealed_ms: nowMs(),
      };
      if (!opts.dryRun) {
        await writeFileAtomic(mPath, JSON.stringify(seal));
      }
      report.segments.push({
        segment: name,
        ordinal: segmentOrdinalOf(name) ?? 0,
        sealed: true,
        length: end,
        records: retained.length,
        consumed: scan.starts.length, // ordinals consumed incl. dead tail
        written_base: writtenBase,
        line_offsets: retained,
        first_cursor: seal.first_cursor,
        last_cursor: seal.last_cursor,
        raw_sha256: seal.raw_sha256,
      });
      writtenBase += scan.starts.length;
      continue;
    }

    // ---- active (final) segment.
    report.active_segment = name;
    let retained: number[];
    if (opts.committed !== undefined) {
      const end = committedEnd;
      if (data.length < end) {
        report.corrupt.push({
          segment: name,
          reason: `committed bytes missing: file=${data.length} committed=${end}`,
        });
        continue;
      }
      if (!verifyCommitted(name, data, scan, comm?.locators ?? [], end)) {
        continue;
      }
      await preserveOrphanHoles(name, segPath, data, scan, covered, end);
      const moved = await moveTail(segPath, end, opts, report, name);
      if (moved === "corrupt") continue;
      retained = scan.starts.filter((s) => s < end);
    } else {
      // No marker context: complete lines are present; a trailing partial
      // line is torn → quarantine + truncate.
      const end = scan.completeEnd;
      if (data.length > end) {
        const moved = await moveTail(segPath, end, opts, report, name);
        if (moved === "corrupt") continue;
      }
      retained = scan.starts;
    }
    const committedLocs = comm?.locators ?? [];
    report.segments.push({
      segment: name,
      ordinal: segmentOrdinalOf(name) ?? 0,
      sealed: false,
      length:
        opts.committed !== undefined ? committedEnd : scan.completeEnd,
      records: retained.length,
      consumed: retained.length,
      written_base: writtenBase,
      line_offsets: retained,
      first_cursor:
        committedLocs.length > 0 && meta !== null
          ? cursorOf(writtenBase + lineIndexOf(scan.starts, committedLocs[0]!.offset) + 1)
          : retained.length > 0 && opts.committed === undefined && meta !== null
            ? cursorOf(writtenBase + 1)
            : null,
      last_cursor:
        committedLocs.length > 0 && meta !== null
          ? cursorOf(
              writtenBase +
                lineIndexOf(scan.starts, committedLocs[committedLocs.length - 1]!.offset) +
                1,
            )
          : retained.length > 0 && opts.committed === undefined && meta !== null
            ? cursorOf(writtenBase + retained.length)
            : null,
      raw_sha256: null,
    });
    writtenBase += retained.length;

    // opened_ms hint from the untrusted pointer file; fall back to file
    // birth/mtime. Only used for age-based rotation.
    const pointer = await readActivePointer(dir);
    if (pointer !== null && pointer.segment === name) {
      report.active_opened_ms = pointer.opened_ms;
    } else {
      const st = await stat(segPath);
      report.active_opened_ms = st.birthtimeMs || st.mtimeMs || nowMs();
    }
  }
  report.next_record_ordinal = writtenBase + 1;
  return report;
}

async function readActivePointer(dir: string): Promise<ActivePointer | null> {
  const buf = await readFileOrNull(join(dir, ACTIVE_FILE));
  if (buf === null) return null;
  try {
    const u: unknown = JSON.parse(buf.toString("utf8"));
    if (
      typeof u === "object" &&
      u !== null &&
      (u as ActivePointer).v === 1 &&
      typeof (u as ActivePointer).segment === "string"
    ) {
      return u as ActivePointer;
    }
  } catch {
    /* untrusted hint; ignore */
  }
  return null;
}

/**
 * Move bytes `[end, size)` of a segment to quarantine and truncate.
 * Returns "corrupt" when the tail cannot be preserved.
 */
async function moveTail(
  segPath: string,
  end: number,
  opts: LaneRecoverOptions,
  report: LaneRecoverReport,
  name: string,
): Promise<"moved" | "corrupt" | "none"> {
  const size = (await stat(segPath)).size;
  if (size <= end) return "none";
  if (opts.dryRun) {
    report.orphans.push(`${segPath}@${end}..${size}`);
    report.torn_bytes_moved += size - end;
    return "moved";
  }
  if (opts.quarantineDir === undefined) {
    report.corrupt.push({
      segment: name,
      reason: "orphan bytes present but no quarantine dir configured",
    });
    return "corrupt";
  }
  const moved = await quarantineTail(
    segPath,
    end,
    opts.quarantineDir,
    `lane-orphan-${name}`,
  );
  if (moved !== null) {
    report.torn_bytes_moved += moved.bytes;
    report.orphans.push(moved.path);
  }
  return "moved";
}

/** Read exactly `length` bytes at `offset` from a segment file. */
export async function readSegmentSlice(
  segPath: string,
  offset: number,
  length: number,
): Promise<Buffer> {
  const fh = await open(segPath, "r");
  try {
    const buf = Buffer.alloc(length);
    const { bytesRead } = await fh.read(buf, 0, length, offset);
    if (bytesRead !== length) {
      throw storeError("CORRUPT", `short read on ${segPath}@${offset}`, {
        expected: length,
        actual: bytesRead,
      });
    }
    return buf;
  } finally {
    await fh.close();
  }
}
