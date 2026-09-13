import { readdir, readFile, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { Journal, type CommitMarker, type RecordLocator } from "./journal.js";
import {
  ensureLayout,
  type StateLayout,
} from "./layout.js";
import {
  formatCursor,
  lineIndexOf,
  recoverLane,
  segmentOrdinalOf,
  type CommittedSegment,
  type LaneRecoverReport,
} from "./lanes.js";
import { Registry } from "./registry.js";
import { pathExists, quarantineBytes } from "./util.js";

/** One committed record located on disk, with its derived cursor. */
export interface IndexedLocator extends RecordLocator {
  /** `c<lane-ordinal hex>:<record ordinal>` — derived, stable across rebuilds. */
  cursor: string;
  /** Global record ordinal within the lane (1-based). */
  ordinal: number;
}

export interface LaneIndexSegment {
  segment: string;
  ordinal: number;
  locators: IndexedLocator[];
  /** Committed byte end (== last locator offset+length). */
  end: number;
}

export interface LaneIndex {
  lane: string;
  ordinal: bigint;
  segments: Map<string, LaneIndexSegment>;
  totalRecords: number;
}

export interface RecoveryCorrupt {
  where: string;
  reason: string;
}

export interface RecoveryReport {
  status: "READY" | "READ_ONLY" | "RECOVERING";
  /** Committed marker count (verified prefix when READ_ONLY). */
  markers: number;
  last_tx: string | null;
  /** Markers applied into the registry during this recovery. */
  replayed_tx: number;
  last_indexed_tx: string | null;
  /** Quarantine paths (or `path@off..end` refs in read-only mode). */
  orphans: string[];
  torn_bytes_moved: number;
  corrupt: RecoveryCorrupt[];
  /** First unverifiable marker tx when READ_ONLY. */
  at?: string;
  reason?: string;
}

export interface RecoveredStore {
  report: RecoveryReport;
  layout: StateLayout;
  journal: Journal;
  markers: CommitMarker[];
  laneIndex: Map<string, LaneIndex>;
  laneOrdinals: Map<string, bigint>;
  laneReports: Map<string, LaneRecoverReport>;
  laneCommitted: Map<string, Map<string, CommittedSegment>>;
  registry: Registry;
  nextLaneOrdinal: bigint;
  readOnly: { at: string; reason: string } | null;
}

export interface RecoverOptions {
  instance?: string;
}

/** Lane dir names under `bus/`; `legacy` plus every `proof/<partition>`. */
async function discoverLanes(lay: StateLayout): Promise<Map<string, string>> {
  const lanes = new Map<string, string>();
  if (await pathExists(lay.legacyLaneDir)) {
    lanes.set("legacy", lay.legacyLaneDir);
  }
  if (await pathExists(lay.proofBusDir)) {
    for (const name of (await readdir(lay.proofBusDir)).sort()) {
      const dir = join(lay.proofBusDir, name);
      const st = await stat(dir).catch(() => null);
      if (st?.isDirectory() === true) lanes.set(`proof/${name}`, dir);
    }
  }
  return lanes;
}

async function readLaneOrdinal(dir: string): Promise<bigint | null> {
  const buf = await readFile(join(dir, "lane.json"), "utf8").catch(() => null);
  if (buf === null) return null;
  try {
    const u: unknown = JSON.parse(buf);
    if (
      typeof u === "object" &&
      u !== null &&
      typeof (u as { ordinal?: unknown }).ordinal === "string" &&
      /^[0-9a-f]{16}$/.test((u as { ordinal: string }).ordinal)
    ) {
      return BigInt(`0x${(u as { ordinal: string }).ordinal}`);
    }
  } catch {
    /* fall through */
  }
  return null;
}

/**
 * Collect marker-committed record extents per lane/segment, sorted and
 * deduplicated. Duplicate identical locators (idempotent replay) collapse;
 * conflicting or overlapping committed extents are corruption.
 */
export function committedExtents(
  markers: CommitMarker[],
): {
  extents: Map<string, Map<string, CommittedSegment>>;
  corrupt: RecoveryCorrupt[];
} {
  const extents = new Map<string, Map<string, CommittedSegment>>();
  const corrupt: RecoveryCorrupt[] = [];
  for (const marker of markers) {
    for (const rec of marker.records) {
      let lane = extents.get(rec.lane);
      if (lane === undefined) {
        lane = new Map();
        extents.set(rec.lane, lane);
      }
      let seg = lane.get(rec.segment);
      if (seg === undefined) {
        seg = { locators: [] };
        lane.set(rec.segment, seg);
      }
      seg.locators.push({
        offset: rec.offset,
        length: rec.length,
        raw_sha256: rec.raw_sha256,
      });
    }
  }
  for (const [lane, segs] of extents) {
    for (const [segName, seg] of segs) {
      seg.locators.sort((a, b) => a.offset - b.offset);
      const dedup: typeof seg.locators = [];
      for (const loc of seg.locators) {
        const prev = dedup[dedup.length - 1];
        if (prev !== undefined && prev.offset === loc.offset) {
          if (prev.length !== loc.length || prev.raw_sha256 !== loc.raw_sha256) {
            corrupt.push({
              where: `${lane}/${segName}`,
              reason: `conflicting committed locators at offset ${loc.offset}`,
            });
          }
          continue;
        }
        if (prev !== undefined && loc.offset < prev.offset + prev.length) {
          corrupt.push({
            where: `${lane}/${segName}`,
            reason: `overlapping committed records at offset ${loc.offset}`,
          });
          continue;
        }
        dedup.push(loc);
      }
      seg.locators = dedup;
    }
  }
  return { extents, corrupt };
}

/**
 * Build the committed lane index from verified markers + the recovered
 * segment geometry (written-line bases and per-line start offsets), so
 * derived cursors equal the writer-assigned ones even across orphan holes.
 */
export function buildLaneIndex(
  markers: CommitMarker[],
  laneOrdinals: Map<string, bigint>,
  laneReports: Map<string, LaneRecoverReport>,
): { index: Map<string, LaneIndex>; corrupt: RecoveryCorrupt[] } {
  const index = new Map<string, LaneIndex>();
  const corrupt: RecoveryCorrupt[] = [];
  for (const marker of markers) {
    for (const rec of marker.records) {
      let li = index.get(rec.lane);
      if (li === undefined) {
        const ordinal = laneOrdinals.get(rec.lane);
        if (ordinal === undefined) {
          corrupt.push({
            where: rec.lane,
            reason: `marker ${marker.tx} references lane without identity`,
          });
          li = { lane: rec.lane, ordinal: 0n, segments: new Map(), totalRecords: 0 };
          index.set(rec.lane, li);
          continue;
        }
        li = { lane: rec.lane, ordinal, segments: new Map(), totalRecords: 0 };
        index.set(rec.lane, li);
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
      const segInfo = laneReports
        .get(rec.lane)
        ?.segments.find((s) => s.segment === rec.segment);
      let ordinal = 0;
      if (segInfo === undefined) {
        corrupt.push({
          where: `${rec.lane}/${rec.segment}`,
          reason: `marker ${marker.tx} references segment missing on disk`,
        });
      } else {
        const lineIdx = lineIndexOf(segInfo.line_offsets, rec.offset);
        if (lineIdx < 0) {
          corrupt.push({
            where: `${rec.lane}/${rec.segment}`,
            reason: `committed record at offset ${rec.offset} is not a line boundary`,
          });
        } else {
          ordinal = segInfo.written_base + lineIdx + 1;
        }
      }
      const seen = seg.locators.some(
        (l) => l.offset === rec.offset && l.length === rec.length,
      );
      if (seen) continue;
      li.totalRecords += 1;
      seg.locators.push({
        ...rec,
        ordinal,
        cursor: ordinal > 0 ? formatCursor(li.ordinal, ordinal) : "",
      });
      seg.end = Math.max(seg.end, rec.offset + rec.length);
    }
  }
  for (const li of index.values()) {
    for (const seg of li.segments.values()) {
      seg.locators.sort((a, b) => a.offset - b.offset);
    }
  }
  return { index, corrupt };
}

/**
 * Full storage recovery per §2.3:
 * journal verify (torn tail → quarantine; committed corruption →
 * READ_ONLY), per-lane recovery against committed extents (orphan bytes →
 * quarantine, never ACKed), then registry replay beyond `last_indexed_tx`
 * exactly once — or a full derived-index rebuild when the file was lost.
 */
export async function recoverStoreContext(
  root: string,
  opts: RecoverOptions = {},
): Promise<RecoveredStore> {
  const lay = await ensureLayout(root);
  const journal = await Journal.open(lay);
  const jv = await journal.verify();
  const readOnly =
    jv.status === "READ_ONLY" ? { at: jv.at, reason: jv.reason } : null;
  const markers = jv.markers;

  // Lane identity scan (lane.json ordinals feed cursor derivation).
  const laneDirs = await discoverLanes(lay);
  const laneOrdinals = new Map<string, bigint>();
  for (const [lane, dir] of laneDirs) {
    const ord = await readLaneOrdinal(dir);
    if (ord !== null) laneOrdinals.set(lane, ord);
  }

  // Committed extents straight from markers (no ordinal derivation yet).
  const ext = committedExtents(markers);
  const corrupt: RecoveryCorrupt[] = [...ext.corrupt];
  const laneCommitted = ext.extents;

  // Per-lane recovery against committed extents. In READ_ONLY mode
  // nothing is mutated (dry-run detection only).
  const laneReports = new Map<string, LaneRecoverReport>();
  const orphans: string[] = [];
  let tornBytes = 0;
  const allLanes = new Set<string>([...laneDirs.keys(), ...laneCommitted.keys()]);
  for (const lane of allLanes) {
    const dir = laneDirs.get(lane);
    if (dir === undefined || !(await pathExists(dir))) {
      corrupt.push({ where: lane, reason: "committed lane directory missing" });
      continue;
    }
    const committed =
      laneCommitted.get(lane) ?? new Map<string, CommittedSegment>();
    const rep = await recoverLane(dir, {
      quarantineDir: lay.quarantineDir,
      committed,
      dryRun: readOnly !== null,
    });
    laneReports.set(lane, rep);
    orphans.push(...rep.orphans);
    tornBytes += rep.torn_bytes_moved;
    for (const c of rep.corrupt) {
      corrupt.push({ where: `${lane}/${c.segment ?? ""}`, reason: c.reason });
    }
    // Committed segments must exist on disk.
    for (const segName of committed.keys()) {
      if (!rep.segments.some((s) => s.segment === segName)) {
        corrupt.push({ where: `${lane}/${segName}`, reason: "committed segment missing" });
      }
    }
  }

  // Now derive the committed index with recovered segment geometry —
  // cursors equal the writer-assigned values, orphan holes included.
  const { index: laneIndex, corrupt: indexCorrupt } = buildLaneIndex(
    markers,
    laneOrdinals,
    laneReports,
  );
  corrupt.push(...indexCorrupt);

  // Registry: open, rebuild/replay derived index exactly once.
  const staleWal = [`${lay.registryPath}-wal`, `${lay.registryPath}-shm`];
  let registry: Registry;
  let replayed = 0;
  try {
    registry = Registry.open(lay.registryPath, {
      instance: opts.instance,
      resolveCursor: (rec) => lookupCursor(laneIndex, rec),
    });
  } catch {
    // Corrupt sqlite: it is a derived index — preserve evidence, rebuild.
    for (const p of [lay.registryPath, ...staleWal]) {
      const buf = await readFile(p).catch(() => null);
      if (buf !== null) {
        await quarantineBytes(
          lay.quarantineDir,
          `registry-corrupt-${p.split("/").pop()}`,
          buf,
        );
        await unlink(p).catch(() => {});
      }
    }
    registry = Registry.open(lay.registryPath, {
      instance: opts.instance,
      resolveCursor: (rec) => lookupCursor(laneIndex, rec),
    });
  }

  const lastIndexed = registry.lastIndexedTx();
  const headTx = markers.length === 0 ? null : markers[markers.length - 1]!.tx;
  const markerTxs = new Set(markers.map((m) => m.tx));
  const needFullRebuild =
    headTx !== null &&
    (lastIndexed === null ||
      lastIndexed === "0" ||
      !markerTxs.has(lastIndexed));
  if (headTx === null) {
    if (lastIndexed === null) registry.rebuildFromJournal([]);
  } else if (needFullRebuild) {
    registry.rebuildFromJournal(markers);
    replayed = markers.length;
  } else {
    const from = BigInt(lastIndexed ?? "0");
    for (const marker of markers) {
      if (BigInt(marker.tx) > from) {
        registry.applyCommit(marker);
        replayed += 1;
      }
    }
  }

  let maxOrdinal = 0n;
  for (const o of laneOrdinals.values()) {
    if (o > maxOrdinal) maxOrdinal = o;
  }
  const nextLaneOrdinal = maxOrdinal + 1n;

  const report: RecoveryReport = {
    status: readOnly !== null || corrupt.length > 0 ? "READ_ONLY" : "READY",
    markers: markers.length,
    last_tx: headTx,
    replayed_tx: replayed,
    last_indexed_tx: registry.lastIndexedTx(),
    orphans,
    torn_bytes_moved: tornBytes,
    corrupt,
    ...(readOnly !== null ? { at: readOnly.at, reason: readOnly.reason } : {}),
  };
  if (corrupt.length > 0 && readOnly === null) {
    report.at = report.at ?? corrupt[0]!.where;
    report.reason = report.reason ?? corrupt[0]!.reason;
  }
  return {
    report,
    layout: lay,
    journal,
    markers,
    laneIndex,
    laneOrdinals,
    laneReports,
    laneCommitted,
    registry,
    nextLaneOrdinal,
    readOnly: readOnly ?? (corrupt.length > 0 ? { at: report.at ?? "", reason: report.reason ?? "corrupt" } : null),
  };
}

function lookupCursor(
  index: Map<string, LaneIndex>,
  rec: RecordLocator,
): string | null {
  const seg = index.get(rec.lane)?.segments.get(rec.segment);
  const loc = seg?.locators.find(
    (l) => l.offset === rec.offset && l.length === rec.length,
  );
  return loc !== undefined && loc.cursor !== "" ? loc.cursor : null;
}

/** Standalone recovery pass; returns only the report. */
export async function recoverStore(
  root: string,
  opts: RecoverOptions = {},
): Promise<RecoveryReport> {
  const ctx = await recoverStoreContext(root, opts);
  ctx.registry.close();
  return ctx.report;
}
