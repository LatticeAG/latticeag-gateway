import { open, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { storeError, StoreError } from "./errors.js";
import type { StateLayout } from "./layout.js";
import {
  ensureDir,
  FILE_MODE,
  fsyncDir,
  GENESIS_HASH,
  isDecimalString,
  isHex64,
  pathExists,
  quarantineBytes,
  readFileOrNull,
  sha256hex,
  type Json,
} from "./util.js";

/** Locator of one committed lane record inside `journal/commits.jsonl`. */
export interface RecordLocator {
  /** Lane key relative to `bus/` (`legacy`, `proof/<partition>`). */
  lane: string;
  /** Segment file name, e.g. `s0000000000000001.jsonl`. */
  segment: string;
  /** Byte offset of the LF-terminated line inside the segment. */
  offset: number;
  /** Byte length of the line including its terminating LF. */
  length: number;
  /** SHA-256 of the exact on-disk slice [offset, offset+length). */
  raw_sha256: string;
}

/** Immutable object admitted by this commit (§2.3 marker `objects`). */
export interface ObjectDescriptor {
  /** Bare 64-hex SHA-256 of the raw bytes. */
  digest: string;
  /** Canonical decimal byte length. */
  bytes: string;
}

/**
 * Closed commit marker per §2.3:
 * `{v:1,tx,previous,records,objects,mutation,result_sha256}`.
 * `previous` is the raw SHA-256 of the prior marker's LF-terminated line
 * (64 zeros at genesis). `tx` is a canonical decimal string, strictly
 * increasing by 1.
 */
export interface CommitMarker {
  v: 1;
  tx: string;
  previous: string;
  records: RecordLocator[];
  objects: ObjectDescriptor[];
  mutation: Json;
  result_sha256: string;
}

export interface JournalHead {
  tx: string | null;
  /** Raw SHA-256 of the head marker line; 64 zeros at genesis. */
  hash: string;
}

export interface JournalTorn {
  /** Bytes of the uncommitted tail moved to quarantine. */
  bytes: number;
  /** Quarantine evidence path. */
  quarantine: string;
}

export type JournalVerifyResult =
  | {
      status: "OK";
      markers: CommitMarker[];
      headTx: string | null;
      headHash: string;
      torn: JournalTorn | null;
    }
  | {
      status: "READ_ONLY";
      /** tx of the first marker inside the unverifiable region. */
      at: string;
      reason: string;
      /** Fully verified committed prefix (replayable). */
      markers: CommitMarker[];
    };

const LANE_KEY = /^[A-Za-z0-9][A-Za-z0-9/_-]{0,127}$/;
const SEGMENT_NAME = /^s[0-9a-f]{16}\.jsonl$/;
const MARKER_KEYS = [
  "v",
  "tx",
  "previous",
  "records",
  "objects",
  "mutation",
  "result_sha256",
];
const LOCATOR_KEYS = ["lane", "segment", "offset", "length", "raw_sha256"];
const OBJECT_KEYS = ["digest", "bytes"];

function isPlainObject(u: unknown): u is Record<string, unknown> {
  return typeof u === "object" && u !== null && !Array.isArray(u);
}

function keysExactly(u: Record<string, unknown>, keys: string[]): boolean {
  const got = Object.keys(u).sort();
  const want = [...keys].sort();
  return got.length === want.length && got.every((k, i) => k === want[i]);
}

function isNonNegInt(u: unknown): u is number {
  return typeof u === "number" && Number.isSafeInteger(u) && u >= 0;
}

function isLaneKey(u: unknown): u is string {
  return (
    typeof u === "string" &&
    LANE_KEY.test(u) &&
    !u.includes("..") &&
    !u.includes("//")
  );
}

export function isSegmentName(u: unknown): u is string {
  return typeof u === "string" && SEGMENT_NAME.test(u);
}

/** Structural validation of a parsed marker; returns the marker or null. */
export function parseMarker(u: unknown): CommitMarker | null {
  if (!isPlainObject(u) || !keysExactly(u, MARKER_KEYS)) return null;
  if (u.v !== 1) return null;
  if (!isDecimalString(u.tx)) return null;
  if (!isHex64(u.previous)) return null;
  if (!isHex64(u.result_sha256)) return null;
  if (!Array.isArray(u.records) || !Array.isArray(u.objects)) return null;
  if (!("mutation" in u)) return null;
  for (const r of u.records as unknown[]) {
    if (!isPlainObject(r) || !keysExactly(r, LOCATOR_KEYS)) return null;
    if (!isLaneKey(r.lane) || !isSegmentName(r.segment)) return null;
    if (!isNonNegInt(r.offset) || !isNonNegInt(r.length) || r.length < 1) {
      return null;
    }
    if (!isHex64(r.raw_sha256)) return null;
  }
  for (const o of u.objects as unknown[]) {
    if (!isPlainObject(o) || !keysExactly(o, OBJECT_KEYS)) return null;
    if (!isHex64(o.digest) || !isDecimalString(o.bytes)) return null;
  }
  return u as unknown as CommitMarker;
}

/**
 * Append-only `journal/commits.jsonl` writer/verifier.
 *
 * `verify()` implements the §2.3 crash contract:
 * - a torn final uncommitted line is preserved in `journal/quarantine/` and
 *   truncated from the journal;
 * - corruption of committed bytes (unparseable non-final line, broken
 *   previous-link, non-monotonic tx) yields READ_ONLY at the first
 *   unverifiable marker and is never repaired in place.
 */
export class Journal {
  readonly dir: string;
  readonly path: string;
  readonly quarantineDir: string;
  private headTx: string | null = null;
  private headHash: string = GENESIS_HASH;
  private headKnown = false;
  private readOnly: { at: string; reason: string } | null = null;

  private constructor(
    dir: string,
    path: string,
    quarantineDir: string,
  ) {
    this.dir = dir;
    this.path = path;
    this.quarantineDir = quarantineDir;
  }

  static async open(l: StateLayout): Promise<Journal> {
    await ensureDir(l.journalDir);
    await ensureDir(l.quarantineDir);
    return new Journal(l.journalDir, l.commitsPath, l.quarantineDir);
  }

  /** Last verified/appended chain position. */
  head(): JournalHead {
    return { tx: this.headTx, hash: this.headHash };
  }

  get isReadOnly(): boolean {
    return this.readOnly !== null;
  }

  /**
   * Build the next marker: fills `tx` (prev+1) and `previous` (raw hash of
   * the head line). Requires a verified/appended head — call verify() first.
   */
  nextMarker(fields: {
    records: RecordLocator[];
    objects: ObjectDescriptor[];
    mutation: Json;
    result_sha256: string;
  }): CommitMarker {
    if (!this.headKnown) {
      throw storeError(
        "CORRUPT",
        "journal head unknown: run verify() before composing markers",
      );
    }
    const tx =
      this.headTx === null ? "1" : (BigInt(this.headTx) + 1n).toString();
    return {
      v: 1,
      tx,
      previous: this.headHash,
      records: fields.records,
      objects: fields.objects,
      mutation: fields.mutation,
      result_sha256: fields.result_sha256,
    };
  }

  /**
   * Append a marker line and fsync before returning. Enforces chain
   * continuity against the known head.
   */
  async append(marker: CommitMarker): Promise<JournalHead> {
    await this.ensureHead();
    if (this.readOnly) {
      throw storeError("READ_ONLY", "journal is read-only", this.readOnly);
    }
    const expected =
      this.headTx === null ? "1" : (BigInt(this.headTx) + 1n).toString();
    if (marker.tx !== expected || marker.previous !== this.headHash) {
      throw storeError("CHAIN_MISMATCH", "marker does not extend head", {
        expected_tx: expected,
        expected_previous: this.headHash,
        got_tx: marker.tx,
        got_previous: marker.previous,
      });
    }
    if (parseMarker(marker) === null) {
      throw storeError("CORRUPT", "refusing to append malformed marker");
    }
    const created = !(await pathExists(this.path));
    const line = Buffer.concat([
      Buffer.from(JSON.stringify(marker), "utf8"),
      Buffer.from([0x0a]),
    ]);
    const fh = await open(this.path, "a", FILE_MODE);
    try {
      await fh.writeFile(line);
      await fh.sync();
    } finally {
      await fh.close();
    }
    if (created) await fsyncDir(this.dir);
    this.headTx = marker.tx;
    this.headHash = sha256hex(line);
    this.headKnown = true;
    return this.head();
  }

  private async ensureHead(): Promise<void> {
    if (!this.headKnown) await this.verify();
  }

  /**
   * Strict read of every committed marker. Throws READ_ONLY when the chain
   * is corrupt; repairs a torn tail first (same as verify()).
   */
  async readMarkers(): Promise<CommitMarker[]> {
    const r = await this.verify();
    if (r.status === "READ_ONLY") {
      throw new StoreError("READ_ONLY", `journal corrupt at ${r.at}`, {
        at: r.at,
        reason: r.reason,
      });
    }
    return r.markers;
  }

  /**
   * Scan, validate the hash chain, repair a torn uncommitted tail into
   * quarantine, and classify committed corruption as READ_ONLY.
   */
  async verify(): Promise<JournalVerifyResult> {
    const buf = await readFileOrNull(this.path);
    const empty: JournalVerifyResult = {
      status: "OK",
      markers: [],
      headTx: null,
      headHash: GENESIS_HASH,
      torn: null,
    };
    if (buf === null || buf.length === 0) {
      this.headTx = null;
      this.headHash = GENESIS_HASH;
      this.headKnown = true;
      return empty;
    }

    // Split into raw lines, keeping the LF as part of each hashed record.
    const lines: Buffer[] = [];
    let start = 0;
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] === 0x0a) {
        lines.push(buf.subarray(start, i + 1));
        start = i + 1;
      }
    }
    let torn: JournalTorn | null = null;
    if (start < buf.length) {
      // Bytes after the last LF: an uncommitted torn tail.
      const tail = buf.subarray(start);
      const qp = await quarantineBytes(this.quarantineDir, "journal-torn", tail);
      const fh = await open(this.path, "r+");
      try {
        await fh.truncate(start);
        await fh.sync();
      } finally {
        await fh.close();
      }
      await fsyncDir(this.dir);
      torn = { bytes: tail.length, quarantine: qp };
    }

    const markers: CommitMarker[] = [];
    const hashes: string[] = [];
    let prevHash = GENESIS_HASH;
    let prevTx: bigint | null = null;
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i]!;
      // Every remaining line is LF-terminated, hence "committed" — a parse
      // or schema failure is committed corruption, never a torn tail.
      // A line only verifies the byte-content of its predecessor through its
      // `previous` link; when line i cannot be checked, line i-1 is the
      // first unverifiable committed line.
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw.toString("utf8").replace(/\n$/, ""));
      } catch {
        const cut = Math.max(0, i - 1);
        const at = i === 0 ? `#${i + 1}` : markers[i - 1]!.tx;
        return this.failReadOnly(
          at,
          "unparseable committed line",
          markers.slice(0, cut),
          hashes.slice(0, cut),
        );
      }
      const marker = parseMarker(parsed);
      if (marker === null) {
        const cut = Math.max(0, i - 1);
        const at =
          i === 0
            ? isPlainObject(parsed) && isDecimalString(parsed.tx)
              ? parsed.tx
              : `#${i + 1}`
            : markers[i - 1]!.tx;
        return this.failReadOnly(
          at,
          "marker failed closed-schema check",
          markers.slice(0, cut),
          hashes.slice(0, cut),
        );
      }
      if (marker.previous !== prevHash) {
        // The previous-link commitment no longer matches the raw bytes of
        // line i-1 (or marker i's own previous field was altered). The
        // unverifiable region begins at the earlier line.
        const at = i === 0 ? marker.tx : markers[i - 1]!.tx;
        return this.failReadOnly(
          at,
          "previous-link mismatch",
          markers.slice(0, Math.max(0, i - 1)),
          hashes.slice(0, Math.max(0, i - 1)),
        );
      }
      const txNum = BigInt(marker.tx);
      // Marker i's previous-link verified lines 0..i-1; failures of marker
      // i itself leave exactly that verified prefix.
      if (prevTx !== null && txNum <= prevTx) {
        return this.failReadOnly(marker.tx, "non-monotonic tx", markers, hashes);
      }
      if (i === 0 && txNum !== 1n) {
        return this.failReadOnly(marker.tx, "genesis tx is not 1", [], []);
      }
      markers.push(marker);
      hashes.push(sha256hex(raw));
      prevHash = hashes[hashes.length - 1]!;
      prevTx = txNum;
    }

    this.headTx = markers.length === 0 ? null : markers[markers.length - 1]!.tx;
    this.headHash = prevHash;
    this.headKnown = true;
    this.readOnly = null;
    return {
      status: "OK",
      markers,
      headTx: this.headTx,
      headHash: this.headHash,
      torn,
    };
  }

  private failReadOnly(
    at: string,
    reason: string,
    verifiedPrefix: CommitMarker[],
    verifiedHashes: string[],
  ): JournalVerifyResult {
    this.readOnly = { at, reason };
    const head = verifiedPrefix[verifiedPrefix.length - 1];
    this.headTx = head?.tx ?? null;
    this.headHash = verifiedHashes[verifiedHashes.length - 1] ?? GENESIS_HASH;
    this.headKnown = true;
    return { status: "READ_ONLY", at, reason, markers: verifiedPrefix };
  }

  /** List quarantine evidence files (name, bytes, mtime). */
  async quarantineList(): Promise<
    { name: string; path: string; bytes: number; mtime_ms: number }[]
  > {
    await ensureDir(this.quarantineDir);
    const names = (await readdir(this.quarantineDir)).sort();
    const out: { name: string; path: string; bytes: number; mtime_ms: number }[] =
      [];
    for (const name of names) {
      const p = join(this.quarantineDir, name);
      try {
        const st = await stat(p);
        if (!st.isFile()) continue;
        out.push({ name, path: p, bytes: st.size, mtime_ms: st.mtimeMs });
      } catch {
        /* skip unreadable entries */
      }
    }
    return out;
  }
}

/** Convenience re-export for callers that only need append semantics. */
export async function appendMarker(
  journal: Journal,
  marker: CommitMarker,
): Promise<JournalHead> {
  return journal.append(marker);
}
