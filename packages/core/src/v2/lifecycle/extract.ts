/**
 * Safe extraction of §5.1 release archives: the spec `tar()` fixture format
 * plus real POSIX ustar. Two passes — every header is validated before any
 * byte hits disk, then files are written strictly beneath the staging dir
 * with openat-style containment checks.
 *
 * Policy (POLICY_DENIED on violation):
 *  - no absolute paths, `..` segments, backslashes, NUL/control chars,
 *    drive letters, empty segments, or case-colliding names;
 *  - only regular files (typeflag 0/\0) and directories (5); no symlink,
 *    hardlink, device, fifo, or GNU/pax extension entries;
 *  - modes must carry no setuid/setgid/sticky bits and no group/other
 *    write bits;
 *  - ≤10000 entries, ≤1 GiB expanded, ≤256 MiB compressed;
 *  - header checksums verified; only zero blocks may follow the end marker.
 *
 * The extractor runs no callbacks and executes nothing.
 */
import { Buffer } from "node:buffer";
import { chmodSync, lstatSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";

import { RpcError } from "../protocol/errors.js";
import { PRODUCT_LIMITS } from "../protocol/product.js";
import { sha256Hex } from "../crypto/hash.js";

export interface ExtractedEntry {
  /** Normalized relative path inside the archive. */
  readonly path: string;
  /** "file" | "dir". */
  readonly kind: "file" | "dir";
  readonly bytes: number;
  readonly mode: number;
  /** sha256 hex of file bytes (empty string for directories). */
  readonly digest: string;
}

interface TarHeader {
  name: string;
  mode: number;
  size: number;
  typeflag: number;
  linkname: string;
  prefix: string;
}

const BLOCK = 512;

function denied(reason: string): never {
  throw new RpcError("POLICY_DENIED", `unsafe archive: ${reason}`);
}

function parseOctalField(buf: Uint8Array, off: number, len: number, field: string): number {
  let end = off;
  // Skip leading NULs/spaces.
  while (end < off + len && (buf[end] === 0 || buf[end] === 0x20)) end += 1;
  let value = 0;
  let saw = false;
  for (; end < off + len; end += 1) {
    const c = buf[end]!;
    if (c === 0 || c === 0x20) break;
    if (c < 0x30 || c > 0x37) denied(`${field} is not octal`);
    value = value * 8 + (c - 0x30);
    saw = true;
    if (!Number.isSafeInteger(value)) denied(`${field} overflows`);
  }
  if (!saw) return 0;
  return value;
}

function readName(buf: Uint8Array, off: number, len: number): string {
  let end = off;
  while (end < off + len && buf[end] !== 0) end += 1;
  const raw = buf.subarray(off, end);
  const s = Buffer.from(raw).toString("utf8");
  if (s.includes("\uFFFD")) denied("entry name is not valid UTF-8");
  return s;
}

function isZeroBlock(buf: Uint8Array, off: number): boolean {
  for (let i = off; i < off + BLOCK; i += 1) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function checksumOk(buf: Uint8Array, off: number): boolean {
  let sum = 0;
  for (let i = 0; i < BLOCK; i += 1) {
    sum += i >= 148 && i < 156 ? 0x20 : buf[off + i]!;
  }
  const stored = parseOctalField(buf, off + 148, 8, "checksum");
  return sum === stored;
}

/** Per-entry path validation — the openat-style containment precheck. */
function validatePath(name: string): void {
  if (name.length === 0) denied("empty entry name");
  if (name.length > 1024) denied("entry path exceeds 1024 chars");
  if (name.startsWith("/")) denied(`absolute path "${name}"`);
  if (/^[A-Za-z]:/.test(name)) denied(`drive-absolute path "${name}"`);
  if (name.includes("\\")) denied(`backslash in path "${name}"`);
  if (name.includes("\u0000")) denied(`NUL in path`);
  if (/[\u0000-\u001f\u007f]/.test(name)) denied(`control character in path "${name}"`);
  const segments = name.split("/");
  for (const seg of segments) {
    if (seg.length === 0) denied(`empty segment in "${name}"`);
    if (seg === "." || seg === "..") denied(`illegal segment "${seg}" in "${name}"`);
    if (Buffer.byteLength(seg, "utf8") > 255) denied(`segment over 255 bytes in "${name}"`);
  }
}

export interface ParsedEntry {
  path: string;
  kind: "file" | "dir";
  mode: number;
  size: number;
  dataOffset: number; // offset of file data in archive (files only)
}

/**
 * Parse + validate every header. Returns the entry table; throws
 * POLICY_DENIED on any unsafe construct or format violation.
 */
export function scanArchive(archive: Uint8Array): ParsedEntry[] {
  if (archive.length > PRODUCT_LIMITS.archiveCompressedBytes) {
    denied(`compressed archive exceeds ${PRODUCT_LIMITS.archiveCompressedBytes} bytes`);
  }
  if (archive.length % BLOCK !== 0) denied("archive length is not a multiple of 512");
  const entries: ParsedEntry[] = [];
  const seen = new Map<string, string>(); // lowercase → original
  const claimed = new Set<string>(); // normalized paths (files + dirs)
  let expanded = 0;
  let off = 0;
  let endSeen = false;

  while (off + BLOCK <= archive.length) {
    if (isZeroBlock(archive, off)) {
      // End marker: require a second zero block then only zero padding.
      if (off + 2 * BLOCK > archive.length || !isZeroBlock(archive, off + BLOCK)) {
        denied("truncated end-of-archive marker");
      }
      for (let t = off + 2 * BLOCK; t + BLOCK <= archive.length; t += BLOCK) {
        if (!isZeroBlock(archive, t)) denied("nonzero data after end marker");
      }
      endSeen = true;
      break;
    }
    if (!checksumOk(archive, off)) denied("header checksum mismatch");

    const h: TarHeader = {
      name: readName(archive, off + 0, 100),
      mode: parseOctalField(archive, off + 100, 8, "mode"),
      size: parseOctalField(archive, off + 124, 12, "size"),
      typeflag: archive[off + 156]!,
      linkname: readName(archive, off + 157, 100),
      prefix: readName(archive, off + 345, 155),
    };
    const magic = readName(archive, off + 257, 8);
    if (magic !== "ustar" && magic !== "ustar  " && magic !== "" && magic !== "ustar ") {
      denied(`unsupported tar magic ${JSON.stringify(magic)}`);
    }

    const full = h.prefix.length > 0 ? `${h.prefix}/${h.name}` : h.name;
    const isDir = h.typeflag === 0x35; // '5'
    const path = isDir && full.endsWith("/") ? full.slice(0, -1) : full;
    validatePath(path);
    if (h.linkname.length > 0) denied(`link target present on "${path}"`);

    switch (h.typeflag) {
      case 0x30: // '0'
      case 0x00: // '\0' regular
      case 0x35: // '5' directory
        break;
      case 0x31: // '1' hardlink
      case 0x32: // '2' symlink
      case 0x33: // '3' char device
      case 0x34: // '4' block device
      case 0x36: // '6' fifo
      case 0x37: // '7' contiguous
        denied(`special entry type ${String.fromCharCode(h.typeflag)} at "${path}"`);
        break;
      default:
        denied(`unsupported entry type 0x${h.typeflag.toString(16)} at "${path}"`);
    }

    // Mode policy: no setuid/setgid/sticky, no group/other write.
    if ((h.mode & 0o6000) !== 0) denied(`special mode bits on "${path}"`);
    if ((h.mode & 0o022) !== 0) denied(`group/other writable mode on "${path}"`);
    if ((h.mode & ~0o777) !== 0) denied(`mode out of range on "${path}"`);

    // Case-insensitive collision check on the full path AND every ancestor
    // prefix ("Dir/x" collides with "dir/y" on case-folded filesystems).
    let acc = "";
    for (const seg of path.split("/")) {
      acc = acc === "" ? seg : `${acc}/${seg}`;
      const lp = acc.toLowerCase();
      const prior = seen.get(lp);
      if (prior !== undefined && prior !== acc) {
        denied(`case-colliding names "${prior}" vs "${acc}"`);
      }
      seen.set(lp, acc);
    }
    if (claimed.has(path)) denied(`duplicate entry "${path}"`);
    claimed.add(path);

    // Path-prefix consistency: an existing file cannot become a directory
    // ancestor of a later entry and vice versa.
    let prefix = "";
    for (const seg of path.split("/").slice(0, -1)) {
      prefix = prefix === "" ? seg : `${prefix}/${seg}`;
      if (claimed.has(prefix)) {
        const existing = entries.find((e) => e.path === prefix);
        if (existing && existing.kind !== "dir") {
          denied(`"${prefix}" is a file, cannot contain "${path}"`);
        }
      }
    }
    const kind: "file" | "dir" = isDir ? "dir" : "file";
    const dataOffset = off + BLOCK;
    if (kind === "file") {
      expanded += h.size;
      if (expanded > PRODUCT_LIMITS.archiveExpandedBytes) {
        denied(`expanded archive exceeds ${PRODUCT_LIMITS.archiveExpandedBytes} bytes`);
      }
    }
    entries.push({ path, kind, mode: h.mode, size: h.size, dataOffset });
    if (entries.length > PRODUCT_LIMITS.archiveMaxFiles) {
      denied(`more than ${PRODUCT_LIMITS.archiveMaxFiles} entries`);
    }
    off += BLOCK + Math.ceil(h.size / BLOCK) * BLOCK;
  }
  if (!endSeen) denied("archive is missing its zero-block end marker");
  return entries;
}

/**
 * Verify that `abs` lies inside `root` and that every existing ancestor is
 * a real directory (never a symlink) — the openat-style containment check
 * applied per write.
 */
function containedDir(root: string, abs: string): void {
  const resolvedRoot = resolve(root);
  if (abs !== resolvedRoot && !abs.startsWith(resolvedRoot + sep)) {
    denied(`path escapes staging root`);
  }
  const rel = abs.slice(resolvedRoot.length + 1);
  if (rel.length === 0) return;
  let cur = resolvedRoot;
  for (const seg of rel.split(sep)) {
    cur = join(cur, seg);
    try {
      const st = lstatSync(cur);
      if (st.isSymbolicLink()) denied(`symlink component "${cur}"`);
      if (!st.isDirectory() && !st.isFile()) denied(`non-file component "${cur}"`);
    } catch (e) {
      if (e instanceof RpcError) throw e;
      // ENOENT — not yet created; deeper levels are created below.
      break;
    }
  }
}

/**
 * Extract `archive` beneath `destDir` (created when absent). Returns the
 * extracted entry table with per-file digests. All policy violations raise
 * RpcError POLICY_DENIED before any write outside the root can occur —
 * validation of every header completes before the first byte is written.
 */
export function extractArchive(
  archive: Uint8Array,
  destDir: string,
): ExtractedEntry[] {
  const root = resolve(destDir);
  const entries = scanArchive(archive);
  mkdirSync(root, { recursive: true, mode: 0o755 });
  const out: ExtractedEntry[] = [];
  for (const entry of entries) {
    const abs = join(root, ...entry.path.split("/"));
    if (entry.kind === "dir") {
      mkdirSync(abs, { recursive: true, mode: 0o755 });
      containedDir(root, abs);
      chmodSync(abs, 0o755);
      out.push({ path: entry.path, kind: "dir", bytes: 0, mode: 0o755, digest: "" });
      continue;
    }
    const data = archive.subarray(entry.dataOffset, entry.dataOffset + entry.size);
    if (data.length !== entry.size) denied(`truncated data for "${entry.path}"`);
    mkdirSync(dirname(abs), { recursive: true, mode: 0o755 });
    // Post-creation containment walk: every ancestor must be a real
    // directory inside root — a planted symlink fails closed.
    containedDir(root, abs);
    // 'wx' never overwrites an existing path — duplicate wins are denied.
    writeFileSync(abs, data, { flag: "wx", mode: entry.mode & 0o777 });
    chmodSync(abs, entry.mode & 0o777);
    out.push({
      path: entry.path,
      kind: "file",
      bytes: entry.size,
      mode: entry.mode & 0o777,
      digest: sha256Hex(data),
    });
  }
  return out;
}
