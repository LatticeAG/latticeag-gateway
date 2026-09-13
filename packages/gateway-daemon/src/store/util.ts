import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { storeError } from "./errors.js";

/** JSON value type used for journaled mutations and stored descriptors. */
export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };

export const DIR_MODE = 0o700;
export const FILE_MODE = 0o600;

/** `previous` of the first commit marker / genesis prev per spec §2. */
export const GENESIS_HASH = "0".repeat(64);

const HEX64 = /^[0-9a-f]{64}$/;

export function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value);
}

/** Canonical unsigned decimal string (no leading zeros except "0"). */
export function isDecimalString(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^(0|[1-9][0-9]*)$/.test(value) &&
    BigInt(value) <= BigInt("9223372036854775807")
  );
}

export function sha256hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Lowercase, zero-padded 16-hex-digit ordinal used in cursors and ids. */
export function hex16(n: bigint | number): string {
  return BigInt(n).toString(16).padStart(16, "0");
}

export function nowMs(): number {
  return Date.now();
}

/** mkdir -p with owner-only mode; chmod normalizes umask-created parents. */
export async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true, mode: DIR_MODE });
  try {
    await chmod(dir, DIR_MODE);
  } catch {
    /* best-effort normalization */
  }
}

export async function fsyncDir(dir: string): Promise<void> {
  const fh = await open(dir, "r");
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
}

/** Create-or-replace via same-directory tmp + rename + dir fsync. */
export async function writeFileAtomic(
  path: string,
  data: Uint8Array | string,
  mode: number = FILE_MODE,
): Promise<void> {
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const fh = await open(tmp, "w", mode);
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }
  await rename(tmp, path);
  await fsyncDir(dirname(path));
}

/** Immutable create: fails EEXIST if the path is already materialized. */
export async function writeFileExclusive(
  path: string,
  data: Uint8Array | string,
  mode: number = FILE_MODE,
): Promise<void> {
  const fh = await open(path, "wx", mode);
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fsyncDir(dirname(path));
}

export async function fileSize(path: string): Promise<number | null> {
  try {
    return (await stat(path)).size;
  } catch {
    return null;
  }
}

export async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

let quarantineSeq = 0;

/**
 * Write `bytes` into the quarantine dir under a unique evidence name and
 * fsync it. Returns the quarantine path.
 */
export async function quarantineBytes(
  quarantineDir: string,
  label: string,
  bytes: Uint8Array,
): Promise<string> {
  await ensureDir(quarantineDir);
  const safe = label.replace(/[^A-Za-z0-9._-]/g, "_");
  for (;;) {
    quarantineSeq += 1;
    const name = `${new Date().toISOString().replace(/[:.]/g, "")}-${process.pid}-${quarantineSeq}-${safe}.bin`;
    const path = join(quarantineDir, name);
    try {
      await writeFileExclusive(path, bytes, FILE_MODE);
      return path;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") continue;
      throw e;
    }
  }
}

/**
 * Preserve bytes `[fromOffset, end)` of `srcPath` in `quarantineDir`, then
 * truncate the source to `fromOffset` and fsync both file and directory.
 * Returns null when there is nothing past `fromOffset`.
 */
export async function quarantineTail(
  srcPath: string,
  fromOffset: number,
  quarantineDir: string,
  label: string,
): Promise<{ path: string; bytes: number } | null> {
  const size = await fileSize(srcPath);
  if (size === null) {
    throw storeError("NOT_FOUND", `cannot quarantine missing file ${srcPath}`);
  }
  if (size <= fromOffset) return null;
  const fh = await open(srcPath, "r");
  let tail: Buffer;
  try {
    tail = Buffer.alloc(size - fromOffset);
    await fh.read(tail, 0, tail.length, fromOffset);
  } finally {
    await fh.close();
  }
  const path = await quarantineBytes(quarantineDir, label, tail);
  const tfh = await open(srcPath, "r+");
  try {
    await tfh.truncate(fromOffset);
    await tfh.sync();
  } finally {
    await tfh.close();
  }
  await fsyncDir(dirname(srcPath));
  return { path, bytes: tail.length };
}

/** Read a file fully; null when absent. */
export async function readFileOrNull(path: string): Promise<Buffer | null> {
  try {
    return await readFile(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
}

export function isErrno(e: unknown, code: string): boolean {
  return (
    typeof e === "object" &&
    e !== null &&
    (e as NodeJS.ErrnoException).code === code
  );
}
