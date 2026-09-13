import { open, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { storeError } from "./errors.js";
import {
  ensureDir,
  FILE_MODE,
  fsyncDir,
  isErrno,
  isHex64,
  sha256hex,
} from "./util.js";

/** Native Proof object bound (§2.2): objects are at most 1 MiB. */
export const DEFAULT_MAX_OBJECT_BYTES = 1048576;

export interface PutResult {
  /** Bare 64-lowercase-hex SHA-256 of the raw bytes. */
  digest: string;
  /** Byte length actually persisted. */
  bytes: number;
  /** `false` when the object already existed (put is idempotent). */
  created: boolean;
}

/**
 * Content-addressed immutable object store at `objects/sha256/<first2>/<hex>`.
 *
 * - writes are `wx` (never overwrite), fsynced, then verified length+digest;
 * - reads verify length+digest once per process (`verified` set), matching
 *   the §8.3 "verified length/digest on first read and scrub" rule;
 * - corrupt committed bytes are never silently repaired: they raise CORRUPT.
 */
export class ObjectStore {
  readonly dir: string;
  readonly maxBytes: number;
  private readonly verified = new Set<string>();

  constructor(dir: string, opts: { maxBytes?: number } = {}) {
    this.dir = dir;
    this.maxBytes = opts.maxBytes ?? DEFAULT_MAX_OBJECT_BYTES;
  }

  pathFor(digest: string): string {
    if (!isHex64(digest)) {
      throw storeError("BAD_DIGEST", `invalid object digest ${String(digest)}`);
    }
    return join(this.dir, digest.slice(0, 2), digest);
  }

  async put(bytes: Uint8Array): Promise<PutResult> {
    if (bytes.length > this.maxBytes) {
      throw storeError("OBJECT_LIMIT", "object exceeds bound", {
        limit: this.maxBytes,
        actual: bytes.length,
      });
    }
    const digest = sha256hex(bytes);
    const path = this.pathFor(digest);
    await ensureDir(join(this.dir, digest.slice(0, 2)));
    let created = false;
    try {
      const fh = await open(path, "wx", FILE_MODE);
      try {
        await fh.writeFile(bytes);
        await fh.sync();
      } finally {
        await fh.close();
      }
      await fsyncDir(join(this.dir, digest.slice(0, 2)));
      created = true;
    } catch (e) {
      if (!isErrno(e, "EEXIST")) throw e;
      /* same-name object already materialized; verify below */
    }
    // Verify-after-write (and verify-on-put for the EEXIST path): an existing
    // file under this name must hold exactly these bytes.
    await this.verifyFile(path, digest, bytes.length);
    this.verified.add(digest);
    return { digest, bytes: bytes.length, created };
  }

  /** Read object bytes; verifies length+digest on first read per process. */
  async get(digest: string): Promise<Buffer> {
    const path = this.pathFor(digest);
    let data: Buffer;
    try {
      data = await readFile(path);
    } catch (e) {
      if (isErrno(e, "ENOENT")) {
        throw storeError("NOT_FOUND", `object ${digest} not present`, {
          digest,
        });
      }
      throw e;
    }
    if (!this.verified.has(digest)) {
      if (data.length === 0 || sha256hex(data) !== digest) {
        throw storeError("CORRUPT", `object ${digest} failed verification`, {
          digest,
        });
      }
      this.verified.add(digest);
    }
    return data;
  }

  /** Existence + integrity probe; never throws CORRUPT, reports false. */
  async has(digest: string): Promise<boolean> {
    const path = this.pathFor(digest);
    try {
      const st = await stat(path);
      if (!st.isFile()) return false;
      if (this.verified.has(digest)) return true;
      const data = await readFile(path);
      if (sha256hex(data) !== digest) return false;
      this.verified.add(digest);
      return true;
    } catch {
      return false;
    }
  }

  private async verifyFile(
    path: string,
    digest: string,
    expectedLength: number,
  ): Promise<void> {
    const st = await stat(path);
    if (st.size !== expectedLength) {
      throw storeError("CORRUPT", `object ${digest} length mismatch`, {
        digest,
        expected: expectedLength,
        actual: st.size,
      });
    }
    const data = await readFile(path);
    if (sha256hex(data) !== digest) {
      throw storeError("CORRUPT", `object ${digest} digest mismatch`, {
        digest,
      });
    }
  }
}
