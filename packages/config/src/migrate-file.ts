import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  fchmodSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import path from "node:path";
import { latticeagConfigSchema } from "./schema.js";
import { latticeagConfigV2Schema } from "./schema-v2.js";
import { migrateConfig } from "./migrate.js";
import {
  ConfigNotFoundError,
  ConfigParseError,
  ConfigSchemaError,
  formatZodIssue,
  parseJsonStrict,
} from "./load.js";

export class ConfigMigrationError extends Error {
  readonly code = "CONFIG_MIGRATION";
  constructor(
    message: string,
    readonly filePath: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "ConfigMigrationError";
  }
}

export interface MigrateConfigFileOptions {
  workspace: string;
  instance: string;
  dryRun?: boolean;
}

export interface ConfigMigrationReceipt {
  workspace_id: string;
  instance_id: string;
  legacy_log_path: string;
  consent_reset: true;
}

export interface MigrateConfigFileResult {
  backup_path: string;
  old_sha256: string;
  new_sha256: string;
  receipt: ConfigMigrationReceipt;
}

function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function fsyncDir(dir: string): void {
  const fd = openSync(dir, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function writeExclusive(filePath: string, data: Buffer, mode: number): void {
  const fd = openSync(filePath, "wx", mode);
  try {
    let off = 0;
    while (off < data.length) {
      off += writeSync(fd, data, off, data.length - off, off);
    }
    fchmodSync(fd, mode);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Crash-safe on-disk v1 → v2 config migration (spec §8.2).
 *
 * Order of operations:
 *   1. read raw bytes + mode, sha256 them;
 *   2. strictly parse JSON and validate against the exact v1 schema;
 *   3. compute the migrated v2 document and serialize/validate it;
 *   4. create `<path>.v1.<raw-sha256>.bak` exclusively (`wx` — an existing
 *      backup is never overwritten) and fsync it;
 *   5. write the v2 document to a same-directory temp file, re-validate the
 *      bytes on disk, fsync it;
 *   6. atomically rename the temp file over `path` and fsync the directory.
 *
 * A crash before the rename leaves the v1 file active; a failed validation
 * leaves the backup and the original file untouched.
 */
export function migrateConfigFile(
  filePath: string,
  options: MigrateConfigFileOptions,
): MigrateConfigFileResult {
  const abs = path.resolve(filePath);

  let rawBytes: Buffer;
  let mode: number;
  try {
    rawBytes = readFileSync(abs);
    mode = statSync(abs).mode & 0o777;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      throw new ConfigNotFoundError(path.dirname(abs));
    }
    throw err;
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(rawBytes);
  } catch {
    throw new ConfigParseError(
      `${abs}: invalid JSON at byte offset 0: file is not valid UTF-8`,
      abs,
      0,
    );
  }
  if (text.charCodeAt(0) === 0xfeff) {
    text = text.slice(1);
  }

  const raw = parseJsonStrict(text, abs);
  const v1 = latticeagConfigSchema.safeParse(raw);
  if (!v1.success) {
    const first = v1.error.issues[0];
    const summary = first ? formatZodIssue(first) : "invalid config";
    throw new ConfigSchemaError(
      `${abs}: ${summary}`,
      abs,
      v1.error.issues,
    );
  }

  const old_sha256 = sha256Hex(rawBytes);
  const backup_path = `${abs}.v1.${old_sha256}.bak`;

  const v2 = migrateConfig(raw, options.workspace, options.instance);
  const v2Text = `${JSON.stringify(v2, null, 2)}\n`;
  const v2RoundTrip = latticeagConfigV2Schema.safeParse(
    JSON.parse(v2Text) as unknown,
  );
  if (!v2RoundTrip.success) {
    const first = v2RoundTrip.error.issues[0];
    const summary = first ? formatZodIssue(first) : "invalid config";
    throw new ConfigMigrationError(
      `${abs}: migrated v2 document failed schema validation: ${summary}`,
      abs,
    );
  }
  const new_sha256 = sha256Hex(v2Text);

  const receipt: ConfigMigrationReceipt = {
    workspace_id: options.workspace,
    instance_id: options.instance,
    legacy_log_path: v1.data.bus.log_path,
    consent_reset: true,
  };

  if (options.dryRun === true) {
    return { backup_path, old_sha256, new_sha256, receipt };
  }

  // 1. Exclusive backup of the exact original bytes. `wx` fails with EEXIST
  //    rather than clobbering an earlier backup.
  try {
    writeExclusive(backup_path, rawBytes, mode);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EEXIST") {
      throw new ConfigMigrationError(
        `${abs}: backup already exists, refusing to overwrite: ${backup_path}`,
        abs,
        { cause: err },
      );
    }
    throw new ConfigMigrationError(
      `${abs}: failed to create backup ${backup_path}: ${String(err)}`,
      abs,
      { cause: err },
    );
  }

  // 2. Write + fsync the v2 temp file in the same directory, then re-read and
  //    re-validate it before it is allowed to become the live config.
  const tmpPath = `${abs}.v2.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    writeExclusive(tmpPath, Buffer.from(v2Text, "utf8"), mode);
    const onDisk = readFileSync(tmpPath);
    const check = latticeagConfigV2Schema.safeParse(
      JSON.parse(onDisk.toString("utf8")) as unknown,
    );
    if (!check.success) {
      throw new ConfigMigrationError(
        `${abs}: v2 temp file failed validation`,
        abs,
      );
    }
    // 3. Atomic rename, then fsync the parent directory.
    renameSync(tmpPath, abs);
    fsyncDir(path.dirname(abs));
  } catch (err) {
    try {
      unlinkSync(tmpPath);
    } catch {
      // temp file may already be gone (e.g. rename succeeded, dir fsync failed)
    }
    if (err instanceof ConfigMigrationError) {
      throw err;
    }
    throw new ConfigMigrationError(
      `${abs}: migration failed: ${String(err)}`,
      abs,
      { cause: err },
    );
  }

  return { backup_path, old_sha256, new_sha256, receipt };
}
