/**
 * `latticeag gateway config show|validate|migrate` (spec §6.2, §8).
 *
 * Embedded mode: these commands work without the daemon — show/validate
 * read the selected config file directly, migrate drives
 * @latticeag/config migrateConfigFile (backup + atomic replace). When the
 * daemon is reachable, `config show` prefers config.get so the revision is
 * authoritative.
 */
import { openSync, writeSync, closeSync, readFileSync } from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { v2 } from "@latticeag/core";
import {
  ConfigNotFoundError,
  ConfigParseError,
  ConfigSchemaError,
  ConfigMigrationError,
  discoverConfig,
  migrateConfig,
  migrateConfigFile,
  readConfigFile,
  validateConfigV2Semantics,
} from "@latticeag/config";
import { addGlobalOptions } from "../../globals.js";
import { fail, writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  failControl,
  globalsOf,
  planDigest,
  displayPlan,
  requireReviewedPlan,
  resolveClient,
  usageFail,
  EXIT,
} from "../../gateway/common.js";

const { sha256Hex } = v2.crypto;

const SECRETISH = /token|secret|password|credential|api[-_]?key|authorization/i;

function redact(value: unknown, extraKeys: readonly string[]): unknown {
  if (Array.isArray(value)) {
    return value.map((v) => redact(v, extraKeys));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const listed = extraKeys.some((key) => key.toLowerCase() === k.toLowerCase());
      out[k] = listed || (SECRETISH.test(k) && typeof v === "string")
        ? "[redacted]"
        : redact(v, extraKeys);
    }
    return out;
  }
  return value;
}

function selectedConfigPath(ctx: { json: boolean; command: string }): string {
  const found = discoverConfig(process.cwd());
  if (!found) {
    fail(`no ${"latticeag.json"} found from ${process.cwd()}`, {
      json: ctx.json,
      command: ctx.command,
      code: "CONFIG_NOT_FOUND",
      exitCode: EXIT.CONFIG,
    });
  }
  return found.path;
}

async function runShow(opts: { socket?: string }, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };

  // Prefer the daemon's authoritative revision when it answers.
  try {
    const { client } = resolveClient({ socket: opts.socket });
    const current = await client.call<{ revision: string; document: unknown }>(
      "config.get",
      {},
    );
    if (json) {
      writeJson(ctx.command, true, current);
    } else {
      process.stdout.write(`revision ${current.revision}\n`);
      process.stdout.write(`${JSON.stringify(current.document, null, 2)}\n`);
    }
    return;
  } catch {
    // daemon absent → embedded mode below
  }

  const file = selectedConfigPath(ctx);
  try {
    const loaded = readConfigFile(file);
    const keys =
      (loaded.config as { redaction?: { keys?: string[] } }).redaction?.keys ?? [];
    const document = redact(loaded.raw, keys);
    if (json) {
      writeJson(ctx.command, true, {
        path: file,
        revision: null,
        schema_version: loaded.version,
        document,
      });
    } else {
      process.stdout.write(`path ${file}\nrevision -\n`);
      process.stdout.write(`${JSON.stringify(document, null, 2)}\n`);
    }
  } catch (err) {
    if (
      err instanceof ConfigNotFoundError ||
      err instanceof ConfigParseError ||
      err instanceof ConfigSchemaError
    ) {
      fail(err.message, {
        json,
        command: ctx.command,
        code: err.code,
        exitCode: EXIT.CONFIG,
      });
    }
    throw err;
  }
}

async function runValidate(
  file: string | undefined,
  opts: { socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  void opts;
  const target = file ? path.resolve(file) : selectedConfigPath(ctx);

  let loaded;
  try {
    loaded = readConfigFile(target);
  } catch (err) {
    if (
      err instanceof ConfigNotFoundError ||
      err instanceof ConfigParseError ||
      err instanceof ConfigSchemaError
    ) {
      if (json) {
        writeJson(ctx.command, true, {
          valid: false,
          errors: [{ code: err.code, message: err.message }],
        });
        process.exit(EXIT.CONFIG);
      }
      fail(err.message, {
        json,
        command: ctx.command,
        code: err.code,
        exitCode: EXIT.CONFIG,
      });
    }
    throw err;
  }

  // v2 documents also get the offline semantic/path checks (§8.1).
  const errors: Array<{ code: string; path: string; message: string }> = [];
  if (loaded.version === 2) {
    const semantic = validateConfigV2Semantics(loaded.raw);
    errors.push(...semantic.errors);
  }
  const valid = errors.length === 0;
  if (json) {
    writeJson(ctx.command, true, {
      path: target,
      schema_version: loaded.version,
      valid,
      errors,
    });
  } else {
    process.stdout.write(`${target} ${valid ? "valid" : "invalid"}\n`);
    for (const e of errors) {
      process.stdout.write(`  ${e.code} ${e.path}: ${e.message}\n`);
    }
  }
  if (!valid) {
    process.exit(EXIT.CONFIG);
  }
}

/**
 * Deterministic workspace/instance ids for a migration: derived from the
 * migrated file's raw sha256 so --dry-run and the real apply render the
 * exact same document (and the same review digest).
 */
export function migrationIds(oldSha256: string): { workspace: string; instance: string } {
  return {
    workspace: `ws${oldSha256.slice(0, 16)}`,
    instance: `in${oldSha256.slice(16, 32)}`,
  };
}

async function runMigrate(
  opts: {
    from?: string;
    to?: string;
    dryRun?: boolean;
    output?: string;
    yes?: boolean;
    reviewDigest?: string;
    socket?: string;
  },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const from = opts.from ?? "1";
  const to = opts.to ?? "2";
  if (from !== "1" || to !== "2") {
    usageFail(`only --from 1 --to 2 is supported (got ${from} → ${to})`, ctx);
  }
  const file = selectedConfigPath(ctx);
  const abs = path.resolve(file);

  // Validate the input is a v1 document and compute both raw digests up
  // front — the review digest covers exactly what would be written.
  let oldSha: string;
  let newSha: string;
  let rawDoc: unknown;
  try {
    const loaded = readConfigFile(abs);
    if (loaded.version !== 1) {
      fail(`${abs}: schema_version is not 1 — nothing to migrate`, {
        json,
        command: ctx.command,
        code: "SCHEMA_UNSUPPORTED",
        exitCode: EXIT.USAGE,
      });
    }
    rawDoc = loaded.raw;
    oldSha = sha256Hex(readFileSync(abs));
    const ids0 = migrationIds(oldSha);
    const doc = migrateConfig(rawDoc, ids0.workspace, ids0.instance);
    newSha = sha256Hex(`${JSON.stringify(doc, null, 2)}\n`);
  } catch (err) {
    if (
      err instanceof ConfigNotFoundError ||
      err instanceof ConfigParseError ||
      err instanceof ConfigSchemaError
    ) {
      fail(err.message, {
        json,
        command: ctx.command,
        code: err.code,
        exitCode: EXIT.CONFIG,
      });
    }
    throw err;
  }
  const ids = migrationIds(oldSha);

  const fullPlan = {
    method: "config.migrate",
    file: abs,
    from: 1,
    to: 2,
    backup_path: `${abs}.v1.${oldSha}.bak`,
    old_sha256: oldSha,
    new_sha256: newSha,
    output: opts.output ? path.resolve(opts.output) : null,
    workspace_id: ids.workspace,
    instance_id: ids.instance,
  };
  const digest = planDigest(fullPlan);
  displayPlan(ctx.command, fullPlan, digest, json);
  if (opts.dryRun === true) {
    return;
  }
  await requireReviewedPlan({
    yes: opts.yes,
    reviewDigest: opts.reviewDigest,
    digest,
    summary: `migrate ${abs} to schema_version 2`,
    json,
    command: ctx.command,
  });

  try {
    if (opts.output) {
      // Write the v2 document to a new path; the original stays untouched,
      // so no backup is required for this mode.
      const doc = migrateConfig(rawDoc, ids.workspace, ids.instance);
      const outPath = path.resolve(opts.output);
      const fd = openSync(outPath, "wx", 0o600);
      try {
        writeSync(fd, `${JSON.stringify(doc, null, 2)}\n`);
      } finally {
        closeSync(fd);
      }
      if (json) {
        writeJson(ctx.command, true, {
          output: outPath,
          new_sha256: newSha,
          workspace_id: ids.workspace,
          instance_id: ids.instance,
        });
      } else {
        process.stdout.write(`wrote ${outPath}\n`);
      }
      return;
    }
    const result = migrateConfigFile(abs, {
      workspace: ids.workspace,
      instance: ids.instance,
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(
      `migrated ${abs}\nbackup ${result.backup_path}\n` +
        `workspace_id ${result.receipt.workspace_id}\ninstance_id ${result.receipt.instance_id}\n`,
    );
  } catch (err) {
    if (
      err instanceof ConfigNotFoundError ||
      err instanceof ConfigParseError ||
      err instanceof ConfigSchemaError ||
      err instanceof ConfigMigrationError
    ) {
      fail(err.message, {
        json,
        command: ctx.command,
        code: "code" in err ? String((err as { code: unknown }).code) : "CONFIG_MIGRATION",
        exitCode: EXIT.CONFIG,
      });
    }
    failControl(err, ctx);
  }
}

export function registerConfigCommands(gateway: Command): void {
  const config = gateway
    .command("config")
    .description("Show, validate, and migrate latticeag.json.");

  const show = config
    .command("show")
    .description("Print the redacted document and current revision.")
    .action(async (opts: { socket?: string }, command: Command) => {
      await runShow(opts, command);
    });
  addGlobalOptions(show);
  addSocketOption(show);

  const validate = config
    .command("validate")
    .description("Offline schema + semantic validation.")
    .argument("[file]", "Config file (default: discovered latticeag.json)")
    .action(async (file: string | undefined, opts: { socket?: string }, command: Command) => {
      await runValidate(file, opts, command);
    });
  addGlobalOptions(validate);
  addSocketOption(validate);

  const migrate = config
    .command("migrate")
    .description("Migrate a v1 config to v2 (backup + atomic replace).")
    .option("--from <v>", "Source schema version", "1")
    .option("--to <v>", "Target schema version", "2")
    .option("--dry-run", "Print the plan; write nothing")
    .option("--output <new-path>", "Write v2 to a new file instead of replacing")
    .option("--yes", "Approve the displayed plan")
    .option("--review-digest <hash>", "Digest of the displayed plan")
    .action(async (opts, command: Command) => {
      await runMigrate(opts, command);
    });
  addGlobalOptions(migrate);
  addSocketOption(migrate);
}
