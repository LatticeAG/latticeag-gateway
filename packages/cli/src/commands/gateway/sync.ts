/**
 * `latticeag gateway sync status|pause|resume|config|flush` and the root
 * `sync` alias (spec §6.2, §9). Status reports exact stream/cohort/queue
 * state — never inferred hosted success.
 */
import { Command } from "commander";
import { v2 } from "@latticeag/core";
import { addGlobalOptions } from "../../globals.js";
import { fail, writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  connectDaemon,
  failControl,
  globalsOf,
  cliReviewDigestRef,
  parseBoundedInt,
  planDigest,
  readFileOrFail,
  requireReviewedPlan,
  usageFail,
  EXIT,
} from "../../gateway/common.js";

const { isStreamName, STREAMS } = v2.protocol;

function parseStreams(raw: string | undefined, ctx: { json: boolean; command: string }): v2.protocol.StreamName[] {
  if (raw === undefined || raw === "" || raw === "all") {
    return [...STREAMS];
  }
  const names = raw.split(",").map((s) => s.trim()).filter(Boolean);
  for (const name of names) {
    if (!isStreamName(name)) {
      usageFail(`--stream must be ${[...STREAMS, "all"].join("|")}: ${name}`, ctx);
    }
  }
  return names as v2.protocol.StreamName[];
}

async function runStatus(opts: { watch?: boolean; socket?: string }, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  try {
    const { client } = await connectDaemon({
      socket: opts.socket,
      json,
      command: ctx.command,
    });
    for (;;) {
      const status = await client.call("sync.status", {});
      if (json) {
        writeJson(ctx.command, true, status);
      } else {
        process.stdout.write(`${JSON.stringify(status, null, 2)}\n`);
      }
      if (opts.watch !== true) {
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runPauseResume(
  verb: "pause" | "resume",
  opts: { stream?: string; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const streams = parseStreams(opts.stream, ctx);
  try {
    const { client } = await connectDaemon({
      socket: opts.socket,
      json,
      command: ctx.command,
    });
    const result = await client.call(`sync.${verb}`, { streams });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runConfig(
  opts: { file?: string; dryRun?: boolean; yes?: boolean; reviewDigest?: string; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };

  if (opts.file === undefined) {
    // No file: read current sync config (spec §6.2 "or read current config").
    try {
      const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
      const current = await client.call("config.get", {});
      if (json) {
        writeJson(ctx.command, true, current);
      } else {
        process.stdout.write(`${JSON.stringify(current, null, 2)}\n`);
      }
      return;
    } catch (err) {
      failControl(err, ctx);
    }
  }

  const file = opts.file;
  const rawText = readFileOrFail(file, ctx).toString("utf8");
  let syncDoc: unknown;
  try {
    syncDoc = JSON.parse(rawText);
  } catch {
    usageFail(`--file is not valid JSON: ${file}`, ctx);
  }
  const plan = { method: "sync.configure", file, sync: syncDoc };
  const digest = planDigest(plan);
  if (json) {
    writeJson(ctx.command, true, { plan, review_digest: digest, dry_run: opts.dryRun === true });
  } else {
    process.stdout.write(`${JSON.stringify(syncDoc, null, 2)}\nreview_digest ${digest}\n`);
  }
  if (opts.dryRun === true) {
    return;
  }
  await requireReviewedPlan({
    yes: opts.yes,
    reviewDigest: opts.reviewDigest,
    digest,
    summary: `replace sync configuration from ${file}`,
    json,
    command: ctx.command,
  });
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const current = await client.call<{ revision: string }>("config.get", {});
    const result = await client.call("sync.configure", {
      expected_revision: current.revision,
      sync: syncDoc,
      review: cliReviewDigestRef(digest),
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`sync revision ${JSON.stringify(result)}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runFlush(
  opts: { stream?: string; timeoutMs?: string; failOnSync?: boolean; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const streams = parseStreams(opts.stream, ctx);
  const timeoutMs = parseBoundedInt(
    opts.timeoutMs,
    { flag: "--timeout-ms", min: 0, max: 300000, fallback: 30000 },
    ctx,
  );
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const result = await client.call<{ pending: number; blocked: number }>(
      "sync.flush",
      { streams, timeout_ms: timeoutMs },
    );
    if (json) {
      writeJson(ctx.command, true, result);
    } else {
      process.stdout.write(`${JSON.stringify(result)}\n`);
    }
    if (opts.failOnSync === true && (result.pending > 0 || result.blocked > 0)) {
      fail(`sync outbox remains nonempty (pending ${result.pending}, blocked ${result.blocked})`, {
        json,
        command: ctx.command,
        code: "SYNC_BLOCKED",
        exitCode: EXIT.SYNC,
      });
    }
  } catch (err) {
    failControl(err, ctx);
  }
}

/** Register the sync group under any parent (gateway or root alias). */
export function buildSyncCommand(name = "sync"): Command {
  const sync = new Command(name).description("Outbound sync control.");

  const status = sync
    .command("status")
    .description("Exact stream/cohort/queue state.")
    .option("--watch", "Poll status every second", false)
    .action(async (opts: { watch?: boolean; socket?: string }, command: Command) => {
      await runStatus(opts, command);
    });
  addGlobalOptions(status);
  addSocketOption(status);

  for (const verb of ["pause", "resume"] as const) {
    const cmd = sync
      .command(verb)
      .description(`${verb === "pause" ? "Stop new sends" : "Resume configured streams"}.`)
      .option("--stream <stream|all>", "runs|receipts|lineage|approvals|watch|mesh|all", "all")
      .action(async (opts: { stream?: string; socket?: string }, command: Command) => {
        await runPauseResume(verb, opts, command);
      });
    addGlobalOptions(cmd);
    addSocketOption(cmd);
  }

  const config = sync
    .command("config")
    .description("Show or CAS-replace the complete sync object.")
    .option("--file <json>", "Validated sync JSON to apply")
    .option("--dry-run", "Print the plan; commit nothing")
    .option("--yes", "Approve the displayed plan")
    .option("--review-digest <hash>", "Digest of the displayed plan")
    .action(async (opts, command: Command) => {
      await runConfig(opts, command);
    });
  addGlobalOptions(config);
  addSocketOption(config);

  const flush = sync
    .command("flush")
    .description("Deliver through captured high-water marks.")
    .option("--stream <stream|all>", "runs|receipts|lineage|approvals|watch|mesh|all", "all")
    .option("--timeout-ms <n>", "0..300000", "30000")
    .option("--fail-on-sync", "Exit 5 if the outbox remains nonempty")
    .action(async (opts, command: Command) => {
      await runFlush(opts, command);
    });
  addGlobalOptions(flush);
  addSocketOption(flush);

  return sync;
}
