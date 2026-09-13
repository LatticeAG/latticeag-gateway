/**
 * `latticeag gateway receipts show|export` (spec §6.2, §3.3). Disclosure is
 * explicit — hashes by default, never an automatic object fetch; export
 * writes the returned receipt/bundle to a file.
 */
import { writeFileSync } from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { Option } from "commander";
import { v2 } from "@latticeag/core";
import { addGlobalOptions } from "../../globals.js";
import { writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  connectDaemon,
  failControl,
  globalsOf,
  usageFail,
} from "../../gateway/common.js";

const { isHash64 } = v2.crypto;

const DISCLOSURES = {
  hashes: "HASHES_ONLY",
  redacted: "REDACTED",
  full: "FULL",
} as const;

type DisclosureFlag = keyof typeof DISCLOSURES;

/**
 * Map the <action-id> CLI argument to the action reference the daemon
 * expects. A 64-hex id binds raw_sha256; anything else is sent as the
 * object_id for the daemon to resolve.
 */
function actionRef(actionId: string, workspace: string | undefined): v2.protocol.NativeRef {
  return {
    profile: "receipt-action/1",
    namespace: workspace ?? "default",
    object_id: actionId,
    commitment: null,
    raw_sha256: isHash64(actionId) ? actionId : "0".repeat(64),
    bytes: "0",
  };
}

async function runShow(
  actionId: string,
  opts: { workspace?: string; disclosure?: string; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const disclosure = (opts.disclosure ?? "hashes") as DisclosureFlag;
  if (!(disclosure in DISCLOSURES)) {
    usageFail(`--disclosure must be hashes|redacted|full: ${String(opts.disclosure)}`, ctx);
  }
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const result = await client.call("receipt.get", {
      action: actionRef(actionId, opts.workspace),
      disclosure: DISCLOSURES[disclosure],
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runExport(
  actionId: string,
  opts: { workspace?: string; output?: string; disclosure?: string; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  if (!opts.output) {
    usageFail("receipts export requires --output <path>", ctx);
  }
  const disclosure = (opts.disclosure ?? "full") as DisclosureFlag;
  if (!(disclosure in DISCLOSURES)) {
    usageFail(`--disclosure must be hashes|redacted|full: ${String(opts.disclosure)}`, ctx);
  }
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const result = await client.call<{
      bundle?: { content?: string } | null;
    }>("receipt.get", {
      action: actionRef(actionId, opts.workspace),
      disclosure: DISCLOSURES[disclosure],
    });
    const out = path.resolve(opts.output);
    // Export writes the receipt JSON; a native bundle (when its closure
    // fits and the daemon returned it) is embedded base64 in `bundle`.
    writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
    if (json) {
      writeJson(ctx.command, true, {
        output: out,
        bundle: result.bundle != null,
      });
      return;
    }
    process.stdout.write(`wrote ${out}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

export function registerReceiptCommands(gateway: Command): void {
  const receipts = gateway
    .command("receipts")
    .description("Action receipts with explicit disclosure.");

  const show = receipts
    .command("show")
    .description("Show a receipt at the given disclosure level.")
    .argument("<action-id>", "Action id or digest")
    .option("--workspace <ws>", "Receipt workspace")
    .addOption(
      new Option("--disclosure <level>", "Disclosure level")
        .choices(["hashes", "redacted", "full"])
        .default("hashes"),
    )
    .action(async (id: string, opts, command: Command) => {
      await runShow(id, opts, command);
    });
  addGlobalOptions(show);
  addSocketOption(show);

  const exportCmd = receipts
    .command("export")
    .description("Export a receipt/proof-bundle to a file.")
    .argument("<action-id>", "Action id or digest")
    .option("--workspace <ws>", "Receipt workspace")
    .option("--output <path>", "Destination file (required)")
    .addOption(
      new Option("--disclosure <level>", "Disclosure level")
        .choices(["hashes", "redacted", "full"])
        .default("full"),
    )
    .action(async (id: string, opts, command: Command) => {
      await runExport(id, opts, command);
    });
  addGlobalOptions(exportCmd);
  addSocketOption(exportCmd);
}
