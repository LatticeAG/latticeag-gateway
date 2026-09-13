/**
 * `latticeag gateway approvals list|show|decide` (spec §6.2, §4.5).
 * decide requires --decision, --revision, and --action-digest: the digest
 * is verified against the stored action commitment fetched via
 * approval.get before the decision is sent.
 */
import type { Command } from "commander";
import { Option } from "commander";
import { v2 } from "@latticeag/core";
import { addGlobalOptions } from "../../globals.js";
import { fail, writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  connectDaemon,
  failControl,
  globalsOf,
  usageFail,
  EXIT,
} from "../../gateway/common.js";

const { isHash64 } = v2.crypto;

async function runList(opts: { state?: string; socket?: string }, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const state = opts.state ?? "pending";
  if (!["pending", "resolved", "all"].includes(state)) {
    usageFail(`--state must be pending|resolved|all: ${state}`, ctx);
  }
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const page = await client.call<{ items: Array<Record<string, unknown>>; next: string | null }>(
      "approval.list",
      {
        state: state === "all" || state === "resolved" ? undefined : "PENDING",
        after: null,
        limit: 200,
      },
    );
    // "resolved" includes unacknowledged native decisions — everything not
    // PENDING in the offline projection.
    const items =
      state === "resolved"
        ? page.items.filter((a) => String(a["state"]) !== "PENDING")
        : page.items;
    if (json) {
      writeJson(ctx.command, true, { approvals: items, next: page.next });
      return;
    }
    for (const a of items) {
      process.stdout.write(
        `${String(a["approval"] ?? a["id"] ?? "-")}\t${String(a["state"] ?? "-")}\t${String(a["target"] ?? "")}\n`,
      );
    }
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runShow(id: string, opts: { socket?: string }, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const result = await client.call("approval.get", { approval: id });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runDecide(
  id: string,
  opts: {
    decision?: string;
    revision?: string;
    actionDigest?: string;
    reason?: string;
    socket?: string;
  },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  if (opts.decision !== "approve" && opts.decision !== "deny") {
    usageFail("approvals decide requires --decision approve|deny", ctx);
  }
  if (opts.revision === undefined || opts.revision === "" || !/^[0-9]+$/.test(opts.revision)) {
    usageFail("approvals decide requires --revision <count>", ctx);
  }
  if (!opts.actionDigest) {
    usageFail("approvals decide requires --action-digest <hash>", ctx);
  }
  const digest = opts.actionDigest.replace(/^sha256:/, "");
  if (!isHash64(digest)) {
    usageFail(`--action-digest must be a sha256 hex digest: ${opts.actionDigest}`, ctx);
  }
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    // Verify the supplied digest against the stored action commitment —
    // the daemon re-checks expected_revision and the action natively.
    const current = await client.call<{
      revision: string;
      action: { raw_sha256?: string; commitment?: string | null; object_id?: string };
    }>("approval.get", { approval: id });
    const action = current.action;
    const matches =
      action.raw_sha256 === digest ||
      action.commitment === digest ||
      action.object_id === digest;
    if (!matches) {
      fail(`--action-digest does not match the stored action commitment`, {
        json,
        command: ctx.command,
        code: "REVISION_CONFLICT",
        exitCode: EXIT.REVISION,
      });
    }
    const result = await client.call("approval.decide", {
      approval: id,
      expected_revision: opts.revision,
      action,
      decision: opts.decision,
      reason: opts.reason ?? "",
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

export function registerApprovalCommands(gateway: Command): void {
  const approvals = gateway
    .command("approvals")
    .description("Pending and resolved approval projections.");

  const list = approvals
    .command("list")
    .description("List approvals by state.")
    .addOption(
      new Option("--state <state>", "State filter")
        .choices(["pending", "resolved", "all"])
        .default("pending"),
    )
    .action(async (opts: { state?: string; socket?: string }, command: Command) => {
      await runList(opts, command);
    });
  addGlobalOptions(list);
  addSocketOption(list);

  const show = approvals
    .command("show")
    .description("Show an approval's action, binding, revision, expiry.")
    .argument("<id>", "Approval id")
    .action(async (id: string, opts: { socket?: string }, command: Command) => {
      await runShow(id, opts, command);
    });
  addGlobalOptions(show);
  addSocketOption(show);

  const decide = approvals
    .command("decide")
    .description("Approve or deny with the fresh action commitment.")
    .argument("<id>", "Approval id")
    .addOption(
      new Option("--decision <decision>", "Decision").choices(["approve", "deny"]),
    )
    .option("--revision <count>", "Expected CAS revision (required)")
    .option("--action-digest <hash>", "Fresh action commitment (required)")
    .option("--reason <text>", "Decision reason")
    .action(async (id: string, opts, command: Command) => {
      await runDecide(id, opts, command);
    });
  addGlobalOptions(decide);
  addSocketOption(decide);
}
