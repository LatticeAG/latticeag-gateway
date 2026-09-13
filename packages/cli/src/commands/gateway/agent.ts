/**
 * `latticeag gateway agent pair|list|revoke` and the root `agent` alias
 * (spec §6.2, §4). Pairing never takes a code or token in argv: `--key` is
 * a public-key FILE whose digest becomes the proposed key hash, the pair
 * code only ever appears on stdout, and `--qr` prints the canonical
 * J({v:1,instance,pair,code,expires_ms}) payload.
 */
import { Command } from "commander";
import { Option } from "commander";
import { v2 } from "@latticeag/core";
import { addGlobalOptions } from "../../globals.js";
import { writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  connectDaemon,
  failControl,
  gatewayIdentity,
  globalsOf,
  readFileOrFail,
  requireConfirmation,
  usageFail,
} from "../../gateway/common.js";

const { canonicalJson, sha256Hex } = v2.crypto;
const { validateScope } = v2.protocol;

interface PairOpts {
  key?: string;
  role?: string;
  scope?: string[];
  qr?: boolean;
  approve?: string;
  socket?: string;
}

function parseScopes(rawList: string[] | undefined, ctx: { json: boolean; command: string }): v2.protocol.Scope[] {
  const scopes: v2.protocol.Scope[] = [];
  for (const raw of rawList ?? []) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      usageFail(`--scope is not valid JSON: ${raw}`, ctx);
    }
    const verdict = validateScope(parsed);
    if (!verdict.ok) {
      usageFail(`invalid --scope (${verdict.field}): ${verdict.message}`, ctx);
    }
    scopes.push(parsed as v2.protocol.Scope);
  }
  return scopes;
}

async function runPair(opts: PairOpts, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const role = opts.role ?? "agent";
  if (role !== "agent" && role !== "operator") {
    usageFail(`--role must be agent|operator: ${role}`, ctx);
  }
  const scopes = parseScopes(opts.scope, ctx);
  // Usage validation precedes any connect attempt: a missing --key is an
  // exit-2 usage error, not a daemon error.
  if (opts.approve === undefined && (opts.key === undefined || opts.key === "")) {
    usageFail("agent pair requires --key <file>", ctx);
  }

  try {
    const { client } = await connectDaemon({
      socket: opts.socket,
      json,
      command: ctx.command,
    });

    if (opts.approve !== undefined && opts.approve !== "") {
      // Approve an existing invitation: fetch the retained proposal first —
      // the operator reviews the exact proposal/key/scopes being approved.
      const view = await client.call<{
        pair: string;
        state: string;
        proposal: string;
        key: string;
        scopes: v2.protocol.Scope[];
      }>("agent.pair.get", { pair: opts.approve, code: null });
      const approved = await client.call<{ pair: string; state: string }>(
        "agent.pair.approve",
        {
          pair: opts.approve,
          proposal: view.proposal,
          key: view.key,
          scopes: scopes.length > 0 ? scopes : view.scopes,
        },
      );
      if (json) {
        writeJson(ctx.command, true, approved);
      } else {
        process.stdout.write(`pair ${approved.pair} ${approved.state}\n`);
      }
      return;
    }

    const keyBytes = readFileOrFail(opts.key as string, ctx);
    const key = sha256Hex(keyBytes);

    const created = await client.call<{
      pair: string;
      code: string;
      expires_ms: number;
    }>("agent.pair.create", { role, scopes, key });

    const identity = gatewayIdentity();
    if (json) {
      writeJson(ctx.command, true, {
        pair: created.pair,
        code: created.code,
        expires_ms: created.expires_ms,
        instance: identity.instance,
      });
    } else {
      process.stdout.write(
        `pair ${created.pair}\ncode ${created.code}\nexpires_ms ${created.expires_ms}\n`,
      );
    }
    if (opts.qr === true) {
      // Canonical J() payload for the QR payload, per spec §6.2.
      process.stdout.write(
        `${canonicalJson({
          v: 1,
          instance: identity.instance,
          pair: created.pair,
          code: created.code,
          expires_ms: created.expires_ms,
        })}\n`,
      );
    }
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runList(opts: { state?: string; socket?: string }, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const state = opts.state ?? "all";
  const allowed = ["connected", "disconnected", "revoked", "all"];
  if (!allowed.includes(state)) {
    usageFail(`--state must be ${allowed.join("|")}: ${state}`, ctx);
  }
  try {
    const { client } = await connectDaemon({
      socket: opts.socket,
      json,
      command: ctx.command,
    });
    const page = await client.call<{ items: Array<Record<string, unknown>>; next: string | null }>(
      "agent.list",
      { after: null, limit: 200 },
    );
    const wanted = state === "all" ? null : state.toUpperCase();
    const peers = wanted === null
      ? page.items
      : page.items.filter((p) => String(p["state"]) === wanted);
    // Fingerprints identify peers; credentials are never printed (§6.2).
    if (json) {
      writeJson(ctx.command, true, { peers, next: page.next });
      return;
    }
    for (const peer of peers) {
      process.stdout.write(
        `${String(peer["peer"] ?? peer["id"] ?? "-")}\t${String(peer["state"] ?? "-")}\t${String(peer["role"] ?? "-")}\n`,
      );
    }
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runRevoke(
  peer: string,
  opts: { reason?: string; yes?: boolean; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const reason = opts.reason ?? "operator_requested";
  try {
    // Revocation is authorized locally even offline (§6.2): confirm first.
    await requireConfirmation({
      yes: opts.yes,
      summary: `revoke peer ${peer} (${reason})`,
      json,
      command: ctx.command,
    });
    const { client } = await connectDaemon({
      socket: opts.socket,
      json,
      command: ctx.command,
    });
    const result = await client.call("agent.revoke", { peer, reason });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`revoked ${peer}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

/** Register the agent group under any parent (gateway or root alias). */
export function buildAgentCommand(name = "agent"): Command {
  const agent = new Command(name).description(
    "Agent pairing and peer management.",
  );

  const pair = agent
    .command("pair")
    .description("Create or approve a pairing invitation.")
    .option("--key <file>", "Public key file (digest is proposed)")
    .addOption(
      new Option("--role <agent|operator>", "Requested role")
        .choices(["agent", "operator"])
        .default("agent"),
    )
    .option("--scope <JSON>", "Scope grant JSON (repeatable)", collect, [])
    .option("--qr", "Print the canonical QR payload")
    .option("--approve <pair-id>", "Approve an existing invitation")
    .action(async (opts: PairOpts, command: Command) => {
      await runPair(opts, command);
    });
  addGlobalOptions(pair);
  addSocketOption(pair);

  const list = agent
    .command("list")
    .description("List peers by connection state.")
    .addOption(
      new Option("--state <state>", "State filter")
        .choices(["connected", "disconnected", "revoked", "all"])
        .default("all"),
    )
    .action(async (opts: { state?: string; socket?: string }, command: Command) => {
      await runList(opts, command);
    });
  addGlobalOptions(list);
  addSocketOption(list);

  const revoke = agent
    .command("revoke")
    .description("Durably revoke a peer grant.")
    .argument("<peer>", "Peer id/fingerprint")
    .option("--reason <text>", "Revocation reason", "operator_requested")
    .option("--yes", "Confirm revocation")
    .action(async (peer: string, opts: { reason?: string; yes?: boolean; socket?: string }, command: Command) => {
      await runRevoke(peer, opts, command);
    });
  addGlobalOptions(revoke);
  addSocketOption(revoke);

  return agent;
}

function collect(value: string, previous: string[]): string[] {
  return previous.concat([value]);
}
