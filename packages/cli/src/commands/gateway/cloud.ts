/**
 * `latticeag gateway cloud pair|revoke` (spec §6.2, §4.4). Cloud pairing is
 * an explicit user-initiated device enrollment — the CLI begins it and
 * prints the provider confirmation material; the daemon drives completion.
 * Revocation durably stops the relay and queues a remote notice.
 */
import type { Command } from "commander";
import { v2 } from "@latticeag/core";
import { addGlobalOptions } from "../../globals.js";
import { writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  connectDaemon,
  failControl,
  globalsOf,
  requireConfirmation,
  usageFail,
} from "../../gateway/common.js";

const { isStreamName } = v2.protocol;

async function runPair(
  opts: { provider?: string; stream?: string[]; remoteUi?: boolean; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  if (!opts.provider) {
    usageFail("cloud pair requires --provider <configured-name>", ctx);
  }
  const streams: v2.protocol.StreamName[] = [];
  for (const raw of opts.stream ?? []) {
    for (const name of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
      if (!isStreamName(name)) {
        usageFail(`--stream must be a stream name: ${name}`, ctx);
      }
      streams.push(name);
    }
  }
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const result = await client.call<{
      enrollment: string;
      state: string;
      user_code: string;
    }>("cloud.pair.begin", {
      provider: opts.provider,
      streams,
      remote_ui: opts.remoteUi === true,
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(
      `enrollment ${result.enrollment}\nstate ${result.state}\nuser_code ${result.user_code}\n`,
    );
    process.stderr.write(
      "confirm the enrollment with the provider; the daemon completes pairing\n",
    );
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runRevoke(
  opts: { cloud?: string; yes?: boolean; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  if (!opts.cloud) {
    usageFail("cloud revoke requires --cloud <id>", ctx);
  }
  const cloudId = opts.cloud;
  try {
    await requireConfirmation({
      yes: opts.yes,
      summary: `revoke cloud pairing ${cloudId} (stops outbound relay)`,
      json,
      command: ctx.command,
    });
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const result = await client.call("cloud.pair.revoke", { cloud: cloudId });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

export function registerCloudCommands(gateway: Command): void {
  const cloud = gateway.command("cloud").description("Cloud pairing.");

  const pair = cloud
    .command("pair")
    .description("Begin a provider/device enrollment.")
    .option("--provider <name>", "Configured provider name")
    .option("--stream <stream>", "Stream to pair (repeatable)", collect, [])
    .option("--remote-ui", "Grant remote UI access", false)
    .action(async (opts, command: Command) => {
      await runPair(opts, command);
    });
  addGlobalOptions(pair);
  addSocketOption(pair);

  const revoke = cloud
    .command("revoke")
    .description("Stop the outbound relay and queue remote revocation.")
    .option("--cloud <id>", "Cloud pairing id")
    .option("--yes", "Confirm revocation")
    .action(async (opts, command: Command) => {
      await runRevoke(opts, command);
    });
  addGlobalOptions(revoke);
  addSocketOption(revoke);
}

function collect(value: string, previous: string[]): string[] {
  return previous.concat([value]);
}
