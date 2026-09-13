/**
 * `latticeag gateway start|stop|status` (spec §6.2, §1.3).
 *
 * start: on-demand daemon start (detached spawn of `gateway start
 * --foreground` on this same bin) — never a service install. Foreground
 * runs the daemon in-process via a lazy dynamic import of
 * @latticeag/gateway-daemon so the Node >=20.19 v1 path never loads it.
 * stop/status: pure control RPCs.
 */
import { spawn } from "node:child_process";
import type { Command } from "commander";
import { v2 } from "@latticeag/core";
import { addGlobalOptions } from "../../globals.js";
import { fail, writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  connectDaemon,
  failControl,
  gatewayIdentity,
  globalsOf,
  parseBoundedInt,
  parseUiPort,
} from "../../gateway/common.js";
import {
  cliBinPath,
  controlClient,
  discoverControl,
  ensureDaemon,
  ControlRequestError,
  ControlUnavailableError,
} from "../../gateway/client.js";

const { EXIT: E } = v2.protocol;

/** The daemon's isolated SQLite runtime needs Node >=22.13 (§1.3). */
function nodeSupportsDaemon(): boolean {
  const [maj, min] = process.versions.node.split(".").map((s) => Number(s));
  return (maj ?? 0) > 22 || ((maj ?? 0) === 22 && (min ?? 0) >= 13);
}

interface StartOpts {
  foreground?: boolean;
  uiPort?: string;
  ui?: boolean;
  waitMs?: string;
  socket?: string;
}

function daemonSpawnArgs(opts: StartOpts): string[] {
  const args = ["gateway", "start", "--foreground"];
  if (opts.uiPort !== undefined) {
    args.push("--ui-port", String(opts.uiPort));
  }
  if (opts.ui === false) {
    args.push("--no-ui");
  }
  return args;
}

async function runForeground(opts: StartOpts, ctx: { json: boolean; command: string }): Promise<void> {
  if (!nodeSupportsDaemon()) {
    fail(
      `gateway daemon requires Node >=22.13 (running ${process.versions.node}); ` +
        "the v1 CLI surface is unaffected",
      { json: ctx.json, command: ctx.command, code: "RUNTIME_UNSUPPORTED", exitCode: E.UNSUPPORTED },
    );
  }
  const identity = gatewayIdentity();
  const uiPort = parseUiPort(opts.uiPort, ctx);
  // Lazy dynamic import — the ONLY place the daemon package enters the
  // process. Kept behind a computed specifier so bundlers/tsc on the v1
  // path never resolve it eagerly.
  const specifier = "@latticeag/gateway-daemon";
  let mod: Record<string, unknown>;
  try {
    mod = (await import(specifier)) as Record<string, unknown>;
  } catch (err) {
    fail(
      `gateway daemon runtime unavailable: ${err instanceof Error ? err.message : String(err)}`,
      { json: ctx.json, command: ctx.command, code: "RUNTIME_UNSUPPORTED", exitCode: E.UNSUPPORTED },
    );
  }
  const entry =
    (mod["startGatewayDaemon"] as ((o: unknown) => Promise<unknown>) | undefined) ??
    (mod["startDaemon"] as ((o: unknown) => Promise<unknown>) | undefined);
  if (typeof entry !== "function") {
    fail(
      "@latticeag/gateway-daemon does not export a daemon entrypoint in this build",
      { json: ctx.json, command: ctx.command, code: "RUNTIME_UNSUPPORTED", exitCode: E.UNSUPPORTED },
    );
  }
  await entry({
    config_path: identity.configPath,
    ui: { enabled: opts.ui !== false, port: uiPort },
  });
}

async function runStart(opts: StartOpts, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const waitMs = parseBoundedInt(
    opts.waitMs,
    { flag: "--wait-ms", min: 0, max: 30000, fallback: 10000 },
    ctx,
  );
  parseUiPort(opts.uiPort, ctx); // validate even for detached spawn

  if (opts.foreground === true) {
    await runForeground(opts, ctx);
    return;
  }

  const identity = gatewayIdentity();
  const discovered = discoverControl({
    socket: opts.socket,
    configDir: identity.configDir,
    workspace: identity.workspace,
    instance: identity.instance,
  });
  const client = controlClient({
    socketPath: discovered.socketPath,
    workspace: discovered.workspace,
    timeoutMs: 1500,
  });

  const spawnDaemon = (): void => {
    const child = spawn(process.execPath, [cliBinPath(), ...daemonSpawnArgs(opts)], {
      detached: true,
      stdio: "ignore",
      env: process.env,
    });
    child.unref();
  };

  const result = await ensureDaemon({
    client,
    budgetMs: waitMs,
    autostart: true,
    spawnDaemon,
  });
  if (result.mode === "unavailable") {
    fail(`gateway daemon did not reach READY within ${waitMs} ms`, {
      json,
      command: ctx.command,
      code: "RUNTIME_UNAVAILABLE",
      exitCode: E.BUSY,
    });
  }
  if (json) {
    writeJson(ctx.command, true, {
      mode: result.mode,
      status: result.status ?? null,
      socket: discovered.socketPath,
    });
    return;
  }
  const state = result.status?.state ?? "READY";
  process.stdout.write(
    `gateway ${result.mode === "connected" ? "already running" : "started"} (${state})\n`,
  );
  if (result.status?.ui) {
    process.stdout.write(`ui ${result.status.ui}\n`);
  }
}

async function runStop(opts: { graceMs?: string; socket?: string }, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const graceMs = parseBoundedInt(
    opts.graceMs,
    { flag: "--grace-ms", min: 0, max: 30000, fallback: 10000 },
    ctx,
  );
  // Never autostart just to stop: a single probe is the whole budget.
  try {
    const { client } = await connectDaemon({
      socket: opts.socket,
      autostart: false,
      json,
      command: ctx.command,
    });
    const result = await client.call<{ state: string }>("daemon.stop", {
      grace_ms: graceMs,
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`gateway ${result.state}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runStatus(opts: { watch?: boolean; socket?: string }, command: Command): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const identity = gatewayIdentity();
  const discovered = discoverControl({
    socket: opts.socket,
    configDir: identity.configDir,
    workspace: identity.workspace,
    instance: identity.instance,
  });
  const client = controlClient({
    socketPath: discovered.socketPath,
    workspace: discovered.workspace,
    timeoutMs: 1500,
  });

  const print = (status: v2.protocol.DaemonStatusResult): void => {
    if (json) {
      writeJson(ctx.command, true, status);
      return;
    }
    process.stdout.write(
      `instance ${status.instance}\nstate ${status.state}\n` +
        `config_revision ${status.config_revision}\nproducts ${status.products}\n` +
        `peers ${status.peers}\nui ${status.ui ?? "disabled"}\n`,
    );
  };

  for (;;) {
    try {
      const status = await client.call<v2.protocol.DaemonStatusResult>(
        "daemon.status",
        {},
      );
      print(status);
      // exit 0 on READY/DEGRADED; anything else keeps watching or exits 11.
      if (!opts.watch || status.state === "READY" || status.state === "DEGRADED") {
        if (status.state === "READY" || status.state === "DEGRADED") {
          return;
        }
        process.exit(E.BUSY);
      }
    } catch (err) {
      if (err instanceof ControlUnavailableError || err instanceof ControlRequestError) {
        if (!opts.watch) {
          // §6.2: status exits 11 when the daemon is absent/unreachable.
          failControl(err, ctx);
        }
        if (!json) {
          process.stderr.write("gateway daemon unavailable\n");
        }
      } else {
        failControl(err, ctx);
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

export function registerDaemonCommands(gateway: Command): void {
  const start = gateway
    .command("start")
    .description("Start the gateway daemon (on-demand; no service install).")
    .option("--foreground", "Run the daemon in the foreground")
    .option("--ui-port <0|1024..65535>", "Loopback UI port (0 = OS-assigned)")
    .option("--no-ui", "Do not bind the loopback UI listener")
    .option("--wait-ms <n>", "Max wait for READY, 0..30000", "10000")
    .action(async (opts: StartOpts, command: Command) => {
      await runStart(opts, command);
    });
  addGlobalOptions(start);
  addSocketOption(start);

  const stop = gateway
    .command("stop")
    .description("Gracefully stop the gateway daemon.")
    .option("--grace-ms <n>", "Drain budget 0..30000", "10000")
    .action(async (opts: { graceMs?: string; socket?: string }, command: Command) => {
      await runStop(opts, command);
    });
  addGlobalOptions(stop);
  addSocketOption(stop);

  const status = gateway
    .command("status")
    .description("Show daemon status (exit 0 READY/DEGRADED, 11 absent).")
    .option("--watch", "Poll until READY/DEGRADED", false)
    .action(async (opts: { watch?: boolean; socket?: string }, command: Command) => {
      await runStatus(opts, command);
    });
  addGlobalOptions(status);
  addSocketOption(status);
}
