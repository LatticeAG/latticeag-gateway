/**
 * `latticeag gateway ui open|close` and the root `ui` alias (spec §6.2, §7).
 *
 * `ui open` mints a one-use loopback bootstrap through ui.session.create and
 * prints the canonical loopback URL; the browser is opened unless
 * --no-browser. `ui close` revokes a session — never the server or other
 * operators' sessions.
 */
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import { Command } from "commander";
import { Option } from "commander";
import { addGlobalOptions } from "../../globals.js";
import { writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  connectDaemon,
  failControl,
  gatewayIdentity,
  globalsOf,
  usageFail,
} from "../../gateway/common.js";

const SESSION_FILE = "cli-ui-session.json";

function sessionFilePath(configDir: string): string {
  return path.join(configDir, ".latticeag", SESSION_FILE);
}

function openBrowser(url: string): void {
  const opener =
    process.platform === "darwin"
      ? "open"
      : process.platform === "win32"
        ? "cmd"
        : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = spawn(opener, args, { detached: true, stdio: "ignore" });
    child.unref();
  } catch {
    // opening a browser is best-effort; the URL is already printed
  }
}

async function runOpen(
  opts: { role?: string; browser?: boolean; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const role = opts.role ?? "viewer";
  if (role !== "viewer" && role !== "operator") {
    usageFail(`--role must be viewer|operator: ${role}`, ctx);
  }
  try {
    const { client } = await connectDaemon({
      socket: opts.socket,
      json,
      command: ctx.command,
    });
    const created = await client.call<{
      bootstrap: string;
      expires_ms: number;
      url: string;
    }>("ui.session.create", { role });

    // Remember the CLI-created session so `ui close` can revoke it without
    // a --session flag (§6.2 "or current CLI-created session").
    const identity = gatewayIdentity();
    try {
      const dir = path.join(identity.configDir, ".latticeag");
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeFileSync(
        sessionFilePath(identity.configDir),
        JSON.stringify({ bootstrap: created.bootstrap, url: created.url }),
        { mode: 0o600 },
      );
    } catch {
      // session bookkeeping is advisory
    }

    if (json) {
      writeJson(ctx.command, true, created);
    } else {
      process.stdout.write(`${created.url}\n`);
    }
    if (opts.browser !== false) {
      openBrowser(created.url);
    }
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runClose(
  opts: { session?: string; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const identity = gatewayIdentity();
  let session = opts.session;
  if (!session) {
    const file = sessionFilePath(identity.configDir);
    if (existsSync(file)) {
      try {
        const saved = JSON.parse(readFileSync(file, "utf8")) as {
          bootstrap?: string;
        };
        session = saved.bootstrap;
      } catch {
        session = undefined;
      }
    }
  }
  if (!session) {
    usageFail("ui close requires --session <id> (no CLI-created session on record)", ctx);
  }
  try {
    const { client } = await connectDaemon({
      socket: opts.socket,
      json,
      command: ctx.command,
    });
    const result = await client.call<{ session: string; state: string }>(
      "ui.session.revoke",
      { session },
    );
    try {
      unlinkSync(sessionFilePath(identity.configDir));
    } catch {
      // already gone
    }
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`session ${result.session} ${result.state}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

/** Register the ui group under any parent (gateway or root alias). */
export function buildUiCommand(name = "ui"): Command {
  const ui = new Command(name).description("Local Web UI sessions.");

  const open = ui
    .command("open")
    .description("Create a loopback bootstrap session and print the URL.")
    .addOption(
      new Option("--role <viewer|operator>", "Session role")
        .choices(["viewer", "operator"])
        .default("viewer"),
    )
    .option("--no-browser", "Print the URL without opening a browser")
    .action(async (opts: { role?: string; browser?: boolean; socket?: string }, command: Command) => {
      await runOpen(opts, command);
    });
  addGlobalOptions(open);
  addSocketOption(open);

  const close = ui
    .command("close")
    .description("Revoke a UI session (not the server or other operators).")
    .option("--session <id>", "Session to revoke (default: last CLI-created)")
    .action(async (opts: { session?: string; socket?: string }, command: Command) => {
      await runClose(opts, command);
    });
  addGlobalOptions(close);
  addSocketOption(close);

  return ui;
}
