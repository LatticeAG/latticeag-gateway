/**
 * Shared helpers for the §6.2 gateway command surface.
 *
 * Exit-code policy (dual scheme, spec §6.1): the NEW `gateway` command tree
 * maps failures through the v2 table (usage → 2, control errors →
 * exitForError / RUNTIME_UNAVAILABLE → 11). The v1 commands keep their
 * legacy exits untouched (usage → 1, child → 2, bus persist → 4,
 * fail-on-sync → 5) — see commands/*.ts.
 */
import { existsSync, readFileSync } from "node:fs";
import readline from "node:readline";
import type { Command } from "commander";
import { v2 } from "@latticeag/core";
import { fail, writeJson } from "../json-envelope.js";
import { readGlobalOpts, type GlobalOpts } from "../globals.js";
import {
  ControlRequestError,
  ControlUnavailableError,
  ensureDaemon,
  exitForControlError,
  gatewayIdentity,
  resolveRunClient,
  type ControlClient,
  type GatewayIdentity,
} from "./client.js";

export { gatewayIdentity };
export type { GatewayIdentity };

const { canonicalJson, sha256Hex } = v2.crypto;
const { EXIT } = v2.protocol;

export { EXIT };

/** CLI command name recorded in the JSON envelope for a gateway command. */
export function commandName(command: Command): string {
  const names: string[] = [];
  let cur: Command | null = command;
  while (cur) {
    const n = cur.name();
    if (n && n !== "latticeag") {
      names.unshift(n);
    }
    cur = cur.parent as Command | null;
  }
  return names.join(" ");
}

/** Usage failure for the gateway tree: exit 2 (§6.1), not the v1 exit 1. */
export function usageFail(
  message: string,
  opts: { json?: boolean; command: string },
): never {
  fail(message, {
    json: opts.json,
    command: opts.command,
    code: "USAGE",
    exitCode: EXIT.USAGE,
  });
}

/**
 * Map any thrown failure to the v2 exit table and terminate. Wire Failure
 * codes map via exitForError; an unreachable daemon maps to 11 with the
 * CLI-local RUNTIME_UNAVAILABLE code.
 */
export function failControl(
  err: unknown,
  opts: { json?: boolean; command: string },
): never {
  const mapped = exitForControlError(err);
  const message =
    err instanceof ControlRequestError || err instanceof ControlUnavailableError
      ? err.message
      : err instanceof Error
        ? err.message
        : String(err);
  fail(message, {
    json: opts.json,
    command: opts.command,
    code: mapped.code,
    exitCode: mapped.exit,
  });
}

export function parseBoundedInt(
  raw: unknown,
  bounds: { flag: string; min: number; max: number; fallback: number },
  ctx: { json?: boolean; command: string },
): number {
  if (raw === undefined || raw === null || raw === "") {
    return bounds.fallback;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < bounds.min || n > bounds.max) {
    usageFail(
      `${bounds.flag} must be an integer ${bounds.min}..${bounds.max}: ${String(raw)}`,
      ctx,
    );
  }
  return n;
}

export function parseUiPort(
  raw: unknown,
  ctx: { json?: boolean; command: string },
): number | undefined {
  if (raw === undefined || raw === null || raw === "") {
    return undefined;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || !(n === 0 || (n >= 1024 && n <= 65535))) {
    usageFail(`--ui-port must be 0 or 1024..65535: ${String(raw)}`, ctx);
  }
  return n;
}

/** sha256:<H(J(plan))> — the review digest binding the displayed plan. */
export function planDigest(plan: unknown): string {
  return `sha256:${sha256Hex(canonicalJson(plan))}`;
}

/**
 * The review binding sent with commit RPCs: a CLI-local NativeRef naming
 * the displayed plan digest. The daemon re-validates it against the stored
 * plan; the CLI never fabricates native proof material.
 */
export function cliReviewDigestRef(digest: string): v2.protocol.NativeRef {
  return {
    profile: "cli-review/1",
    namespace: "local-operator",
    object_id: digest,
    commitment: digest,
    raw_sha256: sha256Hex(digest),
    bytes: String(Buffer.byteLength(digest)),
  };
}

/** Display a mutation plan plus its review digest (stdout, or JSON data). */
export function displayPlan(
  command: string,
  plan: unknown,
  digest: string,
  json: boolean,
): void {
  if (json) {
    writeJson(command, true, { plan, review_digest: digest });
    return;
  }
  process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  process.stdout.write(`review_digest ${digest}\n`);
}

function stdinIsTty(): boolean {
  return process.stdin.isTTY === true;
}

function askYes(question: string): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
    });
    rl.question(`${question} [y/N] `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === "y" || answer.trim().toLowerCase() === "yes");
    });
  });
}

/**
 * §6.1 review gate for mutations carrying `--yes --review-digest <hash>`.
 * `--yes` approves only the exact already-displayed plan: it must be paired
 * with a matching digest. Non-TTY without approval is an error, never an
 * implicit yes.
 */
export async function requireReviewedPlan(opts: {
  yes?: boolean;
  reviewDigest?: string;
  digest: string;
  summary: string;
  json?: boolean;
  command: string;
}): Promise<void> {
  if (opts.yes === true) {
    if (opts.reviewDigest !== opts.digest) {
      fail(
        `--yes requires --review-digest ${opts.digest} (the exact displayed plan)`,
        {
          json: opts.json,
          command: opts.command,
          code: "POLICY_DENIED",
          exitCode: EXIT.POLICY,
        },
      );
    }
    return;
  }
  if (opts.reviewDigest !== undefined && opts.reviewDigest !== opts.digest) {
    fail(`--review-digest does not match the displayed plan ${opts.digest}`, {
      json: opts.json,
      command: opts.command,
      code: "POLICY_DENIED",
      exitCode: EXIT.POLICY,
    });
  }
  if (!stdinIsTty()) {
    fail(
      `approval required: re-run with --yes --review-digest ${opts.digest}`,
      {
        json: opts.json,
        command: opts.command,
        code: "POLICY_DENIED",
        exitCode: EXIT.POLICY,
      },
    );
  }
  const ok = await askYes(`${opts.summary} — apply?`);
  if (!ok) {
    fail("aborted by operator", {
      json: opts.json,
      command: opts.command,
      code: "POLICY_DENIED",
      exitCode: EXIT.POLICY,
    });
  }
}

/**
 * Simpler confirmation gate (`--yes` or interactive confirm) for mutations
 * that are destructive but carry no reviewable plan digest.
 */
export async function requireConfirmation(opts: {
  yes?: boolean;
  summary: string;
  json?: boolean;
  command: string;
}): Promise<void> {
  if (opts.yes === true) {
    return;
  }
  if (!stdinIsTty()) {
    fail(`confirmation required: re-run with --yes`, {
      json: opts.json,
      command: opts.command,
      code: "POLICY_DENIED",
      exitCode: EXIT.POLICY,
    });
  }
  const ok = await askYes(`${opts.summary} — continue?`);
  if (!ok) {
    fail("aborted by operator", {
      json: opts.json,
      command: opts.command,
      code: "POLICY_DENIED",
      exitCode: EXIT.POLICY,
    });
  }
}

export interface ResolvedClient {
  client: ControlClient;
  identity: GatewayIdentity;
  socketPath: string;
}

/**
 * Build a control client for a gateway command. `opts.start` selects the
 * daemon guarantee:
 *   "probe"    — single connect attempt, never spawn (status-like reads)
 *   "ondemand" — connect, else autostart within budget (default for the
 *                gateway tree, spec §1.3 "default start is on-demand")
 *   "required" — same but callers refuse the unavailable result.
 */
export function resolveClient(
  opts: { socket?: string } & Partial<GlobalOpts>,
): ResolvedClient {
  return resolveRunClient({ socket: opts.socket });
}

/**
 * Connect, autostarting on demand when config allows. Returns the client on
 * success; on failure exits via the v2 table (11 unreachable).
 */
export async function connectDaemon(opts: {
  socket?: string;
  budgetMs?: number;
  /** Force refusal of the on-demand fallback (run --daemon required). */
  required?: boolean;
  /** Skip autostart entirely (run --daemon off handled by caller). */
  autostart?: boolean;
  json?: boolean;
  command: string;
}): Promise<{ client: ControlClient; mode: "connected" | "started"; status?: v2.protocol.DaemonStatusResult }> {
  const resolved = resolveClient(opts);
  const autostart =
    (opts.autostart ?? true) && resolved.identity.autostart === "on-demand";
  const result = await ensureDaemon({
    client: resolved.client,
    budgetMs: opts.budgetMs ?? 1500,
    autostart,
  });
  if (result.mode === "unavailable") {
    fail(
      opts.required
        ? `daemon required but unavailable at ${resolved.socketPath}`
        : `gateway daemon unavailable at ${resolved.socketPath}`,
      {
        json: opts.json,
        command: opts.command,
        code: "RUNTIME_UNAVAILABLE",
        exitCode: EXIT.BUSY,
      },
    );
  }
  return { client: resolved.client, mode: result.mode, status: result.status };
}

/** Read a UTF-8 file or fail with the v2 usage exit. */
export function readFileOrFail(
  file: string,
  ctx: { json?: boolean; command: string },
): Buffer {
  try {
    return readFileSync(file);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      usageFail(`file not found: ${file}`, ctx);
    }
    fail(`cannot read ${file}: ${String(err)}`, {
      json: ctx.json,
      command: ctx.command,
      code: "ERROR",
      exitCode: EXIT.GENERAL,
    });
  }
}

/** The --socket override flag shared by every gateway leaf command. */
export function addSocketOption(cmd: Command): Command {
  return cmd.option(
    "--socket <path>",
    "Control socket override (default: runtime discovery)",
  );
}

/** Read globals off a leaf command action. */
export function globalsOf(command: Command): GlobalOpts {
  return readGlobalOpts(command);
}

export function fileExists(p: string): boolean {
  return existsSync(p);
}
