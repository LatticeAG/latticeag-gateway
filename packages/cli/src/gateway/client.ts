/**
 * Gateway v2 control client (spec §3.1, §6.2).
 *
 * Speaks HTTP/1.1 `POST /v2/rpc` over the owner-only unix socket. This
 * module is Node >=20.19 import-clean: it uses only node:http/node:fs and
 * the pure v2 protocol layer from @latticeag/core — never the daemon
 * package — so the v1 command path can import it unconditionally.
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { request } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { v2 } from "@latticeag/core";
import {
  discoverConfig,
  readConfigFile,
  type LatticeagConfigV2,
} from "@latticeag/config";

const { newControlId } = v2.crypto;
const { exitForError, ERROR_CODES } = v2.protocol;

export type ErrorCode = v2.protocol.ErrorCode;

/** CLI-local code for a daemon that cannot be reached or started. */
export const CONTROL_UNAVAILABLE = "RUNTIME_UNAVAILABLE" as const;

/**
 * Transport/connect failure: socket absent, refused, or timed out. Carries
 * the CLI-local RUNTIME_UNAVAILABLE code (not a wire registry code — the
 * daemon was never reached, so no Failure envelope exists).
 */
export class ControlUnavailableError extends Error {
  readonly code = CONTROL_UNAVAILABLE;
  readonly retryable = true;
  constructor(
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "ControlUnavailableError";
  }
}

/** A wire-level Failure envelope (spec §3.1): closed registry error code. */
export class ControlRequestError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly field: string | null;
  constructor(code: string, message: string, retryable: boolean, field: string | null) {
    super(message);
    this.name = "ControlRequestError";
    this.code = code;
    this.retryable = retryable;
    this.field = field;
  }
}

export interface ControlClientOptions {
  /** Absolute unix socket path (already discovered). */
  socketPath: string;
  /** Workspace id bound into every request envelope. */
  workspace: string;
  /** Per-request connect/response budget, default 1500 ms. */
  timeoutMs?: number;
}

export interface ControlClient {
  readonly socketPath: string;
  readonly workspace: string;
  call<T = unknown>(method: string, params: unknown): Promise<T>;
}

function postRpc(
  socketPath: string,
  body: string,
  timeoutMs: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath,
        method: "POST",
        path: "/v2/rpc",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          connection: "close",
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        res.on("error", reject);
      },
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(
        new ControlUnavailableError(
          `control socket timed out after ${timeoutMs} ms: ${socketPath}`,
        ),
      );
    });
    req.on("error", (err: NodeJS.ErrnoException) => {
      reject(
        new ControlUnavailableError(
          `control socket unreachable: ${socketPath} (${err.code ?? err.message})`,
          { cause: err },
        ),
      );
    });
    req.end(body);
  });
}

/** Create a §3.1 control client bound to an already-discovered socket. */
export function controlClient(opts: ControlClientOptions): ControlClient {
  const timeoutMs = opts.timeoutMs ?? 1500;
  return {
    socketPath: opts.socketPath,
    workspace: opts.workspace,
    async call<T>(method: string, params: unknown): Promise<T> {
      const envelope = {
        v: 2,
        id: newControlId(),
        workspace: opts.workspace,
        method,
        params: (params ?? {}) as v2.protocol.Json,
      };
      const text = await postRpc(
        opts.socketPath,
        JSON.stringify(envelope),
        timeoutMs,
      );
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new ControlRequestError(
          "JSON_INVALID",
          `control response was not JSON: ${text.slice(0, 200)}`,
          false,
          null,
        );
      }
      const resp = parsed as Partial<v2.protocol.Response>;
      if (resp.ok === true) {
        return (resp as v2.protocol.Success).result as T;
      }
      if (resp.ok === false && resp.error && typeof resp.error === "object") {
        const err = resp.error as {
          code?: unknown;
          retryable?: unknown;
          field?: unknown;
        };
        const code = typeof err.code === "string" ? err.code : "METHOD_UNKNOWN";
        throw new ControlRequestError(
          code,
          `control call ${method} failed: ${code}`,
          err.retryable === true,
          typeof err.field === "string" ? err.field : null,
        );
      }
      throw new ControlRequestError(
        "SCHEMA_INVALID",
        `control response malformed for ${method}`,
        false,
        null,
      );
    },
  };
}

/**
 * Resolve the actual socket path inside a runtime directory. A daemon that
 * had to replace a stale path records the live endpoint in
 * `endpoints.json`; fall back to `control.sock`.
 */
function socketFromEndpoints(runtimeDir: string): string {
  const endpointsPath = path.join(runtimeDir, "endpoints.json");
  try {
    const raw = JSON.parse(readFileSync(endpointsPath, "utf8")) as Record<
      string,
      unknown
    >;
    for (const key of ["control", "control_socket", "socket"]) {
      const value = raw[key];
      if (typeof value === "string" && value.length > 0) {
        return path.isAbsolute(value) ? value : path.join(runtimeDir, value);
      }
    }
  } catch {
    // no endpoints file (or malformed): fall back to the canonical name
  }
  return path.join(runtimeDir, "control.sock");
}

export interface DiscoveredControl {
  socketPath: string;
  runtimeDir: string;
  workspace: string;
  instance: string;
}

/**
 * Socket discovery precedence (spec §1.2/§6.2):
 *   explicit flag/env → $XDG_RUNTIME_DIR/latticeag/<instance>/ (with
 *   endpoints.json override) → <configDir>/.latticeag/runtime/control.sock.
 */
export function discoverControl(opts: {
  socket?: string;
  configDir: string;
  workspace: string;
  instance: string;
}): DiscoveredControl {
  const explicit = opts.socket ?? process.env.LATTICEAG_CONTROL_SOCKET;
  const xdg = process.env.XDG_RUNTIME_DIR;
  const runtimeDir =
    xdg && xdg.length > 0
      ? path.join(xdg, "latticeag", opts.instance)
      : path.join(opts.configDir, ".latticeag", "runtime");
  const socketPath = explicit
    ? path.resolve(explicit)
    : socketFromEndpoints(runtimeDir);
  return {
    socketPath,
    runtimeDir,
    workspace: opts.workspace,
    instance: opts.instance,
  };
}

export interface GatewayIdentity {
  workspace: string;
  instance: string;
  configDir: string;
  configPath: string | null;
  config: LatticeagConfigV2 | null;
  /** gateway.autostart; absent config defaults to on-demand. */
  autostart: "on-demand" | "never";
}

/**
 * Resolve workspace/instance/config dir for control discovery. A v2 config
 * supplies the real ids; a v1 or missing config yields defaults — the
 * socket still resolves so commands report a clean unavailable, never a
 * crash.
 */
export function gatewayIdentity(cwd = process.cwd()): GatewayIdentity {
  const found = discoverConfig(cwd);
  if (!found) {
    return {
      workspace: "default",
      instance: "default",
      configDir: path.resolve(cwd),
      configPath: null,
      config: null,
      autostart: "on-demand",
    };
  }
  const configDir = path.dirname(found.path);
  try {
    const loaded = readConfigFile(found.path);
    if (loaded.version === 2) {
      return {
        workspace: loaded.config.gateway.workspace_id,
        instance: loaded.config.gateway.instance_id,
        configDir,
        configPath: found.path,
        config: loaded.config,
        autostart: loaded.config.gateway.autostart,
      };
    }
  } catch {
    // unreadable/migrating config: still resolve a sane endpoint
  }
  return {
    workspace: "default",
    instance: "default",
    configDir,
    configPath: found.path,
    config: null,
    autostart: "on-demand",
  };
}

/**
 * One-call client resolution used by `run --daemon`: identity → discovery
 * → bound client. Pure node + config code; safe on the v1 path.
 */
export function resolveRunClient(opts: {
  socket?: string;
  cwd?: string;
}): { client: ControlClient; identity: GatewayIdentity; socketPath: string } {
  const identity = gatewayIdentity(opts.cwd ?? process.cwd());
  const discovered = discoverControl({
    socket: opts.socket,
    configDir: identity.configDir,
    workspace: identity.workspace,
    instance: identity.instance,
  });
  return {
    client: controlClient({
      socketPath: discovered.socketPath,
      workspace: discovered.workspace,
    }),
    identity,
    socketPath: discovered.socketPath,
  };
}

/** Path of the installed bin entry used when respawning this CLI. */
export function cliBinPath(): string {
  // dist/gateway/client.js → dist/bin.js; under tsx (src/gateway/client.ts)
  // the sibling bin.js does not exist, so fall back to argv[1].
  const sibling = fileURLToPath(new URL("../bin.js", import.meta.url));
  if (existsSync(sibling)) {
    return sibling;
  }
  return process.argv[1] ?? sibling;
}

/**
 * Ensure a daemon answers `daemon.status`, starting one on demand.
 *
 * Order (spec §1.3): try the socket; if unreachable and autostart is
 * on-demand, spawn a detached `gateway start --foreground` of this same bin
 * and poll until READY/DEGRADED or the budget expires. Never kills an
 * existing occupant and never falls back when the caller required a daemon.
 */
export async function ensureDaemon(opts: {
  client: ControlClient;
  /** Connect+start budget; run uses 1500 ms (spec §1.3). */
  budgetMs?: number;
  /** Autostart allowed (config gateway.autostart === "on-demand"). */
  autostart?: boolean;
  /** Poll interval, default 100 ms. */
  pollMs?: number;
  /** Test seam: replace the detached spawn. */
  spawnDaemon?: () => void;
}): Promise<{
  mode: "connected" | "started" | "unavailable";
  status?: v2.protocol.DaemonStatusResult;
}> {
  const budget = opts.budgetMs ?? 1500;
  const pollMs = opts.pollMs ?? 100;
  const deadline = Date.now() + budget;

  const probe = async (): Promise<
    v2.protocol.DaemonStatusResult | "reachable" | null
  > => {
    try {
      return await opts.client.call<v2.protocol.DaemonStatusResult>(
        "daemon.status",
        {},
      );
    } catch (err) {
      if (err instanceof ControlUnavailableError) {
        return null;
      }
      if (err instanceof ControlRequestError) {
        // A wire-level answer — even an error — proves the daemon is up.
        return "reachable";
      }
      throw err;
    }
  };

  const first = await probe();
  if (first === "reachable") {
    return { mode: "connected" };
  }
  if (first) {
    return { mode: "connected", status: first };
  }
  if (opts.autostart === false) {
    return { mode: "unavailable" };
  }

  (opts.spawnDaemon ?? defaultSpawnDaemon)();
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, pollMs));
    const status = await probe();
    if (status === "reachable") {
      return { mode: "started" };
    }
    if (status && (status.state === "READY" || status.state === "DEGRADED")) {
      return { mode: "started", status };
    }
    // Daemon absent or answering but not READY yet — keep polling.
  }
  return { mode: "unavailable" };
}

function defaultSpawnDaemon(): void {
  const child = spawn(
    process.execPath,
    [cliBinPath(), "gateway", "start", "--foreground"],
    {
      detached: true,
      stdio: "ignore",
      env: process.env,
    },
  );
  child.unref();
}

/** True when `code` is a closed §3.1 registry code with an exit mapping. */
export function isRegistryErrorCode(code: string): code is v2.protocol.RegistryErrorCode {
  return (ERROR_CODES as readonly string[]).includes(code);
}

/**
 * Exit code for a control-layer failure. Registry codes map through
 * exitForError (§6.1); an unreachable daemon is RUNTIME_UNAVAILABLE → 11
 * (busy/service-manager-unavailable row — the §6.2 status row assigns 11
 * to absent/unreachable).
 */
export function exitForControlError(err: unknown): { code: string; exit: number } {
  if (err instanceof ControlUnavailableError) {
    return { code: CONTROL_UNAVAILABLE, exit: v2.protocol.EXIT.BUSY };
  }
  if (err instanceof ControlRequestError) {
    if (isRegistryErrorCode(err.code)) {
      return { code: err.code, exit: exitForError(err.code) };
    }
    return { code: err.code, exit: v2.protocol.EXIT.GENERAL };
  }
  return { code: "ERROR", exit: v2.protocol.EXIT.GENERAL };
}
