/**
 * @latticeag/gateway-daemon — Gateway v2 daemon package.
 *
 * `src/store/**` is the durable storage layer; `src/lock.ts`, `src/net/**`,
 * `src/rpc/**`, `src/runtime.ts`, and `src/daemon.ts` implement the Gateway
 * v2 protocol server on top of it (§1.2 lock, §3.1 dispatch pipeline,
 * §4.3 peer proofs, §6 bridge/SSE, §1.3 lifecycle). `src/adapters/**`
 * adapts the store to the core v2 port graph; `src/wiring.ts` assembles
 * the full service aggregate; `src/supervisor.ts` owns daemon-spawned
 * product processes.
 */
import { dirname, resolve } from "node:path";
import {
  GatewayDaemon,
  type GatewayDaemonOptions,
  type StartOutcome,
} from "./daemon.js";

export * from "./store/errors.js";
export * from "./store/util.js";
export * from "./store/layout.js";
export * from "./store/objects.js";
export * from "./store/journal.js";
export * from "./store/lanes.js";
export * from "./store/registry.js";
export * from "./store/outbox.js";
export * from "./store/recovery.js";
export * from "./store/store.js";

// ── daemon protocol server ───────────────────────────────────────────────
export * from "./lock.js";
export * from "./net/strict-json.js";
export * from "./net/http-util.js";
export * from "./net/socket-server.js";
export * from "./net/sse.js";
export * from "./net/bridge.js";
export * from "./rpc/auth.js";
export * from "./rpc/dispatch.js";
export * from "./runtime.js";
export * from "./daemon.js";
export * from "./adapters/store-ports.js";
export * from "./adapters/bridge-state.js";
export * from "./adapters/receipt-writer.js";
export * from "./supervisor.js";
export * from "./wiring.js";

// ── the daemon entrypoint (consumed by the CLI's --foreground path) ────

/** CLI `gateway start --foreground` options (spec §6.2). */
export interface StartGatewayDaemonOptions {
  /** Path to latticeag.json — its directory is the config dir. */
  config_path?: string;
  /** Alternative to config_path: the directory containing latticeag.json. */
  config_dir?: string;
  /** Pre-parsed v2 config document (skips the load). */
  config?: unknown;
  /** UI/bridge overrides from CLI flags. */
  ui?: { enabled?: boolean; port?: number };
  /** Override the unix control socket path. */
  socket_path?: string;
  /** Install SIGTERM/SIGINT handlers (default true in foreground). */
  signals?: boolean;
}

export interface GatewayDaemonHandle {
  /** The daemon object (state `READY` on kind "started"). */
  daemon: GatewayDaemon;
  /** How start resolved — "running" means another instance holds the lock. */
  outcome: StartOutcome;
  /** Resolves when the daemon reaches STOPPED. */
  stopped: Promise<void>;
  /** Stop the daemon (drain ≤ grace ms). */
  stop(graceMs?: number): Promise<void>;
}

/**
 * Start the Gateway v2 daemon in-process. With `signals` enabled (the
 * default) SIGTERM/SIGINT trigger the §1.3 stop; the returned handle's
 * `stopped` resolves at STOPPED so a foreground CLI can await it.
 */
export async function startGatewayDaemon(
  opts: StartGatewayDaemonOptions = {},
): Promise<GatewayDaemonHandle> {
  const configDir = resolve(
    opts.config_dir ??
      (opts.config_path !== undefined ? dirname(opts.config_path) : "."),
  );
  const daemon = new GatewayDaemon();
  const daemonOpts: GatewayDaemonOptions = {
    configDir,
    signals: opts.signals ?? true,
  };
  if (opts.config !== undefined) daemonOpts.config = opts.config;
  if (opts.ui?.enabled !== undefined) daemonOpts.bridge = opts.ui.enabled;
  if (opts.ui?.port !== undefined) daemonOpts.bridgePort = opts.ui.port;
  if (opts.socket_path !== undefined) daemonOpts.socketPath = opts.socket_path;
  const outcome = await daemon.start(daemonOpts);
  let resolveStopped: () => void = () => {};
  const stopped = new Promise<void>((res) => {
    resolveStopped = res;
  });
  const poll = setInterval(() => {
    if (daemon.state === "STOPPED") {
      clearInterval(poll);
      resolveStopped();
    }
  }, 250);
  poll.unref();
  return {
    daemon,
    outcome,
    stopped,
    stop: (graceMs?: number) => daemon.stop(graceMs),
  };
}

/** Back-compat alias for earlier CLI builds. */
export const startDaemon = startGatewayDaemon;
