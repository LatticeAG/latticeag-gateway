/**
 * `GatewayDaemon` — the Gateway v2 daemon lifecycle (spec §1.3, §8, §11).
 *
 * Startup order (each step aborts cleanly on failure):
 *   1. validate the v2 config document (schema + §8 semantics);
 *   2. acquire the exclusive instance lock (`flock`/`O_EXCL` fallback);
 *   3. open the durable store — journal chain verify + lane recovery +
 *      registry replay happen inside `GatewayStore.open`;
 *   4. rebuild derived state (session epoch, audit-lane chain head);
 *   5. bind the unix control socket, then the loopback bridge;
 *   6. publish `endpoints.json` (READY marker) — only now is the daemon
 *      discoverable.
 *
 * A contended lock is not an error: start returns `{kind:"running"}` with
 * the incumbent's `endpoints.json` — the CLI's contract for idempotent
 * `gateway start`.
 *
 * Stop (§1.3): READY → DRAINING (new mutations rejected, in-flight RPCs
 * drain ≤ min(grace,10 s)) → listeners close → supervisor shutdown
 * (SIGTERM→SIGKILL after 5 s for daemon-owned products; CLI-owned runs are
 * never killed) → store close → endpoints.json removed → lock released →
 * STOPPED.
 */
import { join, resolve } from "node:path";
import {
  loadConfigV2,
  validateConfigV2Semantics,
  type LatticeagConfigV2,
} from "@latticeag/config";
import { GatewayStore } from "./store/store.js";
import {
  acquireLock,
  readBootId,
  readProcessStart,
  type LockAcquireResult,
  type LockEndpoint,
} from "./lock.js";

/** A held instance lock (the `held:true` variant of LockAcquireResult). */
type HeldLock = Extract<LockAcquireResult, { held: true }>;
import {
  createControlServer,
  resolveControlSocketPath,
  type ControlServer,
} from "./net/socket-server.js";
import {
  createBridgeListener,
  defaultStaticDir,
  type BridgeHandle,
  type BridgeOptions,
} from "./net/bridge.js";
import {
  dispatchRequest,
  type DispatchContext,
  type DispatchOutcome,
} from "./rpc/dispatch.js";
import {
  InMemoryPeerTokenStore,
  type PeerTokenStore,
  type TransportCredentials,
} from "./rpc/auth.js";
import {
  Metrics,
  RegistryIdempotency,
  loadOrCreateAuditKey,
  nextSessionEpoch,
  readEndpoints,
  removeEndpoints,
  writeEndpoints,
  type DaemonState,
  type EndpointsFile,
} from "./runtime.js";
import {
  DurableBridgeSessions,
  DurableSseRegistry,
  DurableSseSource,
} from "./adapters/bridge-state.js";
import { CoreReceiptWriter } from "./adapters/receipt-writer.js";
import { ProductProcessSupervisor } from "./supervisor.js";
import { wireServices, type WiredRuntime } from "./wiring.js";
import type { ServiceContext } from "../../core/dist/v2/platform/ports.js";
import type { Principal } from "../../core/dist/v2/protocol/services.js";
import {
  RpcError,
  type GatewayServices,
  type Json,
  type JsonObject,
} from "./core-v2.js";

// ── options / results ────────────────────────────────────────────────────

/** Product supervisor surface (§1.3): daemon-owned products only. */
export interface ProductSupervisor {
  /** SIGTERM daemon-owned products; SIGKILL stragglers after `ms`. */
  shutdownAll(graceMs: number): Promise<void>;
  count(): number;
}

export interface GatewayDaemonOptions {
  /** Directory containing latticeag.json (or passed `config`). */
  configDir: string;
  /** Pre-parsed v2 config document; when absent it is loaded+validated. */
  config?: unknown;
  /** Extra/partial service implementations merged over the built-ins. */
  services?: Partial<GatewayServices>;
  /**
   * Peer token store override (tests); defaults to the durable
   * registry-backed store built from the opened `GatewayStore`.
   */
  peers?: PeerTokenStore;
  /** Product supervisor; absent ⇒ the default process supervisor. */
  supervisor?: ProductProcessSupervisor;
  /** Override the bridge port (0 → ephemeral); defaults to config.ui.port. */
  bridgePort?: number;
  /** Force-enable/disable the bridge regardless of config.ui.enabled. */
  bridge?: boolean;
  /** Static UI root; defaults to packages/gateway-web/dist when present. */
  staticDir?: string | null;
  /** Install SIGTERM/SIGINT handlers that call stop() (foreground CLI). */
  signals?: boolean;
  /** Override the unix socket path (tests); default §1.2 resolution. */
  socketPath?: string;
}

export type StartOutcome =
  | { kind: "started"; endpoint: EndpointsFile }
  | { kind: "running"; endpoint: LockEndpoint | EndpointsFile | null };

export class ConfigValidationError extends Error {
  readonly code = "CONFIG_INVALID" as const;
  readonly issues: { code: string; path: string; message: string }[];
  constructor(issues: { code: string; path: string; message: string }[]) {
    super(
      `invalid v2 config: ${issues.map((i) => `${i.path}: ${i.message}`).join("; ")}`,
    );
    this.name = "ConfigValidationError";
    this.issues = issues;
  }
}

const STOP_GRACE_CAP_MS = 10_000;
const SUPERVISOR_KILL_MS = 5_000;
/** Profiles advertised by daemon.hello (spec §1.4). */
const HELLO_PROFILES = [
  "@latticeag/events@0.1.0",
  "proof-evidence/1",
  "proof-bundle/1",
] as const;
const HELLO_INTERFACES = "interfaces/1";

export class GatewayDaemon {
  private state_: DaemonState = "STARTING";
  private lock: HeldLock | null = null;
  private store: GatewayStore | null = null;
  private control: ControlServer | null = null;
  private bridges: BridgeHandle[] = [];
  private config: LatticeagConfigV2 | null = null;
  private configDir = "";
  private configRevision = 1;
  private epoch = "";
  /** Memory-only CSRF mirror: session-token-hash → csrf (spec §3.3). */
  private readonly csrfMirror = new Map<string, string>();
  private bridgeSessions: DurableBridgeSessions | null = null;
  private peers: PeerTokenStore = new InMemoryPeerTokenStore();
  private receipts: CoreReceiptWriter | null = null;
  private readonly metrics = new Metrics();
  private sseRegistry: DurableSseRegistry | null = null;
  private sseSource: DurableSseSource | null = null;
  private runtime: WiredRuntime | null = null;
  private supervisor: ProductProcessSupervisor | null = null;
  private extraServices: Partial<GatewayServices> = {};
  private inflight = 0;
  private inflightWaiters: Array<() => void> = [];
  private stopping = false;
  private signalHandlers: Array<() => void> = [];

  /** The workspace this daemon serves — `gateway.workspace_id`. */
  get workspace(): string {
    return this.config?.gateway.workspace_id ?? "default";
  }

  get instance(): string {
    return this.config?.gateway.instance_id ?? "default";
  }

  get state(): DaemonState {
    return this.state_;
  }

  /** Resolved endpoint info after a successful start (null before). */
  endpoint: EndpointsFile | null = null;

  /** The wired services aggregate (null until the store is open). */
  get servicesRuntime(): WiredRuntime | null {
    return this.runtime;
  }

  // ── start ────────────────────────────────────────────────────────────

  async start(opts: GatewayDaemonOptions): Promise<StartOutcome> {
    // 1. Load + validate the v2 config document.
    const raw =
      opts.config !== undefined
        ? opts.config
        : loadConfigV2(opts.configDir).config;
    const checked = validateConfigV2Semantics(raw);
    if (!checked.valid) throw new ConfigValidationError(checked.errors);
    this.config = raw as LatticeagConfigV2;
    this.configDir = opts.configDir;
    this.extraServices = opts.services ?? {};

    const stateRoot = resolve(this.configDir, this.config.storage.root);
    const runtimeDir = join(stateRoot, "runtime");

    // 2. Exclusive instance lock — a contender returns the incumbent
    //    endpoint instead of failing.
    const lock = await acquireLock(stateRoot, this.instance);
    if (!lock.held) {
      const endpoint = lock.endpoint ?? (await readEndpoints(runtimeDir));
      return { kind: "running", endpoint };
    }
    this.lock = lock;

    try {
      // 3. Store open: journal chain verify + lane recovery + registry
      //    replay all happen inside `GatewayStore.open`.
      this.store = await GatewayStore.open(stateRoot, {
        instance: this.instance,
      });

      // 4. Derived state + the full service wiring. The epoch bumps once
      //    per boot and stamps sessions/bootstraps/peer grants so none
      //    survive a restart.
      const auditKey = await loadOrCreateAuditKey(join(runtimeDir, "keys"));
      this.epoch = nextSessionEpoch(this.store);
      this.supervisor = opts.supervisor ?? new ProductProcessSupervisor();
      this.runtime = wireServices({
        store: this.store,
        config: this.config,
        configDir: this.configDir,
        stateRoot,
        auditKey,
        epoch: this.epoch,
        supervisor: this.supervisor,
        uiEndpoint: () => this.endpoint?.ui_url ?? null,
        onStop: (graceMs) => {
          setTimeout(() => void this.stop(graceMs), 25).unref();
        },
      });
      if (opts.peers !== undefined) this.peers = opts.peers;
      else this.peers = this.runtime.ports.peerTokens;
      this.receipts = new CoreReceiptWriter(this.store, {
        receiptWorkspace: this.runtime.platformPorts.receiptWorkspace,
        auditSource: this.runtime.platformPorts.auditSource,
        auditKey: this.runtime.platformPorts.auditKey,
        newId: this.runtime.platformPorts.newId,
        store: this.runtime.platformPorts.store,
      });
      this.sseRegistry = new DurableSseRegistry(this.store.registry);
      this.sseSource = new DurableSseSource(this.store);
      this.bridgeSessions = new DurableBridgeSessions({
        registry: this.store.registry,
        epoch: this.epoch,
        csrf: this.csrfMirror,
      });
      // Replay-based crash recovery for product generations (daemon-owned
      // children from a prior boot get their liveness re-probed; dead
      // ones transition honestly).
      await this.runtime.product.engine
        .recoverAfterCrash()
        .catch(() => {});

      // 5a. Control socket (§1.2).
      const socketPath =
        opts.socketPath ??
        (await resolveControlSocketPath(stateRoot, this.instance)).path;
      this.control = await createControlServer({
        socketPath,
        holdsLock: true,
        onRpc: async ({ body }) =>
          this.dispatch({
            body,
            transport: "socket",
            credentials: { kind: "local" },
          }),
        healthz: () => ({ alive: this.state_ !== "STOPPED" }),
        metrics: () => this.metrics.render(this.state_),
      });

      // 5b. Loopback bridge (§6) when config.ui.enabled && !remote.
      const uiEnabled =
        opts.bridge ??
        (this.config.gateway.ui.enabled && !this.config.gateway.ui.remote);
      let uiUrl: string | null = null;
      if (uiEnabled) {
        const port = opts.bridgePort ?? this.config.gateway.ui.port;
        const mk = (): Omit<BridgeOptions, "sessions"> => ({
          instance: this.instance,
          staticDir:
            opts.staticDir === undefined ? defaultStaticDir() : opts.staticDir,
          sse: { registry: this.sseRegistry!, source: this.sseSource! },
          onRpc: (body, creds) =>
            this.dispatch({ body, transport: "bridge", credentials: creds }),
          onHealth: () => ({
            ok: true,
            state: this.state_,
            instance: this.instance,
          }),
          onReady: () =>
            this.state_ === "READY"
              ? { ok: true, body: { ok: true, state: this.state_ } }
              : { ok: false, body: { ok: false, state: this.state_ } },
          onMetrics: () => this.metrics.render(this.state_),
        });
        const v4 = await createBridgeListener("127.0.0.1", port, {
          ...mk(),
          sessions: this.bridgeSessions!,
        });
        this.bridges.push(v4);
        if (this.config.gateway.ui.ipv6) {
          this.bridges.push(
            await createBridgeListener("::1", v4.port, {
              ...mk(),
              sessions: this.bridgeSessions!,
            }),
          );
        }
        uiUrl = `http://127.0.0.1:${v4.port}/`;
      }

      // 6. READY marker — endpoints.json is the discovery surface.
      this.endpoint = {
        pid: process.pid,
        instance: this.instance,
        boot_id: await readBootId(),
        process_start: await readProcessStart(process.pid),
        control_sock: this.control.path,
        ui_url: uiUrl,
      };
      await writeEndpoints(runtimeDir, this.endpoint);
      this.state_ = "READY";

      if (opts.signals === true) this.installSignalHandlers();
      return { kind: "started", endpoint: this.endpoint };
    } catch (e) {
      await this.teardown();
      throw e;
    }
  }

  private installSignalHandlers(): void {
    const onSig = (): void => {
      void this.stop();
    };
    process.on("SIGTERM", onSig);
    process.on("SIGINT", onSig);
    this.signalHandlers.push(() => {
      process.off("SIGTERM", onSig);
      process.off("SIGINT", onSig);
    });
  }

  // ── dispatch wiring ──────────────────────────────────────────────────

  private dispatch(input: {
    body: Buffer | unknown;
    transport: "socket" | "bridge";
    credentials: TransportCredentials;
  }): Promise<DispatchOutcome> {
    this.inflight += 1;
    const ctx: DispatchContext = {
      instance: this.instance,
      workspace: this.workspace,
      epoch: this.epoch,
      services: this.mergedServices(null),
      bindServices: ({ principal, requestId }) =>
        this.mergedServices({ principal, requestId }),
      peers: this.peers,
      receipts: this.receipts,
      idempotency:
        this.store !== null
          ? new RegistryIdempotency(this.store.registry)
          : null,
      draining: () => this.state_ === "DRAINING" || this.stopping,
      observe: (m, c) => this.metrics.recordRpc(m, c),
    };
    return dispatchRequest(ctx, input).finally(() => {
      this.inflight -= 1;
      if (this.inflight === 0) {
        for (const w of this.inflightWaiters.splice(0)) w();
      }
    });
  }

  // ── built-in services ────────────────────────────────────────────────

  /**
   * The full service map for one dispatch. The wired aggregate supplies
   * every domain; the daemon's own `daemon` group wins (its hello/status/
   * stop carry daemon-local truth the core service cannot know), and
   * `ui.sessionExchange` is wrapped to mirror the issued CSRF into the
   * memory-only map the bridge checks. `extraServices` overrides last —
   * the test seam.
   */
  private mergedServices(
    ctx: { principal: Principal; requestId: string } | null,
  ): Partial<GatewayServices> {
    const bound: Partial<GatewayServices> =
      this.runtime !== null
        ? this.runtime.bindServices(
            ctx !== null
              ? ({ principal: ctx.principal, requestId: ctx.requestId } as ServiceContext)
              : ({
                  principal: {
                    id: "local",
                    role: "local_operator",
                  } as Principal,
                } as ServiceContext),
          )
        : {};
    if (bound.ui !== undefined) {
      const inner = bound.ui;
      bound.ui = {
        ...inner,
        sessionExchange: async (params: { bootstrap: string }) => {
          const r = await inner.sessionExchange(params);
          this.bridgeSessions?.noteCsrf(r.session, r.csrf);
          return r;
        },
      };
    }
    if (bound.product !== undefined && ctx !== null && this.runtime !== null) {
      // Record which principal launched each lifecycle operation so the
      // durable operations projection carries the real actor, not "local".
      const product = bound.product;
      const runtime = this.runtime;
      const principal = ctx.principal.id;
      const wrapped = {} as Record<
        string,
        (params: unknown) => Promise<unknown>
      >;
      for (const [k, fn] of Object.entries(product)) {
        wrapped[k] = async (params: unknown) => {
          const r = await (fn as (p: unknown) => Promise<unknown>).call(
            product,
            params,
          );
          const op = (r as { operation?: unknown } | null)?.operation;
          if (typeof op === "string") runtime.noteOperationCaller(op, principal);
          return r;
        };
      }
      bound.product =
        wrapped as unknown as GatewayServices["product"];
    }
    return {
      ...bound,
      daemon: this.daemonService(),
      ...this.extraServices,
    };
  }

  private daemonService(): GatewayServices["daemon"] {
    return {
      hello: async (params) => {
        const p = params as { profiles?: unknown; interfaces?: unknown };
        if (p.interfaces !== HELLO_INTERFACES) {
          throw new RpcError(
            "SCHEMA_UNSUPPORTED",
            "interfaces must be interfaces/1",
            { field: "interfaces" },
          );
        }
        if (Array.isArray(p.profiles)) {
          for (const prof of p.profiles) {
            if (!(HELLO_PROFILES as readonly string[]).includes(prof as string)) {
              throw new RpcError(
                "SCHEMA_UNSUPPORTED",
                `unsupported required profile ${String(prof)}`,
                { field: "profiles" },
              );
            }
          }
        }
        return {
          protocol: "latticeag-gateway/2",
          profiles: [...HELLO_PROFILES],
          interfaces: HELLO_INTERFACES,
          mesh: { available: false, code: "CAP_ADAPTER_UNAVAILABLE" },
        };
      },
      status: async () => ({
        instance: this.instance,
        state: this.state_,
        config_revision: String(this.readConfigRevision()),
        products: this.supervisor?.count() ?? 0,
        peers: this.store?.registry.countPeers() ?? 0,
        ui: this.endpoint?.ui_url ?? null,
      }),
      stop: async (params) => {
        const p = params as { grace_ms?: unknown };
        let grace = STOP_GRACE_CAP_MS;
        if (p.grace_ms !== undefined) {
          if (
            typeof p.grace_ms !== "number" ||
            !Number.isInteger(p.grace_ms) ||
            p.grace_ms < 0 ||
            p.grace_ms > 30_000
          ) {
            throw new RpcError(
              "SCHEMA_INVALID",
              "grace_ms must be an integer 0..30000",
              { field: "grace_ms" },
            );
          }
          grace = p.grace_ms;
        }
        setTimeout(() => void this.stop(grace), 25).unref();
        return { state: "DRAINING" };
      },
    };
  }

  private readConfigRevision(): number {
    const raw =
      this.store?.registry.kvGet("config:revision") ??
      this.store?.kv.get("config_revision");
    const n = raw !== null && raw !== undefined ? Number(raw) : this.configRevision;
    return Number.isInteger(n) && n > 0 ? n : this.configRevision;
  }

  // ── stop / teardown ──────────────────────────────────────────────────

  /**
   * READY → DRAINING → STOPPED. `graceMs` bounds the in-flight drain; the
   * hard cap is 10 s regardless. Idempotent.
   */
  async stop(graceMs: number = STOP_GRACE_CAP_MS): Promise<void> {
    if (this.state_ === "STOPPED" || this.stopping) return;
    this.stopping = true;
    this.state_ = "DRAINING";

    // Drain in-flight RPCs up to min(grace, 10 s).
    const deadline = Date.now() + Math.min(graceMs, STOP_GRACE_CAP_MS);
    while (this.inflight > 0 && Date.now() < deadline) {
      await new Promise<void>((res) => {
        const t = setTimeout(res, Math.max(1, deadline - Date.now()));
        t.unref();
        this.inflightWaiters.push(() => {
          clearTimeout(t);
          res();
        });
      });
    }

    await this.teardown();
    this.state_ = "STOPPED";
  }

  private async teardown(): Promise<void> {
    // Listeners first — stop admissions before touching durable state.
    for (const b of this.bridges.splice(0)) {
      await b.close().catch(() => {});
    }
    if (this.control !== null) {
      await this.control.close().catch(() => {});
      this.control = null;
    }
    // Lifecycle engine: stops probes and daemon-owned children first so
    // nothing writes through a closing store.
    if (this.runtime !== null) {
      await this.runtime.product.engine.close().catch(() => {});
    }
    // Supervisor: daemon-owned products only (SIGTERM→SIGKILL 5 s).
    if (this.supervisor !== null) {
      await this.supervisor.shutdownAll(SUPERVISOR_KILL_MS).catch(() => {});
      this.supervisor = null;
    }
    if (this.store !== null) {
      await this.store.close().catch(() => {});
      this.store = null;
    }
    if (this.config !== null) {
      const runtimeDir = join(
        resolve(this.configDir, this.config.storage.root),
        "runtime",
      );
      await removeEndpoints(runtimeDir);
    }
    for (const off of this.signalHandlers.splice(0)) off();
    if (this.lock !== null) {
      await this.lock.release();
      this.lock = null;
    }
  }
}
