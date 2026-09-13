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
  SessionStore,
  type PeerTokenStore,
  type SessionRole,
  type TransportCredentials,
} from "./rpc/auth.js";
import {
  AuditReceiptWriter,
  Metrics,
  RegistryIdempotency,
  SseSubscriptions,
  StoreSseSource,
  loadOrCreateAuditKey,
  nextSessionEpoch,
  readEndpoints,
  removeEndpoints,
  writeEndpoints,
  type DaemonState,
  type EndpointsFile,
} from "./runtime.js";
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
  /** Peer token store; defaults to an empty in-memory store. */
  peers?: PeerTokenStore;
  /** Product supervisor; absent ⇒ no daemon-owned products. */
  supervisor?: ProductSupervisor;
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
  private readonly sessions = new SessionStore();
  private peers: PeerTokenStore = new InMemoryPeerTokenStore();
  private receipts: AuditReceiptWriter | null = null;
  private readonly metrics = new Metrics();
  private readonly sseSubs = new SseSubscriptions();
  private sseSource: StoreSseSource | null = null;
  private supervisor: ProductSupervisor | null = null;
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

  /** Session store (tests reach in to create bootstraps/sessions). */
  get sessionStore(): SessionStore {
    return this.sessions;
  }

  /** The SSE subscription registry (tests/events service populate it). */
  get subscriptions(): SseSubscriptions {
    return this.sseSubs;
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
    this.supervisor = opts.supervisor ?? null;
    if (opts.peers !== undefined) this.peers = opts.peers;
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

      // 4. Derived state: session epoch, audit chain head, receipt writer.
      this.epoch = nextSessionEpoch(this.store);
      const auditKey = await loadOrCreateAuditKey(join(runtimeDir, "keys"));
      this.receipts = new AuditReceiptWriter(this.store, auditKey, {
        workspace: this.workspace,
        stream: "audit",
        partition: "audit",
        source: this.instance,
      });
      await this.receipts.resume();
      this.sseSource = new StoreSseSource(this.store);

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
          sse: { registry: this.sseSubs, source: this.sseSource! },
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
          sessions: this.sessions,
        });
        this.bridges.push(v4);
        if (this.config.gateway.ui.ipv6) {
          this.bridges.push(
            await createBridgeListener("::1", v4.port, {
              ...mk(),
              sessions: this.sessions,
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
      services: { ...this.builtInServices(), ...this.extraServices },
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

  private builtInServices(): Partial<GatewayServices> {
    return {
      daemon: this.daemonService(),
      config: this.configService(),
      ui: this.uiService(),
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
        peers: 0,
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
    const raw = this.store?.kv.get("config_revision");
    const n = raw !== null && raw !== undefined ? Number(raw) : this.configRevision;
    return Number.isInteger(n) && n > 0 ? n : this.configRevision;
  }

  private readConfigDocument(): unknown {
    const raw = this.store?.kv.get("config_document");
    if (raw === null || raw === undefined) return this.config;
    try {
      return JSON.parse(raw);
    } catch {
      return this.config;
    }
  }

  private configService(): GatewayServices["config"] {
    return {
      get: async () => ({
        document: this.readConfigDocument() as JsonObject,
        revision: String(this.readConfigRevision()),
      }),
      validate: async (params) => {
        const p = params as { document?: unknown };
        const r = validateConfigV2Semantics(p.document);
        return { valid: r.valid, errors: r.errors as unknown as Json[] };
      },
      apply: async (params) => {
        const p = params as {
          document?: unknown;
          expected_revision?: unknown;
        };
        const current = this.readConfigRevision();
        if (
          p.expected_revision !== undefined &&
          String(p.expected_revision) !== String(current)
        ) {
          throw new RpcError("REVISION_CONFLICT", "config revision mismatch", {
            field: "expected_revision",
          });
        }
        const r = validateConfigV2Semantics(p.document);
        if (!r.valid) {
          throw new RpcError(
            "SCHEMA_INVALID",
            r.errors.map((e) => `${e.path}: ${e.message}`).join("; "),
            { field: "document" },
          );
        }
        const next = current + 1;
        this.store?.kv.set("config_document", JSON.stringify(p.document));
        this.store?.kv.set("config_revision", String(next));
        this.configRevision = next;
        this.config = p.document as LatticeagConfigV2;
        return { revision: String(next), restart_required: false };
      },
    };
  }

  private uiService(): GatewayServices["ui"] {
    return {
      sessionCreate: async (params) => {
        const p = params as { role?: unknown };
        if (p.role !== "viewer" && p.role !== "operator") {
          throw new RpcError("SCHEMA_INVALID", "role must be viewer|operator", {
            field: "role",
          });
        }
        const b = this.sessions.createBootstrap(p.role as SessionRole);
        const port = this.endpoint?.ui_url
          ? new URL(this.endpoint.ui_url).port
          : String(this.config?.gateway.ui.port ?? 9848);
        return {
          bootstrap: b.bootstrap,
          url: `http://127.0.0.1:${port}/#bootstrap=${b.bootstrap}`,
          expires_ms: b.expires_ms,
        };
      },
      sessionExchange: async (params) => {
        const p = params as { bootstrap?: unknown };
        if (typeof p.bootstrap !== "string") {
          throw new RpcError(
            "SCHEMA_INVALID",
            "bootstrap must be a token string",
            { field: "bootstrap" },
          );
        }
        const session = this.sessions.exchange(p.bootstrap);
        if (session === null) {
          throw new RpcError(
            "AUTH_REQUIRED",
            "bootstrap is unknown, used, or expired",
          );
        }
        return {
          session: session.id,
          csrf: session.csrf,
          role: session.role,
          expires_ms: session.absolute_expires_ms,
        };
      },
      sessionRevoke: async (params) => {
        const p = params as { session?: unknown };
        if (typeof p.session !== "string") {
          throw new RpcError("SCHEMA_INVALID", "session must be a string", {
            field: "session",
          });
        }
        this.sessions.revoke(p.session);
        return { session: p.session, state: "REVOKED" as const };
      },
    };
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
    // Supervisor: daemon-owned products only (SIGTERM→SIGKILL 5 s).
    if (this.supervisor !== null) {
      await this.supervisor.shutdownAll(SUPERVISOR_KILL_MS).catch(() => {});
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
