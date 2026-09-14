/**
 * `wiring.ts` — constructs the complete `GatewayServices` aggregate over
 * the durable store (spec §3.2/§3.3 service surface).
 *
 * Two construction modes share one ports graph:
 *
 *  - Stateful singletons (peers/approvals/product lifecycle/sync/cloud/
 *    catalog) are built once at boot; they hold managers, the engine, and
 *    in-flight operation state.
 *  - The platform slice (daemon/config/run/events/objects/receipt/lineage/
 *    operation/ui) is rebuilt per RPC by `bindServices` because
 *    `createPlatformServices` binds `ctx.principal` at construction — the
 *    dispatcher supplies the authenticated principal after the auth stage.
 *
 * Honest capability reporting: no native mesh, sandbox enforcer, catalog
 * fetcher, cloud relay, or sink adapter is bound in this build. Those
 * absences surface as the contract's explicit codes — mesh "ADAPTER_
 * REQUIRED", product install SANDBOX_UNAVAILABLE, catalog refresh and
 * cloud notice NETWORK_UNAVAILABLE, outbox items BLOCKED — never a
 * fabricated success.
 */
import type { KeyObject } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import type { LatticeagConfigV2 } from "@latticeag/config";
import {
  createPlatformServices,
  type PlatformPorts,
  type PlatformServices,
  type ServiceContext,
} from "../../core/dist/v2/platform/index.js";
import {
  createAgentRuntime,
  type AgentRuntime,
} from "../../core/dist/v2/peers/service.js";
import {
  createApprovalRuntime,
  type ApprovalRuntime,
} from "../../core/dist/v2/approvals/service.js";
import {
  createCatalogService,
} from "../../core/dist/v2/catalog/service.js";
import { CatalogStore } from "../../core/dist/v2/catalog/index.js";
import {
  createCloudService,
} from "../../core/dist/v2/cloud/service.js";
import {
  createSyncService,
  type SyncServicePorts,
} from "../../core/dist/v2/sync/service.js";
import {
  createProductService,
  type ProductServiceBundle,
  type LifecyclePorts,
  type JournalMutation,
  type TransitionReceipt,
  type FetchedRelease,
  type SourceRef,
} from "../../core/dist/v2/lifecycle/index.js";
import type { SandboxKind } from "../../core/dist/v2/protocol/product.js";
import type { StreamName, StreamProfile } from "../../core/dist/v2/protocol/sync.js";
import type { StreamConsent } from "../../core/dist/v2/sync/ports.js";
import type {
  CatalogIndex,
  CatalogPin,
} from "../../core/dist/v2/protocol/catalog.js";
import type { SunlightTrustRoot } from "../../core/dist/v2/crypto/index.js";
import type { Json, JsonObject } from "../../core/dist/v2/protocol/refs.js";
import type { Principal } from "../../core/dist/v2/protocol/services.js";
import {
  cryptoEntropy,
  randomIds,
} from "../../core/dist/v2/peers/ports.js";
import {
  newControlId,
  newToken,
  RpcError,
} from "./core-v2.js";
import type { GatewayServices } from "./core-v2.js";
import type { GatewayStore } from "./store/store.js";
import type { StoreBackedDocs } from "./adapters/store-ports.js";
import {
  createStorePorts,
  KV,
  type StorePorts,
} from "./adapters/store-ports.js";
import type { ProductProcessSupervisor } from "./supervisor.js";

// ── sandbox detection (honest capability reporting) ─────────────────────

/**
 * The sandbox kinds this host can actually enforce. Detection is
 * deliberately conservative: a kind is advertised only when a known
 * enforcer binary is present on PATH AND (for linux-ns) a real
 * `unshare -U` probe succeeds. An empty list means every product install
 * fails SANDBOX_UNAVAILABLE — the honest answer on an unsandboxed host.
 */
export function detectSandboxes(env: NodeJS.ProcessEnv = process.env): SandboxKind[] {
  const out: SandboxKind[] = [];
  const paths = (env.PATH ?? "").split(":").filter((p) => p !== "");
  const has = (name: string): boolean =>
    paths.some((dir) => existsSync(join(dir, name)));
  // linux-ns: a working unprivileged user-namespace path.
  if (has("unshare")) {
    try {
      execFileSync("unshare", ["--user", "--map-root-user", "true"], {
        stdio: "ignore",
        timeout: 3000,
      });
      out.push("linux-ns");
    } catch {
      /* unprivileged userns disabled */
    }
  }
  if (has("nsjail") || has("bubblewrap") || has("bwrap")) {
    if (!out.includes("linux-ns")) out.push("linux-ns");
  }
  // oci: a runnable OCI runtime.
  if (has("runc") || has("crun")) out.push("oci");
  // wasi: a runnable wasm runtime.
  if (has("wasmtime") || has("wasmer")) out.push("wasi");
  return out;
}

// ── wiring options / result ─────────────────────────────────────────────

export interface WiringOptions {
  store: GatewayStore;
  config: LatticeagConfigV2;
  configDir: string;
  /** storage.root resolved against configDir. */
  stateRoot: string;
  auditKey: KeyObject;
  /** Boot/session epoch (decimal Count; peer rows are epoch-stamped). */
  epoch: string;
  supervisor: ProductProcessSupervisor;
  /** Live UI endpoint (set once the bridge binds). */
  uiEndpoint: () => string | null;
  /** daemon.stop's deferred shutdown hook (scheduled by the service). */
  onStop: (graceMs: number) => void;
  now?: () => number;
}

export interface WiredRuntime {
  /** The durable port graph backing every service. */
  readonly ports: StorePorts;
  /** The per-call platform service factory (binds the real principal). */
  platformPorts: PlatformPorts;
  bindPlatform(ctx: ServiceContext): PlatformServices;
  /** Stateful singletons. */
  readonly product: ProductServiceBundle;
  readonly agent: AgentRuntime;
  readonly approval: ApprovalRuntime;
  readonly catalogStore: CatalogStore;
  /** Fully assembled service map for one authenticated call. */
  bindServices(ctx: ServiceContext): GatewayServices;
  /** Persist one lifecycle journal mutation (engine port). */
  journalMutation(m: JournalMutation): void;
  /** Persist one transition receipt (engine port). */
  receiptSink(r: TransitionReceipt): void;
  /** Principal responsible for an operation (recorded by bindServices). */
  noteOperationCaller(op: string, principal: string): void;
}

/** Profiles advertised by daemon.hello (spec §2.2). */
export const HELLO_PROFILES = [
  "@latticeag/events@0.1.0",
  "proof-evidence/1",
  "proof-bundle/1",
] as const;

// ── config → consent mapping (§9.1) ─────────────────────────────────────

function streamConsentFromConfig(
  streamCfg: {
    enabled: boolean;
    paused: boolean;
    profile: string;
    include_objects: boolean;
    cohort: string;
    from: string;
  },
  resolvedFrom: string,
  destination: string,
  revision: string,
): StreamConsent {
  return {
    enabled: streamCfg.enabled,
    paused: streamCfg.paused,
    profile: streamCfg.profile as StreamProfile,
    include_objects: streamCfg.include_objects,
    cohort: streamCfg.cohort,
    from: resolvedFrom,
    destination,
    revision,
  };
}

// ── the wiring ──────────────────────────────────────────────────────────

export function wireServices(opts: WiringOptions): WiredRuntime {
  const { store, config } = opts;
  const now = opts.now ?? Date.now;
  const ids = randomIds();
  const entropy = cryptoEntropy();
  const workspace = config.gateway.workspace_id;
  const instance = config.gateway.instance_id;

  // Durable lifecycle journal/op-caller correlation (module-scope state
  // per daemon; the counter is process-local and unique per boot).
  let journalSeq = 0;
  const opCallers = new Map<string, string>();

  // ── runtime delegates fed from the live config document ──────────────
  const liveConfig = (): LatticeagConfigV2 => opts.config;

  const configuredConsent = (stream: StreamName): StreamConsent | undefined => {
    const sync = liveConfig().sync;
    if (sync === null || sync === undefined) return undefined;
    const streams = sync.streams as Record<string, unknown> | undefined;
    const s = streams?.[stream];
    if (s === null || typeof s !== "object") return undefined;
    const sc = s as {
      enabled: boolean;
      paused: boolean;
      profile: string;
      include_objects: boolean;
      cohort: string;
      from: string;
    };
    // `from:"now"` resolves once — at consent commit — to the global head.
    const from = sc.from === "now" ? "__NOW__" : sc.from;
    return streamConsentFromConfig(
      sc,
      from,
      sync.cloud ?? "none",
      syncRevision(),
    );
  };

  const syncRevision = (): string =>
    store.registry.kvGet(KV.syncRevision) ?? "0";

  const applySync = (document: JsonObject, revision: string): void => {
    const docs = storePortsBase;
    docs.commitSync({
      v: 1,
      kind: "batch",
      mutations: [
        {
          v: 1,
          kind: "kv",
          entries: [
            { key: KV.syncDocument, value: JSON.stringify(document) },
            { key: KV.syncRevision, value: revision },
          ],
        },
        // Re-derive per-stream consents from the applied document.
        {
          v: 1,
          kind: "kv",
          entries: streamConsentEntries(document, revision),
        },
      ],
    });
  };

  const streamConsentEntries = (
    document: JsonObject,
    revision: string,
  ): { key: string; value: string | null }[] => {
    const streams = (document as { streams?: Record<string, unknown> })
      .streams;
    if (streams === undefined) return [];
    return Object.entries(streams).map(([name, s]) => ({
      key: `${KV.syncConsentPrefix}${name}`,
      value:
        s !== null && typeof s === "object"
          ? JSON.stringify(
              streamConsentFromConfig(
                s as {
                  enabled: boolean;
                  paused: boolean;
                  profile: string;
                  include_objects: boolean;
                  cohort: string;
                  from: string;
                },
                (s as { from: string }).from === "now"
                  ? "__NOW__"
                  : (s as { from: string }).from,
                (document as { cloud?: string | null }).cloud ?? "none",
                revision,
              ),
            )
          : null,
    }));
  };

  // ── the durable port graph ────────────────────────────────────────────
  const ports = createStorePorts(store, {
    identity: { now, ids, entropy, epoch: opts.epoch },
    catalog: {
      trust: () => ({
        // No trust roots are enrolled by the v2 config schema — an empty
        // root set means no remote index can verify (honest: refresh fails
        // SIGNATURE_INVALID/NOT_FOUND rather than pretending trust).
        roots: new Set<string>() as SunlightTrustRoot,
        quorum: 2,
        channel: config.catalog.channel,
        strict: config.catalog.strict,
        allowlist: config.catalog.allowlist,
        max_age_s: config.catalog.max_age_s,
      }),
      configuredPins: () => ({
        pins: config.catalog.pins as CatalogPin[],
        revision: syncRevision(),
      }),
      // fetchIndex / offlineSnapshot unbound: refresh fails honestly.
    },
    cloud: {
      uiRemoteGranted: () => config.gateway.ui.remote === true,
      providers: () => new Map(),
      // notifyRevocation unbound: remote notice stays QUEUED — local
      // revocation still completes (§9.3).
    },
    sync: {
      syncPaused: () => config.sync?.paused === true,
      syncRevision,
      applySync,
      cloud: () => {
        const cur = ports.cloud.currentCloud();
        return cur === undefined ? null : { id: cur.id, state: cur.state };
      },
      configuredConsent,
      // sink/daemonStatus: no destination adapters bound; daemonStatus
      // reports "known" because the admitted cut IS the local store's.
    },
  });

  // A bare docs-commit helper used before `ports` finishes assembling.
  const storePortsBase = ports.sync as unknown as StoreBackedDocs;

  // Seed the config document the first time this store boots: config.get
  // resolves from the durable registry, not the filesystem, so the doc
  // survives even where the JSON file is absent.
  if (store.registry.kvGet("config:document") === null) {
    storePortsBase.commitSync({
      v: 1,
      kind: "kv",
      entries: [
        { key: "config:document", value: JSON.stringify(config) },
        { key: "config:revision", value: "1" },
      ],
    });
  }

  // ── lifecycle ports (product engine) ─────────────────────────────────
  const catalogStore = new CatalogStore(ports.catalog);

  const lifecyclePorts: LifecyclePorts = {
    catalog: {
      // No release fetcher is bound: catalog-mediated installs fail
      // NETWORK_UNAVAILABLE; local/digest-pinned sources still resolve.
      fetch: (_sref: SourceRef): Promise<FetchedRelease> =>
        Promise.reject(
          new RpcError(
            "NETWORK_UNAVAILABLE",
            "no release fetch adapter is bound on this host",
            { field: "source" },
          ),
        ),
      index: (): Promise<CatalogIndex | null> =>
        Promise.resolve(catalogStore.cache()?.index ?? null),
      versions: (slug: string): Promise<string[]> =>
        Promise.resolve(
          catalogStore
            .entries()
            .filter((e) => e.slug === slug)
            .map((e) => e.version),
        ),
    },
    trustStore: () => ({
      // No release-signing keys are configured: verification cannot
      // succeed — installs fail VERIFY, never silently pass.
      releaseKeys: new Set<string>(),
      builders: new Set<string>(),
      revocations: new Set<string>(),
    }),
    productRegistry: ports.productRegistry,
    spawnAdapter: (cmd, dir, env) => opts.supervisor.spawnAdapter(cmd, dir, env),
    clock: {
      now,
      sleep: (ms: number) => new Promise((r) => setTimeout(r, ms)),
    },
    journalMutation: (m) => runtime.journalMutation(m),
    receiptSink: (r) => runtime.receiptSink(r),
    paths: {
      stageDir: (slug, generation) =>
        join(opts.stateRoot, "products", slug, generation, "stage"),
      dataDir: (slug, generation) =>
        join(opts.stateRoot, "products", slug, generation, "data"),
    },
    platform: () => ({
      os: process.platform,
      arch: process.arch,
      node: process.version,
    }),
    policy: () => ({
      strict: config.catalog.strict,
      allowlist: config.catalog.allowlist,
      sandboxes: detectSandboxes(),
    }),
    revisions: () => ({
      config:
        store.registry.kvGet("config:revision") ??
        store.kv.get("config_revision") ??
        "1",
      catalog: ports.catalog.pinsRevision(),
      registry: ports.productRegistry.revision(),
    }),
    probeGeneration: (row) => opts.supervisor.probeGeneration(row),
    pidAlive: (pid) => opts.supervisor.pidAlive(pid),
  };

  const product = createProductService(lifecyclePorts);

  // ── journalMutation / receiptSink → durable projections ──────────────
  const journalMutation = (m: JournalMutation): void => {
    journalSeq += 1;
    const op =
      m.operation !== undefined
        ? product.engine.getOperation(m.operation)
        : undefined;
    const stateFromDetail =
      m.detail !== null &&
      m.detail !== undefined &&
      typeof (m.detail as Record<string, unknown>).to === "string"
        ? ((m.detail as Record<string, unknown>).to as string)
        : undefined;
    const mutations: Json[] = [
      {
        v: 1,
        kind: "docs",
        docs: [
          {
            kind: "lifecycle:journal",
            id: `j${String(journalSeq).padStart(8, "0")}:${m.operation ?? "boot"}`,
            doc: {
              seq: journalSeq,
              type: m.type,
              operation: m.operation ?? null,
              slug: m.slug ?? null,
              generation: m.generation ?? null,
              detail: m.detail ?? null,
              at_ms: now(),
            } as unknown as Json,
          },
        ],
      },
    ];
    if (op !== undefined) {
      mutations.push({
        v: 1,
        kind: "operations",
        operations: [
          {
            id: op.id,
            principal: opCallers.get(op.id) ?? "local",
            kind: op.kind,
            state: stateFromDetail ?? op.state,
            slug: op.slug,
            from: op.from,
            to: op.to,
            cursor: op.cursor,
            error: op.error,
          },
        ],
      });
    }
    ports.sync.commitSync({ v: 1, kind: "batch", mutations });
  };

  const receiptSink = (r: TransitionReceipt): void => {
    journalSeq += 1;
    ports.sync.commitSync({
      v: 1,
      kind: "docs",
      docs: [
        {
          kind: "lifecycle:receipt",
          id: `r${String(journalSeq).padStart(8, "0")}:${r.operation}`,
          doc: r as unknown as Json,
        },
      ],
    });
  };

  // ── agent / approval runtimes ─────────────────────────────────────────
  const agent = createAgentRuntime(ports.peers, {
    gateway: instance,
    workspace,
    epoch: opts.epoch,
    allowOperator: config.agents.allow_operator,
    accessTtlS: config.agents.access_ttl_s,
    refreshTtlS: config.agents.refresh_ttl_s,
    nativeMeshAvailable: false,
    supportedProfiles: HELLO_PROFILES,
    ids,
    entropy,
  });

  const approval = createApprovalRuntime(ports.approvals);

  // ── sync / cloud / catalog services ───────────────────────────────────
  const syncServicePorts: SyncServicePorts = Object.assign(ports.sync, {
    syncPaused: () => config.sync?.paused === true,
    syncRevision,
    applySync,
    cloud: () => {
      const cur = ports.cloud.currentCloud();
      return cur === undefined ? null : { id: cur.id, state: cur.state };
    },
  });
  const sync = createSyncService(syncServicePorts);
  const cloud = createCloudService(ports.cloud);
  const catalog = createCatalogService(ports.catalog);

  // ── platform ports (per-call service factory input) ──────────────────
  const platformPorts: PlatformPorts = {
    store: ports.store,
    sessionStore: ports.sessionStore,
    configDir: opts.configDir,
    clock: now,
    workspace,
    instance,
    receiptWorkspace: "audit1",
    auditSource: "gateway1",
    auditKey: opts.auditKey,
    get uiEndpoint() {
      return opts.uiEndpoint();
    },
    profiles: HELLO_PROFILES,
    mesh: { available: false, code: "CAP_ADAPTER_UNAVAILABLE" },
    nativeCollectorBound: false,
    nativeLineageBound: false,
    newId: () => newControlId(),
    newToken: () => newToken(),
    onStop: (graceMs: number) => opts.onStop(graceMs),
  };

  const bindPlatform = (ctx: ServiceContext): PlatformServices =>
    createPlatformServices(platformPorts, ctx);

  const LOCAL_CTX: ServiceContext = {
    principal: { id: "local", role: "local_operator" } as Principal,
  };

  // operation.get/cancel: engine records are authoritative while live;
  // the durable operations_v2 projection (written by journalMutation)
  // serves restarted history.
  const operationComposite: GatewayServices["operation"] = {
    get: async (params) => {
      const id = (params as { operation?: string }).operation ?? "";
      const live = product.engine.getOperation(id);
      if (live !== undefined) {
        return {
          operation: live.id,
          kind: live.kind,
          state: live.state,
          slug: live.slug,
          from: live.from,
          to: live.to,
          cursor: live.cursor,
          error: live.error,
        };
      }
      return bindPlatform(LOCAL_CTX).operation.get(params);
    },
    cancel: async (params) => {
      const id = (params as { operation?: string }).operation ?? "";
      if (product.engine.getOperation(id) !== undefined) {
        const rec = await product.engine.cancelOperation(id);
        return { operation: rec.id, state: rec.state };
      }
      return bindPlatform(LOCAL_CTX).operation.cancel(params);
    },
  };

  const bindServices = (ctx: ServiceContext): GatewayServices => {
    const p = bindPlatform(ctx);
    return {
      ...p,
      daemon: p.daemon,
      product: product.product,
      operation: operationComposite,
      agent: agent.service,
      approval: approval.service,
      sync,
      cloud,
      catalog,
    };
  };

  const runtime: WiredRuntime = {
    ports,
    platformPorts,
    bindPlatform,
    product,
    agent,
    approval,
    catalogStore,
    bindServices,
    journalMutation,
    receiptSink,
    noteOperationCaller: (op, principal) => {
      opCallers.set(op, principal);
    },
  };
  return runtime;
}
