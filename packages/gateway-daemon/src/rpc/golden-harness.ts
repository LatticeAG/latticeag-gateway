/**
 * Golden §3.3 exchange harness — assembles the REAL domain services over
 * their in-memory ports and drives them through the REAL dispatch pipeline
 * (strict-json → envelope → auth → role gate → scope → idempotency →
 * service → receipt attach), matching the spec's seeded-handler exchange
 * model: every exchange is an independent call against a fixture-seeded
 * handler.
 *
 * Determinism: fixture literals (pair1/peer1/src1/sub1/approval1/op1/
 * enroll1/cloud1, token(n), code "6J7K8M9N2P", cursor
 * c0000000000000001:7) are produced by injected allocators/entropy queues
 * and explicit state seeding — never by intercepting responses.
 */
import { generateKeyPairSync } from "node:crypto";
import {
  canonicalJson,
  sha256Hex,
  newToken,
  type GatewayServices,
  type Json,
  type Principal,
  type Scope,
} from "../core-v2.js";
import {
  createMemoryPlatformPorts,
  createPlatformServices,
  type MemoryPlatformPorts,
  type PlatformServices,
  type ServiceContext,
} from "../../../core/dist/v2/platform/index.js";
import {
  createAgentRuntime,
  type AgentRuntime,
} from "../../../core/dist/v2/peers/service.js";
import {
  createMemoryPeerPorts,
  sequentialIds,
  queuedEntropy,
  type MemoryPeerPorts,
  type GrantRecord,
} from "../../../core/dist/v2/peers/ports.js";
import {
  createApprovalRuntime,
  type ApprovalRuntime,
} from "../../../core/dist/v2/approvals/service.js";
import {
  createMemoryApprovalPorts,
  type MemoryApprovalPorts,
} from "../../../core/dist/v2/approvals/ports.js";
import {
  createMemorySyncPorts,
  type MemorySyncPorts,
} from "../../../core/dist/v2/sync/ports.js";
import { createSyncService } from "../../../core/dist/v2/sync/service.js";
import {
  createMemoryCatalogPorts,
  type MemoryCatalogPorts,
} from "../../../core/dist/v2/catalog/ports.js";
import { createCatalogService } from "../../../core/dist/v2/catalog/service.js";
import {
  createMemoryCloudPorts,
  type MemoryCloudPorts,
} from "../../../core/dist/v2/cloud/ports.js";
import { createCloudService } from "../../../core/dist/v2/cloud/service.js";
import {
  createMemoryPorts,
  StubAdapterChild,
  type MemoryPorts,
  type StubScript,
} from "../../../core/dist/v2/lifecycle/testing.js";
import {
  fixtureTrust,
  INDEX2,
} from "../../../core/dist/v2/lifecycle/testbed.js";
import { createProductService } from "../../../core/dist/v2/lifecycle/service.js";
import {
  makeReviewValidator,
} from "../../../core/dist/v2/sync/service.js";
import {
  streamConsent,
} from "../../../core/dist/v2/sync/ports.js";
import type { StreamName } from "../../../core/dist/v2/protocol/sync.js";
import {
  dispatchRequest,
  type DispatchOutcome,
  type DispatchInput,
  type ReceiptWriter,
  type ReceiptPointer,
  type AuditAction,
} from "./dispatch.js";
import type { TransportCredentials, PeerGrant } from "./auth.js";
import { F, blob, J, origin, auditor, sunlight } from "@latticeag/testkit";

/** The scripted adapter every spawned product generation answers with. */
const GOLDEN_ADAPTER: StubScript = {
  methods: {
    describe: () => ({
      contract: "gateway-adapter/1",
      product: "lexverdict",
      config_schema_digest: F.schema.ref.digest,
      profiles: ["@latticeag/events@0.1.0"],
    }),
    configure: (p) => ({ generation: p.generation ?? "1", accepted: true }),
    start: (p) => ({ state: "RUNNING", generation: p.generation ?? "1" }),
    health: () => ({
      liveness: true,
      readiness: true,
      dependencies: [],
      native: { status: "ok" },
    }),
    drain: () => ({ in_flight: 0, uncertain: [] }),
    snapshot: () => ({ supported: false, objects: [] }),
    stop: () => ({ state: "STOPPED", uncertain: [] }),
  },
};

/** A 2-of-2 signed catalog index payload (fixture roots origin+auditor). */
function signedIndex(index: unknown): { index: unknown; signatures: unknown[] } {
  const content = blob(J(index));
  return {
    index,
    signatures: [sunlight(content, origin, 1), sunlight(content, auditor, 2)],
  };
}

export const GOLDEN_NOW = F.now as number;
const HELLO_PROFILES = ["@latticeag/events@0.1.0", "proof-evidence/1"];
const UI_URL = "http://127.0.0.1:9848";

/** Everything a single seeded-handler exchange test can inject. */
export interface GoldenOpts {
  /** Platform newId() results, in order (e.g. "sub1"). */
  platformIds?: string[];
  /** Platform newToken() results, in order (bootstrap, session id, csrf). */
  platformTokens?: string[];
  /** Peer-domain entropy queues (access/refresh tokens, nonces, codes). */
  peerTokens?: string[];
  peerNonces?: string[];
  peerPairCodes?: string[];
  /** Cloud-domain ids ("enroll1","cloud1") and user codes, in order. */
  cloudIds?: string[];
  cloudPairCodes?: string[];
  clock?: number;
  /** Pre-paused sync streams. */
  paused?: string[];
  /** Revision the sync domain reports (sync.configure CAS). */
  syncRevision?: string;
  /** Offline-enrolled catalog index (verified against fixture roots). */
  catalogIndex?: unknown;
  /** Seed the verified catalog cache (for search/show/pin exchanges). */
  catalogCache?: boolean;
  /** ui endpoint; null = unbound. */
  uiEndpoint?: string | null;
  /** Current config document + revision for config.get/apply. */
  configDocument?: unknown;
  configRevision?: string;
  /** Streams with an enabled (paused) sync consent. */
  consented?: StreamName[];
}

export interface GoldenGateway {
  /** Dispatch one method as the local operator (socket-authenticated). */
  call(method: string, params: unknown, id?: string): Promise<DispatchOutcome>;
  /** Dispatch with explicit transport credentials (peer/anonymous/session). */
  callAs(
    credentials: TransportCredentials,
    method: string,
    params: unknown,
    id?: string,
    workspace?: string,
  ): Promise<DispatchOutcome>;
  ports: {
    platform: MemoryPlatformPorts;
    peers: MemoryPeerPorts;
    approvals: MemoryApprovalPorts;
    sync: MemorySyncPorts;
    catalog: MemoryCatalogPorts;
    cloud: MemoryCloudPorts;
    lifecycle: MemoryPorts;
  };
  agent: AgentRuntime;
  approval: ApprovalRuntime;
  product: ReturnType<typeof createProductService>;
  /** Audit actions committed by the receipt writer (assertion aid). */
  auditLog: AuditAction[];
}

/**
 * Minimal receipt writer: produces a real ReceiptPointer per action and
 * honours the idempotency binding contract (saved-result replay).
 */
class GoldenReceipts implements ReceiptWriter {
  readonly actions: AuditAction[] = [];
  private seq = 0;
  private binds = new Map<string, { requestHash: string; resultJson: string }>();

  async commitAction(
    action: AuditAction,
    bind: {
      principalKey: string;
      id: string;
      requestHash: string;
      makeResultJson: (receipt: ReceiptPointer) => string;
    } | null,
  ): Promise<ReceiptPointer> {
    this.seq += 1;
    this.actions.push(action);
    const receipt: ReceiptPointer = {
      workspace: "audit1",
      event: {
        source: "gateway1",
        stream: "gateway.action",
        seq: String(this.seq),
        hash: sha256Hex(canonicalJson(action as unknown as Json)),
      },
    };
    if (bind !== null) {
      this.binds.set(`${bind.principalKey} ${bind.id}`, {
        requestHash: bind.requestHash,
        resultJson: bind.makeResultJson(receipt),
      });
    }
    return receipt;
  }

  async commitBind(bind: {
    principalKey: string;
    id: string;
    requestHash: string;
    resultJson: string;
  }): Promise<void> {
    this.binds.set(`${bind.principalKey} ${bind.id}`, {
      requestHash: bind.requestHash,
      resultJson: bind.resultJson,
    });
  }

  lookup(principalKey: string, id: string) {
    const b = this.binds.get(`${principalKey} ${id}`);
    return b === undefined
      ? null
      : { principalKey, id, requestHash: b.requestHash, saved: b.resultJson };
  }
}

export function createGoldenGateway(opts: GoldenOpts = {}): GoldenGateway {
  const now = opts.clock ?? GOLDEN_NOW;
  const platformIds = [...(opts.platformIds ?? [])];
  const platformTokens = [...(opts.platformTokens ?? [])];
  const cloudIds = [...(opts.cloudIds ?? [])];
  const cloudCodes = [...(opts.cloudPairCodes ?? [])];
  let platformSeq = 0;
  let cloudSeq = 0;

  const platform = createMemoryPlatformPorts({
    now,
    workspace: "ws1",
    instance: "gw1",
    uiEndpoint: opts.uiEndpoint === undefined ? UI_URL : opts.uiEndpoint,
    auditKey: generateKeyPairSync("ed25519").privateKey,
    newId: () => platformIds.shift() ?? `p${++platformSeq}`,
    newToken: () => platformTokens.shift() ?? newToken(),
  });
  if (opts.configDocument !== undefined) {
    platform.store.seedConfig(opts.configDocument, opts.configRevision ?? "1");
  }

  const peerPorts = createMemoryPeerPorts({
    now,
    ids: sequentialIds({ session: "session" }),
    entropy: queuedEntropy({
      tokens: opts.peerTokens ?? [],
      nonces: opts.peerNonces ?? [],
      pairCodes: opts.peerPairCodes ?? [],
    }),
  });
  const approvalPorts = createMemoryApprovalPorts({
    now,
    ids: sequentialIds(),
  });
  const syncPorts = createMemorySyncPorts({ now });
  const catalogPorts = createMemoryCatalogPorts({
    now,
    trust: {
      roots: new Map([
        [origin.sunlight, origin.material.public],
        [auditor.sunlight, auditor.material.public],
      ]),
      quorum: 2,
      channel: "stable",
    },
  });
  const cloudPorts = createMemoryCloudPorts({ now });
  cloudPorts.newId = () => cloudIds.shift() ?? `cloud${++cloudSeq}`;
  cloudPorts.pairCode = () => cloudCodes.shift() ?? "6J7K8M9N2P";
  const lifecyclePorts = createMemoryPorts({
    fakeClock: { startMs: now },
    platform: { os: "linux", arch: "x64", node: "v24.0.0" },
    index: INDEX2,
    trust: fixtureTrust(),
    spawnAdapter: () => new StubAdapterChild(GOLDEN_ADAPTER),
  });
  lifecyclePorts.putRelease(F.release1.wire as never, F.release1.archive);
  lifecyclePorts.putRelease(F.release2.wire as never, F.release2.archive);

  if (opts.catalogIndex !== undefined) {
    catalogPorts.snapshot = signedIndex(opts.catalogIndex);
  }
  if (opts.catalogCache === true) {
    const raw = canonicalJson(opts.catalogIndex ?? F.index);
    catalogPorts.cache = {
      raw,
      digest: sha256Hex(raw),
      signatures: signedIndex(opts.catalogIndex ?? F.index).signatures,
      index: (opts.catalogIndex ?? F.index) as never,
      offline: false,
    };
  }
  for (const s of opts.paused ?? []) {
    syncPorts.paused.add(s as StreamName);
  }
  for (const s of opts.consented ?? []) {
    syncPorts.consents.set(s, streamConsent({ paused: true }));
    syncPorts.paused.add(s);
  }

  const agent = createAgentRuntime(peerPorts, {
    gateway: "gw1",
    workspace: "ws1",
    epoch: "1",
    allowOperator: false,
    accessTtlS: 900,
    refreshTtlS: 2592000,
    nativeMeshAvailable: false,
    supportedProfiles: HELLO_PROFILES,
    ids: sequentialIds({ session: "session" }),
    entropy: queuedEntropy({
      tokens: opts.peerTokens ?? [],
      nonces: opts.peerNonces ?? [],
      pairCodes: opts.peerPairCodes ?? [],
    }),
  });
  const approval = createApprovalRuntime(approvalPorts);
  // The §3.3 review binding names the calling principal ("local" for the
  // socket operator — the spec harness's name is "operator1") and the
  // 300 s review window the spec fixture uses.
  const reviewValidator = makeReviewValidator("local", now + 300_000) as (
    method: string,
    params: unknown,
    review: unknown,
  ) => boolean;
  const syncService = createSyncService(
    Object.assign(syncPorts, {
      syncPaused: () => false,
      syncRevision: () => opts.syncRevision ?? "1",
      applySync: () => true,
      validateReview: reviewValidator,
      cloud: () => {
        const cur = cloudPorts.currentCloud();
        return cur === undefined ? null : { id: cur.id, state: cur.state };
      },
    }),
  );
  cloudPorts.reviewer = reviewValidator;
  const cloudService = createCloudService(cloudPorts);
  const catalogService = createCatalogService(catalogPorts);
  const product = createProductService(lifecyclePorts, {
    engine: { liveProbes: false },
  });

  const receipts = new GoldenReceipts();
  const usedNonces = new Map<string, number>();

  /**
   * Dispatch-side peer token surface: the daemon binds token hashes to
   * PeerGrants out of the same grant table the TokenService writes.
   */
  const peerTokenStore = {
    lookupAccess: (tokenSha256: string): PeerGrant | null => {
      const grant = peerPorts.grantByAccessHash(tokenSha256);
      if (grant === null) return null;
      const peer = peerPorts.getPeer(grant.peer);
      if (peer === null) return null;
      return grantToPeerGrant(grant, peer);
    },
    nonceSeen: (peer: string, nonce: string, untilMs: number): boolean => {
      const key = `${peer}:${nonce}`;
      if (usedNonces.has(key)) return true;
      usedNonces.set(key, untilMs);
      return false;
    },
  };

  function grantToPeerGrant(
    grant: GrantRecord,
    peer: { id: string; state: string; key_material: { public: string }; grant_revision: string },
  ): PeerGrant {
    return {
      peer: peer.id,
      publicKey: peer.key_material.public,
      role: grant.role,
      scopes: grant.scopes as Scope[],
      expires_ms: grant.access_expires_ms,
      revoked:
        grant.state !== "ACTIVE" ||
        peer.state === "REVOKED" ||
        grant.grant_revision !== peer.grant_revision,
      epoch: String(grant.epoch),
    };
  }

  const servicesFor = (ctx: ServiceContext): GatewayServices => {
    const p: PlatformServices = createPlatformServices(platform, ctx);
    return {
      ...p,
      product: product.product,
      agent: agent.service,
      approval: approval.service,
      sync: syncService,
      cloud: cloudService,
      catalog: catalogService,
    };
  };

  const callAs = async (
    credentials: TransportCredentials,
    method: string,
    params: unknown,
    id = "q1",
    workspace = "ws1",
  ): Promise<DispatchOutcome> => {
    const input: DispatchInput = {
      transport: "socket",
      body: canonicalJson({
        v: 2,
        id,
        workspace,
        method,
        params: params ?? {},
      }),
      credentials,
    };
    return dispatchRequest(
      {
        instance: "gw1",
        workspace: "ws1",
        epoch: "1",
        services: servicesFor({
          principal: { id: "local", role: "local_operator" } as Principal,
        }),
        bindServices: ({ principal, requestId }) =>
          servicesFor({ principal, requestId } as ServiceContext),
        peers: peerTokenStore,
        receipts,
        idempotency: receipts,
        now: () => now,
      },
      input,
    );
  };

  const call = (method: string, params: unknown, id = "q1") =>
    callAs({ kind: "local" }, method, params, id);

  return {
    call,
    callAs,
    ports: {
      platform,
      peers: peerPorts,
      approvals: approvalPorts,
      sync: syncPorts,
      catalog: catalogPorts,
      cloud: cloudPorts,
      lifecycle: lifecyclePorts,
    },
    agent,
    approval,
    product,
    auditLog: receipts.actions,
  };
}
