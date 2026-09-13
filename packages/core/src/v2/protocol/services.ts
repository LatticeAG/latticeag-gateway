/**
 * Gateway v2 — core service facade (spec §3.2/§3.3).
 *
 * One typed method per registry RPC; parameter and result shapes follow the
 * §3.3 exchange examples. Implementations live in the daemon; these
 * interfaces are the contract the daemon, CLI, and tests share. Methods are
 * pure RPC boundaries — authentication, idempotency binding, and receipt
 * emission happen in the admission pipeline, not inside these signatures.
 */

import type {
  Blob,
  Count,
  Hash,
  Id,
  Json,
  JsonObject,
  NativeRef,
  ObjectRef,
} from "./refs.js";
import type { Accepted, Page } from "./envelope.js";
import type { Topic } from "./topics.js";
import type { PairState, Peer, Registration, Scope } from "./peers.js";
import type { Series } from "./product.js";
import type { ProductState } from "./lifecycle.js";
import type { StreamName, StreamProfile } from "./sync.js";
import type {
  CatalogEntry,
  CatalogFreshness,
  CatalogPin,
} from "./catalog.js";

/**
 * An authenticated caller. Roles map to §3.2 role letters:
 * viewer→V, agent→A, operator→O, local_operator→L, bootstrap→P.
 * `reviewer` marks a native-enrolled reviewer grant (R) held by an
 * agent/operator principal — enrollment is server-side state, never a
 * caller-supplied claim.
 */
export interface Principal {
  readonly id: Id;
  readonly role: "viewer" | "agent" | "operator" | "local_operator" | "bootstrap";
  /** Set for peer-authenticated principals. */
  readonly peer?: Id;
  /** Enrolled scope grant (already intersected with policy). */
  readonly scopes?: Scope[];
  /** Native-enrolled reviewer (R). */
  readonly reviewer?: boolean;
}

// ── daemon ───────────────────────────────────────────────────────────────

export interface DaemonHelloParams {
  profiles: string[];
  interfaces: string;
}

export interface DaemonHelloResult {
  protocol: string;
  profiles: string[];
  interfaces: string;
  mesh: { available: boolean; code?: string };
}

export interface DaemonStatusResult {
  instance: Id;
  state: string;
  config_revision: Count;
  products: number;
  peers: number;
  ui: string | null;
}

export interface DaemonStopParams {
  /** 0–30000. */
  grace_ms: number;
}

export interface DaemonService {
  hello(params: DaemonHelloParams): Promise<DaemonHelloResult>;
  status(params: Record<string, never>): Promise<DaemonStatusResult>;
  stop(params: DaemonStopParams): Promise<{ state: string }>;
}

// ── config ───────────────────────────────────────────────────────────────

export interface ConfigService {
  get(params: Record<string, never>): Promise<{ revision: Count; document: JsonObject }>;
  validate(params: {
    document: JsonObject;
  }): Promise<{ valid: boolean; errors: Json[] }>;
  apply(params: {
    expected_revision: Count;
    document: JsonObject;
    review: NativeRef;
  }): Promise<{ revision: Count; restart_required: boolean }>;
}

// ── run ──────────────────────────────────────────────────────────────────

export interface RunRegisterParams {
  run_id: string;
  kit: string;
  owner: Id;
  resume: boolean;
}

export interface RunService {
  register(params: RunRegisterParams): Promise<{
    run_id: string;
    owner: Id;
    mode: string;
  }>;
  heartbeat(params: {
    run_id: string;
    owner: Id;
    spool_seq: Count;
  }): Promise<{ accepted: true }>;
  finish(params: {
    run_id: string;
    owner: Id;
    exit_code: number | null;
    signal: string | null;
    spool_seq: Count;
  }): Promise<{ state: string; pending_sync: number }>;
}

// ── events ───────────────────────────────────────────────────────────────

export interface EventPublishParams {
  profile: string;
  topic: Topic;
  producer: Id;
  seq: Count;
  record: Blob | Json;
}

export interface EventService {
  publish(params: EventPublishParams): Promise<{
    cursor: string;
    durable: boolean;
    duplicate: boolean;
  }>;
  query(params: {
    topics: Topic[];
    after: string | null;
    /** 1–200. */
    limit: number;
  }): Promise<Page<Json>>;
  subscribe(params: {
    topics: Topic[];
    after: string | null;
  }): Promise<{ subscription: Id; cursor: string; expires_ms: number }>;
  ack(params: {
    subscription: Id;
    cursor: string;
  }): Promise<{ cursor: string }>;
}

// ── objects / receipt / lineage ──────────────────────────────────────────

export interface ObjectService {
  /** Blob ≤1 MiB referenced by a caller-owned pending/committed action. */
  put(params: { action: NativeRef; blob: Blob }): Promise<{ ref: ObjectRef }>;
  get(params: { action: NativeRef; ref: ObjectRef }): Promise<{ blob: Blob }>;
}

export interface ReceiptService {
  get(params: {
    action: NativeRef;
    disclosure: "HASHES_ONLY" | string;
  }): Promise<{
    action: NativeRef;
    inventory: Json;
    outer: string;
    inner: string;
    bundle: Blob | null;
  }>;
}

export interface LineageService {
  query(params: {
    action: NativeRef;
    /** 1–2000. */
    max_nodes: number;
    /** 1–128. */
    max_depth: number;
  }): Promise<{
    nodes: Json[];
    edges: Json[];
    gaps: string[];
    native_assessment: string;
  }>;
}

// ── operations ───────────────────────────────────────────────────────────

export type OperationKind = "install" | "uninstall" | "update" | "rollback" | string;

export interface OperationService {
  get(params: { operation: Id }): Promise<{
    operation: Id;
    kind: OperationKind;
    state: string;
    slug: string;
    from: string | null;
    to: string | null;
    cursor: string;
    error: { code: string; retryable: boolean; field: string | null } | null;
  }>;
  cancel(params: { operation: Id }): Promise<{ operation: Id; state: string }>;
}

// ── products ─────────────────────────────────────────────────────────────

export interface ProductPlanParams {
  kind: "install" | "uninstall" | "update" | "rollback";
  /** Signed catalog slug, exact npm selector, or local snapshot locator. */
  source: string;
  version?: string;
  cascade?: boolean;
  keep_data?: boolean;
}

export interface ProductHealthResult {
  slug: string;
  state: ProductState;
  liveness: boolean;
  readiness: boolean;
  sandbox: string;
  native: Json;
}

export interface ProductService {
  plan(params: ProductPlanParams): Promise<{ plan: Hash; summary: Json }>;
  install(params: { plan: Hash; review: NativeRef }): Promise<Accepted>;
  uninstall(params: { plan: Hash; review: NativeRef }): Promise<Accepted>;
  update(params: { plan: Hash; review: NativeRef }): Promise<Accepted>;
  rollback(params: { plan: Hash; review: NativeRef }): Promise<Accepted>;
  list(params: { after: string | null; limit: number }): Promise<Page<Json>>;
  health(params: { slug: string }): Promise<ProductHealthResult>;
}

// ── agent ────────────────────────────────────────────────────────────────

export interface PairCreateParams {
  role: "agent" | "operator";
  scopes: Scope[];
  /** May be null until proposal; never wildcard operator by default. */
  key: Hash | null;
}

export interface PairViewResult {
  pair: Id;
  state: PairState;
  proposal: Hash;
  key: Hash;
  scopes: Scope[];
}

export interface ChallengeResult {
  challenge: Id;
  nonce: string;
  audience: string;
  epoch: Count;
  expires_ms: number;
}

export interface RegisterResult {
  peer: Id;
  source: Id;
  role: "agent" | "operator";
  scopes: Scope[];
  access: string;
  refresh: string;
  expires_ms: number;
  /** e.g. "ADAPTER_REQUIRED" when no bound native route exists. */
  mesh: string;
}

export interface RenewParams {
  peer: Id;
  refresh: string;
  challenge: Id;
  server_nonce: string;
  epoch: Count;
  proof: string;
}

export interface AgentService {
  pairCreate(params: PairCreateParams): Promise<{
    pair: Id;
    code: string;
    expires_ms: number;
  }>;
  pairPropose(params: Registration): Promise<PairViewResult>;
  pairGet(params: {
    pair: Id;
    /** Required for P principals, nullable only for L. */
    code: string | null;
  }): Promise<PairViewResult>;
  pairApprove(params: {
    pair: Id;
    proposal: Hash;
    key: Hash;
    scopes: Scope[];
  }): Promise<{ pair: Id; state: "APPROVED" }>;
  pairCancel(params: { pair: Id }): Promise<{ pair: Id; state: "CANCELLED" }>;
  challenge(params: {
    key: string;
    nonce: string;
  }): Promise<ChallengeResult>;
  register(params: Registration): Promise<RegisterResult>;
  renew(params: RenewParams): Promise<{
    access: string;
    refresh: string;
    expires_ms: number;
  }>;
  list(params: { after: string | null; limit: number }): Promise<Page<Peer>>;
  revoke(params: { peer: Id; reason: string }): Promise<{
    peer: Id;
    state: "REVOKED";
    grant_revision: Count;
  }>;
  disconnect(params: { peer: Id }): Promise<{ peer: Id; state: "DISCONNECTED" }>;
}

// ── approvals ────────────────────────────────────────────────────────────

export type ApprovalState = "PENDING" | "APPROVED" | "DENIED" | "CANCELLED" | "EXPIRED";

export interface ApprovalService {
  request(params: {
    action: NativeRef;
    target: string;
    expires_ms: number;
    native: ObjectRef;
  }): Promise<{
    approval: Id;
    revision: Count;
    state: "PENDING";
    authority: string;
  }>;
  list(params: {
    state?: ApprovalState;
    after: string | null;
    limit: number;
  }): Promise<Page<Json>>;
  get(params: { approval: Id }): Promise<{
    approval: Id;
    revision: Count;
    state: ApprovalState;
    action: NativeRef;
    expires_ms: number;
    native_status: string;
  }>;
  decide(params: {
    approval: Id;
    expected_revision: Count;
    action: NativeRef;
    decision: "approve" | "deny";
    reason: string;
  }): Promise<{
    approval: Id;
    revision: Count;
    state: ApprovalState;
    native_status: string;
  }>;
  cancel(params: { approval: Id; expected_revision: Count }): Promise<{
    approval: Id;
    revision: Count;
    state: "CANCELLED";
  }>;
}

// ── ui sessions ──────────────────────────────────────────────────────────

export interface UiService {
  sessionCreate(params: { role: "viewer" | "operator" }): Promise<{
    bootstrap: string;
    expires_ms: number;
    url: string;
  }>;
  sessionExchange(params: { bootstrap: string }): Promise<{
    session: Id;
    role: string;
    csrf: string;
    expires_ms: number;
  }>;
  sessionRevoke(params: { session: Id }): Promise<{
    session: Id;
    state: "REVOKED";
  }>;
}

// ── sync ─────────────────────────────────────────────────────────────────

export interface SyncStreamCounts {
  pending: number;
  in_flight: number;
  blocked: number;
  acked: number;
  cohort: string;
  profile: StreamProfile;
}

export interface SyncService {
  status(params: Record<string, never>): Promise<{
    paused: boolean;
    streams: Record<StreamName, SyncStreamCounts>;
    cloud: { id: Id; state: string } | null;
  }>;
  pause(params: { streams: StreamName[] }): Promise<{ paused: StreamName[] }>;
  resume(params: { streams: StreamName[] }): Promise<{ resumed: StreamName[] }>;
  configure(params: {
    expected_revision: Count;
    sync: JsonObject;
    review: NativeRef;
  }): Promise<{ revision: Count }>;
  flush(params: {
    streams: StreamName[];
    /** 0–300000. */
    timeout_ms: number;
  }): Promise<{ through: Record<string, string>; pending: number; blocked: number }>;
}

// ── cloud pairing ────────────────────────────────────────────────────────

export interface CloudService {
  pairBegin(params: {
    provider: string;
    streams: StreamName[];
    remote_ui: boolean;
  }): Promise<{ enrollment: Id; state: "AWAITING_PROVIDER"; user_code: string }>;
  pairComplete(params: {
    enrollment: Id;
    binding: NativeRef;
    review: NativeRef;
  }): Promise<{ cloud: Id; state: "PAIRED"; remote_ui: boolean }>;
  pairRevoke(params: { cloud: Id }): Promise<{
    cloud: Id;
    state: "REVOKED";
    remote_notice: string;
  }>;
}

// ── catalog ──────────────────────────────────────────────────────────────

export interface CatalogService {
  refresh(params: {
    source: "configured" | string;
    offline?: boolean;
  }): Promise<{
    revision: Count;
    entries: number;
    freshness: CatalogFreshness | "OFFLINE_PINNED";
  }>;
  search(params: {
    /** ≤128 bytes. */
    q: string;
    series: Series | null;
    after: string | null;
    limit: number;
  }): Promise<Page<CatalogEntry>>;
  show(params: { slug: string; version: string }): Promise<{ entry: CatalogEntry }>;
  pin(params: {
    slug: string;
    version: string;
    digest: string;
    expected_revision: Count;
  }): Promise<{ revision: Count; pin: CatalogPin }>;
  unpin(params: { slug: string; expected_revision: Count }): Promise<{ revision: Count }>;
}

// ── aggregate ────────────────────────────────────────────────────────────

/** The complete daemon service surface, one group per RPC prefix. */
export interface GatewayServices {
  daemon: DaemonService;
  config: ConfigService;
  run: RunService;
  events: EventService;
  objects: ObjectService;
  receipt: ReceiptService;
  lineage: LineageService;
  operation: OperationService;
  product: ProductService;
  agent: AgentService;
  approval: ApprovalService;
  ui: UiService;
  sync: SyncService;
  cloud: CloudService;
  catalog: CatalogService;
}
