/**
 * `store-ports.ts` — adapts `GatewayStore` to the core v2 durable ports
 * (spec §2.3, §3.4, §4.2–§4.3, §8, §9).
 *
 * Two persistence disciplines share one commit path:
 *
 *  - Async ports (platform store/session store) run through
 *    `GatewayStore.commit`/`commitSync` — every durable mutation is a
 *    journaled registry mutation replayed identically on rebuild.
 *  - Sync ports (peers, approvals, sync outbox, catalog, cloud, product
 *    registry) use `GatewayStore.commitSync`: a mutation-only journal
 *    marker + registry apply in one synchronous step. Atomic decisions
 *    that cannot fail the journal (bootstrap single-use, lifecycle CAS)
 *    record their outcome under `kv_meta` keys keyed by tx, which the
 *    adapter reads back after the commit.
 *
 * Doc rows (`docs` table) carry whole JSON records for the peer /
 * approval / cloud / lifecycle domains; the registry is the derived index
 * and the journal is the evidence trail.
 */
import type {
  ApprovalPorts,
  ApprovalRecord,
} from "../../../core/dist/v2/approvals/ports.js";
import type {
  CatalogPorts,
  CachedIndex,
  CatalogTrustView,
  Equivocation,
  IndexFetch,
} from "../../../core/dist/v2/catalog/ports.js";
import type {
  CloudEnrollment,
  CloudPairing,
  CloudPorts,
  ProviderBinding,
} from "../../../core/dist/v2/cloud/ports.js";
import type {
  GenerationRow,
  ProductRegistryPort,
} from "../../../core/dist/v2/lifecycle/index.js";
import type {
  ChallengeRecord,
  DeliveryRecord,
  Entropy,
  GrantRecord,
  IdAllocator,
  PairRecord,
  PeerPorts,
  RenewReplayRecord,
  SessionRecord as PeerSessionRecord,
  StoredPeer,
} from "../../../core/dist/v2/peers/ports.js";
import type {
  PlatformActionEntry,
  PlatformBootstrapRecord,
  PlatformCommitInput,
  PlatformCommitResult,
  PlatformCursorResolution,
  PlatformEventEntry,
  PlatformLaneHead,
  PlatformLaneRecord,
  PlatformOperationEntry,
  PlatformRegistry,
  PlatformRunEntry,
  PlatformSessionRecord,
  PlatformSessionStore,
  PlatformSourceEntry,
  PlatformStore,
  PlatformSubscriptionEntry,
} from "../../../core/dist/v2/platform/ports.js";
import type {
  OutboxStore as SyncOutboxStore,
  StreamConsent,
  SyncPorts,
} from "../../../core/dist/v2/sync/ports.js";
import type {
  OutboxItem as SyncOutboxItem,
  StreamName,
} from "../../../core/dist/v2/protocol/sync.js";
import type { SinkAdapter } from "../../../core/dist/v2/sync/sinks.js";
import type { CatalogPin } from "../../../core/dist/v2/protocol/catalog.js";
import type { JsonObject } from "../../../core/dist/v2/protocol/refs.js";
import type { PeerGrant, PeerTokenStore } from "../rpc/auth.js";
import type { GatewayStore } from "../store/store.js";
import type { Registry } from "../store/registry.js";
import { sha256hex, type Json } from "../store/util.js";
import { RpcError, canonicalJson } from "../core-v2.js";

// ── durable document kinds (journaled names — never rename) ─────────────

export const DOC = {
  pair: "peer:pair",
  challenge: "peer:challenge",
  peer: "peer",
  peerSource: "peer:source",
  grant: "peer:grant",
  nonce: "peer:nonce",
  renew: "peer:renew",
  peerSession: "peer:session",
  delivery: "peer:delivery",
  approval: "approval",
  uiSession: "ui:session",
  catalogCache: "catalog:cache",
  catalogEquivocation: "catalog:equivocation",
  cloudEnrollment: "cloud:enrollment",
  cloudPairing: "cloud:pairing",
  lifecycleJournal: "lifecycle:journal",
  lifecycleReceipt: "lifecycle:receipt",
  lifecycleOperation: "lifecycle:operation",
} as const;
export type DocKind = (typeof DOC)[keyof typeof DOC];

/** kv_meta keys for scalar durable state (journaled via "kv" mutations). */
export const KV = {
  syncRevision: "sync:revision",
  syncDocument: "sync:document",
  syncPausedPrefix: "sync:paused:",
  syncThroughPrefix: "sync:through:",
  syncConsentPrefix: "sync:consent:",
  catalogPins: "catalog:pins",
  catalogPinsRevision: "catalog:pins_revision",
  catalogHighest: "catalog:highest",
  catalogTimeHighWater: "catalog:time_high_water",
  cloudCurrent: "cloud:current",
  lifecycleRevision: "lifecycle:revision",
} as const;

// ── shared plumbing ─────────────────────────────────────────────────────

/**
 * The result hash every mutation-only commitSync carries: H(J(mutation)).
 * The marker is itself the evidence; the mutation digest binds it.
 */
function mutationDigest(mutation: Json): string {
  return sha256hex(canonicalJson(mutation));
}

/** Injected identity knobs shared by every synchronous port. */
export interface PortIdentity {
  /** Millisecond clock (defaults to Date.now). */
  now?: () => number;
  /** Control-id mint for newId() ports (defaults to crypto). */
  newId?: () => string;
  /** Kind-aware allocator for peer/approval ids. */
  ids?: IdAllocator;
  /** Secret entropy (tokens/nonces/pair codes). */
  entropy?: Entropy;
  /** Session epoch (boot-scoped) stamped on epoch-bound records. */
  epoch: string;
}

/**
 * Read-model over `store.registry` + synchronous `commitSync` mutations —
 * the base every domain adapter builds on.
 */
export class StoreBackedDocs {
  protected readonly gw: GatewayStore;
  protected readonly registry: Registry;
  readonly epoch: string;
  protected readonly nowFn: () => number;

  constructor(store: GatewayStore, identity: PortIdentity) {
    this.gw = store;
    this.registry = store.registry;
    this.epoch = identity.epoch;
    this.nowFn = identity.now ?? Date.now;
  }

  /**
   * Journal + apply one synchronous mutation; returns the tx so callers
   * can read back recorded outcomes (CAS results, one-use consumes).
   */
  commitSync(mutation: Json): string {
    return this.gw.commitSync({
      mutation,
      result_sha256: mutationDigest(mutation),
    }).tx;
  }

  protected docPut(kind: string, id: string, doc: Json | null): string {
    return this.commitSync({
      v: 1,
      kind: "docs",
      docs: [{ kind, id, doc }],
    });
  }

  protected docGetJson<T>(kind: string, id: string): T | null {
    const row = this.registry.docGet(kind, id);
    if (row === null) return null;
    return JSON.parse(row.doc_json) as T;
  }

  protected docList<T>(kind: string): T[] {
    return this.registry
      .docsList(kind)
      .map((r) => JSON.parse(r.doc_json) as T);
  }

  protected kvPut(key: string, value: string | null): string {
    return this.commitSync({
      v: 1,
      kind: "kv",
      entries: [{ key, value }],
    });
  }
}

// ── platform store (async commit path) ──────────────────────────────────

class StoreBackedPlatformRegistry implements PlatformRegistry {
  private readonly registry: Registry;
  constructor(registry: Registry) {
    this.registry = registry;
  }

  kvGet(key: string): Promise<string | null> {
    return Promise.resolve(this.registry.kvGet(key));
  }

  kvSet(key: string, value: string): Promise<void> {
    // Runtime meta (instance id, daemon state, config revision) — kv_meta
    // is durable and survives rebuilds; it is never journaled because it
    // is not evidence-bearing state (see PlatformRegistry.kvSet).
    this.registry.kvSet(key, value);
    return Promise.resolve();
  }

  private static eventRowToEntry(r: {
    workspace: string;
    source: string;
    stream: string;
    seq: string;
    hash: string;
    conflict: number;
    lane: string | null;
    raw_sha256?: string | null;
    topic?: string | null;
    profile?: string | null;
    media?: string | null;
    record_bytes?: string | null;
    cursor?: string | null;
    record_order?: number | null;
  }): PlatformEventEntry {
    return {
      workspace: r.workspace,
      source: r.source,
      stream: r.stream,
      seq: r.seq,
      hash: r.hash,
      raw_sha256: r.raw_sha256 ?? r.hash,
      topic: (r.topic ?? "") as PlatformEventEntry["topic"],
      profile: r.profile ?? "",
      media: (r.media ?? "application/json") as PlatformEventEntry["media"],
      record_bytes: r.record_bytes ?? "0",
      lane: r.lane ?? "",
      cursor: r.cursor ?? "",
      order: r.record_order ?? 0,
      conflict: r.conflict !== 0,
    };
  }

  eventSlot(
    workspace: string,
    source: string,
    stream: string,
    seq: string,
  ): Promise<PlatformEventEntry[]> {
    return Promise.resolve(
      this.registry
        .eventSlotV2(workspace, source, stream, seq)
        .map(StoreBackedPlatformRegistry.eventRowToEntry),
    );
  }

  eventByCursor(cursor: string): Promise<PlatformEventEntry | null> {
    const row = this.registry.eventByCursor(cursor);
    return Promise.resolve(
      row === null
        ? null
        : StoreBackedPlatformRegistry.eventRowToEntry(row),
    );
  }

  eventLane(
    workspace: string,
    source: string,
    stream: string,
  ): Promise<PlatformEventEntry[]> {
    return Promise.resolve(
      this.registry
        .eventLane(workspace, source, stream)
        .map(StoreBackedPlatformRegistry.eventRowToEntry),
    );
  }

  eventsByTopic(topic: string): Promise<PlatformEventEntry[]> {
    return Promise.resolve(
      this.registry
        .eventsByTopic(topic)
        .map(StoreBackedPlatformRegistry.eventRowToEntry),
    );
  }

  runGet(runId: string): Promise<PlatformRunEntry | null> {
    const row = this.registry.runV2Get(runId);
    if (row === null) return Promise.resolve(null);
    return Promise.resolve({
      run_id: row.run_id,
      owner: row.owner,
      kit: row.kit,
      state: row.state as PlatformRunEntry["state"],
      spool_seq: row.spool_seq,
      exit_code: row.exit_code,
      signal: row.signal,
      pending_sync: row.pending_sync,
    });
  }

  operationGet(id: string): Promise<PlatformOperationEntry | null> {
    const row = this.registry.operationV2Get(id);
    if (row === null) return Promise.resolve(null);
    return Promise.resolve({
      id: row.id,
      principal: row.principal,
      kind: row.kind,
      state: row.state,
      slug: row.slug,
      from: row.from_v,
      to: row.to_v,
      cursor: row.cursor,
      error:
        row.error_json === null
          ? null
          : (JSON.parse(row.error_json) as PlatformOperationEntry["error"]),
    });
  }

  private static subRowToEntry(r: {
    id: string;
    owner: string | null;
    cursor: string | null;
    state: string;
    topics_json: string | null;
    position: number;
    delivered: number;
    expires_ms: number | null;
  }): PlatformSubscriptionEntry {
    let topics: string[] = [];
    if (r.topics_json !== null) {
      try {
        const t = JSON.parse(r.topics_json) as unknown;
        if (Array.isArray(t)) topics = t.filter((x): x is string => typeof x === "string");
      } catch {
        /* malformed filter → no topics */
      }
    }
    return {
      id: r.id,
      owner: r.owner ?? "",
      topics: topics as PlatformSubscriptionEntry["topics"],
      position: r.position,
      cursor: r.cursor ?? "",
      delivered: r.delivered,
      expires_ms: r.expires_ms ?? 0,
      state: r.state === "CLOSED" ? "CLOSED" : "OPEN",
    };
  }

  subscriptionGet(id: string): Promise<PlatformSubscriptionEntry | null> {
    const row = this.registry.subscriptionV2Get(id);
    return Promise.resolve(
      row === null
        ? null
        : StoreBackedPlatformRegistry.subRowToEntry(row),
    );
  }

  subscriptionsByOwner(
    owner: string,
  ): Promise<PlatformSubscriptionEntry[]> {
    return Promise.resolve(
      this.registry
        .subscriptionsV2ByOwner(owner)
        .map(StoreBackedPlatformRegistry.subRowToEntry),
    );
  }

  sourceGet(source: string): Promise<PlatformSourceEntry | null> {
    const row = this.registry.sourceGet(source);
    if (row === null) return Promise.resolve(null);
    return Promise.resolve({
      source: row.source,
      key_id: row.key_id,
      public: row.public as PlatformSourceEntry["public"],
      owner: row.owner,
    });
  }

  private static actionRowToEntry(r: {
    key: string;
    pointer_json: string;
    native_json: string;
    previous_json: string;
    principal: string;
    method: string;
  }): PlatformActionEntry {
    return {
      key: r.key,
      pointer: JSON.parse(r.pointer_json) as PlatformActionEntry["pointer"],
      nativeRef: JSON.parse(r.native_json) as PlatformActionEntry["nativeRef"],
      previous:
        r.previous_json === "null"
          ? null
          : (JSON.parse(r.previous_json) as PlatformActionEntry["previous"]),
      principal: r.principal,
      method: r.method,
    };
  }

  actionGet(key: string): Promise<PlatformActionEntry | null> {
    const row = this.registry.actionGet(key);
    return Promise.resolve(
      row === null
        ? null
        : StoreBackedPlatformRegistry.actionRowToEntry(row),
    );
  }

  actionByNativeId(objectId: string): Promise<PlatformActionEntry | null> {
    const row = this.registry.actionByObjectId(objectId);
    return Promise.resolve(
      row === null
        ? null
        : StoreBackedPlatformRegistry.actionRowToEntry(row),
    );
  }

  countProducts(): Promise<number> {
    return Promise.resolve(this.registry.countProductsInstalled());
  }

  countPeers(): Promise<number> {
    return Promise.resolve(this.registry.countPeers());
  }
}

class StoreBackedPlatformStore implements PlatformStore {
  private readonly store: GatewayStore;
  readonly registry: PlatformRegistry;

  constructor(store: GatewayStore) {
    this.store = store;
    this.registry = new StoreBackedPlatformRegistry(store.registry);
  }

  async commit(input: PlatformCommitInput): Promise<PlatformCommitResult> {
    const r = await this.store.commit({
      records: input.records?.map((rec) => ({
        lane: rec.lane,
        partition: rec.partition,
        data: rec.data,
      })),
      objects: input.objects,
      mutation: input.mutation as Json,
      result_sha256: input.result_sha256,
    });
    return { tx: r.tx, cursors: r.cursors };
  }

  async *laneScan(
    lane: string,
    after?: string | null,
    limit?: number,
  ): AsyncIterable<PlatformLaneRecord> {
    const opts: { from?: string; limit?: number } = {};
    if (after !== undefined && after !== null) opts.from = after;
    if (limit !== undefined) opts.limit = limit;
    for await (const rec of this.store.laneScan(lane, opts)) {
      yield {
        lane,
        cursor: rec.cursor,
        data: rec.data,
        order: rec.order,
      };
    }
  }

  laneHead(lane: string): Promise<PlatformLaneHead> {
    return this.store.laneHead(lane);
  }

  resolveCursor(cursor: string): Promise<PlatformCursorResolution | null> {
    return this.store.resolveCursor(cursor);
  }

  peekNextCursor(lane: string): Promise<string | null> {
    return this.store.peekNextCursor(lane);
  }

  globalHead(): Promise<{ order: number; cursor: string | null }> {
    return this.store.globalHead();
  }

  getRecord(cursor: string): Promise<Uint8Array | null> {
    return this.store.getRecord(cursor);
  }

  async getObject(digest: string): Promise<Uint8Array> {
    return this.store.getObject(digest);
  }

  async putObject(
    bytes: Uint8Array,
    maxBytes: number,
  ): Promise<{ digest: string; bytes: number }> {
    if (bytes.length > maxBytes) {
      throw new RpcError("OBJECT_LIMIT", "object exceeds bound", {
        field: "blob",
      });
    }
    return this.store.putObject(bytes);
  }
}

// ── platform session/bootstrap store (durable, epoch-scoped) ────────────

class StoreBackedSessionStore
  extends StoreBackedDocs
  implements PlatformSessionStore
{
  bootstrapPut(record: PlatformBootstrapRecord): Promise<void> {
    this.commitSync({
      v: 1,
      kind: "bootstraps",
      bootstraps: [
        {
          hash: record.hash,
          role: record.role,
          expires_ms: record.expires_ms,
          consumed: false,
          epoch: this.epoch,
        },
      ],
    });
    return Promise.resolve();
  }

  bootstrapTake(hash: string): Promise<PlatformBootstrapRecord | null> {
    // Atomic one-use consume: the journal marker + conditional update land
    // in one commit; the outcome is read back from the recorded kv flag.
    const tx = this.commitSync({
      v: 1,
      kind: "bootstrap_take",
      hash,
      epoch: this.epoch,
    });
    if (this.registry.kvGet(`bootstrap:took:${tx}`) !== "1") {
      return Promise.resolve(null);
    }
    const row = this.registry.bootstrapGet(hash);
    if (row === null) return Promise.resolve(null);
    return Promise.resolve({
      hash: row.hash,
      role: row.role === "operator" ? "operator" : "viewer",
      expires_ms: row.expires_ms,
    });
  }

  sessionPut(record: PlatformSessionRecord): Promise<void> {
    this.docPut(DOC.uiSession, `${this.epoch}:${record.hash}`, {
      ...record,
      epoch: this.epoch,
    });
    return Promise.resolve();
  }

  sessionGet(hash: string): Promise<PlatformSessionRecord | null> {
    // The epoch prefix binds the record to this boot — sessions never
    // resurrect across a restart (spec §4.2).
    return Promise.resolve(
      this.docGetJson<PlatformSessionRecord>(
        DOC.uiSession,
        `${this.epoch}:${hash}`,
      ),
    );
  }

  sessionRevoke(hash: string): Promise<void> {
    const id = `${this.epoch}:${hash}`;
    const rec = this.docGetJson<PlatformSessionRecord>(DOC.uiSession, id);
    if (rec === null) return Promise.resolve();
    this.docPut(DOC.uiSession, id, { ...rec, state: "REVOKED" });
    return Promise.resolve();
  }
}

// ── peer ports (synchronous, durable) ───────────────────────────────────

class StoreBackedPeerPorts extends StoreBackedDocs implements PeerPorts {
  private readonly ids: IdAllocator;
  readonly entropy: Entropy;

  constructor(
    store: GatewayStore,
    identity: PortIdentity & { ids: IdAllocator; entropy: Entropy },
  ) {
    super(store, identity);
    this.ids = identity.ids;
    this.entropy = identity.entropy;
  }

  now(): number {
    return this.nowFn();
  }

  newId(kind: string): string {
    return this.ids.next(kind);
  }

  putPair(rec: PairRecord): void {
    this.docPut(DOC.pair, rec.pair, rec as unknown as Json);
  }
  getPair(pair: string): PairRecord | null {
    return this.docGetJson(DOC.pair, pair);
  }
  listPairs(): PairRecord[] {
    return this.docList(DOC.pair);
  }
  updatePair(rec: PairRecord): void {
    this.docPut(DOC.pair, rec.pair, rec as unknown as Json);
  }

  putChallenge(rec: ChallengeRecord): void {
    this.docPut(DOC.challenge, rec.challenge, rec as unknown as Json);
  }
  getChallenge(challenge: string): ChallengeRecord | null {
    return this.docGetJson(DOC.challenge, challenge);
  }
  updateChallenge(rec: ChallengeRecord): void {
    this.docPut(DOC.challenge, rec.challenge, rec as unknown as Json);
  }

  putPeer(rec: StoredPeer): void {
    this.docPut(DOC.peer, rec.id, rec as unknown as Json);
  }
  getPeer(peer: string): StoredPeer | null {
    return this.docGetJson(DOC.peer, peer);
  }
  updatePeer(rec: StoredPeer): void {
    this.docPut(DOC.peer, rec.id, rec as unknown as Json);
  }
  listPeers(): StoredPeer[] {
    return this.docList(DOC.peer);
  }
  peerByKey(key: string): StoredPeer | null {
    for (const p of this.docList<StoredPeer>(DOC.peer)) {
      if (p.key === key) return p;
    }
    return null;
  }
  sourceForKey(key: string): string | null {
    const doc = this.docGetJson<{ source: string }>(DOC.peerSource, key);
    return doc?.source ?? null;
  }
  putSource(key: string, source: string): void {
    this.docPut(DOC.peerSource, key, { source });
  }

  putGrant(rec: GrantRecord): void {
    this.docPut(DOC.grant, rec.grant, rec as unknown as Json);
  }
  grantByAccessHash(hash: string): GrantRecord | null {
    for (const g of this.docList<GrantRecord>(DOC.grant)) {
      if (g.access_hash === hash) return g;
    }
    return null;
  }
  grantByRefreshHash(hash: string): GrantRecord | null {
    for (const g of this.docList<GrantRecord>(DOC.grant)) {
      if (g.refresh_hash === hash) return g;
    }
    return null;
  }
  updateGrant(rec: GrantRecord): void {
    this.docPut(DOC.grant, rec.grant, rec as unknown as Json);
  }
  grantsByPeer(peer: string): GrantRecord[] {
    return this.docList<GrantRecord>(DOC.grant).filter((g) => g.peer === peer);
  }
  grantsByFamily(family: string): GrantRecord[] {
    return this.docList<GrantRecord>(DOC.grant).filter(
      (g) => g.family === family,
    );
  }

  hasNonce(tokenHash: string, nonce: string): boolean {
    const rec = this.docGetJson<{ expires_ms: number }>(
      DOC.nonce,
      `${tokenHash}:${nonce}`,
    );
    return rec !== null && rec.expires_ms > this.nowFn();
  }
  putNonce(tokenHash: string, nonce: string, expires_ms: number): void {
    this.docPut(DOC.nonce, `${tokenHash}:${nonce}`, {
      token_hash: tokenHash,
      nonce,
      expires_ms,
    });
  }

  putRenewReplay(rec: RenewReplayRecord): void {
    this.docPut(DOC.renew, rec.key, rec as unknown as Json);
  }
  getRenewReplay(key: string): RenewReplayRecord | null {
    return this.docGetJson(DOC.renew, key);
  }

  putSession(rec: PeerSessionRecord): void {
    this.docPut(DOC.peerSession, rec.session, rec as unknown as Json);
  }
  getSession(session: string): PeerSessionRecord | null {
    return this.docGetJson(DOC.peerSession, session);
  }
  updateSession(rec: PeerSessionRecord): void {
    this.docPut(DOC.peerSession, rec.session, rec as unknown as Json);
  }
  sessionsByPeer(peer: string): PeerSessionRecord[] {
    return this.docList<PeerSessionRecord>(DOC.peerSession).filter(
      (s) => s.peer === peer,
    );
  }

  putDelivery(rec: DeliveryRecord): void {
    this.docPut(DOC.delivery, rec.delivery, rec as unknown as Json);
  }
  updateDelivery(rec: DeliveryRecord): void {
    this.docPut(DOC.delivery, rec.delivery, rec as unknown as Json);
  }
  deliveriesByPeer(peer: string): DeliveryRecord[] {
    return this.docList<DeliveryRecord>(DOC.delivery).filter(
      (d) => d.peer === peer,
    );
  }
}

// ── approval ports ──────────────────────────────────────────────────────

class StoreBackedApprovalPorts
  extends StoreBackedDocs
  implements ApprovalPorts
{
  private readonly ids: IdAllocator;
  readonly entropy: Entropy;

  constructor(
    store: GatewayStore,
    identity: PortIdentity & { ids: IdAllocator; entropy: Entropy },
  ) {
    super(store, identity);
    this.ids = identity.ids;
    this.entropy = identity.entropy;
  }

  now(): number {
    return this.nowFn();
  }

  newId(kind: "approval"): string {
    return this.ids.next(kind);
  }

  putApproval(rec: ApprovalRecord): void {
    this.docPut(DOC.approval, rec.approval, rec as unknown as Json);
  }
  getApproval(approval: string): ApprovalRecord | null {
    return this.docGetJson(DOC.approval, approval);
  }
  updateApproval(rec: ApprovalRecord): void {
    this.docPut(DOC.approval, rec.approval, rec as unknown as Json);
  }
  listApprovals(): ApprovalRecord[] {
    return this.docList(DOC.approval);
  }
}

// ── product registry (lifecycle generations) ────────────────────────────

class StoreBackedProductRegistry
  extends StoreBackedDocs
  implements ProductRegistryPort
{
  private static rowFromDoc(r: {
    row_json: string;
  }): GenerationRow {
    return JSON.parse(r.row_json) as GenerationRow;
  }

  generations(slug: string): GenerationRow[] {
    return this.registry
      .lifecycleGenerations(slug)
      .map(StoreBackedProductRegistry.rowFromDoc);
  }

  all(): GenerationRow[] {
    return this.registry
      .lifecycleGenerationsAll()
      .map(StoreBackedProductRegistry.rowFromDoc);
  }

  get(slug: string, generation: string): GenerationRow | undefined {
    const row = this.registry.lifecycleGenerationGet(slug, generation);
    return row === null
      ? undefined
      : StoreBackedProductRegistry.rowFromDoc(row);
  }

  create(row: GenerationRow): GenerationRow {
    this.commitSync({
      v: 1,
      kind: "lifecycle",
      upserts: [
        {
          slug: row.slug,
          generation: row.generation,
          row: row as unknown as Json,
        },
      ],
    });
    return row;
  }

  update(
    slug: string,
    generation: string,
    patch: Partial<GenerationRow>,
  ): void {
    const cur = this.get(slug, generation);
    if (cur === undefined) return;
    const next = { ...cur, ...patch, slug, generation };
    this.commitSync({
      v: 1,
      kind: "lifecycle",
      upserts: [
        { slug, generation, row: next as unknown as Json },
      ],
    });
  }

  active(slug: string): GenerationRow | undefined {
    return this.generations(slug).find((g) => g.active === true);
  }

  casActive(
    slug: string,
    expected: string | null,
    next: string | null,
  ): boolean {
    const tx = this.commitSync({
      v: 1,
      kind: "lifecycle",
      cas: { slug, expected, next },
    });
    return this.registry.kvGet(`lifecycle:cas:${tx}`) === "1";
  }

  nextGeneration(slug: string): string {
    let max = 0n;
    for (const g of this.generations(slug)) {
      const n = BigInt(g.generation);
      if (n > max) max = n;
    }
    return (max + 1n).toString();
  }

  revision(): string {
    return this.registry.lifecycleRevision();
  }
}

// ── catalog ports (trust-configured; fetch injected, none bound) ────────

export interface CatalogSourcePorts {
  /** Injected bounded fetch — absent ⇒ NETWORK_UNAVAILABLE. */
  fetchIndex?: (source: string) => Promise<IndexFetch>;
  /** Enterprise offline snapshot enrolled out of band. */
  offlineSnapshot?: () => IndexFetch | null;
  /** The configured trust view (roots come from trust config). */
  trust: () => CatalogTrustView;
  /** Configured catalog pins + CAS revision from the live config. */
  configuredPins: () => { pins: CatalogPin[]; revision: string };
}

class StoreBackedCatalogPorts
  extends StoreBackedDocs
  implements CatalogPorts
{
  private readonly source: CatalogSourcePorts;
  constructor(
    store: GatewayStore,
    identity: PortIdentity,
    source: CatalogSourcePorts,
  ) {
    super(store, identity);
    this.source = source;
  }

  now(): number {
    return this.nowFn();
  }
  trust(): CatalogTrustView {
    return this.source.trust();
  }

  loadCache(): CachedIndex | null {
    return this.docGetJson<CachedIndex>(DOC.catalogCache, "current");
  }
  saveCache(cache: CachedIndex): void {
    this.docPut(DOC.catalogCache, "current", cache as unknown as Json);
  }

  highestSeen(): { revision: string; digest: string } | null {
    const raw = this.registry.kvGet(KV.catalogHighest);
    if (raw === null) return null;
    try {
      return JSON.parse(raw) as { revision: string; digest: string };
    } catch {
      return null;
    }
  }
  saveHighestSeen(revision: string, digest: string): void {
    this.kvPut(KV.catalogHighest, JSON.stringify({ revision, digest }));
  }

  recordEquivocation(e: Equivocation): void {
    this.docPut(
      DOC.catalogEquivocation,
      `${e.revision}:${e.candidate}`,
      e as unknown as Json,
    );
  }
  equivocations(): readonly Equivocation[] {
    return this.docList<Equivocation>(DOC.catalogEquivocation);
  }

  pins(): CatalogPin[] {
    const raw = this.registry.kvGet(KV.catalogPins);
    if (raw !== null) {
      try {
        return JSON.parse(raw) as CatalogPin[];
      } catch {
        /* fall through to configured */
      }
    }
    return this.source.configuredPins().pins;
  }
  pinsRevision(): string {
    const raw = this.registry.kvGet(KV.catalogPinsRevision);
    return raw ?? this.source.configuredPins().revision;
  }
  setPins(pins: CatalogPin[], revision: string): void {
    this.commitSync({
      v: 1,
      kind: "kv",
      entries: [
        { key: KV.catalogPins, value: JSON.stringify(pins) },
        { key: KV.catalogPinsRevision, value: revision },
      ],
    });
  }

  fetchIndex(source: string): Promise<IndexFetch> {
    if (this.source.fetchIndex === undefined) {
      return Promise.reject(
        new RpcError(
          "NETWORK_UNAVAILABLE",
          "no catalog fetch adapter is bound on this host",
          { field: "source" },
        ),
      );
    }
    return this.source.fetchIndex(source);
  }
  offlineSnapshot(): IndexFetch | null {
    return this.source.offlineSnapshot?.() ?? null;
  }

  timeHighWater(): number {
    const raw = this.registry.kvGet(KV.catalogTimeHighWater);
    const n = raw === null ? 0 : Number(raw);
    return Number.isSafeInteger(n) && n >= 0 ? n : 0;
  }
  saveTimeHighWater(ms: number): void {
    const cur = this.timeHighWater();
    if (ms > cur) this.kvPut(KV.catalogTimeHighWater, String(ms));
  }
}

// ── cloud ports (local pairing state; remote notice when unpaired) ──────

export interface CloudRuntimePorts {
  /** The `gateway.ui.remote` local grant flag from live config. */
  uiRemoteGranted: () => boolean;
  /** Pinned provider bindings by provider name (enrolled out of band). */
  providers: () => ReadonlyMap<string, ProviderBinding>;
  /** Remote revoke notice delivery — absent ⇒ notice stays QUEUED. */
  notifyRevocation?: (cloud: CloudPairing) => Promise<boolean>;
}

class StoreBackedCloudPorts extends StoreBackedDocs implements CloudPorts {
  private readonly runtime: CloudRuntimePorts;
  private readonly entropy: Entropy;
  constructor(
    store: GatewayStore,
    identity: PortIdentity & { entropy: Entropy; ids: IdAllocator },
    runtime: CloudRuntimePorts,
  ) {
    super(store, identity);
    this.runtime = runtime;
    this.entropy = identity.entropy;
    this.ids = identity.ids;
  }

  now(): number {
    return this.nowFn();
  }
  newId(): string {
    return this.ids.next("cloud");
  }
  pairCode(): string {
    return this.entropy.pairCode();
  }
  private readonly ids: IdAllocator;

  uiRemoteGranted(): boolean {
    return this.runtime.uiRemoteGranted();
  }
  providers(): ReadonlyMap<string, ProviderBinding> {
    return this.runtime.providers();
  }
  enrollmentTtlMs(): number {
    return 300_000;
  }

  getEnrollment(id: string): CloudEnrollment | undefined {
    return this.docGetJson<CloudEnrollment>(DOC.cloudEnrollment, id) ?? undefined;
  }
  putEnrollment(enrollment: CloudEnrollment): void {
    this.docPut(
      DOC.cloudEnrollment,
      enrollment.id,
      enrollment as unknown as Json,
    );
  }

  getCloud(id: string): CloudPairing | undefined {
    return this.docGetJson<CloudPairing>(DOC.cloudPairing, id) ?? undefined;
  }
  putCloud(cloud: CloudPairing): void {
    this.commitSync({
      v: 1,
      kind: "batch",
      mutations: [
        {
          v: 1,
          kind: "docs",
          docs: [
            {
              kind: DOC.cloudPairing,
              id: cloud.id,
              doc: cloud as unknown as Json,
            },
          ],
        },
        // Single active pairing pointer: revocations null it locally even
        // when the remote notice cannot be delivered (§9.3).
        {
          v: 1,
          kind: "kv",
          entries: [
            {
              key: KV.cloudCurrent,
              value: cloud.state === "PAIRED" ? cloud.id : null,
            },
          ],
        },
      ],
    });
  }
  currentCloud(): CloudPairing | undefined {
    const id = this.registry.kvGet(KV.cloudCurrent);
    return id === null ? undefined : this.getCloud(id);
  }

  notifyRevocation(cloud: CloudPairing): Promise<boolean> {
    if (this.runtime.notifyRevocation === undefined) {
      return Promise.resolve(false); // stays QUEUED — never fabricated
    }
    return this.runtime.notifyRevocation(cloud);
  }
}

// ── sync ports (outbox + consent + pause + acked-through) ───────────────

export interface SyncRuntimePorts {
  /** Global sync.paused flag from the applied config document. */
  syncPaused: () => boolean;
  /** Current sync-config CAS revision. */
  syncRevision: () => string;
  /** Apply a validated sync document at the next revision (CAS write). */
  applySync: (document: JsonObject, revision: string) => void;
  /** Current cloud pairing for status reporting. */
  cloud: () => { id: string; state: string } | null;
  /** Configured consent source (config streams → StreamConsent). */
  configuredConsent: (stream: StreamName) => StreamConsent | undefined;
  /** Destination adapter lookup — absent ⇒ BLOCKED / CAP_ADAPTER_UNAVAILABLE. */
  sink?: (destination: string) => SinkAdapter | undefined;
  /** Whether the daemon's admitted sync cut is provably known. */
  daemonStatus?: () => "known" | "unknown";
  /** Cooperative wait used by flush/pump loops. */
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  newId?: () => string;
}

class StoreBackedOutboxStore implements SyncOutboxStore {
  private readonly docs: StoreBackedDocs;
  private readonly registry: Registry;
  constructor(docs: StoreBackedDocs, registry: Registry) {
    this.docs = docs;
    this.registry = registry;
  }

  all(): SyncOutboxItem[] {
    return this.registry
      .outboxWhere("1 = 1")
      .map((r) => JSON.parse(r.item_json) as SyncOutboxItem);
  }
  get(id: string): SyncOutboxItem | undefined {
    const row = this.registry.outboxGet(id);
    return row === null
      ? undefined
      : (JSON.parse(row.item_json) as SyncOutboxItem);
  }
  put(item: SyncOutboxItem): void {
    this.docs.commitSync({
      v: 1,
      kind: "outbox",
      items: [
        {
          id: item.id,
          destination: item.destination,
          cohort: item.cohort,
          stream: item.stream,
          batch_hash: null,
          state: item.state,
          item: item as unknown as Json,
        },
      ],
    });
  }
}

class StoreBackedSyncPorts extends StoreBackedDocs implements SyncPorts {
  private readonly runtime: SyncRuntimePorts;
  private readonly outbox: StoreBackedOutboxStore;
  readonly store: SyncOutboxStore;

  constructor(
    store: GatewayStore,
    identity: PortIdentity & { ids: IdAllocator },
    runtime: SyncRuntimePorts,
  ) {
    super(store, identity);
    this.runtime = runtime;
    this.syncIds = identity.ids;
    this.outbox = new StoreBackedOutboxStore(this, this.registry);
    this.store = this.outbox;
  }

  now(): number {
    return this.nowFn();
  }
  newId(): string {
    return (
      this.runtime.newId?.() ?? this.syncIds.next("sync")
    );
  }
  private readonly syncIds: IdAllocator;
  random(): number {
    return this.runtime.random?.() ?? Math.random();
  }
  sleep(ms: number): Promise<void> {
    if (this.runtime.sleep !== undefined) return this.runtime.sleep(ms);
    return new Promise((r) => setTimeout(r, ms));
  }

  consent(stream: StreamName): StreamConsent | undefined {
    const raw = this.registry.kvGet(`${KV.syncConsentPrefix}${stream}`);
    if (raw !== null) {
      try {
        return JSON.parse(raw) as StreamConsent;
      } catch {
        /* fall through to configured */
      }
    }
    return this.runtime.configuredConsent(stream);
  }

  sink(destination: string): SinkAdapter | undefined {
    return this.runtime.sink?.(destination);
  }

  isPaused(stream: StreamName): boolean {
    return this.registry.kvGet(`${KV.syncPausedPrefix}${stream}`) === "1";
  }
  setPaused(stream: StreamName, paused: boolean): void {
    this.kvPut(`${KV.syncPausedPrefix}${stream}`, paused ? "1" : "0");
  }

  ackedThrough(stream: StreamName): string | undefined {
    return this.registry.kvGet(`${KV.syncThroughPrefix}${stream}`) ?? undefined;
  }
  setAckedThrough(stream: StreamName, through: string): void {
    this.kvPut(`${KV.syncThroughPrefix}${stream}`, through);
  }

  daemonStatus(): "known" | "unknown" {
    return this.runtime.daemonStatus?.() ?? "known";
  }
}

// ── peer-token bridge for the dispatcher ────────────────────────────────

/**
 * Bridges the dispatcher's `PeerTokenStore` (token-hash → grant binding)
 * onto the durable peer ports: access-token hashes resolve to their grant
 * row, the peer row supplies the enrolled public key, and nonces replay
 * through the durable nonce documents.
 */
export class DurablePeerTokenStore implements PeerTokenStore {
  private readonly ports: StoreBackedPeerPorts;
  constructor(ports: StoreBackedPeerPorts) {
    this.ports = ports;
  }

  lookupAccess(tokenSha256: string): PeerGrant | null {
    const grant = this.ports.grantByAccessHash(tokenSha256);
    if (grant === null) return null;
    const peer = this.ports.getPeer(grant.peer);
    if (peer === null) return null;
    const reviewer = peer.capabilities.some(
      (c) => c.name === "reviewer" || c.name === "approvals.review",
    );
    return {
      peer: grant.peer,
      publicKey: peer.key_material.public,
      role: grant.role,
      scopes: grant.scopes,
      expires_ms: grant.access_expires_ms,
      revoked: grant.state !== "ACTIVE" || peer.state === "REVOKED",
      epoch: String(grant.epoch),
      reviewer,
    };
  }

  nonceSeen(peer: string, nonce: string, untilMs: number): boolean {
    // Nonces are keyed by token hash in the durable store; the dispatcher
    // tracks them per peer — use the peer id as the key namespace, which
    // is at least as strict (§4.3 replay is per-grant in practice).
    if (this.ports.hasNonce(peer, nonce)) return true;
    this.ports.putNonce(peer, nonce, untilMs);
    return false;
  }
}

// ── assembled surface ───────────────────────────────────────────────────

export interface StorePorts {
  readonly store: PlatformStore;
  readonly sessionStore: PlatformSessionStore;
  readonly peers: StoreBackedPeerPorts;
  readonly approvals: StoreBackedApprovalPorts;
  readonly productRegistry: StoreBackedProductRegistry;
  readonly catalog: StoreBackedCatalogPorts;
  readonly cloud: StoreBackedCloudPorts;
  readonly sync: StoreBackedSyncPorts;
  /** Dispatcher-facing peer token/nonce store. */
  readonly peerTokens: DurablePeerTokenStore;
}

export interface StorePortsDeps {
  identity: PortIdentity & { ids: IdAllocator; entropy: Entropy };
  catalog: CatalogSourcePorts;
  cloud: CloudRuntimePorts;
  sync: SyncRuntimePorts;
}

/** Adapt one open `GatewayStore` to every injected core port. */
export function createStorePorts(
  store: GatewayStore,
  deps: StorePortsDeps,
): StorePorts {
  const sessionStore = new StoreBackedSessionStore(store, deps.identity);
  const peers = new StoreBackedPeerPorts(store, deps.identity);
  const approvals = new StoreBackedApprovalPorts(store, deps.identity);
  const productRegistry = new StoreBackedProductRegistry(store, deps.identity);
  const catalog = new StoreBackedCatalogPorts(store, deps.identity, deps.catalog);
  const cloud = new StoreBackedCloudPorts(store, deps.identity, deps.cloud);
  const sync = new StoreBackedSyncPorts(store, deps.identity, deps.sync);
  return {
    store: new StoreBackedPlatformStore(store),
    sessionStore,
    peers,
    approvals,
    productRegistry,
    catalog,
    cloud,
    sync,
    peerTokens: new DurablePeerTokenStore(peers),
  };
}
