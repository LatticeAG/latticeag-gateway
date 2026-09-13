/**
 * Runtime plumbing shared by the daemon lifecycle: boot identity, session
 * epoch, endpoints.json publication, the audit signing key, the durable
 * receipt writer, the registry-backed idempotency lookup, and metrics.
 *
 * Nothing here touches src/store internals — every durable write goes
 * through `GatewayStore.commit` (objects → lane records → journal marker →
 * registry mutation, in §2.3 order) and every read goes through the public
 * store/registry surface.
 */
import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import { readFile, writeFile, chmod, rename, unlink, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { ensureDir, pathExists } from "./store/util.js";
import type { GatewayStore } from "./store/store.js";
import type { Registry, RegistryMutation } from "./store/registry.js";
import type { Json as StoreJson } from "./store/util.js";
import {
  GENESIS_PREV,
  canonicalJson,
  eventRefOf,
  keyIdOfPublic,
  newControlId,
  proofBody,
  sealProofEvent,
  sha256Hex,
  type ProofEvent,
} from "./core-v2.js";
import type {
  AuditAction,
  IdempotencyLookup,
  ReceiptPointer,
  ReceiptWriter,
  SavedBinding,
} from "./rpc/dispatch.js";
import type { SseFrame, SseRegistry, SseSource, SseSubscription } from "./net/sse.js";

// ── endpoints.json ───────────────────────────────────────────────────────

/** `endpoints.json` contents — discovery + the lock-contender handoff. */
export interface EndpointsFile {
  pid: number;
  instance: string;
  boot_id: string | null;
  process_start: string | null;
  control_sock: string;
  ui_url: string | null;
}

export async function writeEndpoints(
  runtimeDir: string,
  ep: EndpointsFile,
): Promise<void> {
  await ensureDir(runtimeDir);
  const tmp = join(runtimeDir, `.endpoints.json.tmp-${process.pid}`);
  const final = join(runtimeDir, "endpoints.json");
  await writeFile(tmp, JSON.stringify(ep, null, 2) + "\n", { mode: 0o600 });
  await rename(tmp, final);
}

export async function readEndpoints(
  runtimeDir: string,
): Promise<EndpointsFile | null> {
  try {
    const raw = await readFile(join(runtimeDir, "endpoints.json"), "utf8");
    const ep = JSON.parse(raw) as EndpointsFile;
    if (typeof ep.pid !== "number" || typeof ep.control_sock !== "string") {
      return null;
    }
    return ep;
  } catch {
    return null;
  }
}

export async function removeEndpoints(runtimeDir: string): Promise<void> {
  try {
    await unlink(join(runtimeDir, "endpoints.json"));
  } catch {
    /* absent is fine */
  }
}

// ── session epoch ────────────────────────────────────────────────────────

/**
 * Bump the per-boot session epoch (§4.2): every boot invalidates sessions,
 * bootstraps, challenges, and invitations. The counter lives in durable
 * kv_meta so epochs never repeat even across runtime restores.
 */
export function nextSessionEpoch(store: GatewayStore): string {
  const current = store.kv.get("session_epoch_counter");
  const n = (current !== null && /^[0-9]+$/.test(current) ? Number(current) : 0) + 1;
  store.kv.set("session_epoch_counter", String(n));
  return `e${n.toString(16)}-${newControlId().slice(1)}`;
}

// ── audit signing key ────────────────────────────────────────────────────

const PKCS8_ED25519_SEED_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/**
 * Load or create the daemon-local Ed25519 audit key under
 * `<keysDir>/audit.seed` (0600). The key never leaves the node; the Proof
 * body `key` field is `keyIdOfPublic(publicKey)`.
 */
export async function loadOrCreateAuditKey(keysDir: string): Promise<KeyObject> {
  await mkdir(keysDir, { recursive: true, mode: 0o700 });
  const seedPath = join(keysDir, "audit.seed");
  if (await pathExists(seedPath)) {
    const raw = (await readFile(seedPath, "utf8")).trim();
    const seed = Buffer.from(raw, "base64url");
    if (seed.length !== 32) {
      throw Object.assign(new Error("audit key seed is malformed"), {
        code: "CORRUPT",
      });
    }
    return createPrivateKey({
      key: Buffer.concat([PKCS8_ED25519_SEED_PREFIX, seed]),
      format: "der",
      type: "pkcs8",
    });
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  const seed = der.subarray(der.length - 32);
  await writeFile(seedPath, seed.toString("base64url") + "\n", {
    mode: 0o600,
  });
  await chmod(seedPath, 0o600);
  return privateKey;
}

// ── audit receipt writer ─────────────────────────────────────────────────

export interface AuditReceiptWriterOptions {
  /** Audit stream id — receipts point at `{source,stream,seq,hash}`. */
  stream?: string;
  /** Proof partition (the `proof/<partition>` lane key). */
  partition?: string;
  /** Event source id. */
  source?: string;
  /** Workspace stamped on each Proof body. */
  workspace?: string;
}

/**
 * Seals each §3.1 action record into a Proof event on `gateway.action` and
 * durably commits it — lane record + optional operations-table idempotency
 * binding in ONE commit — through `GatewayStore.commit`.
 *
 * The writer owns the audit lane's chain head (seq/prev/lamport); sealing
 * and committing happen inside one serialized queue so concurrent RPCs can
 * never seal the same seq or write a prev link out of order.
 */
export class AuditReceiptWriter implements ReceiptWriter {
  private readonly store: GatewayStore;
  private readonly key: KeyObject;
  private readonly keyId: string;
  private readonly source: string;
  private readonly stream: string;
  private readonly partition: string;
  private readonly workspace: string;
  private seq: bigint = 0n;
  private prev: string = GENESIS_PREV;
  private lamport: bigint = 0n;
  private tail: Promise<ReceiptPointer> | Promise<void> = Promise.resolve();

  constructor(
    store: GatewayStore,
    key: KeyObject,
    opts: AuditReceiptWriterOptions = {},
  ) {
    this.store = store;
    this.key = key;
    this.keyId = keyIdOfPublic(createPublicKey(key));
    this.source = opts.source ?? "gateway";
    this.stream = opts.stream ?? "audit";
    this.partition = opts.partition ?? "audit";
    this.workspace = opts.workspace ?? "daemon";
  }

  /**
   * Re-derive the chain head from the persisted lane tail so restarts
   * continue the same audit stream (prev/seq/lamport resume).
   */
  async resume(): Promise<void> {
    let last: ProofEvent | null = null;
    for await (const rec of this.store.laneScan(`proof/${this.partition}`)) {
      try {
        last = JSON.parse(rec.data.toString("utf8")) as ProofEvent;
      } catch {
        /* torn tail was already recovered by the store */
      }
    }
    if (last !== null) {
      this.seq = BigInt(last.body.seq);
      this.prev = last.hash;
      this.lamport = BigInt(last.body.lamport);
    }
  }

  /**
   * Seal `action` at the current head and commit it (plus the idempotency
   * binding) in one store commit. Serialized through `tail`.
   */
  commitAction(
    action: AuditAction,
    bind: {
      principalKey: string;
      id: string;
      requestHash: string;
      makeResultJson: (receipt: ReceiptPointer) => string;
    } | null,
  ): Promise<ReceiptPointer> {
    const run = async (): Promise<ReceiptPointer> => {
      const seq = this.seq + 1n;
      const lamport = this.lamport + 1n;
      const body = proofBody({
        workspace: this.workspace,
        source: this.source,
        stream: this.stream,
        seq: seq.toString(),
        prev: this.prev,
        lamport: lamport.toString(),
        key: this.keyId,
        parents: [],
        data: action,
      });
      const event = sealProofEvent(body, this.key);
      const pointer: ReceiptPointer = {
        workspace: this.workspace,
        event: eventRefOf(event),
      };
      const mutation =
        bind !== null
          ? ({
              v: 1,
              kind: "operations",
              operations: [
                {
                  principal: bind.principalKey,
                  id: bind.id,
                  request_hash: bind.requestHash,
                  result_json: bind.makeResultJson(pointer),
                  state: "COMPLETED",
                },
              ],
            } satisfies RegistryMutation)
          : ({ v: 1, kind: "noop" } satisfies RegistryMutation);
      await this.store.commit({
        records: [
          {
            lane: "proof",
            partition: this.partition,
            data: canonicalJson(event),
          },
        ],
        mutation: mutation as unknown as StoreJson,
        result_sha256: event.hash,
      });
      this.seq = seq;
      this.prev = event.hash;
      this.lamport = lamport;
      return pointer;
    };
    const p = this.tail.then(run, run);
    this.tail = p.then(
      () => undefined,
      () => undefined,
    );
    return p;
  }

  /**
   * Mutation-only idempotency binding for mutating NO_RECEIPT methods —
   * no audit event is sealed, matching `receipt: null` semantics.
   */
  commitBind(bind: {
    principalKey: string;
    id: string;
    requestHash: string;
    resultJson: string;
  }): Promise<void> {
    const run = async (): Promise<void> => {
      const mutation = {
        v: 1,
        kind: "operations",
        operations: [
          {
            principal: bind.principalKey,
            id: bind.id,
            request_hash: bind.requestHash,
            result_json: bind.resultJson,
            state: "COMPLETED",
          },
        ],
      } satisfies RegistryMutation;
      await this.store.commit({
        records: [],
        mutation: mutation as unknown as StoreJson,
        result_sha256: sha256Hex(bind.resultJson),
      });
    };
    const p = this.tail.then(run, run);
    this.tail = p.then(
      () => undefined,
      () => undefined,
    );
    return p;
  }
}

// ── registry-backed idempotency lookup ───────────────────────────────────

/** §3.1 idempotency read side over the durable operations table. */
export class RegistryIdempotency implements IdempotencyLookup {
  private readonly registry: Registry;

  constructor(registry: Registry) {
    this.registry = registry;
  }

  lookup(principalKey: string, id: string): SavedBinding | null {
    const row = this.registry.operationLookup(principalKey, id);
    if (row === null || row.result_json === null) return null;
    return {
      principalKey,
      id,
      requestHash: row.request_hash,
      saved: row.result_json,
    };
  }
}

// ── SSE over the store ───────────────────────────────────────────────────

/**
 * Subscription lookup for GET /v2/events. The store's subscription table
 * has no public reader, so live subscriptions are memory-resident here;
 * `events.subscribe` writes the durable row via mutation AND registers the
 * live record (durable cursor state resumes after restart).
 */
export class SseSubscriptions implements SseRegistry {
  private readonly subs = new Map<string, SseSubscription>();

  register(sub: SseSubscription): void {
    this.subs.set(sub.id, sub);
  }

  unregister(id: string): void {
    this.subs.delete(id);
  }

  lookup(id: string): SseSubscription | null {
    return this.subs.get(id) ?? null;
  }
}

/** Fields the SSE source extracts from one committed bus-lane record. */
function eventFields(data: Buffer): {
  topic: string;
  profile: string;
  ref: string;
  availability: "INLINE" | "OBJECT";
} | null {
  try {
    const rec = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
    const topic = rec.topic;
    const profile = rec.profile;
    if (typeof topic !== "string" || typeof profile !== "string") {
      return null;
    }
    const ref =
      typeof rec.hash === "string" ? rec.hash : sha256Hex(data.toString("utf8"));
    const availability = rec.object !== null && rec.object !== undefined
      ? "OBJECT"
      : "INLINE";
    return { topic, profile, ref, availability };
  } catch {
    return null;
  }
}

/**
 * Tails a durable bus lane for one subscription: frames strictly after a
 * cursor, filtered to the subscription's topics (filter_json `topics`
 * array; absent ⇒ all topics).
 */
export class StoreSseSource implements SseSource {
  private readonly store: GatewayStore;
  private readonly lane: string;
  /** id → topics filter (mirrors the subscriptions table's filter_json). */
  private readonly filters = new Map<string, Set<string> | null>();

  constructor(store: GatewayStore, opts: { lane?: string } = {}) {
    this.store = store;
    this.lane = opts.lane ?? "legacy";
  }

  /** Topic filter for a subscription (null ⇒ all topics pass). */
  setFilter(subscription: string, topics: string[] | null): void {
    this.filters.set(
      subscription,
      topics === null ? null : new Set(topics),
    );
  }

  earliestRetainedCursor(_subscription: string): string | null {
    return this.firstCursor;
  }

  private firstCursor: string | null = null;
  private firstScanned = false;

  private async ensureFirst(): Promise<void> {
    if (this.firstScanned) return;
    this.firstScanned = true;
    for await (const rec of this.store.laneScan(this.lane, { limit: 1 })) {
      this.firstCursor = rec.cursor;
    }
  }

  async readAfter(
    subscription: string,
    cursor: string,
    limit: number,
  ): Promise<SseFrame[]> {
    await this.ensureFirst();
    const filter = this.filters.get(subscription);
    const frames: SseFrame[] = [];
    for await (const rec of this.store.laneScan(this.lane, {
      from: cursor === "" ? undefined : cursor,
      limit: limit * 4,
    })) {
      const f = eventFields(rec.data);
      if (f === null) continue;
      if (filter !== undefined && filter !== null && !filter.has(f.topic)) {
        continue;
      }
      frames.push({
        cursor: rec.cursor,
        topic: f.topic,
        profile: f.profile,
        record_ref: f.ref,
        availability: f.availability,
      });
      if (frames.length >= limit) break;
    }
    return frames;
  }

  async waitFor(
    _subscription: string,
    _cursor: string,
    signal: AbortSignal,
  ): Promise<void> {
    // Poll tail: cheap and correct over the append-only lane.
    await new Promise<void>((resolveWait) => {
      if (signal.aborted) {
        resolveWait();
        return;
      }
      const t = setTimeout(resolveWait, 100);
      signal.addEventListener(
        "abort",
        () => {
          clearTimeout(t);
          resolveWait();
        },
        { once: true },
      );
    });
  }
}

// ── metrics (§11 Prometheus text) ────────────────────────────────────────

export type DaemonState = "STARTING" | "READY" | "DRAINING" | "STOPPED";

export class Metrics {
  private rpc = new Map<string, number>();
  private sseOpenCount = 0;
  private sseOpenedTotal = 0;
  private eventPublishes = new Map<string, number>();
  private readonly started = Date.now();

  recordRpc(method: string, code: string): void {
    const k = `${method}|${code}`;
    this.rpc.set(k, (this.rpc.get(k) ?? 0) + 1);
  }

  recordEventPublish(topic: string): void {
    this.eventPublishes.set(topic, (this.eventPublishes.get(topic) ?? 0) + 1);
  }

  sseOpened(): void {
    this.sseOpenCount += 1;
    this.sseOpenedTotal += 1;
  }

  sseClosed(): void {
    if (this.sseOpenCount > 0) this.sseOpenCount -= 1;
  }

  render(state: DaemonState): string {
    const stateNum = { STARTING: 0, READY: 1, DRAINING: 2, STOPPED: 3 }[state];
    const lines: string[] = [
      "# HELP latticeag_daemon_state Current lifecycle state",
      "# TYPE latticeag_daemon_state gauge",
      `latticeag_daemon_state ${stateNum}`,
      "# HELP latticeag_daemon_uptime_seconds Daemon uptime",
      "# TYPE latticeag_daemon_uptime_seconds counter",
      `latticeag_daemon_uptime_seconds ${((Date.now() - this.started) / 1000).toFixed(3)}`,
      "# HELP latticeag_sse_open Currently open SSE streams",
      "# TYPE latticeag_sse_open gauge",
      `latticeag_sse_open ${this.sseOpenCount}`,
      "# HELP latticeag_sse_opened_total SSE streams opened",
      "# TYPE latticeag_sse_opened_total counter",
      `latticeag_sse_opened_total ${this.sseOpenedTotal}`,
      "# HELP latticeag_rpc_total RPCs by method and outcome code",
      "# TYPE latticeag_rpc_total counter",
    ];
    for (const [k, n] of [...this.rpc.entries()].sort()) {
      const [method, code] = k.split("|");
      lines.push(`latticeag_rpc_total{method="${method}",code="${code}"} ${n}`);
    }
    lines.push(
      "# HELP latticeag_events_published_total Events published by topic",
      "# TYPE latticeag_events_published_total counter",
    );
    for (const [t, n] of [...this.eventPublishes.entries()].sort()) {
      lines.push(`latticeag_events_published_total{topic="${t}"} ${n}`);
    }
    return lines.join("\n") + "\n";
  }
}
