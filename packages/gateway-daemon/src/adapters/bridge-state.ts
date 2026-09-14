/**
 * `bridge-state.ts` — durable-backed bridge state: session resolution
 * (cookie token → SessionRecord) and the SSE event source/subscription
 * registry, all reading the registry tables the commit path maintains.
 *
 * Durable vs memory split (spec §3.3):
 *  - session state (role, absolute expiry, revocation) lives in `docs`
 *    (`ui:session` class, epoch-namespaced) — survives restarts.
 *  - the CSRF secret is memory-only — a boot's csrf map is discarded with
 *    the daemon, so a restarted daemon authenticates the session token
 *    but mutating bridge calls fail FORBIDDEN until the client
 *    re-exchanges (which re-issues both token and csrf).
 *  - idle-window sliding rides a memory map on top of the durable
 *    absolute expiry — avoids a journal write per bridge request.
 */
import { createHash } from "node:crypto";
import type { Registry } from "../store/registry.js";
import type { GatewayStore } from "../store/store.js";
import { sha256hex, type Json } from "../store/util.js";
import type { SessionRecord, SessionRole } from "../rpc/auth.js";
import { SESSION_LIMITS } from "../rpc/auth.js";
import type {
  SseFrame,
  SseRegistry,
  SseSource,
  SseSubscription,
} from "../net/sse.js";
import { parseCursor } from "../store/lanes.js";

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** The bridge-side view of `ui:session` docs (token hash-keyed). */
export interface BridgeSessions {
  peek(id: string): SessionRecord | null;
  resolve(id: string): SessionRecord | null;
}

export class DurableBridgeSessions implements BridgeSessions {
  private readonly registry: Registry;
  private readonly epoch: string;
  private readonly csrf: Map<string, string>;
  private readonly lastSeen = new Map<string, number>();
  private readonly now: () => number;

  constructor(opts: {
    registry: Registry;
    epoch: string;
    /** token-hash → plaintext csrf (memory-only per boot). */
    csrf: Map<string, string>;
    now?: () => number;
  }) {
    this.registry = opts.registry;
    this.epoch = opts.epoch;
    this.csrf = opts.csrf;
    this.now = opts.now ?? Date.now;
  }

  /** Record (or refresh) the csrf for a freshly-issued session token. */
  noteCsrf(token: string, csrf: string): void {
    this.csrf.set(sha256Hex(token), csrf);
  }

  private load(id: string): {
    doc: Record<string, Json> | null;
    hash: string;
  } {
    const hash = sha256Hex(id);
    const row = this.registry.docGet("ui:session", `${this.epoch}:${hash}`);
    if (row === null) return { doc: null, hash };
    try {
      return { doc: JSON.parse(row.doc_json) as Record<string, Json>, hash };
    } catch {
      return { doc: null, hash };
    }
  }

  private toRecord(hash: string, doc: Record<string, Json>): SessionRecord | null {
    const role = String(doc.role ?? "viewer") as SessionRole;
    const limits = SESSION_LIMITS[role === "operator" ? "operator" : "viewer"];
    const expires = Number(doc.expires_ms ?? 0);
    const idleExpires = Number(doc.idle_expires_ms ?? 0);
    const now = this.now();
    const seen = this.lastSeen.get(hash) ?? Number(doc.issued_ms ?? now);
    const revoked = doc.state === "REVOKED";
    if (revoked || now >= expires || now >= idleExpires) return null;
    if (now - seen >= limits.idleMs) return null;
    return {
      id: hash,
      role: role === "operator" ? "operator" : "viewer",
      csrf: this.csrf.get(hash) ?? "",
      created_ms: Number(doc.issued_ms ?? now),
      last_seen_ms: seen,
      absolute_expires_ms: Math.min(expires, idleExpires || expires),
      idle_ms: limits.idleMs,
      revoked: false,
    };
  }

  peek(id: string): SessionRecord | null {
    const { doc, hash } = this.load(id);
    return doc === null ? null : this.toRecord(hash, doc);
  }

  resolve(id: string): SessionRecord | null {
    const { doc, hash } = this.load(id);
    if (doc === null) return null;
    const rec = this.toRecord(hash, doc);
    if (rec !== null) {
      this.lastSeen.set(hash, this.now());
      rec.last_seen_ms = this.now();
    }
    return rec;
  }
}

/** Durable `SseRegistry` over the `subscriptions` table. */
export class DurableSseRegistry implements SseRegistry {
  private readonly registry: Registry;
  constructor(registry: Registry) {
    this.registry = registry;
  }
  lookup(id: string): SseSubscription | null {
    const row = this.registry.subscriptionV2Get(id);
    if (row === null || (row.state !== "OPEN" && row.state !== "LIVE")) {
      return null;
    }
    if (row.expires_ms !== null && Date.now() >= row.expires_ms) return null;
    return { id: row.id, lastAckCursor: row.cursor ?? null };
  }
}

/**
 * Durable `SseSource`: reads committed event rows in global commit order
 * and bumps the subscription's `delivered` high-water mark as it streams.
 */
export class DurableSseSource implements SseSource {
  private readonly store: GatewayStore;
  private readonly registry: Registry;

  constructor(store: GatewayStore) {
    this.store = store;
    this.registry = store.registry;
  }

  earliestRetainedCursor(_subscription: string): string | null {
    // Events are append-only and never GC'd; everything is retained.
    const first = this.registry.eventsAfter(0, 1);
    return first.length === 0 ? null : first[0]!.cursor;
  }

  async readAfter(
    subscription: string,
    cursor: string,
    limit: number,
  ): Promise<SseFrame[]> {
    const row = this.registry.subscriptionV2Get(subscription);
    if (row === null) return [];
    const order = await this.orderOf(cursor);
    const topics = new Set<string>(
      row.topics_json !== null
        ? (JSON.parse(row.topics_json) as string[])
        : [],
    );
    // Read a window; topic-filter in memory (topics are few).
    const out: SseFrame[] = [];
    let scanned = 0;
    let scanOrder = order;
    while (out.length < limit && scanned < 4096) {
      const batch = this.registry.eventsAfter(scanOrder, 256);
      if (batch.length === 0) break;
      for (const r of batch) {
        scanned += 1;
        if (r.record_order !== null) scanOrder = r.record_order;
        if (r.cursor === null || r.topic === null || r.profile === null) {
          continue;
        }
        if (topics.size > 0 && !topics.has(r.topic)) continue;
        out.push({
          cursor: r.cursor,
          topic: r.topic,
          profile: r.profile,
          record_ref: r.raw_sha256 ?? r.hash,
          availability: "INLINE",
        });
        if (out.length >= limit) break;
      }
      if (batch.length < 256) break;
    }
    if (out.length > 0) {
      const last = out[out.length - 1]!;
      const maxOrder = await this.orderOf(last.cursor);
      if (maxOrder > row.delivered) {
        // Bump the durable high-water mark (§6 "durable subscription").
        // The row must carry the v2 entry shape — spreading the SQL row
        // would lose `topics` and corrupt the lease on replay.
        this.store.commitSync({
          mutation: {
            v: 1,
            kind: "subscriptions",
            subscriptions: [
              {
                id: row.id,
                owner: row.owner,
                cursor: row.cursor,
                topics: [...topics],
                position: row.position,
                delivered: maxOrder,
                expires_ms: row.expires_ms,
                state: row.state,
              },
            ],
          } as Json,
          result_sha256: sha256hex(last.cursor),
        });
      }
    }
    return out;
  }

  async waitFor(
    _subscription: string,
    _cursor: string,
    signal: AbortSignal,
  ): Promise<void> {
    // Poll tail: cheap and correct over the append-only index.
    if (signal.aborted) return;
    await new Promise<void>((resolveWait) => {
      const t = setTimeout(resolveWait, 100);
      t.unref?.();
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

  private async orderOf(cursor: string): Promise<number> {
    if (cursor === "") return 0;
    const resolved = await this.store.resolveCursor(cursor);
    if (resolved === null) {
      const parsed = parseCursor(cursor);
      if (
        parsed !== null &&
        parsed.laneOrdinal === 0n &&
        parsed.recordOrdinal === 0n
      ) {
        return 0;
      }
      const err = new Error(`unknown cursor ${cursor}`);
      (err as { code?: string }).code = "STALE_CURSOR";
      throw err;
    }
    return resolved.order;
  }
}
