/**
 * Gateway v2 sync — the outbox engine (spec §9.1–§9.2).
 *
 *  - `enqueue` creates immutable redacted payload bytes and journals the
 *    intent in the same logical commit as the caller's source-event
 *    mutation hook. Disabled streams produce no work.
 *  - State machine per OUTBOX_TRANSITIONS: PENDING→IN_FLIGHT→ACKED|RETRY|
 *    BLOCKED; ACKED terminal; BLOCKED→PENDING only via explicit repair.
 *  - Full-jitter backoff `[0, min(300000, 1000*2^attempt)]` honoring a
 *    bounded Retry-After floor; retries are never exhausted to discard.
 *  - Concurrency: ≤2 global sends, 1 per stream, approvals/receipts
 *    priority with fair service for all enabled streams.
 *  - Pause is a durable per-stream flag: no new sends; an in-flight
 *    request may finish and its ACK is still recorded.
 *  - `flush` captures high-water marks and drives the captured set to
 *    ACKED or returns pending/blocked counts for the exit-5 gate;
 *    `failOnSyncStatus` reports {empty,unknown} — an unknowable daemon cut
 *    plus admitted work is nonempty, never success.
 */

import type { Count, Hash, Id, NativeRef, ObjectRef } from "../protocol/refs.js";
import type { ErrorCode } from "../protocol/errors.js";
import { RpcError } from "../protocol/errors.js";
import {
  STREAMS,
  SYNC_LIMITS,
  backoffCap,
  canOutboxTransition,
} from "../protocol/sync.js";
import type { OutboxItem, OutboxState, StreamName } from "../protocol/sync.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import {
  projectForStream,
} from "./disclosure.js";
import type { DisclosureConsent } from "./disclosure.js";
import {
  SinkError,
  isSinkError,
  outboxBatch,
} from "./sinks.js";
import type { OutboxBatch } from "./sinks.js";
import type { StreamConsent, SyncPorts } from "./ports.js";

/** Send scheduling priority (§9.2): approvals/receipts first. */
export const STREAM_PRIORITY: readonly StreamName[] = [
  "approvals",
  "receipts",
  "lineage",
  "runs",
  "watch",
  "mesh",
];

export interface EnqueueArgs {
  readonly stream: StreamName;
  /** NativeRef of the source event being exported. */
  readonly source: NativeRef;
  /** Decoded source event/object — never mutated, never exported raw. */
  readonly envelope: unknown;
  /** Content objects available for export, keyed by digest. */
  readonly objects?: Readonly<Record<string, unknown>>;
  /** True when `envelope` is a signed native envelope. */
  readonly signed?: boolean;
  /** CIS/personal receipt marker (E48). */
  readonly personal?: boolean;
  /** Remote cut this item covers (source cursor). */
  readonly through: string;
  /** Admit the intent under a run for failOnSyncStatus accounting. */
  readonly run?: string;
  /**
   * The caller's source-event mutation. Runs in the same logical commit
   * as the outbox intent: if it throws, no sendable item is persisted.
   */
  readonly commit?: () => void;
}

export interface FlushResult {
  readonly through: Record<string, string>;
  readonly pending: number;
  readonly blocked: number;
}

export interface SyncRunStatus {
  readonly empty: boolean;
  readonly unknown: boolean;
}

function toDisclosureConsent(consent: StreamConsent): DisclosureConsent {
  return {
    includeObjects: consent.include_objects,
    hashes: consent.hashes,
    ids: consent.ids,
    existence: consent.existence,
    personalData: consent.personalData,
    deletionContract: consent.deletionContract,
    allowedObjects: consent.allowedObjects,
    redactKeys: consent.redactKeys,
    includeRawText: consent.includeRawText,
  };
}

/** Redaction-policy hash for item dedup (§9.1). */
function redactionPolicyHash(consent: StreamConsent): Hash {
  return sha256Hex(
    canonicalJson({
      profile: consent.profile,
      include_objects: consent.include_objects,
      hashes: consent.hashes === true,
      ids: consent.ids !== false,
      existence: consent.existence === true,
      personal: consent.personalData === true,
      deletion: consent.deletionContract === true,
      allowed: [...(consent.allowedObjects ?? [])].sort(),
      keys: [...(consent.redactKeys ?? [])].map((k) => k.toLowerCase()).sort(),
      raw_text: consent.includeRawText === true,
    }),
  );
}

/**
 * Outbox item identity/dedup (§9.1): destination, cohort, source
 * namespace, native slot/commitment, and the redaction-policy hash — the
 * same bytes in another tenant/cohort are not interchangeable delivery
 * authority. Rendered under the Id grammar (40 chars).
 */
function outboxItemId(
  consent: StreamConsent,
  stream: StreamName,
  source: NativeRef,
  redaction: Hash,
): Id {
  const dedup = sha256Hex(
    canonicalJson({
      destination: consent.destination,
      cohort: consent.cohort,
      stream,
      namespace: source.namespace,
      slot: source.object_id,
      commitment: source.commitment,
      raw_sha256: source.raw_sha256,
      redaction,
    }),
  );
  return `ob${dedup.slice(0, 38)}`;
}

export class OutboxEngine {
  private readonly ports: SyncPorts;
  /** Item id → hash of the batch it was first journaled into. */
  private readonly itemBatch = new Map<Id, Hash>();
  /** Batch hash → member item ids, journaled at PENDING→IN_FLIGHT. */
  private readonly batchMembers = new Map<Hash, Id[]>();
  /** Run id → admitted item ids (failOnSyncStatus scope). */
  private readonly runItems = new Map<string, Set<Id>>();
  private inFlightSends = 0;
  private readonly streamInFlight = new Set<StreamName>();
  private readonly pendingSends = new Set<Promise<void>>();
  /** Diagnostic: last blocking code per item (kept off the closed item). */
  private readonly blockedCode = new Map<Id, ErrorCode>();

  constructor(ports: SyncPorts) {
    this.ports = ports;
  }

  // ── enqueue ────────────────────────────────────────────────────────────

  /**
   * Journal an outbox intent in the same logical commit as the source
   * event: build immutable redacted payload bytes first, run the caller's
   * commit hook, then persist the sendable item. Returns the item, the
   * deduplicated existing item, or null when the stream is disabled.
   * @throws {RpcError} POLICY_DENIED / OBJECT_LIMIT / SCHEMA_INVALID.
   */
  enqueue(args: EnqueueArgs): OutboxItem | null {
    const consent = this.ports.consent(args.stream);
    if (consent === undefined || !consent.enabled) {
      // Disabled streams produce no outbox work (§9.2).
      return null;
    }
    const projection = projectForStream(
      args.stream,
      {
        source: args.source,
        envelope: args.envelope,
        objects: args.objects,
        signed: args.signed,
        personal: args.personal,
        consent: toDisclosureConsent(consent),
      },
      consent.profile,
    );
    if (!projection.ok) {
      // Denied export audits retain only the generic denial — never the
      // personal NativeRef, content digest, or blocked payload hash.
      throw new RpcError("POLICY_DENIED", `sync disclosure: ${projection.reason}`, {
        retryable: false,
        field: "stream",
      });
    }
    let payloadBytes: string;
    try {
      payloadBytes = canonicalJson(projection.export);
    } catch {
      throw new RpcError(
        "SCHEMA_INVALID",
        "sync disclosure: projection is outside the canonical JSON domain",
        { retryable: false, field: "envelope" },
      );
    }
    const byteLength = Buffer.byteLength(payloadBytes, "utf8");
    if (byteLength > SYNC_LIMITS.payloadBytes) {
      throw new RpcError(
        "OBJECT_LIMIT",
        `sync payload ${byteLength} exceeds ${SYNC_LIMITS.payloadBytes}`,
        { retryable: false, field: "payload" },
      );
    }
    const payload: ObjectRef = {
      digest: sha256Hex(payloadBytes),
      bytes: String(byteLength),
      media: "application/json",
    };
    // Immutable redacted payload bytes exist before the item is sendable.
    this.ports.putObject?.(payload, payloadBytes);
    const redaction = redactionPolicyHash(consent);
    const id = outboxItemId(consent, args.stream, args.source, redaction);
    const existing = this.ports.store.get(id);
    if (existing !== undefined) {
      // Same destination/cohort/slot/policy → duplicate intent.
      return existing;
    }
    const item: OutboxItem = {
      v: 1,
      id,
      destination: consent.destination,
      cohort: consent.cohort,
      stream: args.stream,
      source: args.source,
      payload,
      consent_revision: consent.revision,
      redaction_sha256: redaction,
      from: consent.from,
      through: args.through,
      state: "PENDING",
      attempts: 0,
      next_attempt_ms: this.ports.now(),
      remote_stage: null,
    };
    // Same logical commit as the source event: the caller's mutation hook
    // runs before the sendable intent is persisted; a throw here leaves
    // no dangling outbox work.
    args.commit?.();
    this.ports.store.put(item);
    if (args.run !== undefined) {
      let set = this.runItems.get(args.run);
      if (set === undefined) {
        set = new Set();
        this.runItems.set(args.run, set);
      }
      set.add(item.id);
    }
    return item;
  }

  // ── state machine ──────────────────────────────────────────────────────

  private transition(item: OutboxItem, to: OutboxState): void {
    if (!canOutboxTransition(item.state, to)) {
      throw new RpcError(
        "STATE_TRANSITION",
        `outbox ${item.id}: ${item.state} → ${to} is not a legal transition`,
        { retryable: false },
      );
    }
    item.state = to;
    this.ports.store.put(item);
  }

  /**
   * Explicit repair/review: the only BLOCKED→PENDING path (§9.2).
   */
  repair(id: Id): OutboxItem {
    const item = this.ports.store.get(id);
    if (item === undefined) {
      throw new RpcError("NOT_FOUND", `no outbox item ${id}`, {
        retryable: false,
        field: "id",
      });
    }
    if (item.state !== "BLOCKED") {
      throw new RpcError(
        "STATE_TRANSITION",
        `outbox ${id} is ${item.state}, not BLOCKED`,
        { retryable: false },
      );
    }
    item.next_attempt_ms = this.ports.now();
    this.blockedCode.delete(id);
    this.transition(item, "PENDING");
    return item;
  }

  /** The last blocking code recorded for an item, if any. */
  blockedCodeOf(id: Id): ErrorCode | undefined {
    return this.blockedCode.get(id);
  }

  // ── pause / resume ─────────────────────────────────────────────────────

  isPaused(stream: StreamName): boolean {
    return this.ports.isPaused(stream);
  }

  pause(streams: readonly StreamName[]): StreamName[] {
    const done: StreamName[] = [];
    for (const stream of streams) {
      this.ports.setPaused(stream, true);
      done.push(stream);
    }
    return done;
  }

  resume(streams: readonly StreamName[]): StreamName[] {
    const done: StreamName[] = [];
    for (const stream of streams) {
      const consent = this.ports.consent(stream);
      if (consent === undefined || !consent.enabled) continue;
      this.ports.setPaused(stream, false);
      done.push(stream);
    }
    this.pump();
    return done;
  }

  // ── scheduling ─────────────────────────────────────────────────────────

  private sendable(item: OutboxItem, now: number): boolean {
    if (this.ports.isPaused(item.stream)) return false;
    if (item.state === "PENDING") return true;
    return item.state === "RETRY" && item.next_attempt_ms <= now;
  }

  /**
   * Start sends while concurrency allows: ≤2 global, ≤1 per stream,
   * approvals/receipts first then fair stream order. Returns the number
   * of sends started.
   */
  pump(scope?: ReadonlySet<StreamName>): number {
    let started = 0;
    const now = this.ports.now();
    while (this.inFlightSends < SYNC_LIMITS.globalSenders) {
      const picked = this.pickStream(now, scope);
      if (picked === null) break;
      this.startSend(picked, now);
      started += 1;
    }
    return started;
  }

  private pickStream(now: number, scope?: ReadonlySet<StreamName>): StreamName | null {
    for (const stream of STREAM_PRIORITY) {
      if (scope !== undefined && !scope.has(stream)) continue;
      if (this.streamInFlight.has(stream)) continue;
      if (this.ports.isPaused(stream)) continue;
      const ready = this.ports.store
        .all()
        .some((item) => item.stream === stream && this.sendable(item, now));
      if (ready) return stream;
    }
    return null;
  }

  /**
   * Form the next batch for a stream: retry items keep the batch
   * membership journaled at their first IN_FLIGHT transition so a resend
   * is byte/ID-identical (§9.2, TV-GW-30); fresh items form a new batch
   * bounded by the §9.1 Proof caps.
   */
  private nextBatchMembers(stream: StreamName, now: number): Id[] {
    const ready = this.ports.store
      .all()
      .filter((item) => item.stream === stream && this.sendable(item, now));
    // Prior batch members first (identical retry), grouped by batch hash.
    const byBatch = new Map<Hash, Id[]>();
    const fresh: OutboxItem[] = [];
    for (const item of ready) {
      const prior = this.itemBatch.get(item.id);
      if (prior !== undefined) {
        const group = byBatch.get(prior);
        if (group === undefined) byBatch.set(prior, [item.id]);
        else group.push(item.id);
      } else {
        fresh.push(item);
      }
    }
    for (const members of byBatch.values()) {
      return members; // oldest recorded batch wins; one batch per send
    }
    const members: Id[] = [];
    let bytes = 0;
    for (const item of fresh.slice(0, SYNC_LIMITS.batchEvents)) {
      const size = Number(item.payload.bytes);
      if (members.length > 0 && bytes + size >= SYNC_LIMITS.batchBytes) break;
      members.push(item.id);
      bytes += size;
    }
    return members;
  }

  private startSend(stream: StreamName, now: number): void {
    const memberIds = this.nextBatchMembers(stream, now);
    if (memberIds.length === 0) return;
    this.inFlightSends += 1;
    this.streamInFlight.add(stream);
    const send = this.runSend(stream, memberIds).finally(() => {
      this.inFlightSends -= 1;
      this.streamInFlight.delete(stream);
      this.pendingSends.delete(send);
    });
    this.pendingSends.add(send);
    // Attach a no-op rejection handler; runSend never rejects, but the
    // finally() chain must not produce unhandled rejections.
    send.catch(() => undefined);
  }

  private async runSend(stream: StreamName, memberIds: Id[]): Promise<void> {
    const items = memberIds
      .map((id) => this.ports.store.get(id))
      .filter((item): item is OutboxItem => item !== undefined)
      .filter((item) => item.state === "PENDING" || item.state === "RETRY");
    if (items.length === 0) return;
    const batch = outboxBatch(items, items[0]!.remote_stage);
    const sink = this.ports.sink(batch.destination);
    if (sink === undefined) {
      // Absent adapter → stream BLOCKED / CAP_ADAPTER_UNAVAILABLE; never
      // invent an endpoint (§9.2, TV-GW-63).
      for (const item of items) {
        this.blockedCode.set(item.id, "CAP_ADAPTER_UNAVAILABLE");
        this.transition(item, "BLOCKED");
      }
      return;
    }
    // Journal the batch and remote-stage identity before send (§9.2).
    let stage: Id | null = batch.stage;
    if (sink.prepare !== undefined) {
      stage = (await sink.prepare(batch)) ?? batch.stage;
    }
    const staged: OutboxBatch = { ...batch, stage };
    this.batchMembers.set(staged.hash, memberIds);
    for (const item of items) {
      this.itemBatch.set(item.id, staged.hash);
      item.remote_stage = stage;
      item.attempts += 1;
      this.transition(item, "IN_FLIGHT");
    }
    try {
      const ack = await sink.send(staged);
      if (
        this.ports.validateAck !== undefined &&
        !this.ports.validateAck(staged, ack)
      ) {
        // Native ACK bytes failed pinned-binding validation — stored=true
        // is not trusted; treat as a lost ACK.
        throw new SinkError(
          "NETWORK_UNAVAILABLE",
          "native ACK failed destination-binding validation",
          { retryable: true },
        );
      }
      if (ack.conflicts.length > 0) {
        // Source-slot conflict: all signed candidates retained, marked
        // CONFLICTED — never a wall-clock last-write-wins (§9.2).
        for (const item of items) {
          this.blockedCode.set(item.id, "OBJECT_CONFLICT");
          this.transition(item, "BLOCKED");
        }
        return;
      }
      if (ack.stored) {
        for (const item of items) this.transition(item, "ACKED");
        this.ports.setAckedThrough(stream, ack.through);
        return;
      }
      this.retryAll(items, undefined);
    } catch (error) {
      if (isSinkError(error) && !error.retryable) {
        for (const item of items) {
          this.blockedCode.set(item.id, error.code);
          this.transition(item, "BLOCKED");
        }
        return;
      }
      const retryAfter =
        isSinkError(error) ? error.retryAfterMs : undefined;
      this.retryAll(items, retryAfter);
    }
  }

  private retryAll(items: readonly OutboxItem[], retryAfterMs: number | undefined): void {
    const now = this.ports.now();
    for (const item of items) {
      // Full jitter [0, min(300000, 1000*2^(attempts-1))]; an
      // authenticated Retry-After is a bounded floor, never below the
      // sampled delay and never above the cap (§9.2).
      const jitter = Math.floor(
        this.ports.random() * (backoffCap(item.attempts - 1) + 1),
      );
      let delay = jitter;
      if (retryAfterMs !== undefined) {
        delay = Math.max(
          jitter,
          Math.min(retryAfterMs, SYNC_LIMITS.backoffCapMs),
        );
      }
      item.next_attempt_ms = now + delay;
      this.transition(item, "RETRY");
    }
  }

  // ── status / flush / exit-5 ────────────────────────────────────────────

  counts(stream: StreamName): {
    pending: number;
    in_flight: number;
    blocked: number;
    acked: number;
  } {
    const counts = { pending: 0, in_flight: 0, blocked: 0, acked: 0 };
    for (const item of this.ports.store.all()) {
      if (item.stream !== stream) continue;
      if (item.state === "IN_FLIGHT") counts.in_flight += 1;
      else if (item.state === "BLOCKED") counts.blocked += 1;
      else if (item.state === "ACKED") counts.acked += 1;
      else counts.pending += 1; // PENDING + RETRY
    }
    return counts;
  }

  /**
   * §3.3/§9.2 sync.flush: capture the enabled-stream high-water marks for
   * this run/flush, then drive captured items to ACKED until timeout_ms
   * (0–300000). Returns per-stream remote cuts plus pending/blocked
   * counts; items admitted after the captured cut do not extend the wait.
   */
  async flush(
    streams: readonly StreamName[],
    timeout_ms: number,
  ): Promise<FlushResult> {
    const scope = new Set(streams);
    const deadline = this.ports.now() + timeout_ms;
    const captured = new Map<Id, OutboxItem>();
    for (const item of this.ports.store.all()) {
      if (scope.has(item.stream)) captured.set(item.id, item);
    }
    const outstanding = () =>
      [...captured.values()].filter((item) => item.state !== "ACKED");

    for (;;) {
      this.pump(scope);
      const open = outstanding();
      if (open.length === 0) break;
      const remaining = deadline - this.ports.now();
      if (remaining <= 0) break;
      // Items that can still progress: not BLOCKED and not under a paused
      // stream. When none exist and no send is in flight, the captured set
      // can never reach ACKED — return now instead of spinning.
      const progressing = open.filter(
        (item) => item.state !== "BLOCKED" && !this.ports.isPaused(item.stream),
      );
      if (progressing.length === 0 && this.pendingSends.size === 0) break;
      // In-flight sends settle first — their ACK/failure is what drives
      // progress — then the clock advances to the earliest eligible retry
      // time (or the deadline) when nothing is in flight.
      if (this.pendingSends.size > 0) {
        await Promise.race([...this.pendingSends]);
        continue;
      }
      const retryTimes = progressing
        .filter((item) => !this.streamInFlight.has(item.stream))
        .map((item) => item.next_attempt_ms);
      const until = Math.min(
        deadline,
        retryTimes.length > 0 ? Math.min(...retryTimes) : deadline,
      );
      await this.ports.sleep(Math.max(0, until - this.ports.now()));
    }

    const through: Record<string, string> = {};
    for (const stream of streams) {
      let cut: string | undefined;
      for (const item of captured.values()) {
        if (item.stream === stream && item.state === "ACKED") {
          cut = item.through;
        }
      }
      through[stream] = cut ?? this.ports.ackedThrough(stream) ?? "0";
    }
    const open = outstanding();
    return {
      through,
      pending: open.filter((i) => i.state !== "BLOCKED").length,
      blocked: open.filter((i) => i.state === "BLOCKED").length,
    };
  }

  /**
   * §6.2/§9.2 fail-on-sync accounting for one run's captured intents (or
   * the whole outbox when `run` is undefined). {empty:false} whenever any
   * captured item is PENDING/RETRY/BLOCKED/IN_FLIGHT; {unknown:true} when
   * the daemon's admitted cut cannot be proven while work was admitted,
   * or an item's outcome is unknown (in-flight). Daemon death cannot
   * turn a nonempty outbox into exit 0.
   */
  failOnSyncStatus(run?: string): SyncRunStatus {
    const ids =
      run === undefined
        ? this.ports.store.all().map((item) => item.id)
        : [...(this.runItems.get(run) ?? [])];
    const items = ids
      .map((id) => this.ports.store.get(id))
      .filter((item): item is OutboxItem => item !== undefined);
    const admitted = items.length > 0;
    const outstanding = items.filter((item) => item.state !== "ACKED");
    const daemonUnknown =
      this.ports.daemonStatus() === "unknown" && admitted;
    const outcomeUnknown = outstanding.some(
      (item) => item.state === "IN_FLIGHT",
    );
    const unknown = daemonUnknown || outcomeUnknown;
    return { empty: outstanding.length === 0 && !unknown, unknown };
  }
}

export { STREAMS };
