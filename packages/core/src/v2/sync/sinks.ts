/**
 * Gateway v2 sync — sink adapters (spec §9.1–§9.2).
 *
 * A `SinkAdapter` is a consumer-owned destination adapter: `send(batch)`
 * returns a `SinkAck` (`{stored,batch,through,conflicts,native}`), which is
 * an adapter result — never a new native receipt or mesh packet.
 *
 * Included bindings:
 *  - Proof native import (`source.register`, `import.stage`, `import.get`,
 *    `import.commit`, `revision.get` with their existing request/response
 *    shapes and CAS rules). Lost commit ACKs recover through `import.get`
 *    on the same stage — never a second logical import (TV-GW-31).
 *    expected_revision conflicts retry once only after reading the new
 *    revision and rechecking source scope (§9.2), and source-slot
 *    conflicts retain all signed candidates and mark CONFLICTED — wall-
 *    clock last-write-wins is forbidden (TV-GW-32/33).
 *  - VekInbox-compatible approvals adapter preserving the E07
 *    `{card_id,revision,stored}` acknowledgement shape (TV-GW-33).
 *
 * An absent adapter is surfaced by the engine as stream BLOCKED /
 * CAP_ADAPTER_UNAVAILABLE; this module never invents endpoints.
 */

import type { Count, Hash, Id, NativeRef } from "../protocol/refs.js";
import type { ErrorCode, RegistryErrorCode } from "../protocol/errors.js";
import { RETRYABLE } from "../protocol/errors.js";
import type { OutboxItem, SinkAck, StreamName } from "../protocol/sync.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";

// ── errors ───────────────────────────────────────────────────────────────

/**
 * Adapter-visible send failure. `retryable` defaults to the registry
 * RETRYABLE set; `retryAfterMs` carries a bounded authenticated
 * Retry-After honored by the engine's backoff.
 */
export class SinkError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly retryAfterMs: number | undefined;

  constructor(
    code: ErrorCode,
    message: string,
    options?: { retryable?: boolean; retryAfterMs?: number; cause?: unknown },
  ) {
    super(message, options);
    this.name = "SinkError";
    this.code = code;
    this.retryable =
      options?.retryable ?? RETRYABLE.has(code as RegistryErrorCode);
    this.retryAfterMs = options?.retryAfterMs;
  }
}

export function isSinkError(value: unknown): value is SinkError {
  return value instanceof SinkError;
}

// ── batch ────────────────────────────────────────────────────────────────

/**
 * One immutable egress batch (§9.1): the same items produce the same
 * `hash`, so a retry resends identical bytes/IDs (TV-GW-30).
 */
export interface OutboxBatch {
  readonly destination: Id;
  readonly cohort: string;
  readonly stream: StreamName;
  readonly items: readonly OutboxItem[];
  /** Deterministic over item ids + payload digests + cuts. */
  readonly hash: Hash;
  /** Remote cut this batch delivers through. */
  readonly through: string;
  /** Journaled remote stage identity (PENDING→IN_FLIGHT), if any. */
  readonly stage: Id | null;
}

export function batchHash(items: readonly OutboxItem[]): Hash {
  return sha256Hex(
    canonicalJson(
      items.map((item) => [item.id, item.payload.digest, item.through]),
    ),
  );
}

export function outboxBatch(
  items: readonly OutboxItem[],
  stage: Id | null = null,
): OutboxBatch {
  if (items.length === 0) {
    throw new SinkError("SCHEMA_INVALID", "an outbox batch is never empty", {
      retryable: false,
    });
  }
  const first = items[0]!;
  return {
    destination: first.destination,
    cohort: first.cohort,
    stream: first.stream,
    items,
    hash: batchHash(items),
    through: items[items.length - 1]!.through,
    stage,
  };
}

// ── adapter interface ────────────────────────────────────────────────────

export interface SinkAdapter {
  /**
   * Resolve the remote stage identity for a batch *before* send so the
   * PENDING→IN_FLIGHT transition can journal it (§9.2). Defaults to the
   * batch's existing `stage` when not implemented.
   */
  prepare?(batch: OutboxBatch): Promise<Id | null> | Id | null;
  /**
   * Deliver the batch. Must return a SinkAck; throw `SinkError` for
   * failure — retryable codes drive RETRY, permanent codes drive BLOCKED.
   * On retry (`batch.stage` set / items carry `remote_stage`) the adapter
   * must query the existing native stage first or resend identical
   * bytes/IDs — never create a second logical delivery.
   */
  send(batch: OutboxBatch): Promise<SinkAck>;
}

// ── Proof native import binding ──────────────────────────────────────────

/**
 * The native Proof import port (§9.2): existing request/response shapes
 * and CAS rules, implemented by the paired adapter — not an invented
 * Proof HTTP endpoint.
 */
export interface ProofImportPort {
  sourceRegister(input: {
    source: NativeRef;
    destination: Id;
    cohort: string;
  }): Promise<{ source: Id }>;
  importStage(input: {
    destination: Id;
    cohort: string;
    batch: Hash;
    through: string;
    items: readonly NativeRef[];
  }): Promise<{ stage: Id; expected_revision: Count }>;
  /** Lost-ACK probe: the same stage resolves its committed revision. */
  importGet(
    stage: Id,
  ): Promise<{
    stage: Id;
    committed: boolean;
    revision: Count;
    batch: Hash | null;
  } | null>;
  importCommit(
    stage: Id,
    expected_revision: Count,
  ): Promise<{ revision: Count; conflicts?: NativeRef[] }>;
  revisionGet(): Promise<Count>;
}

export interface ProofImportSinkOptions {
  /**
   * On an expected_revision conflict: "retry-once" reads revision.get and
   * rechecks source scope before a single retry (default, §9.2);
   * "conflict" surfaces REVISION_CONFLICT immediately.
   */
  readonly onRevisionConflict?: "retry-once" | "conflict";
  /** Source-scope recheck before a CAS retry; default allow. */
  readonly recheckScope?: (stage: Id, revision: Count) => boolean;
  /** Synthetic NativeRef namespace for adapter results. */
  readonly nativeNamespace?: string;
}

function stageRef(stage: Id, namespace: string): NativeRef {
  return {
    profile: "proof.import-stage/1",
    namespace,
    object_id: stage,
    commitment: null,
    raw_sha256: sha256Hex(stage),
    bytes: "0",
  };
}

export function createProofImportSink(
  port: ProofImportPort,
  options?: ProofImportSinkOptions,
): SinkAdapter {
  const namespace = options?.nativeNamespace ?? "proof-import";
  const onConflict = options?.onRevisionConflict ?? "retry-once";
  const recheckScope = options?.recheckScope ?? (() => true);

  async function stageIdFor(batch: OutboxBatch): Promise<Id> {
    const existing =
      batch.stage ?? batch.items.find((i) => i.remote_stage !== null)?.remote_stage;
    if (existing !== undefined && existing !== null) return existing;
    const staged = await port.importStage({
      destination: batch.destination,
      cohort: batch.cohort,
      batch: batch.hash,
      through: batch.through,
      items: batch.items.map((i) => i.source),
    });
    return staged.stage;
  }

  return {
    prepare: (batch) => stageIdFor(batch),
    async send(batch) {
      const stage = await stageIdFor(batch);
      // Lost-ACK recovery (TV-GW-31): query the existing native stage
      // before any second commit — a committed stage resolves the
      // original import; no second logical import is created.
      const prior = await port.importGet(stage);
      if (prior !== null && prior.committed) {
        return {
          stored: true,
          batch: batch.hash,
          through: batch.through,
          conflicts: [],
          native: stageRef(stage, namespace),
        };
      }
      await port.sourceRegister({
        source: batch.items[0]!.source,
        destination: batch.destination,
        cohort: batch.cohort,
      });
      // CAS against the destination's current revision, read fresh.
      const expected = await port.revisionGet();
      let committed: Count;
      try {
        committed = (await port.importCommit(stage, expected)).revision;
      } catch (error) {
        const conflicted =
          (isSinkError(error) && error.code === "REVISION_CONFLICT") ||
          (error instanceof Error && error.message.includes("REVISION_CONFLICT"));
        if (!conflicted) throw error;
        // §9.2: retry the commit only after reading the new revision and
        // rechecking source scope — never regenerate events.
        const current = await port.revisionGet();
        if (onConflict === "conflict" || !recheckScope(stage, current)) {
          throw isSinkError(error)
            ? error
            : new SinkError("REVISION_CONFLICT", String(error), {
                retryable: false,
              });
        }
        committed = (await port.importCommit(stage, current)).revision;
      }
      void committed;
      // Surface retained source-slot conflicts (CONFLICTED) to the engine;
      // it blocks the item rather than claiming a clean cut (§9.2).
      const after = await port.importGet(stage);
      const conflicts = (after as { conflicts?: NativeRef[] } | null)?.conflicts ?? [];
      return {
        stored: conflicts.length === 0,
        batch: batch.hash,
        through: batch.through,
        conflicts,
        native: stageRef(stage, namespace),
      };
    },
  };
}

// ── VekInbox-compatible approvals binding ────────────────────────────────

/**
 * E07 VekInbox upsert port: `{card_id,revision,stored}` acknowledgement
 * shape preserved verbatim; decision callbacks stay native (§9.2).
 */
export interface VekInboxPort {
  upsertCard(input: {
    card_id: Id;
    expected_revision: Count | null;
    cohort: string;
    body: unknown;
  }): Promise<{ card_id: Id; revision: Count; stored: boolean }>;
}

export interface VekInboxSinkOptions {
  /** Item → card id (default: item.source.object_id). */
  readonly cardIdOf?: (item: OutboxItem) => Id;
  /** Item → expected revision for the CAS (default: consent_revision−1). */
  readonly expectedRevisionOf?: (item: OutboxItem) => Count | null;
  readonly nativeNamespace?: string;
}

export function createVekInboxSink(
  port: VekInboxPort,
  options?: VekInboxSinkOptions,
): SinkAdapter {
  const cardIdOf = options?.cardIdOf ?? ((item: OutboxItem) => item.source.object_id);
  const expectedRevisionOf =
    options?.expectedRevisionOf ??
    ((item: OutboxItem) => {
      // consent_revision records the binding revision the item was built
      // against; the card CAS expects the revision before it (or null on
      // first write).
      const prior = BigInt(item.consent_revision) - 1n;
      return prior >= 0n ? prior.toString() : null;
    });
  const namespace = options?.nativeNamespace ?? "vekinbox";

  return {
    async send(batch) {
      let last: { card_id: Id; revision: Count; stored: boolean } | null = null;
      for (const item of batch.items) {
        // Absent native Card/decision contract blocks the stream rather
        // than translating an arbitrary JSON approval (§9.2).
        const result = await port.upsertCard({
          card_id: cardIdOf(item),
          expected_revision: expectedRevisionOf(item),
          cohort: batch.cohort,
          body: item.payload,
        });
        last = result;
      }
      return {
        stored: last?.stored ?? false,
        batch: batch.hash,
        through: batch.through,
        conflicts: [],
        native: {
          profile: "vekinbox.card/1",
          namespace,
          object_id: last?.card_id ?? "none",
          commitment: last !== null ? `rev:${last.revision}` : null,
          raw_sha256: sha256Hex(canonicalJson(last ?? {})),
          bytes: "0",
        },
      };
    },
  };
}

// ── in-memory destinations (tests / fallback) ────────────────────────────

/** Generic recording sink: stores every accepted batch verbatim. */
export interface MemorySink extends SinkAdapter {
  /** Every send call, including failed ones (identical retries share hash). */
  readonly attempts: OutboxBatch[];
  /** Successfully stored batches. */
  readonly sent: OutboxBatch[];
  /** One-shot failure script; consumed FIFO. */
  failWith: Array<SinkError | "timeout">;
  /** When true, every send fails as a timeout (lost ACK). */
  offline: boolean;
}

export function createMemorySink(namespace = "memory"): MemorySink {
  const attempts: OutboxBatch[] = [];
  const sent: OutboxBatch[] = [];
  const sink: MemorySink = {
    attempts,
    sent,
    failWith: [],
    offline: false,
    async send(batch) {
      attempts.push(batch);
      const failure = sink.failWith.shift();
      if (sink.offline || failure === "timeout") {
        throw new SinkError("NETWORK_UNAVAILABLE", "send timed out (lost ACK)", {
          retryable: true,
        });
      }
      if (failure instanceof SinkError) throw failure;
      sent.push(batch);
      return {
        stored: true,
        batch: batch.hash,
        through: batch.through,
        conflicts: [],
        native: {
          profile: "memory.ack/1",
          namespace,
          object_id: batch.hash.slice(0, 16),
          commitment: null,
          raw_sha256: batch.hash,
          bytes: "0",
        },
      };
    },
  };
  return sink;
}

/**
 * Source-slot conflict index (§9.2 / TV-GW-32): all signed candidates for
 * one `(source,stream,seq)` slot are retained; equal hash is a duplicate;
 * different hash marks the slot CONFLICTED. Wall-clock last-write-wins is
 * forbidden — candidates are kept in arrival order and never overwritten.
 */
export type SlotState = "ACCEPTED" | "DUPLICATE" | "CONFLICTED";

export interface SlotCandidate {
  readonly hash: Hash;
  readonly body: unknown;
  readonly signatures: readonly NativeRef[];
}

export class SlotConflictIndex {
  private readonly slots = new Map<string, SlotCandidate[]>();
  private readonly conflicted = new Set<string>();

  /** Record a signed candidate for a slot; returns the slot state. */
  admit(slot: string, candidate: SlotCandidate): SlotState {
    const existing = this.slots.get(slot);
    if (existing === undefined) {
      this.slots.set(slot, [candidate]);
      return "ACCEPTED";
    }
    if (existing.some((c) => c.hash === candidate.hash)) {
      return "DUPLICATE";
    }
    existing.push(candidate);
    this.conflicted.add(slot);
    return "CONFLICTED";
  }

  isConflicted(slot: string): boolean {
    return this.conflicted.has(slot);
  }

  candidates(slot: string): readonly SlotCandidate[] {
    return this.slots.get(slot) ?? [];
  }
}

/**
 * In-memory Proof import destination implementing ProofImportPort: stage
 * registry, monotonic revision CAS, source-slot conflict retention, and a
 * `dropAcks` switch simulating the lost-commit-ACK restart path.
 */
export class MemoryProofDestination implements ProofImportPort {
  revision = 0n;
  readonly sources = new Map<string, Id>();
  readonly stages = new Map<
    Id,
    {
      batch: Hash;
      through: string;
      items: readonly NativeRef[];
      committed: boolean;
      revision: Count;
      conflicts: NativeRef[];
    }
  >();
  readonly slots = new SlotConflictIndex();
  /** Logical imported event count (remote event count). */
  readonly imported: unknown[] = [];
  /** Count of logical imports durably committed. */
  commits = 0;
  /** When true, importCommit applies durably but the ACK is "lost". */
  dropAcks = false;
  private stageSeq = 0;

  async sourceRegister(input: {
    source: NativeRef;
    destination: Id;
    cohort: string;
  }): Promise<{ source: Id }> {
    const key = `${input.source.namespace}/${input.source.object_id}`;
    let id = this.sources.get(key);
    if (id === undefined) {
      id = `src${this.sources.size + 1}`;
      this.sources.set(key, id);
    }
    return { source: id };
  }

  async importStage(input: {
    destination: Id;
    cohort: string;
    batch: Hash;
    through: string;
    items: readonly NativeRef[];
  }): Promise<{ stage: Id; expected_revision: Count }> {
    this.stageSeq += 1;
    const stage = `stage${this.stageSeq}`;
    this.stages.set(stage, {
      batch: input.batch,
      through: input.through,
      items: input.items,
      committed: false,
      revision: "0",
      conflicts: [],
    });
    return { stage, expected_revision: this.revision.toString() };
  }

  async importGet(stage: Id) {
    const s = this.stages.get(stage);
    if (s === undefined) return null;
    return {
      stage,
      committed: s.committed,
      revision: s.revision,
      batch: s.batch,
      conflicts: s.conflicts,
    };
  }

  async importCommit(
    stage: Id,
    expected_revision: Count,
  ): Promise<{ revision: Count; conflicts?: NativeRef[] }> {
    const s = this.stages.get(stage);
    if (s === undefined) {
      throw new SinkError("NOT_FOUND", `unknown stage ${stage}`, {
        retryable: false,
      });
    }
    if (s.committed) {
      return { revision: s.revision, conflicts: s.conflicts };
    }
    if (expected_revision !== this.revision.toString()) {
      // Concurrent commit won the CAS: the stale writer conflicts and its
      // candidate is retained — never merged, never overwritten (§9.2).
      throw new SinkError(
        "REVISION_CONFLICT",
        `expected ${expected_revision}, current ${this.revision.toString()}`,
        { retryable: false },
      );
    }
    this.commits += 1;
    this.revision += 1n;
    s.committed = true;
    s.revision = this.revision.toString();
    for (const ref of s.items) {
      const slot = `${ref.namespace}/${ref.object_id}`;
      const hash = ref.commitment ?? ref.raw_sha256;
      const state = this.slots.admit(slot, {
        hash,
        body: ref,
        signatures: [],
      });
      if (state === "CONFLICTED") {
        // Retained alongside the original; the slot is CONFLICTED and
        // carries zero authority (TV-GW-32).
        s.conflicts.push(ref);
        continue;
      }
      if (state === "ACCEPTED") this.imported.push(ref);
    }
    if (this.dropAcks) {
      // Commit is durable; the ACK itself is lost (TV-GW-31).
      throw new SinkError("NETWORK_UNAVAILABLE", "commit ACK lost", {
        retryable: true,
      });
    }
    return { revision: s.revision, conflicts: s.conflicts };
  }

  async revisionGet(): Promise<Count> {
    return this.revision.toString();
  }
}

/**
 * In-memory VekInbox endpoint preserving the E07 `{card_id,revision,
 * stored}` acknowledgement and the home-owned revision CAS: a concurrent
 * upsert at a stale expected revision conflicts — never merges, never
 * resurrects a denied/expired/cancelled request (§9.2 / TV-GW-33).
 */
export class MemoryVekInbox implements VekInboxPort {
  readonly cards = new Map<Id, { revision: bigint; body: unknown }>();
  readonly calls: Array<{ card_id: Id; expected_revision: Count | null }> = [];

  async upsertCard(input: {
    card_id: Id;
    expected_revision: Count | null;
    cohort: string;
    body: unknown;
  }): Promise<{ card_id: Id; revision: Count; stored: boolean }> {
    this.calls.push({
      card_id: input.card_id,
      expected_revision: input.expected_revision,
    });
    const existing = this.cards.get(input.card_id);
    if (existing !== undefined) {
      if (
        input.expected_revision === null ||
        input.expected_revision !== existing.revision.toString()
      ) {
        throw new SinkError(
          "REVISION_CONFLICT",
          `card ${input.card_id} at revision ${existing.revision.toString()}, ` +
            `expected ${input.expected_revision ?? "null"}`,
          { retryable: false },
        );
      }
      existing.revision += 1n;
      existing.body = input.body;
      return {
        card_id: input.card_id,
        revision: existing.revision.toString(),
        stored: true,
      };
    }
    if (input.expected_revision !== null && input.expected_revision !== "0") {
      throw new SinkError(
        "REVISION_CONFLICT",
        `card ${input.card_id} does not exist at revision ${input.expected_revision}`,
        { retryable: false },
      );
    }
    this.cards.set(input.card_id, { revision: 1n, body: input.body });
    return { card_id: input.card_id, revision: "1", stored: true };
  }
}
