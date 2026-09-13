/**
 * Gateway v2 sync — SyncService implementation (spec §3.2/§3.3, §9.2).
 *
 * Exchange shapes (§3.3):
 *  - sync.status    {} → {paused, streams:{s:{pending,in_flight,blocked,
 *                     acked[,cohort,profile]}}, cloud:{id,state}|null}
 *  - sync.pause     {streams} → {paused:[...]}
 *  - sync.resume    {streams} → {resumed:[...]} — re-checks consent.
 *  - sync.configure {expected_revision,sync,review} → {revision} — CAS;
 *                     the review is bound to exactly this method, the
 *                     document, and the prior revision (§3.3 note).
 *  - sync.flush     {streams,timeout_ms} → {through,pending,blocked}
 */

import type { Count, Hash, Id, JsonObject, NativeRef } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type {
  StreamName,
  SyncService,
  SyncStreamCounts,
} from "../protocol/index.js";
import { STREAMS, SYNC_LIMITS, isStreamName } from "../protocol/sync.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import { isId } from "../crypto/ids.js";
import { OutboxEngine } from "./outbox.js";
import type { StreamConsent, SyncPorts } from "./ports.js";

/**
 * Review-binding hash per the §3.3 exchange convention:
 * `H(J({method, params, operator, expires_ms}))` where `params` is the
 * request params object with `review` removed.
 */
export function reviewBindingHash(
  method: string,
  params: unknown,
  operator: string,
  expires_ms: number,
): Hash {
  return sha256Hex(canonicalJson({ method, params, operator, expires_ms }));
}

/** Build the §3.3 review validator: recomputes the binding hash. */
export function makeReviewValidator(
  operator: string,
  expires_ms: number,
): (method: string, params: unknown, review: string) => boolean {
  return (method, params, review) =>
    review === reviewBindingHash(method, params, operator, expires_ms);
}

export interface SyncServicePorts extends SyncPorts {
  /** Global sync.paused flag from the applied config document. */
  syncPaused(): boolean;
  /** Current sync-config CAS revision. */
  syncRevision(): Count;
  /** Apply a validated sync document at the next revision (CAS write). */
  applySync(document: JsonObject, revision: Count): void;
  /**
   * Validate a review binding for a mutating method: the review commits
   * to exactly (method, params-without-review, prior revision). Absent
   * validator → the review must be a well-formed 64-hex hash.
   */
  validateReview?(method: string, params: unknown, review: string): boolean;
  /** Current cloud pairing for status reporting. */
  cloud(): { id: Id; state: string } | null;
}

function requireStreams(value: unknown): StreamName[] {
  if (!Array.isArray(value)) {
    throw new RpcError("SCHEMA_INVALID", "streams must be an array", {
      retryable: false,
      field: "streams",
    });
  }
  const out: StreamName[] = [];
  for (const name of value) {
    if (typeof name !== "string" || !isStreamName(name)) {
      throw new RpcError(
        "SCHEMA_INVALID",
        `unknown stream ${String(name)}`,
        { retryable: false, field: "streams" },
      );
    }
    out.push(name);
  }
  return out;
}

const SYNC_DOC_KEYS = new Set(["enabled", "paused", "cloud", "streams", "legacy"]);
const STREAM_KEYS = new Set([
  "enabled",
  "paused",
  "profile",
  "include_objects",
  "cohort",
  "from",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasExactly(obj: Record<string, unknown>, keys: ReadonlySet<string>): boolean {
  const own = Object.keys(obj);
  return own.length === keys.size && own.every((k) => keys.has(k));
}

/** Closed §8.1 sync document shape (legacy tolerated as opaque). */
function validateSyncDocument(doc: unknown): JsonObject {
  const fail = (field: string): never => {
    throw new RpcError("SCHEMA_INVALID", `sync document invalid at ${field}`, {
      retryable: false,
      field,
    });
  };
  if (!isPlainObject(doc)) fail("sync");
  const d = doc as Record<string, unknown>;
  for (const key of Object.keys(d)) {
    if (!SYNC_DOC_KEYS.has(key)) fail(key);
  }
  if (typeof d.enabled !== "boolean") fail("enabled");
  if (typeof d.paused !== "boolean") fail("paused");
  if (d.cloud !== null && (typeof d.cloud !== "string" || !isId(d.cloud))) {
    fail("cloud");
  }
  if (!isPlainObject(d.streams)) fail("streams");
  const streamsDoc = d.streams as Record<string, unknown>;
  for (const stream of STREAMS) {
    const s = streamsDoc[stream] as Record<string, unknown>;
    if (!isPlainObject(s) || !hasExactly(s, STREAM_KEYS)) fail(`streams.${stream}`);
    if (typeof s.enabled !== "boolean" || typeof s.paused !== "boolean") {
      fail(`streams.${stream}`);
    }
    if (s.profile !== "metadata" && s.profile !== "masked" && s.profile !== "full") {
      fail(`streams.${stream}.profile`);
    }
    if (typeof s.include_objects !== "boolean") fail(`streams.${stream}.include_objects`);
    if (typeof s.cohort !== "string" || s.cohort.length === 0 || s.cohort.length > 128) {
      fail(`streams.${stream}.cohort`);
    }
    if (typeof s.from !== "string" || !/^(now|c[0-9a-f]{16}:[0-9]+)$/.test(s.from)) {
      fail(`streams.${stream}.from`);
    }
  }
  return d as JsonObject;
}

export function createSyncService(ports: SyncServicePorts): SyncService {
  const engine = new OutboxEngine(ports);

  return {
    async status() {
      const streams = {} as Record<StreamName, SyncStreamCounts>;
      for (const stream of STREAMS) {
        const consent = ports.consent(stream);
        const counts = engine.counts(stream);
        streams[stream] = {
          ...counts,
          cohort: consent?.cohort ?? "",
          profile: consent?.profile ?? "metadata",
        };
      }
      return {
        paused: ports.syncPaused(),
        streams,
        cloud: ports.cloud(),
      };
    },

    async pause(params: { streams: StreamName[] }) {
      const streams = requireStreams(params.streams);
      return { paused: engine.pause(streams) };
    },

    async resume(params: { streams: StreamName[] }) {
      const streams = requireStreams(params.streams);
      // Resume re-checks consent: a disabled stream is never resumed.
      return { resumed: engine.resume(streams) };
    },

    async configure(params: {
      expected_revision: Count;
      sync: JsonObject;
      review: NativeRef;
    }) {
      const { expected_revision, sync, review } = params;
      if (typeof expected_revision !== "string") {
        throw new RpcError("SCHEMA_INVALID", "expected_revision required", {
          retryable: false,
          field: "expected_revision",
        });
      }
      // The review binds exactly this method + params-without-review +
      // the prior revision (§3.3 note on config.apply/sync.configure).
      const { review: _review, ...sansReview } = params;
      const reviewHash = typeof review === "string" ? review : canonicalJson(review);
      const valid =
        ports.validateReview !== undefined
          ? ports.validateReview("sync.configure", sansReview, reviewHash)
          : typeof reviewHash === "string" && /^[0-9a-f]{64}$/.test(reviewHash);
      if (!valid) {
        throw new RpcError("POLICY_DENIED", "sync.configure review binding invalid", {
          retryable: false,
          field: "review",
        });
      }
      const current = ports.syncRevision();
      if (current !== expected_revision) {
        throw new RpcError(
          "REVISION_CONFLICT",
          `sync revision is ${current}, expected ${expected_revision}`,
          { retryable: false, field: "expected_revision" },
        );
      }
      validateSyncDocument(sync);
      const next = (BigInt(current) + 1n).toString();
      ports.applySync(sync, next);
      return { revision: next };
    },

    async flush(params: { streams: StreamName[]; timeout_ms: number }) {
      const streams = requireStreams(params.streams);
      const timeout = params.timeout_ms;
      if (
        typeof timeout !== "number" ||
        !Number.isSafeInteger(timeout) ||
        timeout < 0 ||
        timeout > SYNC_LIMITS.flushTimeoutMaxMs
      ) {
        throw new RpcError(
          "SCHEMA_INVALID",
          "timeout_ms must be an integer in 0..300000",
          { retryable: false, field: "timeout_ms" },
        );
      }
      return engine.flush(streams, timeout);
    },
  };
}
