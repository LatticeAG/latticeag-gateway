/**
 * EventService — events.publish / query / subscribe / ack (spec §3.2, §3.4).
 *
 * Publish admission order: envelope schema → profile in the negotiated set
 * → topic in the closed registry → producer enrolled to this principal →
 * declared size cap BEFORE payload decode (TV-GW-18 style, no allocation)
 * → ref/content digest agreement → native Proof body binding + signature →
 * slot dedupe (same raw bytes → duplicate:true without a second commit;
 * different bytes → retained as a conflicted candidate per P06/TV-GW-32)
 * → durable commit → {cursor,durable:true}.
 *
 * Subscriptions are 60 s finite leases (P10: expiry at equality). ACK only
 * advances over cursors the lease delivered (delivered ≤ the frontier the
 * SSE bridge last reported); stale or never-committed cursors surface
 * CURSOR_GONE (TV-GW-37). Slow subscribers never stall the durable writer:
 * publish has no subscriber dependency; credit enforcement/disconnect is
 * the SSE layer's job against this retained state.
 */
import { Buffer } from "node:buffer";
import type { Count, Hash, Id, Json, Media, ObjectRef } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type {
  EventPublishParams,
  EventService,
} from "../protocol/services.js";
import type { Page } from "../protocol/envelope.js";
import { isTopic, TOPICS, type Topic } from "../protocol/topics.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex, isHash64 } from "../crypto/hash.js";
import { isB64uCanonical } from "../crypto/ed25519.js";
import {
  verifyProofEvent,
  type ProofEvent,
} from "../crypto/proof.js";
import { isId, parseCursor } from "../crypto/ids.js";
import { COUNT_RE } from "../crypto/proof.js";
import type {
  PlatformEventEntry,
  PlatformPorts,
  PlatformSubscriptionEntry,
  ServiceContext,
} from "./ports.js";
import { LOCAL_OPERATOR_CONTEXT } from "./ports.js";

/** Proof lane record cap (spec §2.2: serialized event ≤ 64 KiB). */
export const PROOF_RECORD_MAX_BYTES = 64 * 1024;
/** Legacy lane record cap (§2.3: 1 MiB). */
export const LEGACY_RECORD_MAX_BYTES = 1_048_576;
/** events.subscribe lease: 60 s, finite, renewable (§3.2). */
export const SUBSCRIPTION_LEASE_MS = 60_000;
/** events.query page bound (§3.2). */
export const QUERY_LIMIT_MAX = 200;
/** Legacy events keep their original namespace; the slot stream is fixed. */
const LEGACY_STREAM = "default";
/** Topic the external publish path may never claim (core writer only). */
const CORE_TOPIC: Topic = "gateway.action";

const MEDIAS: ReadonlySet<string> = new Set([
  "application/json",
  "application/octet-stream",
  "text/plain",
]);

function bad(field: string, message: string): never {
  throw new RpcError("SCHEMA_INVALID", message, { field });
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asId(value: unknown, field: string): Id {
  if (typeof value !== "string" || !isId(value)) {
    bad(field, `${field} must match the Proof Id grammar`);
  }
  return value as Id;
}

function asCount(value: unknown, field: string): Count {
  if (typeof value !== "string" || !COUNT_RE.test(value)) {
    bad(field, `${field} must be a canonical decimal Count`);
  }
  return value as Count;
}

function asTopics(value: unknown, field: string): Topic[] {
  if (!Array.isArray(value)) bad(field, `${field} must be an array`);
  for (const t of value) {
    if (typeof t !== "string" || !isTopic(t)) {
      bad(field, `${field} entries must be registry topics`);
    }
  }
  return [...new Set(value as Topic[])];
}

interface DecodedRecord {
  bytes: Uint8Array;
  text: string | null;
  digest: Hash;
  byteLen: number;
  media: Media;
}

/**
 * Accept `Blob | Json` records. A Blob carries its declared ObjectRef —
 * declared bytes are checked against the lane cap BEFORE the base64url
 * payload is materialized (spec §3.2 OBJECT_LIMIT precedence).
 */
function decodeRecord(
  record: Blob | Json,
  capBytes: number,
): DecodedRecord {
  if (
    isObj(record) &&
    isObj(record.ref) &&
    typeof record.content === "string"
  ) {
    const ref = record.ref;
    if (
      !isHash64(ref.digest) ||
      typeof ref.bytes !== "string" ||
      !COUNT_RE.test(ref.bytes) ||
      typeof ref.media !== "string" ||
      !MEDIAS.has(ref.media)
    ) {
      bad("record.ref", "record.ref must be a valid ObjectRef");
    }
    // Declared-size rejection happens before payload decode/allocation.
    if (BigInt(ref.bytes as string) > BigInt(capBytes)) {
      throw new RpcError("OBJECT_LIMIT", "record exceeds lane cap", {
        field: "record.ref.bytes",
      });
    }
    if (!isB64uCanonical(record.content)) {
      bad("record.content", "record.content must be canonical base64url");
    }
    const bytes = Buffer.from(record.content as string, "base64url");
    if (bytes.length > capBytes) {
      throw new RpcError("OBJECT_LIMIT", "record exceeds lane cap", {
        field: "record.content",
      });
    }
    if (String(bytes.length) !== ref.bytes) {
      throw new RpcError(
        "ARTIFACT_MISMATCH",
        "record.ref.bytes does not match content length",
        { field: "record.ref.bytes" },
      );
    }
    const digest = sha256Hex(bytes);
    if (digest !== ref.digest) {
      throw new RpcError(
        "ARTIFACT_MISMATCH",
        "record.ref.digest does not match content",
        { field: "record.ref.digest" },
      );
    }
    let text: string | null = null;
    try {
      text = bytes.toString("utf8");
    } catch {
      text = null;
    }
    return {
      bytes,
      text,
      digest,
      byteLen: bytes.length,
      media: ref.media as Media,
    };
  }
  // Plain Json record: canonical bytes are the record.
  let text: string;
  try {
    text = canonicalJson(record);
  } catch {
    bad("record", "record must be a Blob or canonical JSON value");
  }
  const bytes = Buffer.from(text!, "utf8");
  if (bytes.length > capBytes) {
    throw new RpcError("OBJECT_LIMIT", "record exceeds lane cap", {
      field: "record",
    });
  }
  return {
    bytes,
    text,
    digest: sha256Hex(bytes),
    byteLen: bytes.length,
    media: "application/json",
  };
}

interface Admission {
  /** Proof slot identity. */
  workspace: Id;
  source: Id;
  stream: Id;
  seq: Count;
  /** Event hash (proof) or record digest (legacy). */
  hash: Hash;
  lane: string;
  lanePartition?: string;
}

export function createEventService(
  ports: PlatformPorts,
  ctx: ServiceContext = LOCAL_OPERATOR_CONTEXT,
): EventService {
  const registry = ports.store.registry;

  async function admit(params: EventPublishParams): Promise<{
    admission: Admission;
    rec: DecodedRecord;
  }> {
    if (!isObj(params)) bad("params", "params must be an object");
    const profile = params.profile;
    if (typeof profile !== "string" || !ports.profiles.includes(profile)) {
      throw new RpcError(
        "SCHEMA_UNSUPPORTED",
        `profile ${String(profile)} is not in the negotiated set`,
        { field: "profile" },
      );
    }
    if (typeof params.topic !== "string" || !isTopic(params.topic)) {
      bad("topic", "topic must be a registry topic");
    }
    if (params.topic === CORE_TOPIC) {
      throw new RpcError(
        "POLICY_DENIED",
        "gateway.action is reserved to the core writer",
        { field: "topic" },
      );
    }
    const producer = asId(params.producer, "producer");
    const seq = asCount(params.seq, "seq");

    const source = await registry.sourceGet(producer);
    if (source === null || source.owner !== ctx.principal.id) {
      throw new RpcError(
        "POLICY_DENIED",
        `producer ${producer} is not enrolled to this principal`,
        { field: "producer" },
      );
    }

    const isProof = profile === "proof-evidence/1";
    const cap = isProof ? PROOF_RECORD_MAX_BYTES : LEGACY_RECORD_MAX_BYTES;
    const rec = decodeRecord(params.record, cap);

    if (!isProof) {
      // Legacy profile: accepted opaque bytes; the producer's original
      // namespace maps to a fixed slot stream.
      return {
        admission: {
          workspace: ports.workspace,
          source: producer,
          stream: LEGACY_STREAM,
          seq,
          hash: rec.digest,
          lane: "legacy",
        },
        rec,
      };
    }

    let event: ProofEvent;
    try {
      event = JSON.parse(rec.text ?? "") as ProofEvent;
    } catch {
      bad("record", "proof-evidence/1 record must be a serialized Proof event");
    }
    const body = event!.body;
    if (!isObj(body)) bad("record", "proof event body missing");
    // Binding checks precede signature verification (policy stage first).
    if (body.source !== producer) {
      throw new RpcError(
        "POLICY_DENIED",
        "producer does not match the Proof source",
        { field: "producer" },
      );
    }
    if (body.seq !== seq) {
      throw new RpcError(
        "POLICY_DENIED",
        "seq does not match the Proof body seq",
        { field: "seq" },
      );
    }
    if (body.workspace !== ports.workspace) {
      throw new RpcError(
        "POLICY_DENIED",
        "cross-workspace publish is not admitted",
        { field: "record" },
      );
    }
    if (!verifyProofEvent(event, source.public)) {
      throw new RpcError(
        "SIGNATURE_INVALID",
        "Proof event hash/signature verification failed",
        { field: "record" },
      );
    }
    if (body.key !== source.key_id) {
      throw new RpcError(
        "SIGNATURE_INVALID",
        "event key id does not match the enrolled source key",
        { field: "record" },
      );
    }
    return {
      admission: {
        workspace: body.workspace as Id,
        source: body.source as Id,
        stream: body.stream as Id,
        seq: body.seq as Count,
        hash: event!.hash,
        lane: "proof",
        lanePartition: body.workspace as string,
      },
      rec,
    };
  }

  return {
    async publish(params: EventPublishParams) {
      const { admission, rec } = await admit(params);

      const existing = await registry.eventSlot(
        admission.workspace,
        admission.source,
        admission.stream,
        admission.seq,
      );
      const dup = existing.find((e) => e.raw_sha256 === rec.digest);
      if (dup !== undefined) {
        // Same producer slot, same raw bytes: idempotent duplicate ACK —
        // no second commit, no second record.
        return { cursor: dup.cursor, durable: true, duplicate: true };
      }

      const commitResult = await ports.store.commit({
        records: [
          {
            lane: admission.lane,
            partition: admission.lanePartition,
            data: rec.bytes,
          },
        ],
        mutation: {
          v: 1,
          kind: "events",
          events: [
            {
              workspace: admission.workspace,
              source: admission.source,
              stream: admission.stream,
              seq: admission.seq,
              hash: admission.hash,
              raw_sha256: rec.digest,
              topic: params.topic,
              profile: params.profile,
              media: rec.media,
              record_bytes: String(rec.byteLen),
              record: 0,
            },
          ],
        } as unknown as Json,
        result_sha256: sha256Hex(
          canonicalJson({
            durable: true,
            duplicate: false,
            record_sha256: rec.digest,
          }),
        ),
      });
      const cursor = commitResult.cursors[0];
      if (cursor === undefined) {
        throw new RpcError("STORAGE_UNAVAILABLE", "commit produced no cursor");
      }
      return { cursor, durable: true, duplicate: false };
    },

    async query(params: {
      topics: Topic[];
      after: string | null;
      limit: number;
    }): Promise<Page<Json>> {
      const topics = asTopics(params.topics, "topics");
      if (
        !Number.isSafeInteger(params.limit) ||
        params.limit < 1 ||
        params.limit > QUERY_LIMIT_MAX
      ) {
        bad("limit", `limit must be an integer 1–${QUERY_LIMIT_MAX}`);
      }
      let afterOrder = 0;
      if (params.after !== null && params.after !== undefined) {
        if (parseCursor(params.after) === null) {
          bad("after", "after must be a transport cursor");
        }
        const resolved = await ports.store.resolveCursor(params.after);
        if (resolved === null || !resolved.retained) {
          throw new RpcError(
            "CURSOR_GONE",
            "cursor is not a retained committed position",
            { field: "after" },
          );
        }
        afterOrder = resolved.order;
      }
      const wanted = topics.length === 0 ? [...TOPICS] : topics;
      const merged: PlatformEventEntry[] = [];
      for (const topic of wanted) {
        merged.push(...(await registry.eventsByTopic(topic)));
      }
      merged.sort((a, b) => a.order - b.order);
      const page = merged.filter((e) => e.order > afterOrder);
      const items = page.slice(0, params.limit).map(
        (e): Json => ({
          cursor: e.cursor,
          topic: e.topic,
          profile: e.profile,
          record_ref: {
            digest: e.raw_sha256,
            bytes: e.record_bytes,
            media: e.media,
          } satisfies ObjectRef,
          availability: "WITHHELD",
          ...(e.conflict ? { conflict: true } : {}),
        }),
      );
      return {
        items,
        next:
          page.length > params.limit
            ? (items[items.length - 1] as { cursor: string }).cursor
            : null,
      };
    },

    async subscribe(params: { topics: Topic[]; after: string | null }) {
      const topics = asTopics(params.topics, "topics");
      let position = 0;
      let cursor: string;
      if (params.after !== null && params.after !== undefined) {
        if (parseCursor(params.after) === null) {
          bad("after", "after must be a transport cursor");
        }
        const resolved = await ports.store.resolveCursor(params.after);
        if (resolved === null || !resolved.retained) {
          // TV-GW-37: a stale retained cursor must surface 410 CURSOR_GONE
          // rather than silently restarting the stream.
          throw new RpcError(
            "CURSOR_GONE",
            "cursor is not a retained committed position",
            { field: "after" },
          );
        }
        position = resolved.order;
        cursor = params.after;
      } else {
        const head = await ports.store.globalHead();
        position = head.order;
        cursor = head.cursor ?? `c${"0".repeat(16)}:0`;
      }
      const subscription: PlatformSubscriptionEntry = {
        id: ports.newId(),
        owner: ctx.principal.id,
        topics,
        position,
        cursor,
        delivered: position,
        expires_ms: ports.clock() + SUBSCRIPTION_LEASE_MS,
        state: "OPEN",
      };
      await ports.store.commit({
        mutation: {
          v: 1,
          kind: "subscriptions",
          subscriptions: [subscription],
        } as unknown as Json,
        result_sha256: sha256Hex(
          canonicalJson({ subscription: subscription.id }),
        ),
      });
      return {
        subscription: subscription.id,
        cursor,
        expires_ms: subscription.expires_ms,
      };
    },

    async ack(params: { subscription: Id; cursor: string }) {
      const id = asId(params.subscription, "subscription");
      const sub = await registry.subscriptionGet(id);
      if (
        sub === null ||
        sub.owner !== ctx.principal.id ||
        sub.state !== "OPEN" ||
        ports.clock() >= sub.expires_ms
      ) {
        // Unknown, foreign, closed, or expired leases are indistinguishable.
        throw new RpcError("NOT_FOUND", `subscription ${id} is not live`, {
          field: "subscription",
        });
      }
      if (parseCursor(params.cursor) === null) {
        bad("cursor", "cursor must be a transport cursor");
      }
      const resolved = await ports.store.resolveCursor(params.cursor);
      if (resolved === null || !resolved.retained) {
        throw new RpcError(
          "CURSOR_GONE",
          "cursor is not a retained committed position",
          { field: "cursor" },
        );
      }
      const entry = await registry.eventByCursor(params.cursor);
      if (entry === null) {
        throw new RpcError(
          "POLICY_DENIED",
          "cursor does not name a deliverable event",
          { field: "cursor" },
        );
      }
      if (sub.topics.length > 0 && !sub.topics.includes(entry.topic)) {
        throw new RpcError(
          "POLICY_DENIED",
          "cannot ACK an event outside the subscription topics",
          { field: "cursor" },
        );
      }
      if (entry.order > sub.delivered) {
        throw new RpcError(
          "POLICY_DENIED",
          "cannot ACK a cursor the lease has not delivered",
          { field: "cursor" },
        );
      }
      const nextPosition = Math.max(sub.position, entry.order);
      await ports.store.commit({
        mutation: {
          v: 1,
          kind: "subscriptions",
          subscriptions: [
            { ...sub, position: nextPosition, cursor: params.cursor },
          ],
        } as unknown as Json,
        result_sha256: sha256Hex(canonicalJson({ cursor: params.cursor })),
      });
      return { cursor: params.cursor };
    },
  };
}
