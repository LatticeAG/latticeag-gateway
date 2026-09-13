/**
 * ObjectService — objects.put / objects.get (spec §3.2) plus the shared
 * action-resolution helpers used by receipt.get and lineage.query.
 *
 * Objects are content-addressed (P04: {digest,bytes,media}, SHA-256 of the
 * raw bytes) and immutable. Authorization is binding-based: a put or get
 * must name a committed caller-visible action whose event-lane cut
 * (seq ≤ the action's own seq) references the object digest. Failure at any
 * stage — unknown action, foreign action, unbound digest, absent object —
 * is uniformly NOT_FOUND so the RPC is not an existence oracle.
 *
 * TV-GW-18: a declared `ref.bytes` above the 1 MiB native cap is
 * OBJECT_LIMIT before the payload is decoded or stored — no allocation,
 * no truncation, no invented chunk profile.
 */
import { Buffer } from "node:buffer";
import type { EventRef } from "../protocol/refs.js";
import type {
  Blob,
  Count,
  Hash,
  Media,
  NativeRef,
  ObjectRef,
} from "../protocol/refs.js";
import type { ReceiptPointer } from "../protocol/envelope.js";
import { RpcError } from "../protocol/errors.js";
import type { ObjectService } from "../protocol/services.js";
import { sha256Hex, isHash64 } from "../crypto/hash.js";
import { isB64uCanonical } from "../crypto/ed25519.js";
import { canonicalJson } from "../crypto/canonical.js";
import { ID_RE } from "../crypto/ids.js";
import { COUNT_RE } from "../crypto/proof.js";
import type {
  PlatformEventEntry,
  PlatformPorts,
  ServiceContext,
} from "./ports.js";
import { LOCAL_OPERATOR_CONTEXT } from "./ports.js";

/** Native object cap: exactly 1 MiB (spec §2.2). */
export const OBJECT_MAX_BYTES = 1_048_576;

const MEDIAS: ReadonlySet<string> = new Set([
  "application/json",
  "application/octet-stream",
  "text/plain",
]);

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ── action addressing ────────────────────────────────────────────────────

function isEventRefShape(v: unknown): v is EventRef {
  return (
    isObj(v) &&
    Object.keys(v).length === 4 &&
    typeof v.source === "string" &&
    ID_RE.test(v.source) &&
    typeof v.stream === "string" &&
    ID_RE.test(v.stream) &&
    typeof v.seq === "string" &&
    COUNT_RE.test(v.seq) &&
    isHash64(v.hash)
  );
}

/**
 * The wire `action` parameter is a transport ReceiptPointer
 * `{workspace, event:{source,stream,seq,hash}}`; a NativeRef form (with
 * `object_id`) resolves through the committed-action index.
 */
export function asActionAddress(
  action: unknown,
): { kind: "pointer"; pointer: ReceiptPointer } | { kind: "native"; objectId: string } {
  if (
    isObj(action) &&
    typeof action.workspace === "string" &&
    ID_RE.test(action.workspace) &&
    isEventRefShape(action.event)
  ) {
    return {
      kind: "pointer",
      pointer: {
        workspace: action.workspace,
        event: action.event,
      },
    };
  }
  if (isObj(action) && typeof action.object_id === "string") {
    return { kind: "native", objectId: action.object_id };
  }
  throw new RpcError("SCHEMA_INVALID", "action must be a receipt pointer", {
    field: "action",
  });
}

function pointerOfEntry(entry: PlatformEventEntry): ReceiptPointer {
  return {
    workspace: entry.workspace,
    event: {
      source: entry.source,
      stream: entry.stream,
      seq: entry.seq,
      hash: entry.hash,
    },
  };
}

/**
 * Resolve an action address to its committed event entry. Never
 * distinguishes "unknown" from "forbidden" — every miss is NOT_FOUND.
 */
export async function resolveActionEntry(
  ports: PlatformPorts,
  action: unknown,
): Promise<{ entry: PlatformEventEntry; pointer: ReceiptPointer }> {
  const address = asActionAddress(action);
  if (address.kind === "native") {
    const idx = await ports.store.registry.actionByNativeId(address.objectId);
    if (idx === null) {
      throw new RpcError("NOT_FOUND", "action is not committed", {
        field: "action",
      });
    }
    return resolveActionEntry(ports, idx.pointer);
  }
  const { pointer } = address;
  const slot = await ports.store.registry.eventSlot(
    pointer.workspace,
    pointer.event.source,
    pointer.event.stream,
    pointer.event.seq,
  );
  const entry = slot.find((e) => e.hash === pointer.event.hash);
  if (entry === undefined) {
    throw new RpcError("NOT_FOUND", "action is not committed", {
      field: "action",
    });
  }
  return { entry, pointer };
}

/**
 * Caller-ownership check for mutation paths: the action's indexed
 * principal, the enrolled owner of its event source, or the
 * socket-authenticated local operator.
 */
export async function callerOwnsAction(
  ports: PlatformPorts,
  ctx: ServiceContext,
  entry: PlatformEventEntry,
): Promise<boolean> {
  if (ctx.principal.role === "local_operator") return true;
  const idx = await ports.store.registry.actionGet(
    sha256Hex(canonicalJson(pointerOfEntry(entry))),
  );
  if (idx !== null && idx.principal === ctx.principal.id) return true;
  const source = await ports.store.registry.sourceGet(entry.source);
  return source !== null && source.owner === ctx.principal.id;
}

// ── object references bound to an action's lane cut ─────────────────────

/** Closed-ObjectRef detector: exactly {digest,bytes,media}, all valid. */
export function isObjectRefShape(v: unknown): v is ObjectRef {
  return (
    isObj(v) &&
    Object.keys(v).length === 3 &&
    isHash64(v.digest) &&
    typeof v.bytes === "string" &&
    COUNT_RE.test(v.bytes) &&
    typeof v.media === "string" &&
    MEDIAS.has(v.media)
  );
}

function collectRefs(value: unknown, out: Map<Hash, ObjectRef>): void {
  if (isObjectRefShape(value)) {
    out.set(value.digest, value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectRefs(item, out);
    return;
  }
  if (isObj(value)) {
    for (const child of Object.values(value)) collectRefs(child, out);
  }
}

/**
 * The object reference set bound to an action: every closed ObjectRef in
 * the `data` of events in the action's `(source,stream)` lane at seq ≤ the
 * action's own seq — the receipt's "fixed cut". EventRefs and hashes are
 * not object references and are never collected.
 */
export async function collectActionObjectRefs(
  ports: PlatformPorts,
  entry: PlatformEventEntry,
): Promise<Map<Hash, ObjectRef>> {
  const out = new Map<Hash, ObjectRef>();
  const laneEntries = await ports.store.registry.eventLane(
    entry.workspace,
    entry.source,
    entry.stream,
  );
  for (const e of laneEntries) {
    if (BigInt(e.seq) > BigInt(entry.seq)) continue;
    const raw = await ports.store.getRecord(e.cursor);
    if (raw === null) continue;
    let event: { body?: { data?: unknown } };
    try {
      event = JSON.parse(Buffer.from(raw).toString("utf8")) as typeof event;
    } catch {
      continue; // non-JSON legacy records carry no Proof data refs
    }
    const data = event.body?.data;
    if (data !== undefined) collectRefs(data, out);
  }
  return out;
}

// ── the service ──────────────────────────────────────────────────────────

function notFound(field: string): never {
  throw new RpcError("NOT_FOUND", "action or object reference not found", {
    field,
  });
}

export function createObjectService(
  ports: PlatformPorts,
  ctx: ServiceContext = LOCAL_OPERATOR_CONTEXT,
): ObjectService {
  return {
    async put(params: { action: NativeRef; blob: Blob }) {
      const blob = params?.blob;
      if (!isObj(blob) || !isObj(blob.ref) || typeof blob.content !== "string") {
        throw new RpcError("SCHEMA_INVALID", "blob must be {ref,content}", {
          field: "blob",
        });
      }
      const ref = blob.ref;
      if (
        !isHash64(ref.digest) ||
        typeof ref.bytes !== "string" ||
        !COUNT_RE.test(ref.bytes) ||
        typeof ref.media !== "string" ||
        !MEDIAS.has(ref.media)
      ) {
        throw new RpcError("SCHEMA_INVALID", "blob.ref must be an ObjectRef", {
          field: "blob.ref",
        });
      }
      // TV-GW-18: declared size over the cap fails before the payload is
      // materialized — no allocation, no import, no truncation.
      if (BigInt(ref.bytes as string) > BigInt(OBJECT_MAX_BYTES)) {
        throw new RpcError("OBJECT_LIMIT", "object exceeds the 1 MiB cap", {
          field: "blob.ref.bytes",
        });
      }
      if (!isB64uCanonical(blob.content)) {
        throw new RpcError(
          "SCHEMA_INVALID",
          "blob.content must be canonical base64url",
          { field: "blob.content" },
        );
      }
      const content = Buffer.from(blob.content as string, "base64url");
      if (content.length > OBJECT_MAX_BYTES) {
        throw new RpcError("OBJECT_LIMIT", "object exceeds the 1 MiB cap", {
          field: "blob.content",
        });
      }
      if (String(content.length) !== ref.bytes) {
        throw new RpcError(
          "ARTIFACT_MISMATCH",
          "blob.ref.bytes does not match content length",
          { field: "blob.ref.bytes" },
        );
      }
      if (sha256Hex(content) !== ref.digest) {
        throw new RpcError(
          "ARTIFACT_MISMATCH",
          "blob.ref.digest does not match content",
          { field: "blob.ref.digest" },
        );
      }

      // Authorization: committed action owned by this caller whose lane
      // cut references the object. Every failure is the same NOT_FOUND.
      const resolved = await resolveActionEntry(ports, params.action).catch(
        () => notFound("action"),
      );
      if (!(await callerOwnsAction(ports, ctx, resolved.entry))) {
        notFound("action");
      }
      const refs = await collectActionObjectRefs(ports, resolved.entry);
      if (!refs.has(ref.digest as Hash)) notFound("ref");

      const objectRef: ObjectRef = {
        digest: ref.digest as Hash,
        bytes: String(content.length) as Count,
        media: ref.media as Media,
      };
      await ports.store.putObject(content, OBJECT_MAX_BYTES);
      return { ref: objectRef };
    },

    async get(params: { action: NativeRef; ref: ObjectRef }) {
      const ref = params?.ref;
      if (!isObjectRefShape(ref)) {
        throw new RpcError("SCHEMA_INVALID", "ref must be an ObjectRef", {
          field: "ref",
        });
      }
      const resolved = await resolveActionEntry(ports, params.action).catch(
        () => notFound("action"),
      );
      const refs = await collectActionObjectRefs(ports, resolved.entry);
      if (!refs.has(ref.digest)) notFound("ref");
      let content: Uint8Array;
      try {
        content = await ports.store.getObject(ref.digest);
      } catch {
        notFound("ref");
      }
      return {
        blob: {
          ref: {
            digest: ref.digest,
            bytes: ref.bytes,
            media: ref.media,
          },
          content: Buffer.from(content!).toString("base64url"),
        },
      };
    },
  };
}
