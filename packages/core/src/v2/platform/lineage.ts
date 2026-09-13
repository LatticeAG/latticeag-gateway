/**
 * LineageService — lineage.query (spec §3.2, §3.3 line 326).
 *
 * Nodes are actions addressed by transport ReceiptPointer; the addressed
 * action is always node[0]. Expansion walks the action graph only — a
 * `previous_action` NativeRef inside the action's committed
 * gateway.action/1 observation (reached through the StepClosed →
 * ObservationRecorded → object join) and Proof parents that themselves
 * resolve to action anchors. Raw event prev/parents are not action edges;
 * nothing is manufactured (§3.4: lineage never invents a prerequisite).
 *
 * With no bound native lineage adapter, `native_assessment` is
 * "NOT_EVALUATED" and the gap list carries "CAP_ADAPTER_UNAVAILABLE";
 * unresolved references add "MISSING_REFERENCE" gaps instead of being
 * silently dropped.
 */
import { Buffer } from "node:buffer";
import type { EventRef, Json, NativeRef } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type { LineageService } from "../protocol/services.js";
import type { ReceiptPointer } from "../protocol/envelope.js";
import { sha256Hex } from "../crypto/hash.js";
import { canonicalJson } from "../crypto/canonical.js";
import { ID_RE } from "../crypto/ids.js";
import { COUNT_RE } from "../crypto/proof.js";
import type {
  PlatformEventEntry,
  PlatformPorts,
  ServiceContext,
} from "./ports.js";
import { LOCAL_OPERATOR_CONTEXT } from "./ports.js";
import { resolveActionEntry } from "./objects.js";

export const LINEAGE_MAX_NODES = 2000;
export const LINEAGE_MAX_DEPTH = 128;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isEventRefShape(v: unknown): v is EventRef {
  return (
    isObj(v) &&
    typeof v.source === "string" &&
    ID_RE.test(v.source) &&
    typeof v.stream === "string" &&
    ID_RE.test(v.stream) &&
    typeof v.seq === "string" &&
    COUNT_RE.test(v.seq) &&
    typeof v.hash === "string" &&
    /^[0-9a-f]{64}$/.test(v.hash)
  );
}

function pointerOfEntry(e: PlatformEventEntry): ReceiptPointer {
  return {
    workspace: e.workspace,
    event: { source: e.source, stream: e.stream, seq: e.seq, hash: e.hash },
  };
}

/** Look up a committed event by its full slot identity; null when absent. */
async function entryForRef(
  ports: PlatformPorts,
  workspace: string,
  ref: EventRef,
): Promise<PlatformEventEntry | null> {
  const slot = await ports.store.registry.eventSlot(
    workspace,
    ref.source,
    ref.stream,
    ref.seq,
  );
  return slot.find((e) => e.hash === ref.hash) ?? null;
}

async function recordJson(
  ports: PlatformPorts,
  entry: PlatformEventEntry,
): Promise<Record<string, unknown> | null> {
  const raw = await ports.store.getRecord(entry.cursor);
  if (raw === null) return null;
  try {
    return JSON.parse(Buffer.from(raw).toString("utf8")) as Record<
      string,
      unknown
    >;
  } catch {
    return null;
  }
}

/**
 * Resolve the gateway.action/1 observation joined to an action anchor:
 * StepClosed.data.observation (or an ObservationRecorded anchor directly)
 * → ObservationRecorded.data.value ObjectRef → object bytes → payload.
 * Returns the parsed payload or null (missing object ⇒ caller adds a gap).
 */
async function actionPayloadOf(
  ports: PlatformPorts,
  workspace: string,
  entry: PlatformEventEntry,
): Promise<{ payload: Record<string, unknown> | null; missing: boolean }> {
  const event = await recordJson(ports, entry);
  const data = event?.body !== undefined ? (event.body as Record<string, unknown>).data : undefined;
  if (!isObj(data)) return { payload: null, missing: false };

  let observationRef: EventRef | null = null;
  let valueRef: { digest?: unknown } | null = null;
  if (data.kind === "StepClosed" && isEventRefShape(data.observation)) {
    observationRef = data.observation;
  } else if (data.kind === "ObservationRecorded" && isObj(data.value)) {
    valueRef = data.value;
  }
  if (observationRef !== null) {
    const obs = await entryForRef(ports, workspace, observationRef);
    if (obs === null) return { payload: null, missing: true };
    const obsEvent = await recordJson(ports, obs);
    const obsData = isObj(obsEvent?.body)
      ? (obsEvent!.body as Record<string, unknown>).data
      : undefined;
    if (isObj(obsData) && isObj(obsData.value)) {
      valueRef = obsData.value;
    } else {
      return { payload: null, missing: false };
    }
  }
  if (valueRef === null || typeof valueRef.digest !== "string") {
    return { payload: null, missing: false };
  }
  let bytes: Uint8Array;
  try {
    bytes = await ports.store.getObject(valueRef.digest);
  } catch {
    return { payload: null, missing: true };
  }
  try {
    const payload = JSON.parse(
      Buffer.from(bytes).toString("utf8"),
    ) as Record<string, unknown>;
    if (isObj(payload) && payload.v === 1 && typeof payload.method === "string") {
      return { payload, missing: false };
    }
    return { payload: null, missing: false };
  } catch {
    return { payload: null, missing: false };
  }
}

export function createLineageService(
  ports: PlatformPorts,
  _ctx: ServiceContext = LOCAL_OPERATOR_CONTEXT,
): LineageService {
  void _ctx;
  return {
    async query(params: {
      action: NativeRef;
      max_nodes: number;
      max_depth: number;
    }) {
      if (
        !Number.isSafeInteger(params?.max_nodes) ||
        params.max_nodes < 1 ||
        params.max_nodes > LINEAGE_MAX_NODES
      ) {
        throw new RpcError(
          "SCHEMA_INVALID",
          `max_nodes must be an integer 1–${LINEAGE_MAX_NODES}`,
          { field: "max_nodes" },
        );
      }
      if (
        !Number.isSafeInteger(params?.max_depth) ||
        params.max_depth < 1 ||
        params.max_depth > LINEAGE_MAX_DEPTH
      ) {
        throw new RpcError(
          "SCHEMA_INVALID",
          `max_depth must be an integer 1–${LINEAGE_MAX_DEPTH}`,
          { field: "max_depth" },
        );
      }

      // Resolve the addressed action to its committed anchor event.
      const { entry: anchor } = await resolveActionEntry(ports, params.action);

      const nodes: Json[] = [];
      const edges: Json[] = [];
      const gaps: string[] = [];
      if (!ports.nativeLineageBound) gaps.push("CAP_ADAPTER_UNAVAILABLE");
      const seen = new Set<string>();

      /** True when the event is a registered action anchor. */
      const isAction = async (e: PlatformEventEntry): Promise<boolean> =>
        (await ports.store.registry.actionGet(
          sha256Hex(canonicalJson(pointerOfEntry(e))),
        )) !== null;

      interface Frontier {
        entry: PlatformEventEntry;
        pointer: ReceiptPointer;
        depth: number;
      }
      const queue: Frontier[] = [
        { entry: anchor, pointer: pointerOfEntry(anchor), depth: 0 },
      ];
      while (queue.length > 0 && nodes.length < params.max_nodes) {
        const { entry, pointer, depth } = queue.shift()!;
        const key = sha256Hex(canonicalJson(pointer));
        if (seen.has(key)) continue;
        seen.add(key);
        nodes.push(pointer as unknown as Json);
        if (depth >= params.max_depth) continue;

        const event = await recordJson(ports, entry);
        const body = isObj(event?.body)
          ? (event!.body as Record<string, unknown>)
          : null;

        // The action's previous_action link (inside its committed
        // gateway.action/1 observation) is the primary typed edge.
        const { payload, missing } = await actionPayloadOf(
          ports,
          entry.workspace,
          entry,
        );
        if (missing) gaps.push("MISSING_REFERENCE");
        const previous = payload?.previous_action;
        if (isObj(previous) && typeof previous.object_id === "string") {
          const target = await ports.store.registry.actionByNativeId(
            previous.object_id,
          );
          const targetEntry =
            target === null
              ? null
              : await entryForRef(
                  ports,
                  target.pointer.workspace,
                  target.pointer.event,
                );
          if (target === null || targetEntry === null) {
            gaps.push("MISSING_REFERENCE");
          } else {
            const to = pointerOfEntry(targetEntry);
            edges.push({
              from: pointer,
              to,
              kind: "previous_action",
            } as unknown as Json);
            queue.push({ entry: targetEntry, pointer: to, depth: depth + 1 });
          }
        }

        // Walk prev/parents for continuity: an unresolvable reference is an
        // explicit gap; a resolved non-action event is not a node; a
        // resolved action anchor is a node with a typed edge.
        if (body !== null) {
          if (typeof body.prev === "string" && body.seq !== "1") {
            const lane = await ports.store.registry.eventLane(
              entry.workspace,
              entry.source,
              entry.stream,
            );
            const pred = lane.find(
              (e) => BigInt(e.seq) === BigInt(entry.seq) - 1n,
            );
            if (pred === undefined || pred.hash !== body.prev) {
              gaps.push("MISSING_REFERENCE");
            } else if (await isAction(pred)) {
              const pp = pointerOfEntry(pred);
              edges.push({ from: pointer, to: pp, kind: "prev" } as unknown as Json);
              queue.push({ entry: pred, pointer: pp, depth: depth + 1 });
            }
          }
          if (Array.isArray(body.parents)) {
            for (const p of body.parents) {
              if (!isEventRefShape(p)) continue;
              const parent = await entryForRef(ports, entry.workspace, p);
              if (parent === null) {
                gaps.push("MISSING_REFERENCE");
                continue;
              }
              if (await isAction(parent)) {
                const pp = pointerOfEntry(parent);
                edges.push({ from: pointer, to: pp, kind: "parent" } as unknown as Json);
                queue.push({ entry: parent, pointer: pp, depth: depth + 1 });
              }
            }
          }
        }
      }
      if (nodes.length >= params.max_nodes && queue.length > 0) {
        gaps.push("TRUNCATED");
      }
      return {
        nodes,
        edges,
        gaps: [...new Set(gaps)],
        native_assessment: "NOT_EVALUATED",
      };
    },
  };
}
