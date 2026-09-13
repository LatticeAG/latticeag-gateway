/**
 * OperationService — operation.get / operation.cancel (spec §3.2).
 *
 * get returns the stored job verbatim — transition cursor, old/new
 * version, retained error — never a re-execution. cancel is safe only
 * before effect admission: QUEUED/PLANNED/FETCHING/VERIFIED/READY-class
 * states move to CANCELLED through a commit mutation; once the operation
 * has admitted native effects (STAGED/STARTING/RUNNING/DRAINING and every
 * terminal-or-active state beyond), cancel returns CANCEL_UNSAFE and the
 * operation is preserved (an UNKNOWN outcome is never rewritten).
 */
import type { Id } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type { OperationService } from "../protocol/services.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import { isId } from "../crypto/ids.js";
import type {
  PlatformOperationEntry,
  PlatformPorts,
  ServiceContext,
} from "./ports.js";
import { LOCAL_OPERATOR_CONTEXT } from "./ports.js";

/**
 * States where cancellation precedes any admitted effect. QUEUED/READY
 * cover the §3.3 exchange; PLANNED/FETCHING/VERIFIED are pre-activation
 * product candidate states (§5.4).
 */
const CANCELLABLE: ReadonlySet<string> = new Set([
  "QUEUED",
  "PLANNED",
  "FETCHING",
  "VERIFIED",
  "READY",
  "STAGED",
]);

async function getEntry(
  ports: PlatformPorts,
  id: Id,
): Promise<PlatformOperationEntry> {
  const entry = await ports.store.registry.operationGet(id);
  if (entry === null) {
    throw new RpcError("NOT_FOUND", `operation ${id} unknown`, {
      field: "operation",
    });
  }
  return entry;
}

export function createOperationService(
  ports: PlatformPorts,
  _ctx: ServiceContext = LOCAL_OPERATOR_CONTEXT,
): OperationService {
  void _ctx;
  return {
    async get(params: { operation: Id }) {
      if (!isId(params?.operation)) {
        throw new RpcError(
          "SCHEMA_INVALID",
          "operation must match the Proof Id grammar",
          { field: "operation" },
        );
      }
      const e = await getEntry(ports, params.operation);
      return {
        operation: e.id,
        kind: e.kind,
        state: e.state,
        slug: e.slug,
        from: e.from,
        to: e.to,
        cursor: e.cursor ?? "",
        error: e.error,
      };
    },

    async cancel(params: { operation: Id }) {
      if (!isId(params?.operation)) {
        throw new RpcError(
          "SCHEMA_INVALID",
          "operation must match the Proof Id grammar",
          { field: "operation" },
        );
      }
      const e = await getEntry(ports, params.operation);
      if (e.state === "CANCELLED") {
        return { operation: e.id, state: "CANCELLED" };
      }
      if (!CANCELLABLE.has(e.state)) {
        // Past effect admission (or already terminal): never pretend the
        // native effect was un-run.
        throw new RpcError(
          "CANCEL_UNSAFE",
          `operation ${e.id} is ${e.state}; effects may already be admitted`,
          { field: "operation" },
        );
      }
      const result = { operation: e.id, state: "CANCELLED" };
      await ports.store.commit({
        mutation: {
          v: 1,
          kind: "operations",
          operations: [{ ...e, state: "CANCELLED" }],
        } as never,
        result_sha256: sha256Hex(canonicalJson(result)),
      });
      return result;
    },
  };
}
