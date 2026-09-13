/**
 * ReceiptService — receipt.get (spec §3.2, §3.3 line 325).
 *
 * Without a bound native Proof collector the result is the object-only
 * index summary, never a canonical Bundle: every object reference in the
 * action's lane cut is listed with availability "WITHHELD" (the feed has
 * not disclosed those bytes), the outer envelope is SIGNED_UNANCHORED, the
 * inner native assessment is NOT_EVALUATED, and bundle is null. The code
 * path never fabricates a native bundle or upgrades the summary into a
 * receipt.
 */
import type { Blob, Json, NativeRef } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type { ReceiptService } from "../protocol/services.js";
import type { PlatformPorts, ServiceContext } from "./ports.js";
import { LOCAL_OPERATOR_CONTEXT } from "./ports.js";
import { collectActionObjectRefs, resolveActionEntry } from "./objects.js";

export function createReceiptService(
  ports: PlatformPorts,
  _ctx: ServiceContext = LOCAL_OPERATOR_CONTEXT,
): ReceiptService {
  void _ctx;
  return {
    async get(params: { action: NativeRef; disclosure: "HASHES_ONLY" | string }) {
      if (typeof params?.disclosure !== "string" || params.disclosure === "") {
        throw new RpcError(
          "SCHEMA_INVALID",
          "disclosure must be an explicit string",
          { field: "disclosure" },
        );
      }
      const { entry } = await resolveActionEntry(ports, params.action);
      const refs = await collectActionObjectRefs(ports, entry);
      const inventory: Json[] = [...refs.values()]
        .map((r) => ({
          kind: "object",
          digest: r.digest,
          bytes: r.bytes,
          availability: "WITHHELD",
        }))
        .sort((a, b) => (a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0));
      return {
        action: params.action,
        inventory,
        outer: "SIGNED_UNANCHORED",
        inner: "NOT_EVALUATED",
        bundle: null as Blob | null,
      };
    },
  };
}
