/**
 * Gateway v2 — approval.* RPC service facade (spec §3.2/§3.3).
 *
 * Wraps ApprovalManager behind the ApprovalService contract. Methods
 * accept an optional trailing `caller` (the authenticated principal
 * context threaded by the dispatcher) without changing the interface
 * signatures — `ApprovalCaller` carries the server-side reviewer flag and
 * requester id used by decide/cancel.
 */
import type { Count, Id, Json, NativeRef, ObjectRef } from "../protocol/refs.js";
import type { Page } from "../protocol/envelope.js";
import type { ApprovalService, ApprovalState } from "../protocol/services.js";
import { ApprovalManager, type ApprovalCaller } from "./approvals.js";
import type { ApprovalPorts } from "./ports.js";

export interface ApprovalRuntime {
  service: ApprovalService;
  manager: ApprovalManager;
  ports: ApprovalPorts;
}

export function createApprovalRuntime(ports: ApprovalPorts): ApprovalRuntime {
  const manager = new ApprovalManager(ports);

  const service: ApprovalService = {
    async request(
      params: { action: NativeRef; target: string; expires_ms: number; native: ObjectRef },
      caller?: ApprovalCaller,
    ) {
      const rec = manager.request(params, caller);
      return {
        approval: rec.approval,
        revision: rec.revision,
        state: "PENDING" as const,
        authority: rec.authority,
      };
    },

    async list(
      params: { state?: ApprovalState; after: string | null; limit: number },
    ): Promise<Page<Json>> {
      return manager.list(params);
    },

    async get(params: { approval: Id }) {
      return manager.view(manager.get(params));
    },

    async decide(
      params: {
        approval: Id;
        expected_revision: Count;
        action: NativeRef;
        decision: "approve" | "deny";
        reason: string;
      },
      caller?: ApprovalCaller,
    ) {
      const rec = manager.decide(params, caller);
      return {
        approval: rec.approval,
        revision: rec.revision,
        state: rec.state,
        native_status: rec.native_status,
      };
    },

    async cancel(
      params: { approval: Id; expected_revision: Count },
      caller?: ApprovalCaller,
    ) {
      const rec = manager.cancel(params, caller);
      return {
        approval: rec.approval,
        revision: rec.revision,
        state: "CANCELLED" as const,
      };
    },
  };

  return { service, manager, ports };
}

/** createApprovalService facade: returns just the ApprovalService contract. */
export function createApprovalService(ports: ApprovalPorts): ApprovalService {
  return createApprovalRuntime(ports).service;
}
