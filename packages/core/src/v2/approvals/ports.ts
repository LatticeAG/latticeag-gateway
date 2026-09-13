/**
 * Gateway v2 — approval store ports (spec §3.2/§3.3 approval.*).
 *
 * An approval row is an immutable binding between a native action
 * NativeRef, a target, an expiry, and a native object reference; the
 * revision counter is the CAS handle for decide/cancel. All persistence
 * is behind `ApprovalPorts`; `createMemoryApprovalPorts()` is the
 * deterministic in-memory implementation used by tests.
 */
import type { Count, Hash, Id, NativeRef, ObjectRef } from "../protocol/refs.js";
import type { ApprovalState } from "../protocol/services.js";
import { sequentialIds, type Clock, type Entropy, type IdAllocator, cryptoEntropy } from "../peers/ports.js";

/** Durable approval row; `action`/`action_hash` never change after commit. */
export interface ApprovalRecord {
  approval: Id;
  /** CAS revision, decimal Count ("1" at creation). */
  revision: Count;
  state: ApprovalState;
  /** Immutable action commitment (native Proof action reference). */
  action: NativeRef;
  /** H(J(action)) — stored commitment compared on decide. */
  action_hash: Hash;
  target: string;
  expires_ms: number;
  /** Native object binding (ObjectRef) carried at request time. */
  native: ObjectRef;
  /** Native dispatch status observed by Gateway (never mutated by decide). */
  native_status: string;
  /** Hosted authority channel — always "NONE" locally. */
  authority: string;
  /** Requester principal id; only the requester may cancel. */
  requester: Id;
  created_ms: number;
  decided_ms: number | null;
  decision: "approve" | "deny" | null;
  reason: string | null;
  reviewer: Id | null;
}

export interface ApprovalPorts {
  /** Injectable clock (ms). */
  now(): number;
  /** ID allocator (approval ids). */
  newId(kind: "approval"): Id;
  readonly entropy: Entropy;

  putApproval(rec: ApprovalRecord): void;
  getApproval(approval: Id): ApprovalRecord | null;
  updateApproval(rec: ApprovalRecord): void;
  listApprovals(): ApprovalRecord[];
}

/** In-memory ApprovalPorts with a manual clock — deterministic tests. */
export interface MemoryApprovalPorts extends ApprovalPorts {
  readonly clock: { value: number };
  readonly ids: IdAllocator;
  readonly approvals: Map<Id, ApprovalRecord>;
  advance(ms: number): void;
}

export function createMemoryApprovalPorts(opts?: {
  now?: number;
  ids?: IdAllocator;
  entropy?: Entropy;
}): MemoryApprovalPorts {
  const clock = { value: opts?.now ?? 0 };
  const ids = opts?.ids ?? sequentialIds();
  const approvals = new Map<Id, ApprovalRecord>();
  const ports: MemoryApprovalPorts = {
    clock,
    ids,
    approvals,
    entropy: opts?.entropy ?? cryptoEntropy(),
    now: () => clock.value,
    newId: () => ids.next("approval"),
    advance(ms: number) {
      clock.value += ms;
    },
    putApproval: (rec) => {
      approvals.set(rec.approval, rec);
    },
    getApproval: (approval) => approvals.get(approval) ?? null,
    updateApproval: (rec) => {
      approvals.set(rec.approval, rec);
    },
    listApprovals: () => [...approvals.values()],
  };
  return ports;
}

export type { Clock, IdAllocator, Entropy };
