/**
 * Gateway v2 — approval lifecycle manager (spec §3.2/§3.3 approval.*).
 *
 * request commits an immutable action binding (NativeRef + target +
 * expiry + native object) at revision "1" in state PENDING with
 * authority "NONE" — requesting confers no execute permission. decide is
 * a CAS on expected_revision by a native-enrolled reviewer or operator:
 * first commit wins, later same-revision decisions get REVISION_CONFLICT
 * with no resurrection (TV-GW-33). Expiry applies at equality:
 * `now >= expires_ms` decides nothing but APPROVAL_EXPIRED (TV-GW-34).
 * cancel is requester-only on a still-pending row and never undoes
 * applied native effects. Non-reviewers and viewers get FORBIDDEN
 * (TV-GW-36) — hosted receipts never confer reviewer authority.
 */
import { Buffer } from "node:buffer";
import type { Count, Hash, Id, Json, NativeRef, ObjectRef } from "../protocol/refs.js";
import type { Page } from "../protocol/envelope.js";
import { RpcError } from "../protocol/errors.js";
import type { ApprovalState, Principal } from "../protocol/services.js";
import { canonicalJson } from "../crypto/canonical.js";
import { isHash64, sha256Hex } from "../crypto/hash.js";
import { isId } from "../crypto/ids.js";
import { bumpCount } from "../peers/registry.js";
import type { ApprovalPorts, ApprovalRecord } from "./ports.js";

function rpc(code: RpcError["code"], message: string, field?: string): never {
  throw new RpcError(code, message, { field: field ?? null });
}

/** Caller context for decide/cancel (server-side principal, never self-claimed). */
export interface ApprovalCaller {
  /** Principal id (peer id, operator id, session principal). */
  id?: Id;
  /** §3.2 principal role. */
  role?: Principal["role"];
  /** Native-enrolled reviewer grant (R) — server-side enrollment state. */
  reviewer?: boolean;
}

/** Default when no caller context is threaded: the local operator. */
const LOCAL_OPERATOR: Required<ApprovalCaller> = {
  id: "operator1",
  role: "local_operator",
  reviewer: true,
};

const APPROVAL_STATES: readonly ApprovalState[] = [
  "PENDING",
  "APPROVED",
  "DENIED",
  "CANCELLED",
  "EXPIRED",
];

const NATIVEREF_KEYS = [
  "profile",
  "namespace",
  "object_id",
  "commitment",
  "raw_sha256",
  "bytes",
] as const;

const OBJECTREF_KEYS = ["digest", "bytes", "media"] as const;
const MEDIA = ["application/json", "application/octet-stream", "text/plain"];
const COUNT_RE = /^(0|[1-9][0-9]*)$/;
const ASCII_RE = /^[\x20-\x7e]+$/;

function validateNativeRef(v: unknown, field: string): NativeRef {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    rpc("SCHEMA_INVALID", `${field} must be an object`, field);
  }
  const o = v as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!NATIVEREF_KEYS.includes(k as (typeof NATIVEREF_KEYS)[number])) {
      rpc("SCHEMA_INVALID", `unknown ${field} field ${k}`, field);
    }
  }
  for (const k of NATIVEREF_KEYS) {
    if (!(k in o)) rpc("SCHEMA_INVALID", `missing ${field}.${k}`, field);
  }
  for (const k of ["profile", "namespace", "object_id"] as const) {
    const s = o[k];
    if (
      typeof s !== "string" ||
      s.length === 0 ||
      Buffer.byteLength(s, "utf8") > (k === "object_id" ? 256 : 128) ||
      !ASCII_RE.test(s)
    ) {
      rpc("SCHEMA_INVALID", `${field}.${k} is out of range`, field);
    }
  }
  if (o.commitment !== null && typeof o.commitment !== "string") {
    rpc("SCHEMA_INVALID", `${field}.commitment must be a string or null`, field);
  }
  if (!isHash64(o.raw_sha256)) {
    rpc("SCHEMA_INVALID", `${field}.raw_sha256 must be 64 lowercase hex`, field);
  }
  if (typeof o.bytes !== "string" || !COUNT_RE.test(o.bytes)) {
    rpc("SCHEMA_INVALID", `${field}.bytes must be a canonical Count`, field);
  }
  return o as unknown as NativeRef;
}

function validateObjectRef(v: unknown, field: string): ObjectRef {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    rpc("SCHEMA_INVALID", `${field} must be an object`, field);
  }
  const o = v as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!OBJECTREF_KEYS.includes(k as (typeof OBJECTREF_KEYS)[number])) {
      rpc("SCHEMA_INVALID", `unknown ${field} field ${k}`, field);
    }
  }
  for (const k of OBJECTREF_KEYS) {
    if (!(k in o)) rpc("SCHEMA_INVALID", `missing ${field}.${k}`, field);
  }
  if (!isHash64(o.digest)) rpc("SCHEMA_INVALID", `${field}.digest must be 64 hex`, field);
  if (typeof o.bytes !== "string" || !COUNT_RE.test(o.bytes)) {
    rpc("SCHEMA_INVALID", `${field}.bytes must be a canonical Count`, field);
  }
  if (typeof o.media !== "string" || !MEDIA.includes(o.media)) {
    rpc("SCHEMA_INVALID", `${field}.media must be a closed Media value`, field);
  }
  return o as unknown as ObjectRef;
}

/** Commitment used to compare a re-supplied action against the binding. */
export function actionCommitment(action: NativeRef): Hash {
  return sha256Hex(canonicalJson(action));
}

export class ApprovalManager {
  private readonly ports: ApprovalPorts;

  constructor(ports: ApprovalPorts) {
    this.ports = ports;
  }

  private now(): number {
    return this.ports.now();
  }

  /** Lazily apply P10 expiry-at-equality to a PENDING row. */
  private expireIfDue(rec: ApprovalRecord): void {
    if (rec.state === "PENDING" && this.now() >= rec.expires_ms) {
      rec.state = "EXPIRED";
      this.ports.updateApproval(rec);
    }
  }

  private getLive(approval: Id): ApprovalRecord {
    if (!isId(approval)) rpc("SCHEMA_INVALID", "approval must be an Id", "approval");
    const rec = this.ports.getApproval(approval);
    if (rec === null) rpc("NOT_FOUND", "unknown approval", "approval");
    this.expireIfDue(rec);
    return rec;
  }

  // ── RPC-facing operations ──────────────────────────────────────────────

  /**
   * approval.request: commit the immutable action binding. No execute
   * permission is conferred; the stored row is what decide/cancel act on.
   */
  request(
    params: { action: NativeRef; target: string; expires_ms: number; native: ObjectRef },
    caller?: ApprovalCaller,
  ): ApprovalRecord {
    const action = validateNativeRef(params.action, "action");
    const native = validateObjectRef(params.native, "native");
    if (typeof params.target !== "string" || params.target.length === 0 || Buffer.byteLength(params.target, "utf8") > 1024) {
      rpc("SCHEMA_INVALID", "target must be a nonempty string ≤1024 bytes", "target");
    }
    if (!Number.isSafeInteger(params.expires_ms)) {
      rpc("SCHEMA_INVALID", "expires_ms must be a safe integer", "expires_ms");
    }
    const now = this.now();
    const rec: ApprovalRecord = {
      approval: this.ports.newId("approval"),
      revision: "1",
      state: "PENDING",
      action,
      action_hash: actionCommitment(action),
      target: params.target,
      expires_ms: params.expires_ms,
      native,
      native_status: "NOT_DISPATCHED",
      authority: "NONE",
      requester: caller?.id ?? LOCAL_OPERATOR.id,
      created_ms: now,
      decided_ms: null,
      decision: null,
      reason: null,
      reviewer: null,
    };
    this.ports.putApproval(rec);
    return rec;
  }

  /** approval.list: scoped pending/history page, insertion order. */
  list(params: {
    state?: ApprovalState;
    after: string | null;
    limit: number;
  }): Page<Json> {
    if (params.state !== undefined && !APPROVAL_STATES.includes(params.state)) {
      rpc("SCHEMA_INVALID", "unknown approval state", "state");
    }
    if (!Number.isSafeInteger(params.limit) || params.limit < 1 || params.limit > 200) {
      rpc("SCHEMA_INVALID", "limit must be 1–200", "limit");
    }
    const all = this.ports
      .listApprovals()
      .sort((a, b) => a.created_ms - b.created_ms || (a.approval < b.approval ? -1 : 1));
    for (const rec of all) this.expireIfDue(rec);
    const filtered =
      params.state === undefined ? all : all.filter((r) => r.state === params.state);
    let start = 0;
    if (params.after !== null) {
      const idx = filtered.findIndex((r) => r.approval === params.after);
      if (idx === -1) rpc("CURSOR_GONE", "unknown page cursor", "after");
      start = idx + 1;
    }
    const page = filtered.slice(start, start + params.limit);
    return {
      items: page.map((r) => this.view(r) as unknown as Json),
      next: start + params.limit < filtered.length ? page[page.length - 1]!.approval : null,
    };
  }

  /** approval.get view. */
  get(params: { approval: Id }): ApprovalRecord {
    return this.getLive(params.approval);
  }

  /** Public view fields matching §3.3 approval.get. */
  view(rec: ApprovalRecord): {
    approval: Id;
    revision: Count;
    state: ApprovalState;
    action: NativeRef;
    expires_ms: number;
    native_status: string;
  } {
    return {
      approval: rec.approval,
      revision: rec.revision,
      state: rec.state,
      action: rec.action,
      expires_ms: rec.expires_ms,
      native_status: rec.native_status,
    };
  }

  /**
   * approval.decide: CAS `expected_revision` then commit APPROVED/DENIED.
   * Ordering is deliberate — caller authorization (method stage), then
   * NOT_FOUND, then the revision CAS (a committed decision beats a stale
   * same-revision attempt — TV-GW-33), then expiry at equality
   * (TV-GW-34), then terminal-state and action-commitment checks.
   */
  decide(
    params: {
      approval: Id;
      expected_revision: Count;
      action: NativeRef;
      decision: "approve" | "deny";
      reason: string;
    },
    caller?: ApprovalCaller,
  ): ApprovalRecord {
    const who = caller ?? LOCAL_OPERATOR;
    const isReviewer =
      who.reviewer === true || who.role === "operator" || who.role === "local_operator";
    if (!isReviewer) {
      rpc("FORBIDDEN", "approval.decide requires a native-enrolled reviewer or operator");
    }
    const rec = this.getLive(params.approval);
    if (params.expected_revision !== rec.revision) {
      rpc("REVISION_CONFLICT", "expected_revision does not match", "expected_revision");
    }
    if (rec.state === "EXPIRED") {
      rpc("APPROVAL_EXPIRED", "approval expired", "approval");
    }
    if (rec.state !== "PENDING") {
      rpc("STATE_TRANSITION", `approval is ${rec.state}`, "approval");
    }
    if (params.decision !== "approve" && params.decision !== "deny") {
      rpc("SCHEMA_INVALID", "decision must be approve|deny", "decision");
    }
    if (typeof params.reason !== "string") {
      rpc("SCHEMA_INVALID", "reason must be a string", "reason");
    }
    // The fresh action commitment must match the immutable binding.
    const action = validateNativeRef(params.action, "action");
    if (actionCommitment(action) !== rec.action_hash) {
      rpc("REVISION_CONFLICT", "action does not match the requested binding", "action");
    }
    rec.revision = bumpCount(rec.revision);
    rec.state = params.decision === "approve" ? "APPROVED" : "DENIED";
    rec.decision = params.decision;
    rec.reason = params.reason;
    rec.decided_ms = this.now();
    rec.reviewer = who.id ?? null;
    this.ports.updateApproval(rec);
    return rec;
  }

  /**
   * approval.cancel: the requester cancels its still-pending request.
   * Authorization precedes the CAS (the requester check needs the row);
   * cancelling never undoes already-applied native effects.
   */
  cancel(
    params: { approval: Id; expected_revision: Count },
    caller?: ApprovalCaller,
  ): ApprovalRecord {
    const who = caller ?? LOCAL_OPERATOR;
    if (who.role === "viewer" || who.role === "bootstrap") {
      rpc("FORBIDDEN", "approval.cancel is not available to this principal");
    }
    const rec = this.getLive(params.approval);
    if (who.id !== rec.requester) {
      rpc("FORBIDDEN", "only the requester may cancel an approval", "approval");
    }
    if (params.expected_revision !== rec.revision) {
      rpc("REVISION_CONFLICT", "expected_revision does not match", "expected_revision");
    }
    if (rec.state === "EXPIRED") {
      rpc("APPROVAL_EXPIRED", "approval expired", "approval");
    }
    if (rec.state !== "PENDING") {
      rpc("STATE_TRANSITION", `approval is ${rec.state}`, "approval");
    }
    rec.revision = bumpCount(rec.revision);
    rec.state = "CANCELLED";
    this.ports.updateApproval(rec);
    return rec;
  }
}
