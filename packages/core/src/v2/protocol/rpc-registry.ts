/**
 * Gateway v2 — complete RPC registry (spec §3.2): all 58 methods.
 *
 * Roles: V viewer; A agent intersected with exact scopes; O operator;
 * R native-enrolled reviewer; L locally authenticated operator;
 * P pairing/session bootstrap with no product authority.
 *
 * `mutating` records whether the method changes server-side state —
 * durable or connection-accounted — so read-only/CSRF paths can gate it.
 * `receipt` is false only for the six connection-accounted methods in
 * NO_RECEIPT_METHODS (spec §3.1); every other method, including
 * authenticated rejections, gets a receipt.
 */

import { NO_RECEIPT_METHODS } from "./envelope.js";

export type Role = "V" | "A" | "O" | "R" | "L" | "P";

export const ROLES: readonly Role[] = ["V", "A", "O", "R", "L", "P"];

export interface RpcMethodSpec {
  /** Authorized role set, exactly as listed in the §3.2 table. */
  readonly roles: readonly Role[];
  /** Changes server-side state (durable or connection-accounted). */
  readonly mutating: boolean;
  /** Emits a semantic admission receipt (false = connection-accounted). */
  readonly receipt: boolean;
}

function spec(roles: readonly Role[], mutating: boolean): RpcMethodSpec {
  return { roles, mutating, receipt: true };
}

/** No-receipt variant for connection-accounted methods. */
function conn(roles: readonly Role[], mutating: boolean): RpcMethodSpec {
  return { roles, mutating, receipt: false };
}

export const RPC_METHODS = {
  // ── daemon ────────────────────────────────────────────────────────────
  /** Advertise exact supported profiles; no mutation. */
  "daemon.hello": conn(["V", "A", "O"], false),
  /** Instance/state/counts/current endpoint; no tokens or peer detail. */
  "daemon.status": spec(["V", "O"], false),
  /** Graceful stop; grace_ms 0–30000; response durably precedes shutdown. */
  "daemon.stop": spec(["L"], true),

  // ── config ────────────────────────────────────────────────────────────
  /** Current complete redacted config and revision. */
  "config.get": spec(["O"], false),
  /** Validate full document; no write. */
  "config.validate": spec(["O"], false),
  /** Full document with expected_revision; protected changes need review. */
  "config.apply": spec(["O"], true),

  // ── run ───────────────────────────────────────────────────────────────
  /** Register CLI owner, exact legacy ULID, kit, resume flag. */
  "run.register": spec(["A", "O"], true),
  /** Own run only; monotonic progress, 10 s cadence. */
  "run.heartbeat": conn(["A", "O"], true),
  /** Own child exit/signal and durable local-spool cut. */
  "run.finish": spec(["A", "O"], true),

  // ── events ────────────────────────────────────────────────────────────
  /** One Blob/native event; validate before durable ACK. */
  "events.publish": spec(["A", "O"], true),
  /** Filtered cursor page of authorized transport references. */
  "events.query": spec(["V", "A", "O"], false),
  /** Create 60 s renewable stream lease, topic filter, starting cursor. */
  "events.subscribe": spec(["V", "A", "O"], true),
  /** Advance only delivered cursor for own subscription. */
  "events.ack": conn(["V", "A", "O"], true),

  // ── objects / receipt / lineage ───────────────────────────────────────
  /** ≤1 MiB Blob referenced by caller-owned pending/committed actions. */
  "objects.put": spec(["A", "O"], true),
  /** Authorized reference plus receipt/cohort binding required. */
  "objects.get": spec(["V", "A", "O"], false),
  /** Native Proof receipt inventory/verification at a fixed cut. */
  "receipt.get": spec(["V", "A", "O"], false),
  /** Typed edges, gaps, grades; max_nodes 1–2000, max_depth 1–128. */
  "lineage.query": spec(["V", "A", "O"], false),

  // ── operations ────────────────────────────────────────────────────────
  /** Current stored job, transition cursor, old/new version, error. */
  "operation.get": spec(["V", "O"], false),
  /** Cancel before activation; CANCEL_UNSAFE after effect admission. */
  "operation.cancel": spec(["O"], true),

  // ── products ──────────────────────────────────────────────────────────
  /** Resolve and store a hash-bound reviewed plan; no hooks run. */
  "product.plan": spec(["O"], true),
  /** Commit reviewed install plan at expected revisions → Accepted. */
  "product.install": spec(["O"], true),
  /** Commit uninstall plan (cascade/data disposition already bound). */
  "product.uninstall": spec(["O"], true),
  /** Commit immutable replacement plan; old instance stays active. */
  "product.update": spec(["O"], true),
  /** Commit retained-version plan; rechecks trust/caps/deps/storage. */
  "product.rollback": spec(["O"], true),
  /** Page of installed instances. */
  "product.list": spec(["V", "O"], false),
  /** Bounded native health plus registry and sandbox status; ≤2000 ms. */
  "product.health": spec(["V", "O"], false),

  // ── agent pairing ─────────────────────────────────────────────────────
  /** Create 5-minute invitation with exact role/scopes. */
  "agent.pair.create": spec(["L"], true),
  /** Validate Registration proof/challenge/code; retain bounded proposal. */
  "agent.pair.propose": spec(["P"], true),
  /** Invitation/proposal state; code required for P, nullable only for L. */
  "agent.pair.get": spec(["P", "L"], false),
  /** Confirm fingerprint, proposal hash and narrowed scopes. */
  "agent.pair.approve": spec(["L"], true),
  /** Cancel unused invitation and retained pending registration. */
  "agent.pair.cancel": spec(["L"], true),

  // ── agent session ─────────────────────────────────────────────────────
  /** Single-use 60 s server nonce, gateway audience, boot/session epoch. */
  "agent.challenge": conn(["P", "A"], true),
  /** Verify challenge/key/pairing/consent; issue key-bound scoped token. */
  "agent.register": spec(["P"], true),
  /** Valid refresh proof rotates access/refresh tokens; same or narrower. */
  "agent.renew": conn(["A"], true),
  /** Authorized peer identities, connection state, capabilities, scopes. */
  "agent.list": spec(["V", "A", "O"], false),
  /** Durably revoke peer/grant before closing every connection. */
  "agent.revoke": spec(["O"], true),
  /** Disconnect self or operator-selected peer; keeps enrollment. */
  "agent.disconnect": spec(["A", "O"], true),

  // ── approvals ─────────────────────────────────────────────────────────
  /** Register immutable action NativeRef, target, expiry, reviewer policy. */
  "approval.request": spec(["A", "O"], true),
  /** Scoped pending/history page. */
  "approval.list": spec(["V", "R", "O"], false),
  /** Exact action commitment, revision, status, expiry, outcome. */
  "approval.get": spec(["V", "R", "O"], false),
  /** Native-enrolled reviewer; expected_revision + fresh commitment. */
  "approval.decide": spec(["R", "O"], true),
  /** Requester cancels its still-pending request. */
  "approval.cancel": spec(["A", "O"], true),

  // ── ui sessions ───────────────────────────────────────────────────────
  /** Mint one-use 60 s local browser bootstrap. */
  "ui.session.create": spec(["L"], true),
  /** Exchange fragment bootstrap for HttpOnly session cookie/CSRF. */
  "ui.session.exchange": conn(["P"], true),
  /** Revoke own session or operator-selected session. */
  "ui.session.revoke": spec(["V", "O"], true),

  // ── sync ──────────────────────────────────────────────────────────────
  /** Per-stream pending/in-flight/blocked/acked counts and metadata. */
  "sync.status": spec(["V", "O"], false),
  /** Stop new sends; already-sent requests still reach a recorded outcome. */
  "sync.pause": spec(["O"], true),
  /** Resume selected streams after renewed consent/trust checks. */
  "sync.resume": spec(["O"], true),
  /** CAS replace complete sync object; widening disclosure needs review. */
  "sync.configure": spec(["O"], true),
  /** Capture high-water marks, attempt delivery until timeout_ms 0–300000. */
  "sync.flush": spec(["O"], true),

  // ── cloud pairing ─────────────────────────────────────────────────────
  /** User-initiated device enrollment through a pinned provider binding. */
  "cloud.pair.begin": spec(["L"], true),
  /** Confirm returned tenant/device/key/scopes and egress preview. */
  "cloud.pair.complete": spec(["L"], true),
  /** Durably stop relay/sync credentials and remote sessions. */
  "cloud.pair.revoke": spec(["L"], true),

  // ── catalog ───────────────────────────────────────────────────────────
  /** Fetch bounded signed index or import cached bundle. */
  "catalog.refresh": spec(["O"], true),
  /** Query signed cached entries; q ≤128 bytes; series filter or null. */
  "catalog.search": spec(["V", "O"], false),
  /** Exact slug/version metadata, edge statuses, trust freshness. */
  "catalog.show": spec(["V", "O"], false),
  /** Pin slug/version/archive digest and index commitment. */
  "catalog.pin": spec(["O"], true),
  /** CAS remove one pin. */
  "catalog.unpin": spec(["O"], true),
} as const satisfies Record<string, RpcMethodSpec>;

export type RpcMethodName = keyof typeof RPC_METHODS;

export function isRpcMethod(name: string): name is RpcMethodName {
  return Object.prototype.hasOwnProperty.call(RPC_METHODS, name);
}

export function rpcMethodSpec(name: RpcMethodName): RpcMethodSpec {
  return RPC_METHODS[name];
}

/** True when the method gets a semantic receipt (not connection-accounted). */
export function methodHasReceipt(name: RpcMethodName): boolean {
  return RPC_METHODS[name].receipt && !NO_RECEIPT_METHODS.has(name);
}
