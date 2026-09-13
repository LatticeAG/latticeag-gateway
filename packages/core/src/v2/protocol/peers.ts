/**
 * Gateway v2 — agent peer identity, capability admission, and the pairing
 * state machine (spec §4.1–§4.3).
 *
 * The Capability/Scope structure is a Gateway access-control overlay, not a
 * replacement serialization of PolyMesh capabilities. The effective grant
 * is requested ∩ operator-approved ∩ configured policy ∩ native capability
 * binding; discovery advertises that intersection.
 */

import type { Count, Hash, Id, KeyMaterial, Signature } from "./refs.js";
import type { RegistryErrorCode } from "./errors.js";
import { TOPICS, type Topic } from "./topics.js";

// ── §4.1 verbatim types ──────────────────────────────────────────────────

export type ScopePermission =
  | "events.emit"
  | "events.consume"
  | "approvals.request"
  | "lineage.read"
  | "products.manage";

export const SCOPE_PERMISSIONS: readonly ScopePermission[] = [
  "events.emit",
  "events.consume",
  "approvals.request",
  "lineage.read",
  "products.manage",
];

export type Scope = {
  permission: ScopePermission;
  topics: string[];
  runs: string[];
  products: string[];
};

export type Capability = {
  name: string;
  revision: 1;
  profiles: string[];
  emit: string[];
  consume: string[];
  request_approvals: boolean;
  lineage: "none" | "own";
};

export type Registration = {
  pair: Id;
  code: string;
  key: KeyMaterial;
  challenge: Id;
  client_nonce: string;
  server_nonce: string;
  epoch: Count;
  profiles: string[];
  interfaces: "interfaces/1";
  capabilities: Capability[];
  proof: Signature;
};

export type PeerState = "REGISTERED" | "CONNECTED" | "DISCONNECTED" | "REVOKED";

export const PEER_STATES: readonly PeerState[] = [
  "REGISTERED",
  "CONNECTED",
  "DISCONNECTED",
  "REVOKED",
];

export type Peer = {
  id: Id;
  source: Id;
  key: Hash;
  role: "agent" | "operator";
  scopes: Scope[];
  capabilities: Capability[];
  state: PeerState;
  grant_revision: Count;
};

// ── Limits (§4.1–§4.3) ───────────────────────────────────────────────────

export const PEER_LIMITS = {
  /** Max capabilities per peer (§4.1). */
  maxCapabilities: 32,
  /** Max scopes per peer (§4.1). */
  maxScopes: 64,
  /** Max entries per nested set (topics/runs/products/profiles/emit/consume). */
  maxSetEntries: 64,
  /** Max bytes per capability name (§4.1). */
  maxNameBytes: 64,
  /** Max pending invitations per instance (§4.2). */
  maxPendingInvitations: 128,
  /** Invitation validity, ms (300 s). */
  invitationTtlMs: 300_000,
  /** Crockford-base32 invitation code length (50 bits). */
  invitationCodeChars: 10,
  /** Failed code/key attempts before an invitation is LOCKED (§4.2). */
  maxCodeAttempts: 5,
  /** Single-use challenge validity, ms (60 s). */
  challengeTtlMs: 60_000,
  /** Challenge/registration attempts per key per minute (§4.2). */
  authAttemptsPerKeyPerMinute: 5,
  /** Challenge/registration attempts per instance per minute (§4.2). */
  authAttemptsPerInstancePerMinute: 100,
  /** Access token lifetime, s (900). */
  accessTtlS: 900,
  /** Refresh token lifetime, s (30 days). */
  refreshTtlS: 2_592_000,
  /** Raw token bytes before base64url encoding. */
  tokenBytes: 32,
  /** Challenge/proof nonce bytes. */
  nonceBytes: 32,
  /** Max request-proof TTL, ms. */
  proofTtlMs: 60_000,
  /** Max issued_ms future skew, ms. */
  proofIssuedSkewMs: 5_000,
} as const;

// ── Pairing state machine (§4.2) ─────────────────────────────────────────

/**
 * Pair states: CREATED→AWAITING_OPERATOR→APPROVED→CONSUMED; a changed
 * proposal returns to AWAITING_OPERATOR, and any unconsumed non-terminal
 * state may become CANCELLED/EXPIRED/LOCKED. CONSUMED, CANCELLED, EXPIRED
 * and LOCKED are terminal: a cancelled invitation does not later expire.
 */
export const PAIR_STATES = [
  "CREATED",
  "AWAITING_OPERATOR",
  "APPROVED",
  "CONSUMED",
  "CANCELLED",
  "EXPIRED",
  "LOCKED",
] as const;

export type PairState = (typeof PAIR_STATES)[number];

export const PAIR_TRANSITIONS: Readonly<Record<PairState, readonly PairState[]>> = {
  CREATED: ["AWAITING_OPERATOR", "CANCELLED", "EXPIRED", "LOCKED"],
  AWAITING_OPERATOR: ["APPROVED", "CANCELLED", "EXPIRED", "LOCKED"],
  APPROVED: ["CONSUMED", "AWAITING_OPERATOR", "CANCELLED", "EXPIRED", "LOCKED"],
  CONSUMED: [],
  CANCELLED: [],
  EXPIRED: [],
  LOCKED: [],
};

export function canPairTransition(from: PairState, to: PairState): boolean {
  return PAIR_TRANSITIONS[from].includes(to);
}

// ── Scope validation (§4.1) ──────────────────────────────────────────────

export type ScopeValidation =
  | { ok: true }
  | { ok: false; code: RegistryErrorCode; field: string; message: string };

function scopeFail(field: string, message: string): ScopeValidation {
  return { ok: false, code: "SCHEMA_INVALID", field, message };
}

/**
 * Which scope dimensions each permission uses (§4.1): irrelevant
 * dimensions MUST be empty — empty arrays mean no resources, and no
 * wildcard or prefix match grants anything.
 *   events.emit / events.consume → topics + runs
 *   approvals.request / lineage.read → runs
 *   products.manage → products
 */
export const SCOPE_DIMENSIONS: Readonly<
  Record<ScopePermission, { topics: boolean; runs: boolean; products: boolean }>
> = {
  "events.emit": { topics: true, runs: true, products: false },
  "events.consume": { topics: true, runs: true, products: false },
  "approvals.request": { topics: false, runs: true, products: false },
  "lineage.read": { topics: false, runs: true, products: false },
  "products.manage": { topics: false, runs: false, products: true },
};

const SLUG_RE = /^[a-z][a-z0-9-]{0,63}$/;

/** The only run selector: `self` scopes to this peer's own runs (§4.1). */
export const RUN_SELECTOR_SELF = "self";

function checkSet(
  values: unknown,
  field: string,
): ScopeValidation | null {
  if (!Array.isArray(values)) {
    return scopeFail(field, `${field} must be an array`);
  }
  if (values.length > PEER_LIMITS.maxSetEntries) {
    return scopeFail(field, `${field} exceeds ${PEER_LIMITS.maxSetEntries} entries`);
  }
  const seen = new Set<string>();
  for (const entry of values) {
    if (typeof entry !== "string" || entry.length === 0) {
      return scopeFail(field, `${field} entries must be nonempty strings`);
    }
    if (seen.has(entry)) {
      return scopeFail(field, `${field} entries must be unique`);
    }
    seen.add(entry);
  }
  return null;
}

/**
 * Validate one scope's shape and dimension rules:
 *  - closed object {permission,topics,runs,products};
 *  - permission is a known ScopePermission;
 *  - topics entries are exact members of the §3.4 registry — wildcards and
 *    prefix matches are rejected, and no other topic names exist;
 *  - runs entries are the `self` selector or opaque native run text
 *    (never "*");
 *  - products entries are exact slugs;
 *  - irrelevant dimensions for the permission are empty;
 *  - nested sets are ≤64 entries, sorted-unique enforced for uniqueness.
 */
export function validateScope(scope: unknown): ScopeValidation {
  if (typeof scope !== "object" || scope === null || Array.isArray(scope)) {
    return scopeFail("scope", "scope must be an object");
  }
  const s = scope as Record<string, unknown>;
  for (const key of Object.keys(s)) {
    if (key !== "permission" && key !== "topics" && key !== "runs" && key !== "products") {
      return scopeFail(key, `unknown scope field ${key}`);
    }
  }
  const permission = s.permission;
  if (
    typeof permission !== "string" ||
    !(SCOPE_PERMISSIONS as readonly string[]).includes(permission)
  ) {
    return scopeFail("permission", "unknown scope permission");
  }
  for (const dim of ["topics", "runs", "products"] as const) {
    const bad = checkSet(s[dim], dim);
    if (bad) return bad;
  }
  const topics = s.topics as string[];
  const runs = s.runs as string[];
  const products = s.products as string[];
  const dims = SCOPE_DIMENSIONS[permission as ScopePermission];

  if (!dims.topics && topics.length > 0) {
    return scopeFail("topics", `topics must be empty for ${permission}`);
  }
  if (!dims.runs && runs.length > 0) {
    return scopeFail("runs", `runs must be empty for ${permission}`);
  }
  if (!dims.products && products.length > 0) {
    return scopeFail("products", `products must be empty for ${permission}`);
  }

  for (const t of topics) {
    if (t.includes("*")) {
      return scopeFail("topics", "wildcards never grant topics");
    }
    if (!(TOPICS as readonly string[]).includes(t)) {
      return scopeFail("topics", `topic ${t} is not in the §3.4 registry`);
    }
  }
  for (const r of runs) {
    if (r.includes("*")) {
      return scopeFail("runs", "wildcards never grant runs");
    }
    // RUN_SELECTOR_SELF selects only this peer's runs; every other value
    // is retained as opaque native run text within the enrolled
    // source/profile and grants nothing by prefix.
  }
  for (const p of products) {
    if (p.includes("*")) {
      return scopeFail("products", "wildcards never grant products");
    }
    if (!SLUG_RE.test(p)) {
      return scopeFail("products", `product ${p} is not an exact slug`);
    }
  }
  return { ok: true };
}

/** Validate a scope array: ≤64 entries, each valid, no exact duplicates. */
export function validateScopes(scopes: unknown): ScopeValidation {
  if (!Array.isArray(scopes)) {
    return scopeFail("scopes", "scopes must be an array");
  }
  if (scopes.length > PEER_LIMITS.maxScopes) {
    return scopeFail("scopes", `scopes exceed ${PEER_LIMITS.maxScopes} entries`);
  }
  const seen = new Set<string>();
  for (let i = 0; i < scopes.length; i += 1) {
    const result = validateScope(scopes[i]);
    if (!result.ok) return result;
    const key = JSON.stringify(scopes[i]);
    if (seen.has(key)) {
      return scopeFail("scopes", "duplicate scope entry");
    }
    seen.add(key);
  }
  return { ok: true };
}

// ── Scope admission (§4.1) ───────────────────────────────────────────────

/**
 * Admission context for a scope check: the enrolled peer tier, the
 * agents.allow_operator config flag, and whether a local operator
 * confirmation was collected for this grant.
 */
export interface ScopeAdmissionContext {
  /** Enrolled peer tier — never the peer's self-declared label. */
  readonly role: "agent" | "operator";
  /** Config agents.allow_operator. */
  readonly allowOperator: boolean;
  /** A local operator confirmation accompanied the grant. */
  readonly localOperatorConfirmation: boolean;
}

/**
 * §4.1 admission: `products.manage` requires an explicitly enrolled
 * operator-tier peer, config agents.allow_operator=true, a local operator
 * confirmation, and exact target products; a normal agent always receives
 * FORBIDDEN. Other permissions are structurally admitted once
 * validateScope passes (intersection with approved/policy/native binding
 * happens at grant computation).
 */
export function checkScopeAdmission(
  scope: Scope,
  ctx: ScopeAdmissionContext,
): ScopeValidation {
  if (scope.permission === "products.manage") {
    if (
      ctx.role !== "operator" ||
      !ctx.allowOperator ||
      !ctx.localOperatorConfirmation ||
      scope.products.length === 0
    ) {
      return {
        ok: false,
        code: "FORBIDDEN",
        field: "permission",
        message:
          "products.manage requires an enrolled operator peer, " +
          "agents.allow_operator=true, a local operator confirmation, " +
          "and exact target products",
      };
    }
  }
  return { ok: true };
}

/** True when a topic set grants a given topic (exact membership only). */
export function scopeGrantsTopic(scope: Scope, topic: Topic): boolean {
  return (
    (scope.permission === "events.emit" || scope.permission === "events.consume") &&
    scope.topics.includes(topic)
  );
}
