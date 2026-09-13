/**
 * Gateway v2 — CLI exit codes (spec §6.1) and the error-code → exit map.
 *
 * The §6.1 table is authoritative for meanings; `exitForError` maps each
 * registry error code onto it. Choices the spec leaves implicit are
 * documented on the map below; the guiding rule is that a conflict that
 * requires a new reviewed request maps to 10, an authority/identity
 * failure to 7, and a capability/composition gap to 12.
 */

import type { ErrorCode, RegistryErrorCode } from "./errors.js";

/** Exit code constants (§6.1 table). */
export const EXIT = {
  /** Requested operation completed, or explicit detached admission. */
  OK: 0,
  /** Child/general execution failure not otherwise classified. */
  GENERAL: 1,
  /** Usage, malformed flag, or schema/request syntax. */
  USAGE: 2,
  /** Config discovery/validation/migration failure. */
  CONFIG: 3,
  /** Policy/approval refusal, native authority unavailable, entitlement. */
  POLICY: 4,
  /** --fail-on-sync captured outbox nonempty, blocked, or unknowable. */
  SYNC: 5,
  /** Network/registry transport failure. */
  NETWORK: 6,
  /** Authentication, pairing, expiration, or revocation failure. */
  AUTH: 7,
  /** Signature/provenance/trust/dependency/platform rejection. */
  SIGNATURE: 8,
  /** Storage/journal corruption or unavailable persistence. */
  STORAGE: 9,
  /** Revision/idempotency/plan conflict requiring a new reviewed request. */
  REVISION: 10,
  /** Busy, backpressure, port collision, or service manager unavailable. */
  BUSY: 11,
  /** Unsupported native composition/profile/sandbox/runtime. */
  UNSUPPORTED: 12,
  /** CLI timeout (128+signal is Unix signal termination). */
  TIMEOUT: 124,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

/**
 * Registry code → CLI exit mapping.
 *
 * Resolved choices (documented because the spec table names error
 * categories, not individual codes):
 *  - CURSOR_GONE / APPROVAL_EXPIRED / CATALOG_ROLLBACK / STATE_TRANSITION /
 *    CANCEL_UNSAFE / OUTCOME_UNKNOWN → REVISION(10): each is a
 *    conflict-or-stale-state failure resolved by a fresh reviewed request
 *    rather than a policy or usage fault.
 *  - DEPENDENCY_CONFLICT → SIGNATURE(8): §6.1 groups dependency and
 *    platform rejections under 8.
 *  - DEPENDENTS_PRESENT → REVISION(10): the plan must change (cascade or
 *    remove dependents), like other conflicts.
 *  - OBJECT_LIMIT / OBJECT_CONFLICT / BODY_LIMIT → USAGE(2): request-shape
 *    violations of declared bounds.
 *  - HEALTH_FAILED → GENERAL(1): runtime failure not otherwise classified.
 *  - PAIRING_ codes → AUTH(7) alongside AUTH_ and TOKEN_ codes;
 *    FORBIDDEN / POLICY_DENIED / ENTITLEMENT_REQUIRED → POLICY(4).
 *  - READ_ONLY (internal daemon state) → POLICY(4): mutations are refused
 *    while evidence is quarantined.
 */
export const EXIT_FOR_ERROR: Readonly<Record<RegistryErrorCode, number>> = {
  JSON_INVALID: EXIT.USAGE,
  SCHEMA_INVALID: EXIT.USAGE,
  SCHEMA_UNSUPPORTED: EXIT.USAGE,
  METHOD_UNKNOWN: EXIT.USAGE,
  AUTH_REQUIRED: EXIT.AUTH,
  TOKEN_EXPIRED: EXIT.AUTH,
  TOKEN_REVOKED: EXIT.AUTH,
  FORBIDDEN: EXIT.POLICY,
  NOT_FOUND: EXIT.GENERAL,
  REVISION_CONFLICT: EXIT.REVISION,
  IDEMPOTENCY_CONFLICT: EXIT.REVISION,
  BUSY: EXIT.BUSY,
  BACKPRESSURE: EXIT.BUSY,
  STORAGE_UNAVAILABLE: EXIT.STORAGE,
  CURSOR_GONE: EXIT.REVISION,
  OBJECT_LIMIT: EXIT.USAGE,
  OBJECT_CONFLICT: EXIT.USAGE,
  SIGNATURE_INVALID: EXIT.SIGNATURE,
  PROVENANCE_INVALID: EXIT.SIGNATURE,
  TRUST_EXPIRED: EXIT.SIGNATURE,
  DEPENDENCY_CONFLICT: EXIT.SIGNATURE,
  DEPENDENTS_PRESENT: EXIT.REVISION,
  UNSUPPORTED_COMPOSITION: EXIT.UNSUPPORTED,
  CAP_ADAPTER_UNAVAILABLE: EXIT.UNSUPPORTED,
  MINT_EXCLUSIVE_HOLD_UNAVAILABLE: EXIT.UNSUPPORTED,
  HEALTH_FAILED: EXIT.GENERAL,
  SANDBOX_UNAVAILABLE: EXIT.UNSUPPORTED,
  PLAN_STALE: EXIT.REVISION,
  CANCEL_UNSAFE: EXIT.REVISION,
  OUTCOME_UNKNOWN: EXIT.REVISION,
  PORT_IN_USE: EXIT.BUSY,
  RUNTIME_UNSUPPORTED: EXIT.UNSUPPORTED,
  SERVICE_MANAGER_UNAVAILABLE: EXIT.BUSY,
  NETWORK_DENIED: EXIT.NETWORK,
  NETWORK_UNAVAILABLE: EXIT.NETWORK,
  SYNC_BLOCKED: EXIT.SYNC,
  ENTITLEMENT_REQUIRED: EXIT.POLICY,
  PAIRING_EXPIRED: EXIT.AUTH,
  PAIRING_LOCKED: EXIT.AUTH,
  APPROVAL_EXPIRED: EXIT.REVISION,
  POLICY_DENIED: EXIT.POLICY,
  CATALOG_ROLLBACK: EXIT.REVISION,
  STATE_TRANSITION: EXIT.REVISION,
  ARTIFACT_MISMATCH: EXIT.SIGNATURE,
  BODY_LIMIT: EXIT.USAGE,
};

/** Map an error code to a §6.1 exit code. */
export function exitForError(code: ErrorCode): number {
  if (code === "READ_ONLY") return EXIT.POLICY;
  return EXIT_FOR_ERROR[code];
}
