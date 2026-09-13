/**
 * Gateway v2 — closed error-code registry (spec §3.1).
 *
 * Errors are closed codes, not exception messages. The registry is exactly
 * 45 codes; `READ_ONLY` is included in the wider `ErrorCode` union because
 * §2.3 uses it as a daemon state (corrupt committed bytes enter READ_ONLY),
 * but it is not part of the wire registry and has no HTTP mapping.
 */

/** The 45 closed wire error codes, transcribed in spec order (§3.1). */
export const ERROR_CODES = [
  // Base codes
  "JSON_INVALID",
  "SCHEMA_INVALID",
  "SCHEMA_UNSUPPORTED",
  "METHOD_UNKNOWN",
  "AUTH_REQUIRED",
  "TOKEN_EXPIRED",
  "TOKEN_REVOKED",
  "FORBIDDEN",
  "NOT_FOUND",
  // Revision/idempotency/storage/object/trust codes
  "REVISION_CONFLICT",
  "IDEMPOTENCY_CONFLICT",
  "BUSY",
  "BACKPRESSURE",
  "STORAGE_UNAVAILABLE",
  "CURSOR_GONE",
  "OBJECT_LIMIT",
  "OBJECT_CONFLICT",
  "SIGNATURE_INVALID",
  "PROVENANCE_INVALID",
  "TRUST_EXPIRED",
  // Lifecycle/dependency codes
  "DEPENDENCY_CONFLICT",
  "DEPENDENTS_PRESENT",
  "UNSUPPORTED_COMPOSITION",
  "CAP_ADAPTER_UNAVAILABLE",
  "MINT_EXCLUSIVE_HOLD_UNAVAILABLE",
  "HEALTH_FAILED",
  "SANDBOX_UNAVAILABLE",
  "PLAN_STALE",
  "CANCEL_UNSAFE",
  "OUTCOME_UNKNOWN",
  // Operational codes
  "PORT_IN_USE",
  "RUNTIME_UNSUPPORTED",
  "SERVICE_MANAGER_UNAVAILABLE",
  "NETWORK_DENIED",
  "NETWORK_UNAVAILABLE",
  "SYNC_BLOCKED",
  "ENTITLEMENT_REQUIRED",
  "PAIRING_EXPIRED",
  "PAIRING_LOCKED",
  "APPROVAL_EXPIRED",
  "POLICY_DENIED",
  "CATALOG_ROLLBACK",
  "STATE_TRANSITION",
  "ARTIFACT_MISMATCH",
  "BODY_LIMIT",
] as const;

/** A code from the closed 45-entry wire registry. */
export type RegistryErrorCode = (typeof ERROR_CODES)[number];

/**
 * Daemon-internal state code: corrupt committed bytes enter READ_ONLY
 * (spec §2.3). Never sent as a wire `error.code`; surfaced through
 * STATE_TRANSITION / POLICY_DENIED instead.
 */
export const READ_ONLY = "READ_ONLY" as const;

/** Any code this layer can name: the wire registry plus internal states. */
export type ErrorCode = RegistryErrorCode | typeof READ_ONLY;

/**
 * HTTP status map per spec §3.1 (success is 200):
 *  400 JSON_INVALID/SCHEMA_INVALID/SCHEMA_UNSUPPORTED/METHOD_UNKNOWN
 *  401 AUTH_REQUIRED/TOKEN_EXPIRED/TOKEN_REVOKED
 *  403 FORBIDDEN/POLICY_DENIED/ENTITLEMENT_REQUIRED/NETWORK_DENIED/PAIRING_LOCKED
 *  404 NOT_FOUND
 *  409 REVISION_CONFLICT/IDEMPOTENCY_CONFLICT/OBJECT_CONFLICT/
 *      DEPENDENCY_CONFLICT/DEPENDENTS_PRESENT/PLAN_STALE/CANCEL_UNSAFE/
 *      OUTCOME_UNKNOWN/CATALOG_ROLLBACK/STATE_TRANSITION/PORT_IN_USE
 *  410 CURSOR_GONE/PAIRING_EXPIRED/APPROVAL_EXPIRED/TRUST_EXPIRED
 *  413 OBJECT_LIMIT/BODY_LIMIT
 *  422 SIGNATURE_INVALID/PROVENANCE_INVALID/ARTIFACT_MISMATCH
 *  429 BUSY/BACKPRESSURE
 *  501 UNSUPPORTED_COMPOSITION/CAP_ADAPTER_UNAVAILABLE/
 *      MINT_EXCLUSIVE_HOLD_UNAVAILABLE/SANDBOX_UNAVAILABLE/
 *      RUNTIME_UNSUPPORTED/SERVICE_MANAGER_UNAVAILABLE
 *  503 STORAGE_UNAVAILABLE/NETWORK_UNAVAILABLE/HEALTH_FAILED/SYNC_BLOCKED
 */
export const HTTP_STATUS: Record<RegistryErrorCode, number> = {
  JSON_INVALID: 400,
  SCHEMA_INVALID: 400,
  SCHEMA_UNSUPPORTED: 400,
  METHOD_UNKNOWN: 400,
  AUTH_REQUIRED: 401,
  TOKEN_EXPIRED: 401,
  TOKEN_REVOKED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  REVISION_CONFLICT: 409,
  IDEMPOTENCY_CONFLICT: 409,
  BUSY: 429,
  BACKPRESSURE: 429,
  STORAGE_UNAVAILABLE: 503,
  CURSOR_GONE: 410,
  OBJECT_LIMIT: 413,
  OBJECT_CONFLICT: 409,
  SIGNATURE_INVALID: 422,
  PROVENANCE_INVALID: 422,
  TRUST_EXPIRED: 410,
  DEPENDENCY_CONFLICT: 409,
  DEPENDENTS_PRESENT: 409,
  UNSUPPORTED_COMPOSITION: 501,
  CAP_ADAPTER_UNAVAILABLE: 501,
  MINT_EXCLUSIVE_HOLD_UNAVAILABLE: 501,
  HEALTH_FAILED: 503,
  SANDBOX_UNAVAILABLE: 501,
  PLAN_STALE: 409,
  CANCEL_UNSAFE: 409,
  OUTCOME_UNKNOWN: 409,
  PORT_IN_USE: 409,
  RUNTIME_UNSUPPORTED: 501,
  SERVICE_MANAGER_UNAVAILABLE: 501,
  NETWORK_DENIED: 403,
  NETWORK_UNAVAILABLE: 503,
  SYNC_BLOCKED: 503,
  ENTITLEMENT_REQUIRED: 403,
  PAIRING_EXPIRED: 410,
  PAIRING_LOCKED: 403,
  APPROVAL_EXPIRED: 410,
  POLICY_DENIED: 403,
  CATALOG_ROLLBACK: 409,
  STATE_TRANSITION: 409,
  ARTIFACT_MISMATCH: 422,
  BODY_LIMIT: 413,
};

/**
 * Codes eligible for `retryable: true` (spec §3.1): BUSY/BACKPRESSURE/
 * NETWORK_UNAVAILABLE always; STORAGE_UNAVAILABLE only when transient;
 * SYNC_BLOCKED only when caused solely by a transient destination outage.
 * Membership here is necessary, not sufficient — the handler decides.
 */
export const RETRYABLE: ReadonlySet<RegistryErrorCode> = new Set([
  "BUSY",
  "BACKPRESSURE",
  "NETWORK_UNAVAILABLE",
  "STORAGE_UNAVAILABLE",
  "SYNC_BLOCKED",
]);

/**
 * Error precedence (spec §3.1), earliest stage first:
 * transport cap → JSON → envelope/schema → authentication → method
 * authorization → resource scope → idempotency → revision/dependency/policy
 * → storage → execution.
 */
export const ERROR_PRECEDENCE = [
  "TRANSPORT_CAP",
  "JSON",
  "ENVELOPE_SCHEMA",
  "AUTHENTICATION",
  "METHOD_AUTHORIZATION",
  "RESOURCE_SCOPE",
  "IDEMPOTENCY",
  "REVISION_DEPENDENCY_POLICY",
  "STORAGE",
  "EXECUTION",
] as const;

export type ErrorStage = (typeof ERROR_PRECEDENCE)[number];

/**
 * Structured RPC failure. `code` is a closed registry code, `retryable`
 * defaults to RETRYABLE membership, `field` names the offending request
 * field or null.
 */
export class RpcError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly field: string | null;

  constructor(
    code: ErrorCode,
    message: string,
    options?: { retryable?: boolean; field?: string | null; cause?: unknown },
  ) {
    super(message, options);
    this.name = "RpcError";
    this.code = code;
    this.retryable =
      options?.retryable ?? RETRYABLE.has(code as RegistryErrorCode);
    this.field = options?.field ?? null;
  }
}
