/**
 * Gateway v2 — envelope framing types and admission validation (spec §3.1).
 *
 * Only POST /v2/rpc carries control RPC: application/json, identity encoding,
 * one request per body ≤2 MiB, no batches or notifications. All objects are
 * closed, all listed fields required; duplicates, BOM, lone surrogates,
 * depth >32, and unknown methods/fields are rejected.
 */

import type { EventRef, Id, Json } from "./refs.js";
import type { RegistryErrorCode } from "./errors.js";

/** Wire request envelope (closed object). */
export type Request = {
  v: 2;
  id: Id;
  workspace: Id;
  method: string;
  params: Json;
};

/** Success envelope; receipt is null only for admission/transport failures. */
export type Success = {
  v: 2;
  id: Id;
  ok: true;
  result: Json;
  receipt: { workspace: Id; event: EventRef } | null;
};

/** Failure envelope; id is null when the request id could not be parsed. */
export type Failure = {
  v: 2;
  id: Id | null;
  ok: false;
  error: { code: string; retryable: boolean; field: string | null };
  receipt: { workspace: Id; event: EventRef } | null;
};

export type Response = Success | Failure;

/** Cursor page; `next` is an opaque cursor or null (§3.2 paging rules). */
export type Page<T> = { items: T[]; next: string | null };

/**
 * Durable job admission, not successful installation. Poll operation.get or
 * consume its events to observe terminal state.
 */
export type Accepted = { operation: Id; state: "QUEUED" };

/** Transport receipt pointer: adds workspace scope to a Proof EventRef. */
export type ReceiptPointer = { workspace: Id; event: EventRef };

/** Envelope/transport limits (spec §3.1). */
export const ENVELOPE_LIMITS = {
  /** POST body cap for control RPC. */
  requestBodyBytes: 2 * 1024 * 1024,
  /** Ordinary response cap (receipt.get native bundle may reach 80 MiB). */
  responseBodyBytes: 2 * 1024 * 1024,
  /** receipt.get native bundle response cap. */
  receiptResponseBytes: 80 * 1024 * 1024,
  /** Canonical Bundle cap inside a receipt response. */
  bundleBytes: 64 * 1024 * 1024,
  /** Config document cap. */
  configDocumentBytes: 512 * 1024,
  /** Maximum JSON nesting depth accepted anywhere in an envelope. */
  maxJsonDepth: 32,
  /** Strings are ≤1024 UTF-8 bytes unless an imported type is narrower. */
  maxStringBytes: 1024,
} as const;

/**
 * Connection-accounted methods that never receive a semantic receipt
 * (spec §3.1): transport hello, challenge, refresh, heartbeat, cursor ACK,
 * and session bootstrap exchange.
 */
export const NO_RECEIPT_METHODS: ReadonlySet<string> = new Set([
  "daemon.hello",
  "run.heartbeat",
  "events.ack",
  "agent.challenge",
  "agent.renew",
  "ui.session.exchange",
]);

/**
 * Idempotency binding exceptions (spec §3.1): every mutation binds
 * `(workspace,principal,id)` to `H(J({method,params}))` except the
 * authentication methods, which bind only the listed param subsets so
 * retries can re-prove possession (fresh code/challenge/nonce/epoch/proof)
 * without changing semantic intent.
 */
export const IDEMPOTENCY_EXEMPT_BINDING: Readonly<Record<string, readonly string[]>> = {
  "agent.register": ["pair", "key", "profiles", "interfaces", "capabilities"],
  "agent.pair.propose": ["pair", "key", "profiles", "interfaces", "capabilities"],
  "agent.renew": ["peer", "refresh_hash"],
};

/** Result of validateEnvelopeRequest. */
export type EnvelopeValidation =
  | { ok: true; request: Request }
  | { ok: false; code: RegistryErrorCode; field: string | null };

const REQUEST_KEYS = new Set(["v", "id", "workspace", "method", "params"]);
const ID_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

function utf8Bytes(s: string): number {
  // CESU-8 style count: each UTF-16 unit maps to its UTF-8 length without
  // decoding, so lone surrogates are measured (3 bytes) rather than throwing.
  let n = 0;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        n += 4;
        i += 1;
      } else {
        n += 3;
      }
    } else n += 3;
  }
  return n;
}

/**
 * Maximum JSON nesting depth of a value: scalars have depth 0; each
 * object/array level adds 1. Returns `Infinity` for non-JSON inputs
 * (undefined, functions, symbols, bigint, non-finite numbers) so callers
 * can treat them as over-limit. Cyclic values are bounded by depth, not
 * visited sets — canonical JSON cannot contain cycles.
 */
export function jsonDepth(value: unknown, depth = 0): number {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return depth;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? depth : Number.POSITIVE_INFINITY;
  }
  if (Array.isArray(value)) {
    let max = depth + 1;
    if (max > ENVELOPE_LIMITS.maxJsonDepth + 1) return max; // already over
    for (const item of value) {
      const d = jsonDepth(item, depth + 1);
      if (d > max) max = d;
      if (max > ENVELOPE_LIMITS.maxJsonDepth + 1) return max;
    }
    return max;
  }
  if (typeof value === "object") {
    let max = depth + 1;
    if (max > ENVELOPE_LIMITS.maxJsonDepth + 1) return max;
    for (const key of Object.keys(value as object)) {
      const d = jsonDepth((value as Record<string, unknown>)[key], depth + 1);
      if (d > max) max = d;
      if (max > ENVELOPE_LIMITS.maxJsonDepth + 1) return max;
    }
    return max;
  }
  return Number.POSITIVE_INFINITY; // undefined, function, symbol, bigint
}

/**
 * True when every leaf is a JSON value (finite number, no
 * undefined/function/symbol/bigint). Callers must bound recursion by
 * checking `jsonDepth(value) <= ENVELOPE_LIMITS.maxJsonDepth` first, as
 * validateEnvelopeRequest does.
 */
export function isJson(value: unknown): boolean {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return true;
  }
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    for (const item of value) if (!isJson(item)) return false;
    return true;
  }
  if (typeof value === "object") {
    for (const key of Object.keys(value as object)) {
      if (!isJson((value as Record<string, unknown>)[key])) return false;
    }
    return true;
  }
  return false;
}

function fail(code: RegistryErrorCode, field: string | null): EnvelopeValidation {
  return { ok: false, code, field };
}

/**
 * Admission-shape validation of a parsed request envelope.
 *
 * Enforces, in spec precedence order: JSON validity of the parsed value
 * (all leaves are JSON, depth ≤32), then the closed envelope schema —
 * exactly {v,id,workspace,method,params}, all required, v===2, ids match
 * the Proof Id grammar, method is a nonempty ≤1024-byte string.
 * Method-name registry lookup is a later stage (METHOD_UNKNOWN) and is
 * not performed here.
 */
export function validateEnvelopeRequest(value: unknown): EnvelopeValidation {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return fail("SCHEMA_INVALID", null);
  }
  if (jsonDepth(value) > ENVELOPE_LIMITS.maxJsonDepth) {
    return fail("JSON_INVALID", null);
  }
  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!REQUEST_KEYS.has(key)) return fail("SCHEMA_INVALID", key);
  }
  for (const key of REQUEST_KEYS) {
    if (!(key in obj)) return fail("SCHEMA_INVALID", key);
  }
  if (obj.v !== 2) {
    return fail("SCHEMA_UNSUPPORTED", "v");
  }
  if (typeof obj.id !== "string" || !ID_RE.test(obj.id)) {
    return fail("SCHEMA_INVALID", "id");
  }
  if (typeof obj.workspace !== "string" || !ID_RE.test(obj.workspace)) {
    return fail("SCHEMA_INVALID", "workspace");
  }
  if (
    typeof obj.method !== "string" ||
    obj.method.length === 0 ||
    utf8Bytes(obj.method) > ENVELOPE_LIMITS.maxStringBytes
  ) {
    return fail("SCHEMA_INVALID", "method");
  }
  return {
    ok: true,
    request: {
      v: 2,
      id: obj.id,
      workspace: obj.workspace,
      method: obj.method,
      params: obj.params as Json,
    },
  };
}
