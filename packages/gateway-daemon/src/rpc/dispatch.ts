/**
 * §3.1 dispatch pipeline — the single path every control RPC takes
 * regardless of listener (unix socket, loopback bridge, run relay).
 *
 * Error precedence (spec §3.1), earliest first:
 *   transport cap → JSON → envelope/schema → authentication → method
 *   authorization → resource scope → idempotency → revision/dependency/
 *   policy → storage → execution.
 *
 * Additional contract enforced here:
 *  - `receipt`: every authenticated semantic read/mutation gets an audit
 *    Proof event on `gateway.action`; the six NO_RECEIPT_METHODS and any
 *    transport/admission failure carry `receipt: null`.
 *  - `idempotency`: mutations bind `(workspace, principal, id)` to
 *    `H(J({method, params}))`; semantic replays return the saved result and
 *    receipt after fresh authorization; changed content returns
 *    `IDEMPOTENCY_CONFLICT`. Methods in IDEMPOTENCY_EXEMPT_BINDING bind
 *    only their listed param subset (`agent.renew` binds `refresh_hash =
 *    H(refresh)`).
 *  - `unavailable`: an absent service implementation never reports success
 *    — it raises the domain's unavailable code (CAP_ADAPTER_UNAVAILABLE for
 *    native-adapter-backed domains, STORAGE_UNAVAILABLE for durable-state
 *    domains, NETWORK_UNAVAILABLE for cloud/sync egress).
 *  - DRAINING: new mutations are rejected once the daemon begins draining.
 */
import {
  ENVELOPE_LIMITS,
  HTTP_STATUS,
  IDEMPOTENCY_EXEMPT_BINDING,
  RETRYABLE,
  RPC_METHODS,
  RpcError,
  canonicalJson,
  isRpcMethod,
  isTopic,
  methodHasReceipt,
  sha256Hex,
  validateEnvelopeRequest,
  type GatewayServices,
  type Json,
  type Principal,
  type RegistryErrorCode,
  type Request as RpcRequest,
  type Role,
  type Scope,
  type Topic,
} from "../core-v2.js";
import { parseStrictJson } from "../net/strict-json.js";
import { principalRoles, resolvePrincipal, type PeerAuthEnv, type TransportCredentials } from "./auth.js";

// ── outcomes ─────────────────────────────────────────────────────────────

export interface DispatchOutcome {
  status: number;
  response: Record<string, unknown>;
  headers: Record<string, string>;
}

/** Receipt pointer attached to semantic calls (§3.1). */
export type ReceiptPointer = {
  workspace: string;
  event: { source: string; stream: string; seq: string; hash: string };
};

/** The action record sealed into the audit Proof event's `data`. */
export interface AuditAction {
  v: 1;
  kind: "rpc";
  method: string;
  principal: string;
  request: string;
  operation: string | null;
  redacted_params_sha256: string;
  result_sha256: string | null;
  outcome: "SUCCEEDED" | "FAILED" | "REJECTED";
  code: string;
  previous_action: string | null;
}

/**
 * Durable audit-receipt sink; implemented by runtime.AuditReceiptWriter.
 * One call seals the action into the audit-lane Proof event AND commits it
 * (lane record + optional operations-table idempotency row) atomically.
 * `bind.makeResultJson` receives the receipt pointer so the saved response
 * embeds the same pointer the caller is about to see.
 */
export interface ReceiptWriter {
  commitAction(
    action: AuditAction,
    bind: {
      principalKey: string;
      id: string;
      requestHash: string;
      makeResultJson: (receipt: ReceiptPointer) => string;
    } | null,
    /**
     * Already-scrubbed params/result material for the audit payload's
     * intent/observation objects (the sealed event carries only hashes).
     */
    material?: { params: unknown; result: unknown },
  ): Promise<ReceiptPointer>;
  /**
   * Durable idempotency binding WITHOUT an audit event — for mutating
   * NO_RECEIPT methods (run.heartbeat, agent.renew, ui.session.exchange).
   */
  commitBind?(bind: {
    principalKey: string;
    id: string;
    requestHash: string;
    resultJson: string;
  }): Promise<void>;
}

/** A stored idempotency binding and its saved response payload. */
export interface SavedBinding {
  /** `principal` column key: `${workspace}:${principal.id}`. */
  principalKey: string;
  id: string;
  requestHash: string;
  /** Serialized {status,response} — replayed verbatim on hash match. */
  saved: string;
}

/** Read side of the idempotency store (writes ride the receipt commit). */
export interface IdempotencyLookup {
  lookup(principalKey: string, id: string): SavedBinding | null;
}

/** Observability hook (§11): one call per completed RPC. */
export interface RpcObserver {
  (method: string, code: string, durationMs: number): void;
}

export interface DispatchContext {
  /** Gateway instance id — the audience inside peer proofs. */
  instance: string;
  /** The workspace this daemon is bound to; envelope `workspace` must equal it. */
  workspace: string;
  /** Current boot/session epoch. */
  epoch: string;
  /** Injected service implementations (may be partial). */
  services: Partial<GatewayServices>;
  /**
   * Per-call service binding: when present, the dispatcher builds the
   * service map AFTER authentication so platform services see the real
   * `ctx.principal`/`requestId` rather than a boot-time default.
   */
  bindServices?: (ctx: {
    principal: Principal;
    requestId: string;
  }) => Partial<GatewayServices>;
  /** Peer token store — required before any peer credential resolves. */
  peers?: PeerAuthEnv["peers"];
  /** Audit receipt sink; null disables receipts (transport failures only). */
  receipts?: ReceiptWriter | null;
  /** Registry-backed idempotency lookup; null disables binding. */
  idempotency?: IdempotencyLookup | null;
  /** True while the daemon is draining (new mutations rejected). */
  draining?: () => boolean;
  /** Per-method override for missing-service error codes. */
  unavailableCodes?: Readonly<Record<string, RegistryErrorCode>>;
  /** Per-RPC observation hook (metrics/log). */
  observe?: RpcObserver;
  now?: () => number;
}

// ── method → service map ─────────────────────────────────────────────────

/** method → [service group, method on that service]. */
export const METHOD_SERVICE_MAP: Readonly<Record<string, readonly [keyof GatewayServices, string]>> = {
  "daemon.hello": ["daemon", "hello"],
  "daemon.status": ["daemon", "status"],
  "daemon.stop": ["daemon", "stop"],
  "config.get": ["config", "get"],
  "config.validate": ["config", "validate"],
  "config.apply": ["config", "apply"],
  "run.register": ["run", "register"],
  "run.heartbeat": ["run", "heartbeat"],
  "run.finish": ["run", "finish"],
  "events.publish": ["events", "publish"],
  "events.query": ["events", "query"],
  "events.subscribe": ["events", "subscribe"],
  "events.ack": ["events", "ack"],
  "objects.put": ["objects", "put"],
  "objects.get": ["objects", "get"],
  "receipt.get": ["receipt", "get"],
  "lineage.query": ["lineage", "query"],
  "operation.get": ["operation", "get"],
  "operation.cancel": ["operation", "cancel"],
  "product.plan": ["product", "plan"],
  "product.install": ["product", "install"],
  "product.uninstall": ["product", "uninstall"],
  "product.update": ["product", "update"],
  "product.rollback": ["product", "rollback"],
  "product.list": ["product", "list"],
  "product.health": ["product", "health"],
  "agent.pair.create": ["agent", "pairCreate"],
  "agent.pair.propose": ["agent", "pairPropose"],
  "agent.pair.get": ["agent", "pairGet"],
  "agent.pair.approve": ["agent", "pairApprove"],
  "agent.pair.cancel": ["agent", "pairCancel"],
  "agent.challenge": ["agent", "challenge"],
  "agent.register": ["agent", "register"],
  "agent.renew": ["agent", "renew"],
  "agent.list": ["agent", "list"],
  "agent.revoke": ["agent", "revoke"],
  "agent.disconnect": ["agent", "disconnect"],
  "approval.request": ["approval", "request"],
  "approval.list": ["approval", "list"],
  "approval.get": ["approval", "get"],
  "approval.decide": ["approval", "decide"],
  "approval.cancel": ["approval", "cancel"],
  "ui.session.create": ["ui", "sessionCreate"],
  "ui.session.exchange": ["ui", "sessionExchange"],
  "ui.session.revoke": ["ui", "sessionRevoke"],
  "sync.status": ["sync", "status"],
  "sync.pause": ["sync", "pause"],
  "sync.resume": ["sync", "resume"],
  "sync.configure": ["sync", "configure"],
  "sync.flush": ["sync", "flush"],
  "cloud.pair.begin": ["cloud", "pairBegin"],
  "cloud.pair.complete": ["cloud", "pairComplete"],
  "cloud.pair.revoke": ["cloud", "pairRevoke"],
  "catalog.refresh": ["catalog", "refresh"],
  "catalog.search": ["catalog", "search"],
  "catalog.show": ["catalog", "show"],
  "catalog.pin": ["catalog", "pin"],
  "catalog.unpin": ["catalog", "unpin"],
};

/**
 * Default unavailable code per service domain when no implementation is
 * injected (never a successful stub). Adapter/native-backed domains report
 * CAP_ADAPTER_UNAVAILABLE; durable-state domains STORAGE_UNAVAILABLE;
 * egress domains NETWORK_UNAVAILABLE.
 */
export const UNAVAILABLE_BY_DOMAIN: Readonly<Record<keyof GatewayServices, RegistryErrorCode>> = {
  daemon: "RUNTIME_UNSUPPORTED",
  config: "STORAGE_UNAVAILABLE",
  run: "STORAGE_UNAVAILABLE",
  events: "STORAGE_UNAVAILABLE",
  objects: "STORAGE_UNAVAILABLE",
  receipt: "CAP_ADAPTER_UNAVAILABLE",
  lineage: "CAP_ADAPTER_UNAVAILABLE",
  operation: "STORAGE_UNAVAILABLE",
  product: "CAP_ADAPTER_UNAVAILABLE",
  agent: "STORAGE_UNAVAILABLE",
  approval: "STORAGE_UNAVAILABLE",
  ui: "STORAGE_UNAVAILABLE",
  sync: "NETWORK_UNAVAILABLE",
  cloud: "NETWORK_UNAVAILABLE",
  catalog: "STORAGE_UNAVAILABLE",
};

/** Methods whose success responses carry tokens/secrets → no-store. */
const TOKEN_BEARING_METHODS: ReadonlySet<string> = new Set([
  "agent.register",
  "agent.renew",
  "agent.pair.create",
  "agent.pair.propose",
  "agent.pair.get",
  "agent.challenge",
  "ui.session.create",
  "ui.session.exchange",
]);

// ── credential-bearing param redaction (fixture `scrub` semantics) ───────

const REDACT_KEYS = new Set([
  "access",
  "refresh",
  "access2",
  "refresh2",
  "code",
  "proof",
  "csrf",
  "bootstrap",
  "client_nonce",
  "server_nonce",
]);

/** Redact credential-bearing fields exactly like the §13.1 fixture scrub. */
export function scrubParams(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(scrubParams);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = REDACT_KEYS.has(k) ? "[redacted]" : scrubParams(v);
    }
    return out;
  }
  if (typeof value === "string") {
    return value.replace(/#bootstrap=.*/, "#bootstrap=[redacted]");
  }
  return value;
}

// ── peer scope gate ──────────────────────────────────────────────────────

function scopeHas(scopes: readonly Scope[], permission: Scope["permission"], topic?: string): boolean {
  for (const s of scopes) {
    if (s.permission !== permission) continue;
    if (topic === undefined || s.topics.includes(topic)) return true;
  }
  return false;
}

/**
 * §4.1 scope gate for peer principals (A and operator-tier peers): checks
 * the enrolled grant, never the peer's self-declared labels.
 */
function peerScopeAllows(principal: Principal, method: string, params: unknown): boolean {
  const scopes = principal.scopes ?? [];
  const topics =
    params !== null && typeof params === "object" && !Array.isArray(params)
      ? (params as Record<string, unknown>)
      : {};
  switch (method) {
    case "events.publish": {
      const topic = topics.topic;
      return (
        typeof topic === "string" &&
        isTopic(topic) &&
        scopeHas(scopes, "events.emit", topic as Topic)
      );
    }
    case "events.query":
    case "events.subscribe": {
      const list = topics.topics;
      if (!Array.isArray(list)) return false;
      return list.every(
        (t) => typeof t === "string" && isTopic(t) && scopeHas(scopes, "events.consume", t as Topic),
      );
    }
    case "events.ack":
      return scopes.some((s) => s.permission === "events.consume");
    case "approval.request":
    case "approval.cancel":
      return scopes.some((s) => s.permission === "approvals.request");
    case "lineage.query":
      return scopes.some((s) => s.permission === "lineage.read");
    case "product.plan":
    case "product.install":
    case "product.uninstall":
    case "product.update":
    case "product.rollback":
    case "product.health": {
      const slug = typeof topics.slug === "string" ? topics.slug : null;
      return scopes.some(
        (s) =>
          s.permission === "products.manage" &&
          (slug === null || s.products.includes(slug)),
      );
    }
    default:
      return true;
  }
}

// ── helpers ──────────────────────────────────────────────────────────────

function fail(
  id: string | null,
  code: RegistryErrorCode,
  opts: { field?: string | null; receipt?: ReceiptPointer | null; retryable?: boolean } = {},
): DispatchOutcome {
  const retryable = opts.retryable ?? RETRYABLE.has(code);
  const headers: Record<string, string> = {};
  if (retryable) headers["Retry-After"] = "1";
  return {
    status: HTTP_STATUS[code],
    response: {
      v: 2,
      id,
      ok: false,
      error: { code, retryable, field: opts.field ?? null },
      receipt: opts.receipt ?? null,
    },
    headers,
  };
}

function ok(
  id: string,
  result: Json,
  receipt: ReceiptPointer | null,
  headers: Record<string, string> = {},
): DispatchOutcome {
  return {
    status: 200,
    response: { v: 2, id, ok: true, result, receipt },
    headers,
  };
}

/** Error mapping for exceptions thrown by service implementations. */
export function mapThrown(e: unknown): { code: RegistryErrorCode; field: string | null; retryable?: boolean } {
  if (e instanceof RpcError) {
    const code = e.code === "READ_ONLY" ? "STATE_TRANSITION" : e.code;
    return { code, field: e.field, retryable: e.retryable };
  }
  const anyE = e as { code?: unknown; name?: unknown };
  if (typeof anyE?.code === "string") {
    switch (anyE.code) {
      case "READ_ONLY":
        return { code: "STATE_TRANSITION", field: null };
      case "CORRUPT":
      case "CHAIN_MISMATCH":
      case "IDENTITY_MISMATCH":
      case "MUTATION_UNKNOWN":
        return { code: "STORAGE_UNAVAILABLE", field: null };
      case "OBJECT_LIMIT":
        return { code: "OBJECT_LIMIT", field: null };
      case "BAD_DIGEST":
      case "BAD_RECORD":
      case "BAD_LANE":
      case "BAD_CURSOR":
        return { code: "SCHEMA_INVALID", field: null };
      case "NOT_FOUND":
      case "INVALID_TRANSITION":
        return { code: "NOT_FOUND", field: null };
      default:
        break;
    }
  }
  return { code: "STORAGE_UNAVAILABLE", field: null };
}

/** The idempotency-bound param subset (spec §3.1 auth exceptions). */
export function bindingParams(method: string, params: unknown): unknown {
  const exempt = IDEMPOTENCY_EXEMPT_BINDING[method];
  if (exempt === undefined) return params;
  const src =
    params !== null && typeof params === "object" && !Array.isArray(params)
      ? (params as Record<string, unknown>)
      : {};
  const out: Record<string, unknown> = {};
  for (const key of exempt) {
    if (key === "refresh_hash") {
      const refresh = src.refresh;
      out.refresh_hash =
        typeof refresh === "string" ? sha256Hex(refresh) : null;
    } else {
      out[key] = src[key] ?? null;
    }
  }
  return out;
}

/** H(J({method, params})) — the mutation's semantic binding hash. */
export function bindingHash(method: string, params: unknown): string {
  return sha256Hex(
    canonicalJson({ method, params: bindingParams(method, params) }),
  );
}

// ── the pipeline ─────────────────────────────────────────────────────────

export interface DispatchInput {
  /** Raw body bytes (parsed here) or an already-strict-parsed value. */
  body: Buffer | Uint8Array | string | unknown;
  transport: "socket" | "bridge";
  credentials: TransportCredentials;
}

/**
 * Run one control RPC through the full §3.1 pipeline and produce the HTTP
 * outcome (status + envelope + headers). `credentials` is what the listener
 * already resolved from transport material (local socket, session cookie,
 * bearer header set, or anonymous).
 */
export async function dispatchRequest(
  ctx: DispatchContext,
  input: DispatchInput,
): Promise<DispatchOutcome> {
  const t0 = Date.now();
  const observe = (method: string, code: string): void => {
    try {
      ctx.observe?.(method, code, Date.now() - t0);
    } catch {
      /* observer must not break dispatch */
    }
  };
  try {
    return await run(ctx, input, observe);
  } catch (e) {
    // Defensive last resort: the pipeline must always produce an envelope.
    const m = mapThrown(e);
    observe("?", m.code);
    return fail(null, m.code, { field: m.field, retryable: m.retryable });
  }
}

async function run(
  ctx: DispatchContext,
  input: DispatchInput,
  observe: (method: string, code: string) => void,
): Promise<DispatchOutcome> {
  // ── Stage: transport cap → JSON → envelope/schema ──────────────────────
  let parsed: unknown;
  if (
    input.body instanceof Uint8Array ||
    typeof input.body === "string"
  ) {
    if (input.body.length > ENVELOPE_LIMITS.requestBodyBytes) {
      observe("?", "BODY_LIMIT");
      return fail(null, "BODY_LIMIT");
    }
    const r = parseStrictJson(input.body);
    if (!r.ok) {
      observe("?", "JSON_INVALID");
      return fail(null, "JSON_INVALID", { field: r.field });
    }
    parsed = r.value;
  } else {
    parsed = input.body;
  }

  const env = validateEnvelopeRequest(parsed);
  if (!env.ok) {
    observe("?", env.code);
    return fail(null, env.code, { field: env.field });
  }
  const request: RpcRequest = env.request;
  const id: string = request.id;
  const method = request.method;

  if (!isRpcMethod(method)) {
    observe(method, "METHOD_UNKNOWN");
    return fail(id, "METHOD_UNKNOWN");
  }
  const spec = RPC_METHODS[method];

  // ── Stage: authentication ──────────────────────────────────────────────
  let principal: Principal;
  try {
    if (ctx.peers === undefined && input.credentials.kind === "peer") {
      throw new RpcError("AUTH_REQUIRED", "peer transport is not enabled");
    }
    const authEnv: PeerAuthEnv = {
      instance: ctx.instance,
      workspace: ctx.workspace,
      epoch: ctx.epoch,
      peers: ctx.peers ?? { lookupAccess: () => null, nonceSeen: () => true },
      now: ctx.now,
    };
    principal = resolvePrincipal(input.credentials, request, authEnv);
  } catch (e) {
    const m = mapThrown(e);
    observe(method, m.code);
    return fail(id, m.code, { field: m.field, retryable: m.retryable });
  }

  // The envelope's workspace never selects outside the authenticated
  // binding (spec §3.1): a mismatched workspace is invisible — FORBIDDEN.
  if (request.workspace !== ctx.workspace) {
    observe(method, "FORBIDDEN");
    return fail(id, "FORBIDDEN", { field: "workspace" });
  }

  // ── Stage: method authorization ────────────────────────────────────────
  const roles = principalRoles(principal);
  if (!spec.roles.some((r) => roles.has(r as Role))) {
    observe(method, "FORBIDDEN");
    return fail(id, "FORBIDDEN", { field: "method" });
  }

  // DRAINING rejects new mutations (§1.3 stop semantics).
  if (spec.mutating && ctx.draining?.() === true) {
    observe(method, "STATE_TRANSITION");
    return fail(id, "STATE_TRANSITION");
  }

  // ── Stage: resource scope (peer grants only; §4.1) ─────────────────────
  if (principal.peer !== undefined && !peerScopeAllows(principal, method, request.params)) {
    observe(method, "FORBIDDEN");
    return fail(id, "FORBIDDEN", { field: "params" });
  }

  const needsReceipt = methodHasReceipt(method);
  const receipts = needsReceipt ? (ctx.receipts ?? null) : null;
  const principalKey = `${request.workspace}:${principal.id}`;
  const mutating = spec.mutating === true;

  // ── Stage: idempotency ─────────────────────────────────────────────────
  let requestHash: string | null = null;
  if (mutating) {
    try {
      requestHash = bindingHash(method, request.params);
    } catch {
      observe(method, "SCHEMA_INVALID");
      return fail(id, "SCHEMA_INVALID", { field: "params" });
    }
    const prior = ctx.idempotency?.lookup(principalKey, request.id) ?? null;
    if (prior !== null) {
      if (prior.requestHash === requestHash) {
        // Identical semantic retry: fresh authorization already passed;
        // return the saved response verbatim.
        try {
          const saved = JSON.parse(prior.saved) as {
            status: number;
            response: Record<string, unknown>;
          };
          observe(method, "IDEMPOTENT_REPLAY");
          return { status: saved.status, response: saved.response, headers: {} };
        } catch {
          /* corrupt saved row → treat as conflict below */
        }
      }
      observe(method, "IDEMPOTENCY_CONFLICT");
      return fail(id, "IDEMPOTENCY_CONFLICT");
    }
  }

  // ── Stage: revision/dependency/policy → storage → execution ────────────
  const binding: Omit<SavedBinding, "saved"> | null =
    mutating && requestHash !== null
      ? { principalKey, id: request.id, requestHash }
      : null;

  const makeAction = (
    outcome: AuditAction["outcome"],
    code: string,
    result: unknown,
  ): AuditAction => ({
    v: 1,
    kind: "rpc",
    method,
    principal: principal.id,
    request: request.id,
    operation:
      request.params !== null &&
      typeof request.params === "object" &&
      !Array.isArray(request.params) &&
      typeof (request.params as Record<string, unknown>).operation === "string"
        ? ((request.params as Record<string, unknown>).operation as string)
        : null,
    redacted_params_sha256: sha256Hex(canonicalJson(scrubParams(request.params))),
    result_sha256:
      result === undefined
        ? null
        : sha256Hex(canonicalJson(scrubParams(result))),
    outcome,
    code,
    previous_action: null,
  });

  let result: Json;
  try {
    const services =
      ctx.bindServices?.({ principal, requestId: request.id }) ??
      ctx.services;
    const [group, fn] = METHOD_SERVICE_MAP[method]!;
    const svc = services[group] as
      | Record<string, (params: unknown, caller?: unknown) => Promise<unknown>>
      | undefined;
    const impl = svc?.[fn];
    if (typeof impl !== "function") {
      const code =
        ctx.unavailableCodes?.[method] ?? UNAVAILABLE_BY_DOMAIN[group];
      throw new RpcError(code, `service ${group}.${fn} is not available`);
    }
    // The approval runtime's caller contract (id/role/reviewer) rides as
    // an optional second argument; services that take only params ignore it.
    const caller = {
      id: principal.id,
      role: principal.role,
      reviewer: principal.reviewer === true,
    };
    result = (await impl.call(svc, request.params, caller)) as Json;
  } catch (e) {
    const m = mapThrown(e);
    // Authorized semantic rejection: durable audit receipt (§11), then the
    // error envelope. A receipt-write failure still returns the error.
    let receipt: ReceiptPointer | null = null;
    if (receipts !== null) {
      try {
        receipt = await receipts.commitAction(
          makeAction("FAILED", m.code, undefined),
          null,
          { params: scrubParams(request.params), result: null },
        );
      } catch {
        receipt = null;
      }
    }
    observe(method, m.code);
    return fail(id, m.code, {
      field: m.field,
      retryable: m.retryable,
      receipt,
    });
  }

  // ── Receipt + idempotency bind (durable before the response leaves) ────
  let receipt: ReceiptPointer | null = null;
  if (receipts !== null) {
    try {
      receipt = await receipts.commitAction(
        makeAction("SUCCEEDED", "OK", result),
        binding !== null
          ? {
              principalKey: binding.principalKey,
              id: binding.id,
              requestHash: binding.requestHash,
              makeResultJson: (ptr) =>
                JSON.stringify({
                  status: 200,
                  response: { v: 2, id, ok: true, result, receipt: ptr },
                }),
            }
          : null,
        { params: scrubParams(request.params), result: scrubParams(result) },
      );
    } catch {
      // Audit persistence failure → STORAGE_UNAVAILABLE before disclosure.
      observe(method, "STORAGE_UNAVAILABLE");
      return fail(id, "STORAGE_UNAVAILABLE");
    }
  } else if (binding !== null && ctx.receipts?.commitBind !== undefined) {
    // Connection-accounted mutations still bind durably (mutation-only).
    const saved = JSON.stringify({
      status: 200,
      response: { v: 2, id, ok: true, result, receipt: null },
    });
    try {
      await ctx.receipts.commitBind({
        principalKey: binding.principalKey,
        id: binding.id,
        requestHash: binding.requestHash,
        resultJson: saved,
      });
    } catch {
      observe(method, "STORAGE_UNAVAILABLE");
      return fail(id, "STORAGE_UNAVAILABLE");
    }
  }

  const headers: Record<string, string> = {};
  if (TOKEN_BEARING_METHODS.has(method)) {
    headers["Cache-Control"] = "no-store";
  }
  observe(method, "OK");
  return ok(id, result, receipt, headers);
}
