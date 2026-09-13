/**
 * Gateway v2 — effective-grant intersection and per-RPC scope admission
 * (spec §4.1, §3.2).
 *
 * The effective grant is `requested ∩ operator-approved ∩ configured
 * policy ∩ native capability binding`; discovery advertises that
 * intersection, never the peer's unchecked claims. `assertScope` is the
 * dispatcher hook: it applies the §3.2 role gate first, then the exact
 * scope check for scope-bound agent methods. `products.manage` always
 * requires an enrolled operator-tier peer, agents.allow_operator=true, a
 * local operator confirmation, and exact target products — a normal agent
 * receives FORBIDDEN regardless of claimed status (TV-GW-24).
 */
import type { Json } from "../protocol/refs.js";
import {
  RPC_METHODS,
  type Role,
} from "../protocol/rpc-registry.js";
import { RpcError } from "../protocol/errors.js";
import {
  checkScopeAdmission,
  type Peer,
  type Scope,
  type ScopePermission,
  type ScopeAdmissionContext,
} from "../protocol/peers.js";
import { isTopic } from "../protocol/topics.js";
import type { Principal } from "../protocol/services.js";
import { scopeWithin } from "./pairs.js";

function rpc(code: RpcError["code"], message: string, field?: string): never {
  throw new RpcError(code, message, { field: field ?? null });
}

/** Principal role → §3.2 role letters; reviewer adds R. */
export function principalRoles(principal: {
  role: Principal["role"];
  reviewer?: boolean;
}): Role[] {
  const letter: Record<Principal["role"], Role> = {
    viewer: "V",
    agent: "A",
    operator: "O",
    local_operator: "L",
    bootstrap: "P",
  };
  const roles: Role[] = [letter[principal.role]];
  if (principal.reviewer === true) roles.push("R");
  return roles;
}

/**
 * §3.2 method-authorization gate (TV-GW-28): the principal must hold at
 * least one listed role letter. A viewer submitting config.apply with a
 * valid document/review hash still gets FORBIDDEN — hash possession never
 * elevates a role.
 */
export function assertRole(
  principal: { role: Principal["role"]; reviewer?: boolean },
  method: string,
): void {
  const spec = (RPC_METHODS as Record<string, { roles: readonly Role[] }>)[method];
  if (spec === undefined) rpc("METHOD_UNKNOWN", `unknown method ${method}`, "method");
  const held = principalRoles(principal);
  if (!held.some((r) => spec.roles.includes(r))) {
    rpc("FORBIDDEN", `${method} is not available to this principal`, "method");
  }
}

/** Scope-set intersection: same permission, per-dimension ∩, drop empties. */
export function intersectScopes(a: readonly Scope[], b: readonly Scope[]): Scope[] {
  const out: Scope[] = [];
  for (const s of a) {
    for (const o of b) {
      if (s.permission !== o.permission) continue;
      const merged: Scope = {
        permission: s.permission,
        topics: s.topics.filter((t) => o.topics.includes(t)),
        runs: s.runs.filter((r) => o.runs.includes(r)),
        products: s.products.filter((p) => o.products.includes(p)),
      };
      if (
        !out.some(
          (e) =>
            e.permission === merged.permission &&
            e.topics.join("") === merged.topics.join("") &&
            e.runs.join("") === merged.runs.join("") &&
            e.products.join("") === merged.products.join(""),
        )
      ) {
        out.push(merged);
      }
    }
  }
  return out;
}

/**
 * The §4.1 effective grant: invited ∩ approved ∩ configured policy.
 * `policy` is the config-side scope ceiling (null = no extra narrowing).
 * The native capability binding is applied by the adapter layer; with no
 * pinned artifact the control-plane grant stands and mesh stays
 * ADAPTER_REQUIRED (TV-GW-19).
 */
export function effectiveGrant(
  requested: readonly Scope[],
  approved: readonly Scope[],
  policy?: readonly Scope[] | null,
): Scope[] {
  let grant = intersectScopes(requested, approved);
  if (policy != null) grant = intersectScopes(grant, policy);
  return grant;
}

/**
 * Native capability binding (§4.1): the peer's signed capabilities bound
 * the grant — events.emit topics are clipped to ∪cap.emit, events.consume
 * to ∪cap.consume, approvals.request requires a request_approvals=true
 * capability, and lineage.read requires lineage:"own". With no declared
 * capability for a dimension the grant yields nothing for it.
 */
export function bindCapabilities(
  scopes: readonly Scope[],
  capabilities: readonly {
    emit: string[];
    consume: string[];
    request_approvals: boolean;
    lineage: "none" | "own";
  }[],
): Scope[] {
  const emit = new Set(capabilities.flatMap((c) => c.emit));
  const consume = new Set(capabilities.flatMap((c) => c.consume));
  const canApprove = capabilities.some((c) => c.request_approvals === true);
  const canLineage = capabilities.some((c) => c.lineage === "own");
  const out: Scope[] = [];
  for (const s of scopes) {
    switch (s.permission) {
      case "events.emit":
        out.push({ ...s, topics: s.topics.filter((t) => emit.has(t)) });
        break;
      case "events.consume":
        out.push({ ...s, topics: s.topics.filter((t) => consume.has(t)) });
        break;
      case "approvals.request":
        if (canApprove) out.push({ ...s });
        break;
      case "lineage.read":
        if (canLineage) out.push({ ...s });
        break;
      case "products.manage":
        // Product management is an operator grant, not a capability
        // advertisement — carried through unchanged.
        out.push({ ...s });
        break;
    }
  }
  return out;
}

/** Scopes of `peer` carrying a given permission. */
function scopesFor(peer: Peer, permission: ScopePermission): Scope[] {
  return peer.scopes.filter((s) => s.permission === permission);
}

function hasScopeCovering(
  peer: Peer,
  permission: ScopePermission,
  covers: (s: Scope) => boolean,
): boolean {
  return scopesFor(peer, permission).some(covers);
}

/** True when some scope grants this peer the run (selector or exact id). */
export function scopeCoversRun(peer: Peer, run: string): boolean {
  return peer.scopes.some(
    (s) => s.runs.includes("self") || s.runs.includes(run),
  );
}

/** True when a products.manage scope grants this exact product slug. */
export function scopeCoversProduct(peer: Peer, slug: string): boolean {
  return scopesFor(peer, "products.manage").some((s) =>
    s.products.includes(slug),
  );
}

export interface AssertScopeContext {
  /** config agents.allow_operator (products.manage admission). */
  allowOperator?: boolean;
  /** A local operator confirmation accompanied this grant/call. */
  localOperatorConfirmation?: boolean;
}

function topicParams(params: Json): string[] {
  if (typeof params === "object" && params !== null && !Array.isArray(params)) {
    const topics = (params as Record<string, Json>).topics;
    if (Array.isArray(topics)) {
      return topics.filter((t): t is string => typeof t === "string");
    }
    const topic = (params as Record<string, Json>).topic;
    if (typeof topic === "string") return [topic];
  }
  return [];
}

/**
 * Dispatcher scope admission for an authenticated peer (spec §4.1/§3.2).
 * Applies the role gate, then the method's exact scope requirement; any
 * failure is FORBIDDEN (or METHOD_UNKNOWN outside the registry).
 */
export function assertScope(
  peer: Peer,
  method: string,
  params: Json,
  ctx: AssertScopeContext = {},
): void {
  const spec = (RPC_METHODS as Record<string, { roles: readonly Role[] }>)[method];
  if (spec === undefined) rpc("METHOD_UNKNOWN", `unknown method ${method}`, "method");
  const letter: Role = peer.role === "operator" ? "O" : "A";
  if (!spec.roles.includes(letter)) {
    rpc("FORBIDDEN", `${method} is not available to a ${peer.role} peer`, "method");
  }

  const need = (permission: ScopePermission, covers: (s: Scope) => boolean, what: string): void => {
    if (!hasScopeCovering(peer, permission, covers)) {
      rpc("FORBIDDEN", `no ${permission} scope covers ${what}`, "params");
    }
  };

  switch (method) {
    case "events.publish": {
      const [topic] = topicParams(params);
      if (topic === undefined || !isTopic(topic)) {
        rpc("SCHEMA_INVALID", "topic must be a §3.4 registry topic", "topic");
      }
      need("events.emit", (s) => s.topics.includes(topic), `topic ${topic}`);
      break;
    }
    case "events.query":
    case "events.subscribe": {
      const topics = topicParams(params);
      for (const t of topics) {
        if (!isTopic(t)) rpc("SCHEMA_INVALID", `unknown topic ${t}`, "topics");
        need("events.consume", (s) => s.topics.includes(t), `topic ${t}`);
      }
      break;
    }
    case "events.ack":
      need("events.consume", () => true, "subscription ack");
      break;
    case "approval.request":
    case "approval.cancel":
      need("approvals.request", (s) => s.runs.length > 0, "own-action approval");
      break;
    case "lineage.query":
      need("lineage.read", (s) => s.runs.length > 0, "own lineage");
      break;
    case "run.register":
    case "run.heartbeat":
    case "run.finish": {
      const run =
        typeof params === "object" && params !== null && !Array.isArray(params)
          ? (params as Record<string, Json>).run_id
          : undefined;
      if (
        !peer.scopes.some(
          (s) =>
            s.runs.includes("self") ||
            (typeof run === "string" && s.runs.includes(run)),
        )
      ) {
        rpc("FORBIDDEN", "no scope covers this run", "run_id");
      }
      break;
    }
    case "agent.disconnect": {
      const target =
        typeof params === "object" && params !== null && !Array.isArray(params)
          ? (params as Record<string, Json>).peer
          : undefined;
      if (letter === "A" && target !== peer.id) {
        rpc("FORBIDDEN", "an agent peer disconnects only itself", "peer");
      }
      break;
    }
    case "product.plan":
    case "product.install":
    case "product.uninstall":
    case "product.update":
    case "product.rollback": {
      // §4.1: products.manage needs an operator-tier peer,
      // agents.allow_operator, a local operator confirmation, and exact
      // target products. A normal agent is always FORBIDDEN (TV-GW-24).
      const admission: ScopeAdmissionContext = {
        role: peer.role,
        allowOperator: ctx.allowOperator ?? false,
        localOperatorConfirmation: ctx.localOperatorConfirmation ?? false,
      };
      const manages = scopesFor(peer, "products.manage");
      if (manages.length === 0) {
        rpc("FORBIDDEN", "no products.manage scope", "params");
      }
      for (const s of manages) {
        const verdict = checkScopeAdmission(s, admission);
        if (!verdict.ok) rpc(verdict.code, verdict.message, verdict.field);
      }
      // Exact product check when the params carry the slug/selector
      // directly; plan-hash-bound calls are rechecked by the dispatcher
      // against the resolved plan slug via scopeCoversProduct.
      const slug =
        typeof params === "object" && params !== null && !Array.isArray(params)
          ? ((params as Record<string, Json>).source ??
            (params as Record<string, Json>).slug)
          : undefined;
      if (typeof slug === "string" && !scopeCoversProduct(peer, slug)) {
        rpc("FORBIDDEN", `no products.manage scope covers ${slug}`, "params");
      }
      break;
    }
    default:
      // Authenticated peer + role gate suffices for the remaining methods;
      // action/run ownership is enforced by the semantic layer.
      break;
  }
}

export { scopeWithin };
