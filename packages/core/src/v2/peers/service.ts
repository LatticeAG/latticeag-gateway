/**
 * Gateway v2 — agent.* RPC service facade (spec §3.3/§4).
 *
 * Wires PairingManager + PeerRegistry + TokenService onto the
 * AgentService contract. All ids/clocks/secrets are injectable; with the
 * memory ports and sequential ids the service reproduces the §3.3
 * exchange shapes exactly (pair1/challenge1/peer1/src1, expires offsets,
 * mesh:"ADAPTER_REQUIRED").
 *
 * Rate limits (§4.2): challenge/registration attempts are capped at
 * 5/minute per key and 100/minute per instance; excess is BUSY.
 */
import { Buffer } from "node:buffer";
import type { Count, Hash, Id } from "../protocol/refs.js";
import type { Page } from "../protocol/envelope.js";
import { RpcError } from "../protocol/errors.js";
import {
  PEER_LIMITS,
  validateScopes,
  type Peer,
  type Registration,
  type Scope,
} from "../protocol/peers.js";
import type {
  AgentService,
  ChallengeResult,
  PairCreateParams,
  PairViewResult,
  RegisterResult,
  RenewParams,
} from "../protocol/services.js";
import { isB64uCanonical, keyIdOfPublic } from "../crypto/ed25519.js";
import { isHash64 } from "../crypto/hash.js";
import { isId } from "../crypto/ids.js";
import {
  PairingManager,
  SUPPORTED_INTERFACES,
  SUPPORTED_PROFILES,
  validateRegistrationShape,
} from "./pairs.js";
import { PeerRegistry } from "./registry.js";
import { TokenService } from "./tokens.js";
import { checkScopeAdmission } from "../protocol/peers.js";
import { bindCapabilities } from "./scopes.js";
import {
  type ChallengeRecord,
  type Entropy,
  type IdAllocator,
  type PeerPorts,
} from "./ports.js";

function rpc(code: RpcError["code"], message: string, field?: string): never {
  throw new RpcError(code, message, { field: field ?? null });
}

export interface AgentServiceConfig {
  /** Instance id; challenge audience and signed `gateway` field. */
  gateway?: Id;
  /** Workspace bound into signed bodies. */
  workspace?: Id;
  /** Current boot/session epoch. */
  epoch?: Count;
  /** Advertised profiles (default §2.2 set). */
  supportedProfiles?: readonly string[];
  /** Advertised interfaces bundle (default "interfaces/1"). */
  supportedInterfaces?: string;
  /** config agents.allow_operator (products.manage admission). */
  allowOperator?: boolean;
  /** Configured scope policy ceiling (null = no extra narrowing). */
  policyScopes?: readonly Scope[] | null;
  /** Access/refresh TTLs in seconds (900 / 30 days). */
  accessTtlS?: number;
  refreshTtlS?: number;
  /** A pinned native mesh artifact is bound (else ADAPTER_REQUIRED). */
  nativeMeshAvailable?: boolean;
  ids?: IdAllocator;
  entropy?: Entropy;
}

/** Sliding-window rate limiter (5/key/min, 100/instance/min — §4.2). */
class RateLimiter {
  private readonly perKey = new Map<string, number[]>();
  private instanceHits: number[] = [];

  constructor(private readonly now: () => number) {}

  check(key: string): void {
    const now = this.now();
    const floor = now - 60_000;
    const hits = (this.perKey.get(key) ?? []).filter((t) => t > floor);
    this.instanceHits = this.instanceHits.filter((t) => t > floor);
    if (hits.length >= PEER_LIMITS.authAttemptsPerKeyPerMinute) {
      rpc("BUSY", "too many authentication attempts for this key");
    }
    if (this.instanceHits.length >= PEER_LIMITS.authAttemptsPerInstancePerMinute) {
      rpc("BUSY", "too many authentication attempts for this instance");
    }
    hits.push(now);
    this.instanceHits.push(now);
    this.perKey.set(key, hits);
  }
}

export interface AgentRuntime {
  service: AgentService;
  pairing: PairingManager;
  registry: PeerRegistry;
  tokens: TokenService;
  ports: PeerPorts;
}

/**
 * Build the agent.* service plus its runtime pieces (registry/tokens are
 * also used by the dispatcher for proof verification and revocation).
 */
export function createAgentRuntime(
  ports: PeerPorts,
  cfg: AgentServiceConfig = {},
): AgentRuntime {
  // Allocation/entropy default to the injected ports so a single
  // PeerPorts implementation controls every nondeterministic input.
  const ids: IdAllocator = cfg.ids ?? { next: (kind) => ports.newId(kind) };
  const entropy = cfg.entropy ?? ports.entropy;
  const gateway = cfg.gateway ?? "gw1";
  const workspace = cfg.workspace ?? "ws1";
  const epoch = cfg.epoch ?? "1";
  const limiter = new RateLimiter(() => ports.now());
  const pairing = new PairingManager(ports, {
    clock: { now: () => ports.now() },
    gateway,
    workspace,
    epoch,
    supportedProfiles: cfg.supportedProfiles ?? SUPPORTED_PROFILES,
    supportedInterfaces: cfg.supportedInterfaces ?? SUPPORTED_INTERFACES,
    allowOperator: cfg.allowOperator ?? false,
    ids,
    entropy,
    limiter,
  });
  const registry = new PeerRegistry(ports, { epoch, ids });
  const tokens = new TokenService(ports, {
    gateway,
    workspace,
    epoch,
    accessTtlS: cfg.accessTtlS ?? PEER_LIMITS.accessTtlS,
    refreshTtlS: cfg.refreshTtlS ?? PEER_LIMITS.refreshTtlS,
    ids,
    entropy,
  });
  const accessTtlS = cfg.accessTtlS ?? PEER_LIMITS.accessTtlS;

  const service: AgentService = {
    async pairCreate(params: PairCreateParams) {
      if (params.role !== "agent" && params.role !== "operator") {
        rpc("SCHEMA_INVALID", "role must be agent|operator", "role");
      }
      const valid = validateScopes(params.scopes);
      if (!valid.ok) rpc(valid.code, valid.message, valid.field);
      if (params.key !== null && !isHash64(params.key)) {
        rpc("SCHEMA_INVALID", "key must be a 64-hex fingerprint or null", "key");
      }
      return pairing.createInvitation({
        role: params.role,
        scopes: params.scopes,
        key: params.key,
      });
    },

    async pairPropose(params: Registration) {
      return pairing.propose(params);
    },

    async pairGet(params: { pair: Id; code: string | null }) {
      if (!isId(params.pair)) rpc("SCHEMA_INVALID", "pair must be an Id", "pair");
      return pairing.get(params);
    },

    async pairApprove(params: {
      pair: Id;
      proposal: Hash;
      key: Hash;
      scopes: Scope[];
    }) {
      const valid = validateScopes(params.scopes);
      if (!valid.ok) rpc(valid.code, valid.message, valid.field);
      if (!isHash64(params.proposal)) {
        rpc("SCHEMA_INVALID", "proposal must be 64 hex", "proposal");
      }
      if (!isHash64(params.key)) {
        rpc("SCHEMA_INVALID", "key must be 64 hex", "key");
      }
      const rec = ports.getPair(params.pair);
      const role = rec?.role ?? "agent";
      return pairing.approve({
        ...params,
        admit: (scope) => {
          const verdict = checkScopeAdmission(scope, {
            role,
            allowOperator: cfg.allowOperator ?? false,
            // pair.approve is L-only: the call itself is the local
            // operator confirmation.
            localOperatorConfirmation: true,
          });
          if (!verdict.ok) rpc(verdict.code, verdict.message, verdict.field);
        },
      });
    },

    async pairCancel(params: { pair: Id }) {
      if (!isId(params.pair)) rpc("SCHEMA_INVALID", "pair must be an Id", "pair");
      return pairing.cancel(params);
    },

    async challenge(params: { key: string; nonce: string }) {
      if (!isB64uCanonical(params.key) || Buffer.from(params.key, "base64url").length !== 32) {
        rpc("SCHEMA_INVALID", "key must be a 32-byte base64url public key", "key");
      }
      if (!isB64uCanonical(params.nonce) || Buffer.from(params.nonce, "base64url").length !== 32) {
        rpc("SCHEMA_INVALID", "nonce must be 32-byte base64url", "nonce");
      }
      let keyId: Hash;
      try {
        keyId = keyIdOfPublic(params.key);
      } catch {
        rpc("SCHEMA_INVALID", "malformed public key", "key");
      }
      limiter.check(keyId);
      const now = ports.now();
      const rec: ChallengeRecord = {
        challenge: ids.next("challenge"),
        key_id: keyId,
        key_public: params.key,
        client_nonce: params.nonce,
        server_nonce: entropy.nonce(),
        audience: gateway,
        epoch,
        created_ms: now,
        expires_ms: now + PEER_LIMITS.challengeTtlMs,
        consumed: false,
      };
      ports.putChallenge(rec);
      const result: ChallengeResult = {
        challenge: rec.challenge,
        nonce: rec.server_nonce,
        audience: rec.audience,
        epoch,
        expires_ms: rec.expires_ms,
      };
      return result;
    },

    async register(params: Registration): Promise<RegisterResult> {
      const reg = validateRegistrationShape(params);
      const { pair, reg: valid, scopes } = pairing.assertRegisterable(reg);
      // §4.1 effective grant: approved ∩ configured policy ∩ native
      // capability binding (emit/consume/request_approvals/lineage).
      const grantScopes = bindCapabilities(
        intersectPolicy(scopes, cfg.policyScopes),
        valid.capabilities,
      );
      const peer = registry.registerPeer({
        key_material: valid.key,
        role: pair.role,
        scopes: grantScopes,
        capabilities: valid.capabilities,
      });
      const issued = tokens.issue({ peer });
      pairing.consume(pair, valid);
      return {
        peer: peer.id,
        source: peer.source,
        role: peer.role,
        scopes: grantScopes,
        access: issued.access,
        refresh: issued.refresh,
        expires_ms: ports.now() + accessTtlS * 1000,
        mesh: cfg.nativeMeshAvailable === true ? "AWAITING_NATIVE_ACK" : "ADAPTER_REQUIRED",
      };
    },

    async renew(params: RenewParams & { request_id?: Id | null }) {
      if (!isId(params.peer)) rpc("SCHEMA_INVALID", "peer must be an Id", "peer");
      limiter.check(params.peer);
      return tokens.renew(params);
    },

    async list(params: { after: string | null; limit: number }): Promise<Page<Peer>> {
      return registry.listPeers(params);
    },

    async revoke(params: { peer: Id; reason: string }) {
      if (!isId(params.peer)) rpc("SCHEMA_INVALID", "peer must be an Id", "peer");
      return registry.revoke(params.peer, params.reason);
    },

    async disconnect(params: { peer: Id }) {
      if (!isId(params.peer)) rpc("SCHEMA_INVALID", "peer must be an Id", "peer");
      return registry.disconnect(params.peer);
    },
  };

  return { service, pairing, registry, tokens, ports };
}

/** createAgentService facade: returns just the AgentService contract. */
export function createAgentService(
  ports: PeerPorts,
  cfg: AgentServiceConfig = {},
): AgentService {
  return createAgentRuntime(ports, cfg).service;
}

/** Effective grant = invited/approved ∩ configured policy (§4.1). */
function intersectPolicy(
  approved: Scope[],
  policy: readonly Scope[] | null | undefined,
): Scope[] {
  if (policy == null) return approved;
  const out: Scope[] = [];
  for (const s of approved) {
    for (const p of policy) {
      if (s.permission !== p.permission) continue;
      out.push({
        permission: s.permission,
        topics: s.topics.filter((t) => p.topics.includes(t)),
        runs: s.runs.filter((r) => p.runs.includes(r)),
        products: s.products.filter((x) => p.products.includes(x)),
      });
    }
  }
  return out;
}

