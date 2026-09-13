/**
 * Principal resolution (spec §3.1/§3.2, §4.3, §7.2).
 *
 * Transports produce `TransportCredentials`; this module turns them into a
 * `Principal`:
 *
 *  - `local`    — unix-socket/pipe caller → `local_operator` (L). Peercred
 *                 is unavailable to pure Node; the socket enforces the OS
 *                 boundary with 0700/0600 filesystem permissions instead
 *                 (see net/socket-server.ts).
 *  - `session`  — bridge cookie session → viewer (V) / operator (O).
 *                 Viewer sessions live 8 h absolute / 30 min idle; operator
 *                 elevation 10 min / 5 min idle and cannot renew except via
 *                 a fresh local-operator bootstrap.
 *  - `peer`     — `Authorization: Bearer <access>` plus the X-LatticeAG-*
 *                 proof headers → agent (A) / operator-tier peer (O).
 *                 Verified under `LATTICEAG-GATEWAY-REQUEST/1` with nonce
 *                 replay tracking, proof TTL ≤60 s, issued_ms skew ≤5 s,
 *                 and proof expiry bounded by access-token expiry.
 *  - `anonymous`— no credentials → `bootstrap` (P): only the pairing and
 *                 session-bootstrap methods are reachable.
 *
 * Sessions are epoch-scoped and memory-resident: every daemon boot bumps a
 * session epoch, so a restored runtime directory cannot resurrect a
 * session, bootstrap, challenge, or invitation (§4.2).
 */
import {
  PEER_LIMITS,
  RpcError,
  canonicalJson,
  isB64uCanonical,
  isId,
  newControlId,
  newToken,
  requestProofBody,
  sha256Hex,
  verifyRequest,
  type Principal,
  type Request as RpcRequest,
  type Scope,
} from "../core-v2.js";

// ── role letters ─────────────────────────────────────────────────────────

/** Role letters a principal satisfies for §3.2 authorization. */
export function principalRoles(p: Principal): Set<"V" | "A" | "O" | "R" | "L" | "P"> {
  switch (p.role) {
    case "local_operator":
      // The owner socket is the strongest local authority: it satisfies
      // operator and viewer roles in addition to L-only operations.
      return new Set(["L", "O", "V"]);
    case "operator":
      return new Set(["O", "V"]);
    case "viewer":
      return new Set(["V"]);
    case "agent":
      return p.reviewer === true ? new Set(["A", "R"]) : new Set(["A"]);
    case "bootstrap":
      return new Set(["P"]);
  }
}

// ── browser sessions ─────────────────────────────────────────────────────

export type SessionRole = "viewer" | "operator";

export interface SessionRecord {
  id: string;
  role: SessionRole;
  /** Memory-only CSRF secret returned by ui.session.exchange. */
  csrf: string;
  created_ms: number;
  last_seen_ms: number;
  /** Absolute expiry (8 h viewer / 10 min operator). */
  absolute_expires_ms: number;
  /** Idle timeout (30 min viewer / 5 min operator). */
  idle_ms: number;
  revoked: boolean;
}

export const SESSION_LIMITS = {
  viewer: { absoluteMs: 8 * 3600_000, idleMs: 30 * 60_000 },
  operator: { absoluteMs: 10 * 60_000, idleMs: 5 * 60_000 },
  bootstrapMs: 60_000,
} as const;

interface BootstrapRecord {
  role: SessionRole;
  expires_ms: number;
}

/**
 * Browser session/bootstrap state. Bootstraps are one-use 60 s values
 * exchanged for a cookie session; the resulting record carries the
 * memory-only CSRF secret. Everything is invalidated by epoch change —
 * the store is per-boot and nonces/sessions are never journaled.
 */
export class SessionStore {
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly bootstraps = new Map<string, BootstrapRecord>();
  private readonly now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  /** One-use 60 s bootstrap for `ui.session.create` (L only upstream). */
  createBootstrap(role: SessionRole): { bootstrap: string; expires_ms: number } {
    const bootstrap = newToken();
    const expires_ms = this.now() + SESSION_LIMITS.bootstrapMs;
    this.bootstraps.set(bootstrap, { role, expires_ms });
    return { bootstrap, expires_ms };
  }

  /** Non-consuming bootstrap role lookup (transport principal resolution). */
  peekBootstrap(bootstrap: string): SessionRole | null {
    const rec = this.bootstraps.get(bootstrap);
    if (rec === undefined || this.now() >= rec.expires_ms) return null;
    return rec.role;
  }

  /** Consume a bootstrap exactly once; null when unknown/expired. */
  exchange(bootstrap: string): SessionRecord | null {
    const rec = this.bootstraps.get(bootstrap);
    if (rec === undefined) return null;
    this.bootstraps.delete(bootstrap);
    if (this.now() >= rec.expires_ms) return null;
    const limits = SESSION_LIMITS[rec.role];
    const now = this.now();
    const session: SessionRecord = {
      id: `s${newControlId().slice(1)}`,
      role: rec.role,
      csrf: newToken(),
      created_ms: now,
      last_seen_ms: now,
      absolute_expires_ms: now + limits.absoluteMs,
      idle_ms: limits.idleMs,
      revoked: false,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  /**
   * Resolve a live session: enforces absolute + idle expiry and revocation,
   * and slides the idle window on success.
   */
  resolve(id: string): SessionRecord | null {
    const s = this.sessions.get(id);
    if (s === undefined) return null;
    const now = this.now();
    if (s.revoked || now >= s.absolute_expires_ms || now - s.last_seen_ms >= s.idle_ms) {
      return null;
    }
    s.last_seen_ms = now;
    return s;
  }

  /** Like resolve() but does not extend the idle window (SSE long-poll). */
  peek(id: string): SessionRecord | null {
    const s = this.sessions.get(id);
    if (s === undefined) return null;
    const now = this.now();
    if (s.revoked || now >= s.absolute_expires_ms || now - s.last_seen_ms >= s.idle_ms) {
      return null;
    }
    return s;
  }

  revoke(id: string): boolean {
    const s = this.sessions.get(id);
    if (s === undefined) return false;
    s.revoked = true;
    return true;
  }
}

// ── peer tokens / proofs ─────────────────────────────────────────────────

/** Server-side grant bound to an access token (spec §4.3). */
export interface PeerGrant {
  peer: string;
  /** Canonical base64url raw Ed25519 public key. */
  publicKey: string;
  role: "agent" | "operator";
  scopes: Scope[];
  /** Access-token absolute expiry (ms since epoch). */
  expires_ms: number;
  revoked: boolean;
  /** Boot/session epoch the token was issued under. */
  epoch: string;
  /** Native-enrolled reviewer flag (R). */
  reviewer?: boolean;
}

/** Lookup surface for access-token → grant bindings. */
export interface PeerTokenStore {
  /** H(access token) → grant, or null when unknown. */
  lookupAccess(tokenSha256: string): PeerGrant | null;
  /**
   * Record `nonce` as consumed for `peer` until `untilMs`; returns true
   * when the nonce was already present (replay).
   */
  nonceSeen(peer: string, nonce: string, untilMs: number): boolean;
}

/** Volatile in-memory PeerTokenStore (token→grant binding + nonce sets). */
export class InMemoryPeerTokenStore implements PeerTokenStore {
  private readonly grants = new Map<string, PeerGrant>();
  private readonly nonces = new Map<string, Map<string, number>>();
  private readonly now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  /** Register a grant under the *hash* of its access token. */
  bindAccessToken(accessToken: string, grant: PeerGrant): void {
    this.grants.set(sha256Hex(accessToken), grant);
  }

  bindAccessTokenHash(tokenSha256: string, grant: PeerGrant): void {
    this.grants.set(tokenSha256, grant);
  }

  lookupAccess(tokenSha256: string): PeerGrant | null {
    return this.grants.get(tokenSha256) ?? null;
  }

  nonceSeen(peer: string, nonce: string, untilMs: number): boolean {
    let set = this.nonces.get(peer);
    if (set === undefined) {
      set = new Map();
      this.nonces.set(peer, set);
    }
    const now = this.now();
    for (const [n, until] of set) {
      if (until <= now) set.delete(n);
    }
    if (set.has(nonce)) return true;
    set.set(nonce, untilMs);
    return false;
  }
}

/** Peer proof headers, all required for bearer authentication (§4.3). */
export interface PeerProofHeaders {
  authorization: string;
  nonce: string;
  epoch: string;
  issued_ms: string;
  expires_ms: string;
  key_proof: string;
}

/** Extract the proof header set; null when any member is absent/malformed. */
export function extractPeerProofHeaders(
  get: (name: string) => string | undefined,
): PeerProofHeaders | null {
  const authorization = get("authorization");
  const nonce = get("x-latticeag-nonce");
  const epoch = get("x-latticeag-epoch");
  const issued_ms = get("x-latticeag-issued-ms");
  const expires_ms = get("x-latticeag-expires-ms");
  const key_proof = get("x-latticeag-key-proof");
  if (
    authorization === undefined ||
    nonce === undefined ||
    epoch === undefined ||
    issued_ms === undefined ||
    expires_ms === undefined ||
    key_proof === undefined
  ) {
    return null;
  }
  return { authorization, nonce, epoch, issued_ms, expires_ms, key_proof };
}

export interface PeerAuthEnv {
  instance: string;
  workspace: string;
  /** Current boot/session epoch. */
  epoch: string;
  peers: PeerTokenStore;
  now?: () => number;
}

function authRequired(message: string): never {
  throw new RpcError("AUTH_REQUIRED", message);
}

/**
 * Resolve a bearer+proof peer request into an `agent`/`operator` principal.
 * Enforces the §4.3 checks in order: token known → not revoked → not
 * expired → epoch match → proof header shape/freshness bounds → nonce
 * replay → Ed25519 signature under the enrolled key.
 */
export function resolvePeerPrincipal(
  headers: PeerProofHeaders,
  request: RpcRequest,
  env: PeerAuthEnv,
): Principal {
  const now = env.now ?? Date.now;
  const m = /^Bearer ([A-Za-z0-9_-]+)$/.exec(headers.authorization);
  if (m === null) authRequired("malformed Authorization header");
  const access = m[1]!;
  const tokenHash = sha256Hex(access);
  const grant = env.peers.lookupAccess(tokenHash);
  if (grant === null) authRequired("unknown access token");
  if (grant.revoked) {
    throw new RpcError("TOKEN_REVOKED", "access token revoked");
  }
  const nowMs = now();
  if (nowMs >= grant.expires_ms) {
    throw new RpcError("TOKEN_EXPIRED", "access token expired");
  }
  if (headers.epoch !== env.epoch || headers.epoch !== grant.epoch) {
    authRequired("session epoch mismatch");
  }

  // Proof freshness bounds (§4.3).
  if (!/^[0-9]+$/.test(headers.issued_ms) || !/^[0-9]+$/.test(headers.expires_ms)) {
    authRequired("non-numeric proof timestamps");
  }
  const issuedMs = Number(headers.issued_ms);
  const expiresMs = Number(headers.expires_ms);
  if (!Number.isSafeInteger(issuedMs) || !Number.isSafeInteger(expiresMs)) {
    authRequired("proof timestamps out of range");
  }
  if (expiresMs - issuedMs > PEER_LIMITS.proofTtlMs) {
    authRequired("proof TTL exceeds 60000 ms");
  }
  if (issuedMs > nowMs + PEER_LIMITS.proofIssuedSkewMs) {
    authRequired("proof issued_ms is in the future");
  }
  if (nowMs >= expiresMs) authRequired("proof expired");
  if (expiresMs > grant.expires_ms) {
    authRequired("proof expiry exceeds access-token expiry");
  }

  // 32-byte canonical base64url nonce, replay-checked per peer.
  const nonce = headers.nonce;
  if (
    !isB64uCanonical(nonce) ||
    Buffer.from(nonce, "base64url").length !== PEER_LIMITS.nonceBytes
  ) {
    authRequired("malformed proof nonce");
  }
  if (env.peers.nonceSeen(grant.peer, nonce, grant.expires_ms)) {
    authRequired("replayed proof nonce");
  }

  // Signed request body: {v:1,kind:"request",…} under REQUEST domain.
  let paramsSha256: string;
  try {
    paramsSha256 = sha256Hex(canonicalJson(request.params));
  } catch {
    authRequired("params are outside the canonical domain");
  }
  let body;
  try {
    body = requestProofBody({
      gateway: env.instance,
      workspace: request.workspace,
      epoch: headers.epoch,
      token_hash: tokenHash,
      id: request.id,
      method: request.method,
      params_sha256: paramsSha256,
      nonce,
      issued_ms: issuedMs,
      expires_ms: expiresMs,
    });
  } catch {
    authRequired("request proof body is malformed");
  }
  if (!verifyRequest(body, headers.key_proof, grant.publicKey)) {
    authRequired("request proof signature invalid");
  }
  if (!isId(grant.peer)) authRequired("peer id is malformed");
  return {
    id: grant.peer,
    role: grant.role === "operator" ? "operator" : "agent",
    peer: grant.peer,
    scopes: grant.scopes,
    reviewer: grant.reviewer === true,
  };
}

// ── transport credentials → principal ────────────────────────────────────

/** What each listener resolved before dispatch (session already validated). */
export type TransportCredentials =
  | { kind: "local" }
  | { kind: "session"; session: SessionRecord }
  | { kind: "peer"; headers: PeerProofHeaders }
  | { kind: "anonymous" };

/**
 * Convert transport credentials into a Principal at the authentication
 * stage of the dispatch pipeline (after envelope validation — peer proofs
 * bind id/method/params).
 */
export function resolvePrincipal(
  creds: TransportCredentials,
  request: RpcRequest,
  env: PeerAuthEnv,
): Principal {
  switch (creds.kind) {
    case "local":
      return { id: "local", role: "local_operator" };
    case "session":
      return { id: `session:${creds.session.id}`, role: creds.session.role };
    case "anonymous":
      return { id: "anonymous", role: "bootstrap" };
    case "peer":
      return resolvePeerPrincipal(creds.headers, request, env);
  }
}
