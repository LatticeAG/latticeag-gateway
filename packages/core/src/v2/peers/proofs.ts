/**
 * Gateway v2 — per-request key proof verification (spec §4.3).
 *
 * Every ordinary peer HTTP request carries `Authorization: Bearer
 * <access>` plus a REQUEST/1 signature over
 * `{v:1,kind:"request",gateway,workspace,epoch,token_hash,id,method,
 * params_sha256,nonce,issued_ms,expires_ms}` in X-LatticeAG-Key-Proof,
 * with nonce/epoch/issued_ms/expires_ms in their named headers.
 *
 * Rejection rules (all → AUTH_REQUIRED): proof TTL >60000 ms,
 * issued_ms >now+5000, now >=expires_ms, proof expiry beyond the access
 * token's expiry, a replayed nonce, a stale epoch, or a signature that
 * does not verify under the enrolled peer key. Used nonces persist until
 * the bound token's expiry. Token failures surface first as
 * TOKEN_EXPIRED/TOKEN_REVOKED (authentication precedes the proof).
 */
import { Buffer } from "node:buffer";
import type { Count, Hash, Id } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import { isB64uCanonical } from "../crypto/ed25519.js";
import { requestProofBody, verifyRequest } from "../crypto/pairing.js";
import { PEER_LIMITS } from "../protocol/peers.js";
import type { GrantRecord, PeerPorts, StoredPeer } from "./ports.js";
import type { TokenService, VerifiedGrant } from "./tokens.js";

function rpc(code: RpcError["code"], message: string, field?: string): never {
  throw new RpcError(code, message, { field: field ?? null });
}

/** Wire header names for the per-request proof (§4.3). */
export const REQUEST_PROOF_HEADERS = {
  authorization: "Authorization",
  nonce: "X-LatticeAG-Nonce",
  epoch: "X-LatticeAG-Epoch",
  issuedMs: "X-LatticeAG-Issued-Ms",
  expiresMs: "X-LatticeAG-Expires-Ms",
  keyProof: "X-LatticeAG-Key-Proof",
} as const;

/** Parsed proof fields (header values or their RPC-side equivalents). */
export interface RequestProofFields {
  nonce: string;
  epoch: Count;
  issued_ms: number;
  expires_ms: number;
  /** X-LatticeAG-Key-Proof signature (base64url). */
  proof: string;
}

const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;

/**
 * Extract the proof fields from a case-insensitive header map. Missing or
 * malformed headers are AUTH_REQUIRED — a peer request without a complete
 * proof is unauthenticated, not schema-invalid.
 */
export function readProofHeaders(
  headers: Record<string, string | undefined>,
): RequestProofFields {
  const get = (name: string): string | undefined => {
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === lower) return v;
    }
    return undefined;
  };
  const nonce = get(REQUEST_PROOF_HEADERS.nonce);
  const epoch = get(REQUEST_PROOF_HEADERS.epoch);
  const issued = get(REQUEST_PROOF_HEADERS.issuedMs);
  const expires = get(REQUEST_PROOF_HEADERS.expiresMs);
  const proof = get(REQUEST_PROOF_HEADERS.keyProof);
  if (
    nonce === undefined ||
    epoch === undefined ||
    issued === undefined ||
    expires === undefined ||
    proof === undefined
  ) {
    rpc("AUTH_REQUIRED", "missing request-proof headers");
  }
  if (!DECIMAL_RE.test(issued) || !DECIMAL_RE.test(expires)) {
    rpc("AUTH_REQUIRED", "issued_ms/expires_ms must be canonical decimals");
  }
  return {
    nonce,
    epoch,
    issued_ms: Number(issued),
    expires_ms: Number(expires),
    proof,
  };
}

export interface RequestProofContext {
  ports: PeerPorts;
  tokens: TokenService;
  /** Instance id (signed `gateway` field). */
  gateway: Id;
  workspace: Id;
  /** Current boot/session epoch. */
  epoch: Count;
}

/**
 * Authenticate one peer request: bearer token, proof freshness/skew
 * window, nonce replay, then the REQUEST/1 signature under the enrolled
 * key. On success the nonce is recorded until token expiry and the bound
 * grant/peer are returned for scope admission.
 */
export function verifyRequestProof(
  ctx: RequestProofContext,
  req: {
    /** Bearer access token (plaintext, from Authorization). */
    access: string;
    /** Envelope request id this proof authenticates. */
    id: Id;
    method: string;
    /** H(J(params)) — the params commitment. */
    params_sha256: Hash;
    proof: RequestProofFields;
  },
): VerifiedGrant {
  const { grant, peer } = ctx.tokens.verifyAccess(req.access);
  verifyFreshness(ctx, grant, req.proof);
  assertNonceUnused(ctx, grant, req.proof.nonce);
  assertSignature(ctx, grant, peer, req);
  ctx.ports.putNonce(
    grant.access_hash,
    req.proof.nonce,
    Math.min(req.proof.expires_ms, grant.access_expires_ms),
  );
  return { grant, peer };
}

/** Freshness window checks (§4.3), all mapped to AUTH_REQUIRED. */
export function verifyFreshness(
  ctx: RequestProofContext,
  grant: GrantRecord,
  proof: RequestProofFields,
): void {
  const now = ctx.ports.now();
  if (!Number.isSafeInteger(proof.issued_ms) || !Number.isSafeInteger(proof.expires_ms)) {
    rpc("AUTH_REQUIRED", "issued_ms/expires_ms must be safe integers");
  }
  if (proof.expires_ms - proof.issued_ms > PEER_LIMITS.proofTtlMs) {
    rpc("AUTH_REQUIRED", "request-proof TTL exceeds 60000 ms");
  }
  if (proof.expires_ms <= proof.issued_ms) {
    rpc("AUTH_REQUIRED", "request-proof expiry precedes its issue time");
  }
  if (proof.issued_ms > now + PEER_LIMITS.proofIssuedSkewMs) {
    rpc("AUTH_REQUIRED", "request proof issued too far in the future");
  }
  if (now >= proof.expires_ms) {
    rpc("AUTH_REQUIRED", "request proof expired");
  }
  if (proof.expires_ms > grant.access_expires_ms) {
    rpc("AUTH_REQUIRED", "proof expiry exceeds the access token expiry");
  }
  if (proof.epoch !== ctx.epoch || proof.epoch !== grant.epoch) {
    rpc("AUTH_REQUIRED", "stale proof epoch");
  }
}

/** Persisted-nonce replay check (§4.3): an accepted nonce never replays. */
export function assertNonceUnused(
  ctx: RequestProofContext,
  grant: GrantRecord,
  nonce: string,
): void {
  if (!isB64uCanonical(nonce) || Buffer.from(nonce, "base64url").length !== PEER_LIMITS.nonceBytes) {
    rpc("AUTH_REQUIRED", "proof nonce must be 32 bytes base64url");
  }
  if (ctx.ports.hasNonce(grant.access_hash, nonce)) {
    rpc("AUTH_REQUIRED", "proof nonce already used");
  }
}

/** The REQUEST/1 signature over the canonical body under the peer key. */
export function assertSignature(
  ctx: RequestProofContext,
  grant: GrantRecord,
  peer: StoredPeer,
  req: {
    id: Id;
    method: string;
    params_sha256: Hash;
    proof: RequestProofFields;
  },
): void {
  let body;
  try {
    body = requestProofBody({
      gateway: ctx.gateway,
      workspace: ctx.workspace,
      epoch: req.proof.epoch,
      token_hash: grant.access_hash,
      id: req.id,
      method: req.method,
      params_sha256: req.params_sha256,
      nonce: req.proof.nonce,
      issued_ms: req.proof.issued_ms,
      expires_ms: req.proof.expires_ms,
    });
  } catch {
    rpc("AUTH_REQUIRED", "request-proof body is malformed");
  }
  if (!verifyRequest(body, req.proof.proof, peer.key_material.public)) {
    rpc("AUTH_REQUIRED", "request proof does not verify under the enrolled key");
  }
}
