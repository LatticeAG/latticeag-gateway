/**
 * Gateway v2 — grant/token service (spec §4.3).
 *
 * Access tokens are 32 CSPRNG bytes, base64url, expiring in access_ttl_s
 * (900); refresh tokens expire in refresh_ttl_s (30 days) and rotate on
 * use. Grant rows store only H(token) and bind instance, workspace, key
 * hash, peer, scopes, grant revision, and expiry server-side — tokens are
 * not self-authorizing.
 *
 * Renew (§4.3): verifies the RENEW/1 proof over
 * `{v:1,kind:"renew",gateway,workspace,epoch,peer,refresh_hash,challenge,
 * server_nonce}`, consumes the old grant, and rotates both tokens inside
 * the same family. Reusing a consumed refresh token under a different
 * request id revokes the entire refresh family; the exact retry under its
 * original request id returns the saved result after a fresh key proof.
 */
import type { Count, Id } from "../protocol/refs.js";
import type { RenewParams } from "../protocol/services.js";
import { RpcError } from "../protocol/errors.js";
import { sha256Hex } from "../crypto/hash.js";
import { renewBody, verifyRenew } from "../crypto/pairing.js";
import { PEER_LIMITS } from "../protocol/peers.js";
import type {
  Entropy,
  GrantRecord,
  IdAllocator,
  PeerPorts,
  StoredPeer,
} from "./ports.js";

function rpc(code: RpcError["code"], message: string, field?: string): never {
  throw new RpcError(code, message, { field: field ?? null });
}

export interface TokenServiceConfig {
  gateway: Id;
  workspace: Id;
  epoch: Count;
  /** Access token TTL, seconds (default 900). */
  accessTtlS?: number;
  /** Refresh token TTL, seconds (default 30 days). */
  refreshTtlS?: number;
  ids: IdAllocator;
  entropy: Entropy;
}

export interface IssuedTokens {
  access: string;
  refresh: string;
  /** Access-token expiry (ms). */
  expires_ms: number;
}

export interface VerifiedGrant {
  grant: GrantRecord;
  peer: StoredPeer;
}

export class TokenService {
  private readonly ports: PeerPorts;
  private readonly cfg: Required<TokenServiceConfig>;

  constructor(ports: PeerPorts, cfg: TokenServiceConfig) {
    this.ports = ports;
    this.cfg = {
      gateway: cfg.gateway,
      workspace: cfg.workspace,
      epoch: cfg.epoch,
      ids: cfg.ids,
      entropy: cfg.entropy,
      accessTtlS: cfg.accessTtlS ?? PEER_LIMITS.accessTtlS,
      refreshTtlS: cfg.refreshTtlS ?? PEER_LIMITS.refreshTtlS,
    };
  }

  private now(): number {
    return this.ports.now();
  }

  /**
   * Issue a grant + token pair for a peer. Only H(access)/H(refresh) are
   * persisted; the plaintext pair exists solely in the returned object.
   */
  issue(params: {
    peer: StoredPeer;
    /** Existing family when rotating, else a new one. */
    family?: Id;
  }): IssuedTokens {
    const now = this.now();
    const access = this.cfg.entropy.token();
    const refresh = this.cfg.entropy.token();
    const rec: GrantRecord = {
      grant: this.cfg.ids.next("grant"),
      family: params.family ?? this.cfg.ids.next("family"),
      peer: params.peer.id,
      instance: this.cfg.gateway,
      workspace: this.cfg.workspace,
      key_hash: params.peer.key,
      role: params.peer.role,
      scopes: params.peer.scopes,
      grant_revision: params.peer.grant_revision,
      epoch: this.cfg.epoch,
      access_hash: sha256Hex(access),
      refresh_hash: sha256Hex(refresh),
      access_expires_ms: now + this.cfg.accessTtlS * 1000,
      refresh_expires_ms: now + this.cfg.refreshTtlS * 1000,
      state: "ACTIVE",
      created_ms: now,
    };
    this.ports.putGrant(rec);
    return { access, refresh, expires_ms: rec.access_expires_ms };
  }

  /**
   * Authenticate an access token. Unknown → AUTH_REQUIRED; revoked peer,
   * revoked/consumed grant, or stale grant revision → TOKEN_REVOKED;
   * expiry at equality (now >= expires) or a foreign epoch → TOKEN_EXPIRED.
   */
  verifyAccess(access: string): VerifiedGrant {
    const grant = this.ports.grantByAccessHash(sha256Hex(access));
    if (grant === null) rpc("AUTH_REQUIRED", "unknown access token");
    if (grant.state !== "ACTIVE") rpc("TOKEN_REVOKED", "grant is no longer active");
    const peer = this.ports.getPeer(grant.peer);
    if (peer === null) rpc("AUTH_REQUIRED", "grant principal is gone");
    if (peer.state === "REVOKED" || grant.grant_revision !== peer.grant_revision) {
      rpc("TOKEN_REVOKED", "grant was revoked");
    }
    if (grant.epoch !== this.cfg.epoch) {
      rpc("TOKEN_EXPIRED", "grant predates the current epoch");
    }
    if (this.now() >= grant.access_expires_ms) {
      rpc("TOKEN_EXPIRED", "access token expired");
    }
    return { grant, peer };
  }

  /**
   * agent.renew (§4.3): authenticate the refresh grant and its RENEW/1
   * proof, consume the challenge, then rotate both tokens in the same
   * family. A consumed grant replays its saved result only under the
   * original request id after fresh proof; any other reuse revokes the
   * family. `request_id` is the envelope id, threaded by the dispatcher.
   */
  renew(params: RenewParams & { request_id?: Id | null }): IssuedTokens {
    const now = this.now();
    const refreshHash = sha256Hex(params.refresh);
    const grant = this.ports.grantByRefreshHash(refreshHash);
    if (grant === null) rpc("AUTH_REQUIRED", "unknown refresh token");
    if (grant.peer !== params.peer) {
      rpc("AUTH_REQUIRED", "refresh token does not belong to this peer", "peer");
    }
    const peer = this.ports.getPeer(grant.peer);
    if (peer === null) rpc("AUTH_REQUIRED", "grant principal is gone");
    if (peer.state === "REVOKED") rpc("TOKEN_REVOKED", "peer is revoked");
    if (params.epoch !== this.cfg.epoch || grant.epoch !== this.cfg.epoch) {
      rpc("AUTH_REQUIRED", "stale epoch", "epoch");
    }

    if (grant.state === "CONSUMED") {
      // Refresh reuse: verify a fresh proof first; only the original
      // request id replays the saved result — anything else revokes the
      // whole family (§4.3).
      if (!this.verifyRenewProof(params, grant, peer)) {
        rpc("AUTH_REQUIRED", "renew proof does not verify", "proof");
      }
      const replay = this.ports.getRenewReplay(`${grant.peer}:${refreshHash}`);
      if (
        replay !== null &&
        params.request_id !== undefined &&
        params.request_id !== null &&
        replay.request_id === params.request_id
      ) {
        return replay.result;
      }
      this.revokeFamily(grant.family);
      rpc("TOKEN_REVOKED", "refresh token reuse revoked the grant family");
    }
    if (grant.state === "REVOKED") rpc("TOKEN_REVOKED", "grant was revoked");
    if (grant.grant_revision !== peer.grant_revision) {
      rpc("TOKEN_REVOKED", "grant was superseded by a grant revision");
    }
    if (now >= grant.refresh_expires_ms) {
      rpc("TOKEN_EXPIRED", "refresh token expired");
    }

    // The renew challenge must be live, bound to this key and server
    // nonce, and inside its 60 s window; a successful renew consumes it.
    const ch = this.ports.getChallenge(params.challenge);
    if (ch === null || ch.epoch !== this.cfg.epoch) {
      rpc("AUTH_REQUIRED", "unknown or stale challenge", "challenge");
    }
    if (ch.consumed) rpc("AUTH_REQUIRED", "challenge already consumed", "challenge");
    if (now >= ch.expires_ms) {
      rpc("AUTH_REQUIRED", "challenge outside its 60 s freshness window", "challenge");
    }
    if (ch.server_nonce !== params.server_nonce || ch.key_id !== peer.key) {
      rpc("AUTH_REQUIRED", "challenge does not bind this nonce/key", "challenge");
    }

    if (!this.verifyRenewProof(params, grant, peer)) {
      rpc("AUTH_REQUIRED", "renew proof does not verify", "proof");
    }

    ch.consumed = true;
    this.ports.updateChallenge(ch);
    grant.state = "CONSUMED";
    this.ports.updateGrant(grant);

    const issued = this.issue({ peer, family: grant.family });
    this.ports.putRenewReplay({
      key: `${grant.peer}:${refreshHash}`,
      request_id: params.request_id ?? null,
      result: issued,
    });
    return issued;
  }

  /** RENEW/1 proof over the exact §4.3 body under the enrolled peer key. */
  private verifyRenewProof(
    params: RenewParams,
    grant: GrantRecord,
    peer: StoredPeer,
  ): boolean {
    const body = renewBody({
      gateway: this.cfg.gateway,
      workspace: this.cfg.workspace,
      epoch: params.epoch,
      peer: params.peer,
      refresh_hash: grant.refresh_hash,
      challenge: params.challenge,
      server_nonce: params.server_nonce,
    });
    return verifyRenew(body, params.proof, peer.key_material.public);
  }

  /** Revoke every grant of one peer (peer revocation, §4.3). */
  revokePeer(peer: Id): void {
    for (const grant of this.ports.grantsByPeer(peer)) {
      if (grant.state === "ACTIVE") {
        grant.state = "REVOKED";
        this.ports.updateGrant(grant);
      }
    }
  }

  /** Revoke every grant in a refresh family (token-reuse containment). */
  revokeFamily(family: Id): void {
    for (const grant of this.ports.grantsByFamily(family)) {
      if (grant.state !== "REVOKED") {
        grant.state = "REVOKED";
        this.ports.updateGrant(grant);
      }
    }
  }
}
