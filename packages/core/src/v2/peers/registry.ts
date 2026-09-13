/**
 * Gateway v2 — peer registry on the PeerPorts store (spec §4.1/§4.3).
 *
 * Peer states: REGISTERED → CONNECTED ↔ DISCONNECTED → REVOKED. CONNECTED
 * is reachable only through `markNativeConnected` — a native PolyMesh
 * discovery acknowledgment — never by registration alone (TV-GW-19/63).
 * Revocation commits first: it advances grant_revision, revokes every
 * grant, closes HTTP/SSE/native sessions, and drops queued undispatched
 * deliveries; old tokens and stream resumes then fail TOKEN_REVOKED
 * (TV-GW-25). Registration allocates a stable source id bound to the key
 * (§4.1): re-registering the same key reuses its source.
 */
import type { Count, Hash, Id, KeyMaterial } from "../protocol/refs.js";
import type { Page } from "../protocol/envelope.js";
import {
  PEER_STATES,
  type Capability,
  type Peer,
  type PeerState,
  type Scope,
} from "../protocol/peers.js";
import { RpcError } from "../protocol/errors.js";
import type { IdAllocator, PeerPorts, SessionRecord, StoredPeer } from "./ports.js";

function rpc(code: RpcError["code"], message: string, field?: string): never {
  throw new RpcError(code, message, { field: field ?? null });
}

/** Bump a canonical decimal Count string. */
export function bumpCount(rev: Count): Count {
  return (BigInt(rev) + 1n).toString();
}

export interface PeerRegistryConfig {
  epoch: Count;
  ids: IdAllocator;
}

export class PeerRegistry {
  private readonly ports: PeerPorts;
  private readonly cfg: PeerRegistryConfig;

  constructor(ports: PeerPorts, cfg: PeerRegistryConfig) {
    this.ports = ports;
    this.cfg = cfg;
  }

  /**
   * Allocate the peer row and its stable source id. The source is bound to
   * the key: a re-registration of the same key reuses the first source.
   */
  registerPeer(params: {
    key_material: KeyMaterial;
    role: "agent" | "operator";
    scopes: Scope[];
    capabilities: Capability[];
  }): StoredPeer {
    const key = params.key_material.id;
    let source = this.ports.sourceForKey(key);
    if (source === null) {
      source = this.cfg.ids.next("source");
      this.ports.putSource(key, source);
    }
    const rec: StoredPeer = {
      id: this.cfg.ids.next("peer"),
      source,
      key,
      key_material: params.key_material,
      role: params.role,
      scopes: params.scopes,
      capabilities: params.capabilities,
      state: "REGISTERED",
      grant_revision: "1",
      epoch: this.cfg.epoch,
      registered_ms: this.ports.now(),
    };
    this.ports.putPeer(rec);
    return rec;
  }

  /** Public peer view: the §4.1 Peer shape without key material. */
  static view(rec: StoredPeer): Peer {
    return {
      id: rec.id,
      source: rec.source,
      key: rec.key,
      role: rec.role,
      scopes: rec.scopes,
      capabilities: rec.capabilities,
      state: rec.state,
      grant_revision: rec.grant_revision,
    };
  }

  getPeer(peer: Id): StoredPeer {
    const rec = this.ports.getPeer(peer);
    if (rec === null) rpc("NOT_FOUND", "unknown peer", "peer");
    return rec;
  }

  /** agent.list page: insertion order, opaque `after` = last peer id. */
  listPeers(params: { after: string | null; limit: number }): Page<Peer> {
    if (!Number.isSafeInteger(params.limit) || params.limit < 1 || params.limit > 200) {
      rpc("SCHEMA_INVALID", "limit must be 1–200", "limit");
    }
    const all = this.ports
      .listPeers()
      .sort((a, b) => a.registered_ms - b.registered_ms || (a.id < b.id ? -1 : 1));
    let start = 0;
    if (params.after !== null) {
      const idx = all.findIndex((p) => p.id === params.after);
      if (idx === -1) rpc("CURSOR_GONE", "unknown page cursor", "after");
      start = idx + 1;
    }
    const items = all.slice(start, start + params.limit).map(PeerRegistry.view);
    return {
      items,
      next: start + params.limit < all.length ? items[items.length - 1]!.id : null,
    };
  }

  private transition(rec: StoredPeer, to: PeerState): void {
    if (rec.state === to) {
      this.ports.updatePeer(rec);
      return;
    }
    const allowed: Record<PeerState, readonly PeerState[]> = {
      REGISTERED: ["CONNECTED", "DISCONNECTED", "REVOKED"],
      CONNECTED: ["DISCONNECTED", "REVOKED"],
      DISCONNECTED: ["CONNECTED", "REVOKED"],
      REVOKED: [],
    };
    if (!allowed[rec.state].includes(to)) {
      rpc("STATE_TRANSITION", `peer ${rec.id} cannot move ${rec.state}→${to}`, "peer");
    }
    rec.state = to;
    this.ports.updatePeer(rec);
  }

  /**
   * Native-ACK edge: only a PolyMesh native discovery acknowledgment may
   * mark a peer CONNECTED (§4.2 step 6). Called by the adapter boundary —
   * never by agent.register.
   */
  markNativeConnected(peer: Id): Peer {
    const rec = this.getPeer(peer);
    this.transition(rec, "CONNECTED");
    return PeerRegistry.view(rec);
  }

  /**
   * agent.revoke (§4.3): commit the revocation first, advance
   * grant_revision, revoke every grant, close sessions, and drop queued
   * undispatched deliveries. Idempotent on an already-revoked peer (the
   * committed state is returned, not re-applied).
   */
  revoke(peer: Id, _reason?: string): {
    peer: Id;
    state: "REVOKED";
    grant_revision: Count;
  } {
    const rec = this.getPeer(peer);
    if (rec.state !== "REVOKED") {
      rec.state = "REVOKED";
      rec.grant_revision = bumpCount(rec.grant_revision);
      this.ports.updatePeer(rec);
      for (const grant of this.ports.grantsByPeer(rec.id)) {
        if (grant.state === "ACTIVE") {
          grant.state = "REVOKED";
          this.ports.updateGrant(grant);
        }
      }
      this.closeSessions(rec.id);
      this.dropDeliveries(rec.id);
    }
    return { peer: rec.id, state: "REVOKED", grant_revision: rec.grant_revision };
  }

  /** agent.disconnect: close the connection, keep the enrollment. */
  disconnect(peer: Id): { peer: Id; state: "DISCONNECTED" } {
    const rec = this.getPeer(peer);
    this.transition(rec, "DISCONNECTED");
    this.closeSessions(rec.id);
    return { peer: rec.id, state: "DISCONNECTED" };
  }

  // ── sessions (revocation closes them; TV-GW-25) ────────────────────────

  /** Open a tracked peer session (e.g. an SSE subscription). */
  openSession(peer: Id, kind: string, cursor: string | null = null): SessionRecord {
    const rec = this.getPeer(peer);
    if (rec.state === "REVOKED") rpc("TOKEN_REVOKED", "peer is revoked");
    const session: SessionRecord = {
      session: this.cfg.ids.next("session"),
      peer: rec.id,
      kind,
      state: "OPEN",
      opened_ms: this.ports.now(),
      cursor,
    };
    this.ports.putSession(session);
    return session;
  }

  /**
   * Resume a tracked session (e.g. SSE Last-Event-ID reconnect). A revoked
   * peer or closed session is TOKEN_REVOKED (TV-GW-25).
   */
  resumeSession(session: Id): SessionRecord {
    const rec = this.ports.getSession(session);
    if (rec === null) rpc("NOT_FOUND", "unknown session", "session");
    const peer = this.ports.getPeer(rec.peer);
    if (peer === null || peer.state === "REVOKED" || rec.state === "CLOSED") {
      rpc("TOKEN_REVOKED", "session was closed by revocation");
    }
    return rec;
  }

  private closeSessions(peer: Id): number {
    let n = 0;
    for (const s of this.ports.sessionsByPeer(peer)) {
      if (s.state === "OPEN") {
        s.state = "CLOSED";
        this.ports.updateSession(s);
        n += 1;
      }
    }
    return n;
  }

  private dropDeliveries(peer: Id): number {
    let n = 0;
    for (const d of this.ports.deliveriesByPeer(peer)) {
      if (d.state === "QUEUED") {
        d.state = "DROPPED";
        this.ports.updateDelivery(d);
        n += 1;
      }
    }
    return n;
  }
}

export { PEER_STATES };
