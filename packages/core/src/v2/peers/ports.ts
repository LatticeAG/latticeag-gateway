/**
 * Gateway v2 agent-peer subsystem — injected store ports (spec §4.1–§4.3).
 *
 * All durable side effects of the pairing ceremony, grant/token table,
 * challenge store, replayed-proof nonces, peer registry, live sessions, and
 * queued deliveries live behind `PeerPorts`. `createMemoryPeerPorts()` is
 * the deterministic in-memory implementation used by tests; a daemon port
 * maps the same records onto the §2.3 journal/SQLite projection.
 *
 * Grant rows store only token hashes (H(token)); plaintext access/refresh
 * tokens exist only in the issued result object. Pairing code verification
 * material is likewise stored as H(code): a persisted pair row can prove a
 * presented code without carrying it.
 */

import type { Count, Hash, Id, KeyMaterial } from "../protocol/refs.js";
import type {
  Capability,
  PairState,
  Peer,
  Scope,
} from "../protocol/peers.js";
import { PEER_LIMITS } from "../protocol/peers.js";
import { newControlId, newPairCode, newToken } from "../crypto/ids.js";

// ── Shared injectables ───────────────────────────────────────────────────

/** Injectable wall clock (ms). All expiry math reads only `now()`. */
export interface Clock {
  now(): number;
}

/** Deterministic-or-random ID allocator, one counter family per kind. */
export interface IdAllocator {
  /**
   * Mint the next id for a kind: "pair" | "challenge" | "peer" | "source" |
   * "grant" | "family" | "session" | "delivery" | "approval".
   */
  next(kind: string): Id;
}

/** Default allocator: Proof-grammar control ids with 128 random bits. */
export function randomIds(): IdAllocator {
  return { next: () => newControlId() };
}

/**
 * Deterministic allocator for tests: per-kind counters with fixture-style
 * prefixes — pair1, challenge1, peer1, src1, grant1, fam1, sess1, del1,
 * approval1, … — matching the §3.3/§13.1 placeholder ids.
 */
export function sequentialIds(prefixes?: Record<string, string>): IdAllocator {
  const counters = new Map<string, number>();
  const named: Record<string, string> = {
    pair: "pair",
    challenge: "challenge",
    peer: "peer",
    source: "src",
    grant: "grant",
    family: "fam",
    session: "sess",
    delivery: "del",
    approval: "approval",
    ...prefixes,
  };
  return {
    next(kind: string): Id {
      const prefix = named[kind] ?? kind;
      const n = (counters.get(prefix) ?? 0) + 1;
      counters.set(prefix, n);
      return `${prefix}${n}`;
    },
  };
}

/** CSPRNG sources for secrets; tests inject deterministic sequences. */
export interface Entropy {
  /** 32-byte base64url token (access/refresh/bootstrap). */
  token(): string;
  /** 32-byte base64url nonce (challenge server nonce). */
  nonce(): string;
  /** 10-char Crockford-base32 invitation code (50 bits). */
  pairCode(): string;
}

/** Default entropy: node:crypto CSPRNG via the v2 id primitives. */
export function cryptoEntropy(): Entropy {
  return { token: newToken, nonce: newToken, pairCode: newPairCode };
}

/** Entropy replaying a fixed queue then falling back to `cryptoEntropy`. */
export function queuedEntropy(queue: {
  tokens?: string[];
  nonces?: string[];
  pairCodes?: string[];
}): Entropy {
  const tokens = [...(queue.tokens ?? [])];
  const nonces = [...(queue.nonces ?? [])];
  const codes = [...(queue.pairCodes ?? [])];
  const fallback = cryptoEntropy();
  return {
    token: () => tokens.shift() ?? fallback.token(),
    nonce: () => nonces.shift() ?? fallback.nonce(),
    pairCode: () => codes.shift() ?? fallback.pairCode(),
  };
}

// ── Durable records ──────────────────────────────────────────────────────

/**
 * Invitation/pairing row (§4.2). `proposal*` fields are populated by the
 * first successful propose; `approved` only by operator approval. `code`
 * stores H(code) — a persisted row never carries the plaintext code.
 */
export interface PairRecord {
  pair: Id;
  /** H(invitation code). */
  code_hash: Hash;
  role: "agent" | "operator";
  /** Invited scope ceiling requested at creation (operator may narrow). */
  scopes: Scope[];
  /** Optional key fingerprint pinned at creation (key id, H(public)). */
  pinned_key: Hash | null;
  state: PairState;
  /** Session epoch at creation; an epoch change invalidates the row. */
  epoch: Count;
  /** Failed code/key attempts; ≥5 → LOCKED (one transition). */
  attempts: number;
  /** H(J({key:KeyMaterial,profiles,interfaces,capabilities})) or null. */
  proposal: Hash | null;
  proposal_key: Hash | null;
  proposal_key_material: KeyMaterial | null;
  proposal_profiles: string[] | null;
  proposal_interfaces: string | null;
  proposal_capabilities: Capability[] | null;
  /** Operator-approved commitment, or null while unapproved. */
  approved: { proposal: Hash; key: Hash; scopes: Scope[] } | null;
  created_ms: number;
  expires_ms: number;
}

/** Single-use challenge row (§4.2 step 2); consumed by register commit. */
export interface ChallengeRecord {
  challenge: Id;
  /** H(raw public key) the challenge was issued to. */
  key_id: Hash;
  /** Raw public key (canonical base64url, 32 bytes). */
  key_public: string;
  client_nonce: string;
  server_nonce: string;
  audience: string;
  epoch: Count;
  created_ms: number;
  expires_ms: number;
  consumed: boolean;
}

/** Stored peer row: the §4.1 Peer plus its enrolled key material. */
export interface StoredPeer extends Peer {
  key_material: KeyMaterial;
  epoch: Count;
  registered_ms: number;
}

export type GrantState = "ACTIVE" | "CONSUMED" | "REVOKED";

/**
 * Grant/token row (§4.3). Server-side binding for a token pair: instance,
 * workspace, key hash, principal (peer), scopes, grant revision, expiry.
 * Only token hashes are stored — never token plaintext.
 */
export interface GrantRecord {
  grant: Id;
  /** Refresh family: all rotations of one issued grant share this id. */
  family: Id;
  peer: Id;
  instance: Id;
  workspace: Id;
  key_hash: Hash;
  role: "agent" | "operator";
  scopes: Scope[];
  grant_revision: Count;
  epoch: Count;
  access_hash: Hash;
  refresh_hash: Hash;
  access_expires_ms: number;
  refresh_expires_ms: number;
  state: GrantState;
  created_ms: number;
}

/** Saved agent.renew result for exact-request-id replay (§3.1/§4.3). */
export interface RenewReplayRecord {
  /** `${peer}:${refresh_hash}` of the consumed grant. */
  key: string;
  /** Envelope request id that performed the renew, or null when unknown. */
  request_id: string | null;
  result: { access: string; refresh: string; expires_ms: number };
}

/** Live session/lease row (HTTP RPC session, SSE subscription, …). */
export interface SessionRecord {
  session: Id;
  peer: Id;
  /** e.g. "sse" event subscription, "rpc". */
  kind: string;
  state: "OPEN" | "CLOSED";
  opened_ms: number;
  cursor: string | null;
}

/** Queued-but-undispatched delivery row; revocation drops it (§4.3). */
export interface DeliveryRecord {
  delivery: Id;
  peer: Id;
  topic: string;
  payload: unknown;
  queued_ms: number;
  state: "QUEUED" | "DISPATCHED" | "DROPPED";
}

// ── The port ─────────────────────────────────────────────────────────────

export interface PeerPorts {
  /** Injectable clock (ms). */
  now(): number;
  /** ID allocator (defaults to randomIds()). */
  newId(kind: string): Id;
  /** Secret/nonce/code entropy (defaults to cryptoEntropy()). */
  readonly entropy: Entropy;

  // Invitations (§4.2)
  putPair(rec: PairRecord): void;
  getPair(pair: Id): PairRecord | null;
  listPairs(): PairRecord[];
  updatePair(rec: PairRecord): void;

  // Challenges
  putChallenge(rec: ChallengeRecord): void;
  getChallenge(challenge: Id): ChallengeRecord | null;
  updateChallenge(rec: ChallengeRecord): void;

  // Peers / stable source ids
  putPeer(rec: StoredPeer): void;
  getPeer(peer: Id): StoredPeer | null;
  updatePeer(rec: StoredPeer): void;
  listPeers(): StoredPeer[];
  peerByKey(key: Hash): StoredPeer | null;
  sourceForKey(key: Hash): Id | null;
  putSource(key: Hash, source: Id): void;

  // Grants (token-hash rows only)
  putGrant(rec: GrantRecord): void;
  grantByAccessHash(hash: Hash): GrantRecord | null;
  grantByRefreshHash(hash: Hash): GrantRecord | null;
  updateGrant(rec: GrantRecord): void;
  grantsByPeer(peer: Id): GrantRecord[];
  grantsByFamily(family: Id): GrantRecord[];

  // Used request-proof nonces, retained until the bound token expires
  hasNonce(token_hash: Hash, nonce: string): boolean;
  putNonce(token_hash: Hash, nonce: string, expires_ms: number): void;

  // Renew replay cache keyed by `${peer}:${refresh_hash}`
  putRenewReplay(rec: RenewReplayRecord): void;
  getRenewReplay(key: string): RenewReplayRecord | null;

  // Sessions
  putSession(rec: SessionRecord): void;
  getSession(session: Id): SessionRecord | null;
  updateSession(rec: SessionRecord): void;
  sessionsByPeer(peer: Id): SessionRecord[];

  // Queued deliveries
  putDelivery(rec: DeliveryRecord): void;
  updateDelivery(rec: DeliveryRecord): void;
  deliveriesByPeer(peer: Id): DeliveryRecord[];
}

/** In-memory PeerPorts with a manual clock — deterministic tests. */
export interface MemoryPeerPorts extends PeerPorts {
  readonly clock: { value: number };
  readonly ids: IdAllocator;
  readonly pairs: Map<Id, PairRecord>;
  readonly challenges: Map<Id, ChallengeRecord>;
  readonly peers: Map<Id, StoredPeer>;
  readonly sources: Map<Hash, Id>;
  readonly grants: Map<Id, GrantRecord>;
  readonly nonces: Map<string, number>;
  readonly renewReplays: Map<string, RenewReplayRecord>;
  readonly sessions: Map<Id, SessionRecord>;
  readonly deliveries: Map<Id, DeliveryRecord>;
  /** Advance the manual clock. */
  advance(ms: number): void;
}

export function createMemoryPeerPorts(opts?: {
  now?: number;
  ids?: IdAllocator;
  entropy?: Entropy;
}): MemoryPeerPorts {
  const clock = { value: opts?.now ?? 0 };
  const ids = opts?.ids ?? sequentialIds();
  const pairs = new Map<Id, PairRecord>();
  const challenges = new Map<Id, ChallengeRecord>();
  const peers = new Map<Id, StoredPeer>();
  const sources = new Map<Hash, Id>();
  const grants = new Map<Id, GrantRecord>();
  const nonces = new Map<string, number>();
  const renewReplays = new Map<string, RenewReplayRecord>();
  const sessions = new Map<Id, SessionRecord>();
  const deliveries = new Map<Id, DeliveryRecord>();

  const ports: MemoryPeerPorts = {
    clock,
    ids,
    pairs,
    challenges,
    peers,
    sources,
    grants,
    nonces,
    renewReplays,
    sessions,
    deliveries,
    entropy: opts?.entropy ?? cryptoEntropy(),
    now: () => clock.value,
    newId: (kind) => ids.next(kind),
    advance(ms: number) {
      clock.value += ms;
    },

    putPair: (rec) => {
      pairs.set(rec.pair, rec);
    },
    getPair: (pair) => pairs.get(pair) ?? null,
    listPairs: () => [...pairs.values()],
    updatePair: (rec) => {
      pairs.set(rec.pair, rec);
    },

    putChallenge: (rec) => {
      challenges.set(rec.challenge, rec);
    },
    getChallenge: (challenge) => challenges.get(challenge) ?? null,
    updateChallenge: (rec) => {
      challenges.set(rec.challenge, rec);
    },

    putPeer: (rec) => {
      peers.set(rec.id, rec);
    },
    getPeer: (peer) => peers.get(peer) ?? null,
    updatePeer: (rec) => {
      peers.set(rec.id, rec);
    },
    listPeers: () => [...peers.values()],
    peerByKey: (key) =>
      [...peers.values()].find((p) => p.key === key) ?? null,
    sourceForKey: (key) => sources.get(key) ?? null,
    putSource: (key, source) => {
      sources.set(key, source);
    },

    putGrant: (rec) => {
      grants.set(rec.grant, rec);
    },
    grantByAccessHash: (hash) =>
      [...grants.values()].find((g) => g.access_hash === hash) ?? null,
    grantByRefreshHash: (hash) =>
      [...grants.values()].find((g) => g.refresh_hash === hash) ?? null,
    updateGrant: (rec) => {
      grants.set(rec.grant, rec);
    },
    grantsByPeer: (peer) => [...grants.values()].filter((g) => g.peer === peer),
    grantsByFamily: (family) =>
      [...grants.values()].filter((g) => g.family === family),

    hasNonce: (token_hash, nonce) => nonces.has(`${token_hash}:${nonce}`),
    putNonce: (token_hash, nonce, expires_ms) => {
      nonces.set(`${token_hash}:${nonce}`, expires_ms);
    },

    putRenewReplay: (rec) => {
      renewReplays.set(rec.key, rec);
    },
    getRenewReplay: (key) => renewReplays.get(key) ?? null,

    putSession: (rec) => {
      sessions.set(rec.session, rec);
    },
    getSession: (session) => sessions.get(session) ?? null,
    updateSession: (rec) => {
      sessions.set(rec.session, rec);
    },
    sessionsByPeer: (peer) =>
      [...sessions.values()].filter((s) => s.peer === peer),

    putDelivery: (rec) => {
      deliveries.set(rec.delivery, rec);
    },
    updateDelivery: (rec) => {
      deliveries.set(rec.delivery, rec);
    },
    deliveriesByPeer: (peer) =>
      [...deliveries.values()].filter((d) => d.peer === peer),
  };
  return ports;
}

/** Helper used by the managers: live pair states (non-terminal). */
export const PAIR_LIVE_STATES: readonly PairState[] = [
  "CREATED",
  "AWAITING_OPERATOR",
  "APPROVED",
];

export { PEER_LIMITS };
