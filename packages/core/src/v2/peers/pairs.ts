/**
 * Gateway v2 — pairing ceremony manager (spec §4.1–§4.2).
 *
 * States: CREATED→AWAITING_OPERATOR→APPROVED→CONSUMED; a changed proposal
 * returns to AWAITING_OPERATOR; any unconsumed state may become
 * CANCELLED/EXPIRED/LOCKED. Expiry applies at equality (`now >= expires`,
 * P10). Each invitation permits five failed code/key attempts before a
 * single LOCKED transition; invitations/challenges are bound to the
 * session epoch and are invalid after an epoch change.
 *
 * The proposal hash follows the §13.1 fixture exactly:
 * `H(J({key,profiles,interfaces,capabilities}))` where `key` is the
 * submitted KeyMaterial object `{id,public}` — not the bare key id.
 */
import { Buffer } from "node:buffer";
import {
  PEER_LIMITS,
  canPairTransition,
  type Capability,
  type PairState,
  type Registration,
  type Scope,
} from "../protocol/peers.js";
import type { PairViewResult } from "../protocol/services.js";
import type { Count, Hash, Id, KeyMaterial } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import { canonicalJson } from "../crypto/canonical.js";
import { isB64uCanonical, keyIdOfPublic } from "../crypto/ed25519.js";
import { sha256Hex } from "../crypto/hash.js";
import { isId, isPairCode } from "../crypto/ids.js";
import { registerBody, verifyRegister } from "../crypto/pairing.js";
import {
  PAIR_LIVE_STATES,
  type Clock,
  type Entropy,
  type IdAllocator,
  type PairRecord,
  type PeerPorts,
} from "./ports.js";

/** Profiles the daemon advertises in hello (spec §2.2). */
export const SUPPORTED_PROFILES: readonly string[] = [
  "@latticeag/events@0.1.0",
  "proof-evidence/1",
  "proof-bundle/1",
];

/** The only supported interface bundle (§2.2). */
export const SUPPORTED_INTERFACES = "interfaces/1";

/** Well-formed registration after lexical checks (internal). */
export interface ValidatedRegistration extends Registration {
  key: KeyMaterial;
}

export interface PairingManagerConfig {
  clock: Clock;
  /** Instance id (challenge audience / signed `gateway` field). */
  gateway: Id;
  /** Workspace bound into signed bodies. */
  workspace: Id;
  /** Current boot/session epoch. */
  epoch: Count;
  /** Advertised profile set (defaults to §2.2 SUPPORTED_PROFILES). */
  supportedProfiles?: readonly string[];
  /** Advertised interfaces bundle (default "interfaces/1"). */
  supportedInterfaces?: string;
  ids: IdAllocator;
  entropy: Entropy;
  /** config agents.allow_operator — products.manage admission gate. */
  allowOperator?: boolean;
  /**
   * §4.2 rate limit (5 attempts/min per key): checked after the live-state
   * gate so a terminal pair state (LOCKED/EXPIRED/…) always dominates the
   * generic BUSY rejection.
   */
  limiter?: { check(key: string): void };
}

const Z64 = "0".repeat(64);

function rpc(code: RpcError["code"], message: string, field?: string): never {
  throw new RpcError(code, message, { field: field ?? null });
}

function utf8Bytes(s: string): number {
  return Buffer.byteLength(s, "utf8");
}

/** Closed-object key check. */
function onlyKeys(obj: Record<string, unknown>, allowed: readonly string[]): string | null {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) return k;
  }
  return null;
}

const REGISTRATION_KEYS = [
  "pair",
  "code",
  "key",
  "challenge",
  "client_nonce",
  "server_nonce",
  "epoch",
  "profiles",
  "interfaces",
  "capabilities",
  "proof",
] as const;

const CAPABILITY_KEYS = [
  "name",
  "revision",
  "profiles",
  "emit",
  "consume",
  "request_approvals",
  "lineage",
] as const;

function isStringArray(v: unknown, max: number): v is string[] {
  if (!Array.isArray(v) || v.length > max) return false;
  const seen = new Set<string>();
  for (const e of v) {
    if (typeof e !== "string" || e.length === 0 || seen.has(e)) return false;
    seen.add(e);
  }
  return true;
}

function b64u32(v: unknown): v is string {
  return (
    typeof v === "string" &&
    isB64uCanonical(v) &&
    Buffer.from(v, "base64url").length === 32
  );
}

/**
 * Lexical validation of one signed Capability (§4.1): closed object,
 * revision 1, name ≤64 bytes, ≤64 unique entries per nested set.
 */
export function validateCapability(cap: unknown): Capability {
  if (typeof cap !== "object" || cap === null || Array.isArray(cap)) {
    rpc("SCHEMA_INVALID", "capability must be an object", "capabilities");
  }
  const c = cap as Record<string, unknown>;
  const extra = onlyKeys(c, CAPABILITY_KEYS);
  if (extra !== null) {
    rpc("SCHEMA_INVALID", `unknown capability field ${extra}`, "capabilities");
  }
  if (typeof c.name !== "string" || c.name.length === 0 || utf8Bytes(c.name) > PEER_LIMITS.maxNameBytes) {
    rpc("SCHEMA_INVALID", "capability name must be ≤64 bytes", "capabilities");
  }
  if (c.revision !== 1) {
    rpc("SCHEMA_INVALID", "capability revision must be 1", "capabilities");
  }
  for (const dim of ["profiles", "emit", "consume"] as const) {
    if (!isStringArray(c[dim], PEER_LIMITS.maxSetEntries)) {
      rpc("SCHEMA_INVALID", `capability ${dim} must be ≤64 unique strings`, "capabilities");
    }
  }
  if (typeof c.request_approvals !== "boolean") {
    rpc("SCHEMA_INVALID", "request_approvals must be boolean", "capabilities");
  }
  if (c.lineage !== "none" && c.lineage !== "own") {
    rpc("SCHEMA_INVALID", "lineage must be none|own", "capabilities");
  }
  return c as unknown as Capability;
}

/**
 * Lexical validation of a signed Registration (§4.1/§4.2): closed object,
 * all fields required, Proof-grammar ids, canonical base64url nonces/key,
 * ≤32 capabilities. Does not authenticate anything.
 */
export function validateRegistrationShape(reg: unknown): ValidatedRegistration {
  if (typeof reg !== "object" || reg === null || Array.isArray(reg)) {
    rpc("SCHEMA_INVALID", "registration must be an object");
  }
  const r = reg as Record<string, unknown>;
  const extra = onlyKeys(r, REGISTRATION_KEYS);
  if (extra !== null) rpc("SCHEMA_INVALID", `unknown registration field ${extra}`, extra);
  for (const k of REGISTRATION_KEYS) {
    if (!(k in r)) rpc("SCHEMA_INVALID", `missing registration field ${k}`, k);
  }
  if (!isId(r.pair)) rpc("SCHEMA_INVALID", "pair must be an Id", "pair");
  if (typeof r.code !== "string") rpc("SCHEMA_INVALID", "code must be a string", "code");
  const key = r.key;
  if (typeof key !== "object" || key === null || Array.isArray(key)) {
    rpc("SCHEMA_INVALID", "key must be KeyMaterial", "key");
  }
  const km = key as Record<string, unknown>;
  if (onlyKeys(km, ["id", "public"]) !== null) {
    rpc("SCHEMA_INVALID", "key must be closed {id,public}", "key");
  }
  if (typeof km.id !== "string" || !/^[0-9a-f]{64}$/.test(km.id)) {
    rpc("SCHEMA_INVALID", "key.id must be 64 lowercase hex", "key");
  }
  if (!b64u32(km.public)) {
    rpc("SCHEMA_INVALID", "key.public must be a 32-byte base64url key", "key");
  }
  if (!isId(r.challenge)) rpc("SCHEMA_INVALID", "challenge must be an Id", "challenge");
  if (!b64u32(r.client_nonce)) rpc("SCHEMA_INVALID", "client_nonce must be 32-byte base64url", "client_nonce");
  if (!b64u32(r.server_nonce)) rpc("SCHEMA_INVALID", "server_nonce must be 32-byte base64url", "server_nonce");
  if (typeof r.epoch !== "string" || !/^(0|[1-9][0-9]*)$/.test(r.epoch)) {
    rpc("SCHEMA_INVALID", "epoch must be a canonical Count", "epoch");
  }
  if (!isStringArray(r.profiles, PEER_LIMITS.maxSetEntries)) {
    rpc("SCHEMA_INVALID", "profiles must be ≤64 unique strings", "profiles");
  }
  if (typeof r.interfaces !== "string") {
    rpc("SCHEMA_INVALID", "interfaces must be a string", "interfaces");
  }
  if (!Array.isArray(r.capabilities) || r.capabilities.length > PEER_LIMITS.maxCapabilities) {
    rpc("SCHEMA_INVALID", `capabilities must be ≤${PEER_LIMITS.maxCapabilities} entries`, "capabilities");
  }
  for (const cap of r.capabilities as unknown[]) validateCapability(cap);
  if (typeof r.proof !== "string" || !isB64uCanonical(r.proof)) {
    rpc("SCHEMA_INVALID", "proof must be a base64url signature", "proof");
  }
  return r as unknown as ValidatedRegistration;
}

/**
 * Fixture-exact proposal hash: `H(J({key,profiles,interfaces,capabilities}))`
 * where `key` is the submitted KeyMaterial object (spec §4.2 step 4,
 * §13.1 F.proposal).
 */
export function proposalOfRegistration(reg: {
  key: KeyMaterial;
  profiles: string[];
  interfaces: string;
  capabilities: unknown[];
}): Hash {
  return sha256Hex(
    canonicalJson({
      key: reg.key,
      profiles: reg.profiles,
      interfaces: reg.interfaces,
      capabilities: reg.capabilities,
    }),
  );
}

/** Scope-list equality by canonical encoding (order-sensitive, exact). */
export function scopesEqual(a: Scope[], b: Scope[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (canonicalJson(a[i]) !== canonicalJson(b[i])) return false;
  }
  return true;
}

export class PairingManager {
  private readonly ports: PeerPorts;
  private readonly cfg: Omit<
    PairingManagerConfig,
    "supportedProfiles" | "supportedInterfaces" | "allowOperator"
  > & {
    supportedProfiles: readonly string[];
    supportedInterfaces: string;
    allowOperator: boolean;
  };

  constructor(ports: PeerPorts, cfg: PairingManagerConfig) {
    this.ports = ports;
    this.cfg = {
      clock: cfg.clock,
      ids: cfg.ids,
      entropy: cfg.entropy,
      gateway: cfg.gateway,
      workspace: cfg.workspace,
      epoch: cfg.epoch,
      supportedProfiles: cfg.supportedProfiles ?? SUPPORTED_PROFILES,
      supportedInterfaces: cfg.supportedInterfaces ?? SUPPORTED_INTERFACES,
      allowOperator: cfg.allowOperator ?? false,
      limiter: cfg.limiter,
    };
  }

  private now(): number {
    return this.ports.now();
  }

  /** Persisted state transition through the §4.2 machine. */
  private transition(rec: PairRecord, to: PairState): void {
    if (!canPairTransition(rec.state, to)) {
      rpc("STATE_TRANSITION", `pair ${rec.pair} cannot move ${rec.state}→${to}`, "pair");
    }
    rec.state = to;
    this.ports.updatePair(rec);
  }

  /**
   * Lazily apply expiry/epoch invalidation and translate terminal state to
   * the wire error. Expiry applies at equality (now >= expires_ms, P10);
   * an epoch change invalidates the invitation outright.
   */
  private assertLive(rec: PairRecord): void {
    if (rec.epoch !== this.cfg.epoch) {
      if (PAIR_LIVE_STATES.includes(rec.state)) this.transition(rec, "EXPIRED");
      rpc("PAIRING_EXPIRED", "invitation predates the current epoch", "pair");
    }
    if (PAIR_LIVE_STATES.includes(rec.state) && this.now() >= rec.expires_ms) {
      this.transition(rec, "EXPIRED");
    }
    switch (rec.state) {
      case "EXPIRED":
        rpc("PAIRING_EXPIRED", "invitation expired", "pair");
        break;
      case "LOCKED":
        rpc("PAIRING_LOCKED", "invitation is locked", "pair");
        break;
      case "CANCELLED":
      case "CONSUMED":
        rpc("STATE_TRANSITION", `invitation is ${rec.state}`, "pair");
        break;
      default:
        break;
    }
  }

  /**
   * Failed code/key attempt accounting (§4.2): the fifth failure — and any
   * subsequent attempt — yields PAIRING_LOCKED; the row transitions once.
   */
  private failAttempt(rec: PairRecord, code: "FORBIDDEN" | "SIGNATURE_INVALID", message: string): never {
    rec.attempts += 1;
    if (rec.attempts >= PEER_LIMITS.maxCodeAttempts) {
      if (rec.state !== "LOCKED") this.transition(rec, "LOCKED");
      else this.ports.updatePair(rec);
      rpc("PAIRING_LOCKED", "invitation locked after five failed attempts", "code");
    }
    this.ports.updatePair(rec);
    rpc(code, message, "code");
  }

  private checkCode(rec: PairRecord, code: string): void {
    if (!isPairCode(code)) {
      rpc("SCHEMA_INVALID", "code must be 10 Crockford-base32 characters", "code");
    }
    if (sha256Hex(code) !== rec.code_hash) {
      this.failAttempt(rec, "FORBIDDEN", "invitation code mismatch");
    }
  }

  /**
   * Challenge binding for propose/register (§4.2): the challenge must be
   * issued to this key, carry both nonces, share the session epoch, remain
   * inside its 60 s freshness window (now < expires_ms), and be unconsumed.
   */
  private checkChallenge(reg: ValidatedRegistration): void {
    const ch = this.ports.getChallenge(reg.challenge);
    if (ch === null || ch.epoch !== this.cfg.epoch || reg.epoch !== this.cfg.epoch) {
      rpc("AUTH_REQUIRED", "unknown or stale challenge", "challenge");
    }
    if (ch.consumed) rpc("AUTH_REQUIRED", "challenge already consumed", "challenge");
    if (this.now() >= ch.expires_ms) {
      rpc("AUTH_REQUIRED", "challenge outside its 60 s freshness window", "challenge");
    }
    if (
      ch.client_nonce !== reg.client_nonce ||
      ch.server_nonce !== reg.server_nonce ||
      ch.key_id !== reg.key.id
    ) {
      rpc("AUTH_REQUIRED", "challenge does not bind these nonces/key", "challenge");
    }
  }

  /**
   * Key/proof authentication (§4.2): key material must be self-consistent
   * (id = H(public)) and the PAIR/1 signature must verify under the
   * submitted public key over the exact signed body. Both failures count
   * as code/key attempts against the invitation.
   */
  private checkKeyAndProof(rec: PairRecord, reg: ValidatedRegistration): void {
    let derived: string;
    try {
      derived = keyIdOfPublic(reg.key.public);
    } catch {
      this.failAttempt(rec, "FORBIDDEN", "malformed public key");
    }
    if (derived !== reg.key.id) {
      this.failAttempt(rec, "FORBIDDEN", "key fingerprint does not match public key");
    }
    if (rec.pinned_key !== null && rec.pinned_key !== reg.key.id) {
      this.failAttempt(rec, "FORBIDDEN", "registration key is not the invited key");
    }
    const body = registerBody({
      gateway: this.cfg.gateway,
      workspace: this.cfg.workspace,
      epoch: reg.epoch,
      pair: reg.pair,
      challenge: reg.challenge,
      client_nonce: reg.client_nonce,
      server_nonce: reg.server_nonce,
      key: reg.key.id,
      profiles: reg.profiles,
      interfaces: reg.interfaces,
      capabilities: reg.capabilities,
    });
    if (!verifyRegister(body, reg.proof, reg.key.public)) {
      this.failAttempt(rec, "SIGNATURE_INVALID", "registration proof does not verify");
    }
  }

  /**
   * Required-profile intersection (§2.2): every profile a registration
   * requires must be advertised; no common required profile (or an unknown
   * interfaces bundle) is SCHEMA_UNSUPPORTED before enrollment.
   */
  private checkProfiles(reg: ValidatedRegistration): void {
    if (reg.interfaces !== this.cfg.supportedInterfaces) {
      rpc("SCHEMA_UNSUPPORTED", `interfaces ${reg.interfaces} is not supported`, "interfaces");
    }
    for (const p of reg.profiles) {
      if (!this.cfg.supportedProfiles.includes(p)) {
        rpc("SCHEMA_UNSUPPORTED", `profile ${p} is not supported`, "profiles");
      }
    }
  }

  /**
   * Shared propose/register validation: shape → pair → live → code →
   * challenge → rate-limit → key/proof → profiles. Returns the live pair
   * row. Ordering matters (§4.2): a terminal pair state dominates every
   * later error, failed code/key attempts are governed by the five-
   * attempt invitation lock (they never reach the limiter), and the
   * 5/min per-key limiter counts attempts that present the correct code
   * and a live challenge — bounding signature-verification work per key.
   */
  validateRegistration(reg: unknown): { pair: PairRecord; reg: ValidatedRegistration } {
    const valid = validateRegistrationShape(reg);
    const rec = this.ports.getPair(valid.pair);
    if (rec === null) rpc("NOT_FOUND", "unknown pair", "pair");
    this.assertLive(rec);
    this.checkCode(rec, valid.code);
    this.checkChallenge(valid);
    this.cfg.limiter?.check(valid.key.id);
    this.checkKeyAndProof(rec, valid);
    this.checkProfiles(valid);
    return { pair: rec, reg: valid };
  }

  /** §3.3 pair view: post-proposal fields fall back to the zero hash. */
  private view(rec: PairRecord): PairViewResult {
    return {
      pair: rec.pair,
      state: rec.state,
      proposal: rec.proposal ?? Z64,
      key: rec.proposal_key ?? rec.pinned_key ?? Z64,
      scopes: rec.approved?.scopes ?? rec.scopes,
    };
  }

  // ── RPC-facing operations ──────────────────────────────────────────────

  /**
   * agent.pair.create: mint a 10-char Crockford invitation valid for
   * 300 s; at most 128 pending (non-terminal, unexpired) invitations.
   */
  createInvitation(params: {
    role: "agent" | "operator";
    scopes: Scope[];
    key: Hash | null;
  }): { pair: Id; code: string; expires_ms: number } {
    const now = this.now();
    let pending = 0;
    for (const rec of this.ports.listPairs()) {
      if (
        PAIR_LIVE_STATES.includes(rec.state) &&
        rec.epoch === this.cfg.epoch &&
        now < rec.expires_ms
      ) {
        pending += 1;
      }
    }
    if (pending >= PEER_LIMITS.maxPendingInvitations) {
      rpc("BUSY", "too many pending invitations", "pair");
    }
    const code = this.cfg.entropy.pairCode();
    const rec: PairRecord = {
      pair: this.cfg.ids.next("pair"),
      code_hash: sha256Hex(code),
      role: params.role,
      scopes: params.scopes,
      pinned_key: params.key,
      state: "CREATED",
      epoch: this.cfg.epoch,
      attempts: 0,
      proposal: null,
      proposal_key: null,
      proposal_key_material: null,
      proposal_profiles: null,
      proposal_interfaces: null,
      proposal_capabilities: null,
      approved: null,
      created_ms: now,
      expires_ms: now + PEER_LIMITS.invitationTtlMs,
    };
    this.ports.putPair(rec);
    return { pair: rec.pair, code, expires_ms: rec.expires_ms };
  }

  /**
   * agent.pair.propose: authenticate the registration and retain the
   * bounded proposal. A changed proposal on an APPROVED pair returns it to
   * AWAITING_OPERATOR and drops the stale approval.
   */
  propose(registration: unknown): PairViewResult {
    const { pair: rec, reg } = this.validateRegistration(registration);
    const proposal = proposalOfRegistration(reg);
    if (rec.proposal !== proposal) {
      rec.proposal = proposal;
      rec.proposal_key = reg.key.id;
      rec.proposal_key_material = reg.key;
      rec.proposal_profiles = [...reg.profiles];
      rec.proposal_interfaces = reg.interfaces;
      rec.proposal_capabilities = [...reg.capabilities];
      rec.approved = null;
      if (rec.state !== "AWAITING_OPERATOR") {
        this.transition(rec, "AWAITING_OPERATOR");
      } else {
        this.ports.updatePair(rec);
      }
    } else {
      this.ports.updatePair(rec);
    }
    return this.view(rec);
  }

  /**
   * agent.pair.get: state view. A supplied code must match (mismatches are
   * counted code attempts); `code: null` is admitted only for local
   * operators — caller-side role enforcement, never assumed here.
   */
  get(params: { pair: Id; code: string | null }): PairViewResult {
    const rec = this.ports.getPair(params.pair);
    if (rec === null) rpc("NOT_FOUND", "unknown pair", "pair");
    // Lazily reflect expiry in the reported state (read path, no error).
    if (
      PAIR_LIVE_STATES.includes(rec.state) &&
      (rec.epoch !== this.cfg.epoch || this.now() >= rec.expires_ms)
    ) {
      this.transition(rec, "EXPIRED");
    }
    if (params.code !== null) {
      if (!isPairCode(params.code)) {
        rpc("SCHEMA_INVALID", "code must be 10 Crockford-base32 characters", "code");
      }
      if (sha256Hex(params.code) !== rec.code_hash) {
        this.failAttempt(rec, "FORBIDDEN", "invitation code mismatch");
      }
    }
    return this.view(rec);
  }

  /**
   * agent.pair.approve: commit the operator-approved proposal hash, key
   * fingerprint, and (possibly narrowed) scopes. A stale proposal/key
   * commitment is REVISION_CONFLICT; widening the invited scopes is
   * FORBIDDEN; products.manage admission follows §4.1.
   */
  approve(params: {
    pair: Id;
    proposal: Hash;
    key: Hash;
    scopes: Scope[];
    /** Admission evaluation hook injected by the service. */
    admit?: (scope: Scope) => void;
  }): { pair: Id; state: "APPROVED" } {
    const rec = this.ports.getPair(params.pair);
    if (rec === null) rpc("NOT_FOUND", "unknown pair", "pair");
    this.assertLive(rec);
    if (rec.state === "APPROVED" && rec.approved !== null) {
      if (
        params.proposal === rec.approved.proposal &&
        params.key === rec.approved.key &&
        scopesEqual(params.scopes, rec.approved.scopes)
      ) {
        return { pair: rec.pair, state: "APPROVED" };
      }
      rpc("REVISION_CONFLICT", "approval does not match the committed approval", "proposal");
    }
    if (rec.state !== "AWAITING_OPERATOR" || rec.proposal === null) {
      rpc("STATE_TRANSITION", "no pending proposal to approve", "pair");
    }
    if (params.proposal !== rec.proposal) {
      rpc("REVISION_CONFLICT", "proposal hash does not match the pending proposal", "proposal");
    }
    if (params.key !== rec.proposal_key) {
      rpc("REVISION_CONFLICT", "key does not match the pending proposal", "key");
    }
    // The operator may narrow the invited scopes, never widen them.
    for (const scope of params.scopes) {
      if (!scopeWithin(scope, rec.scopes)) {
        rpc("FORBIDDEN", "approved scopes may only narrow the invitation", "scopes");
      }
      params.admit?.(scope);
    }
    rec.approved = {
      proposal: params.proposal,
      key: params.key,
      scopes: params.scopes,
    };
    this.transition(rec, "APPROVED");
    return { pair: rec.pair, state: "APPROVED" };
  }

  /** agent.pair.cancel: cancel any unconsumed invitation. */
  cancel(params: { pair: Id }): { pair: Id; state: "CANCELLED" } {
    const rec = this.ports.getPair(params.pair);
    if (rec === null) rpc("NOT_FOUND", "unknown pair", "pair");
    this.assertLive(rec);
    this.transition(rec, "CANCELLED");
    return { pair: rec.pair, state: "CANCELLED" };
  }

  /**
   * Register-side validation and commit gate (spec §4.2 step 5): the full
   * propose validation plus the operator-approval binding — the submitted
   * key fingerprint must equal the approved key (TV-GW-20 → FORBIDDEN) and
   * the derived proposal must equal the approved proposal.
   */
  assertRegisterable(registration: unknown): {
    pair: PairRecord;
    reg: ValidatedRegistration;
    scopes: Scope[];
  } {
    const { pair: rec, reg } = this.validateRegistration(registration);
    if (rec.state !== "APPROVED" || rec.approved === null) {
      rpc("STATE_TRANSITION", "invitation has no committed operator approval", "pair");
    }
    if (reg.key.id !== rec.approved.key) {
      rpc("FORBIDDEN", "registration key fingerprint does not match the approval", "key");
    }
    if (proposalOfRegistration(reg) !== rec.approved.proposal) {
      rpc("REVISION_CONFLICT", "registration no longer matches the approved proposal", "proposal");
    }
    return { pair: rec, reg, scopes: rec.approved.scopes };
  }

  /**
   * Final commit (§4.2 step 5): consume the invitation and the challenge,
   * exactly once. Call after peer/token allocation succeeded.
   */
  consume(rec: PairRecord, reg: ValidatedRegistration): void {
    const ch = this.ports.getChallenge(reg.challenge);
    if (ch !== null && !ch.consumed) {
      ch.consumed = true;
      this.ports.updateChallenge(ch);
    }
    this.transition(rec, "CONSUMED");
  }
}

/** True when `inner` is covered by some same-permission scope in `outer`. */
export function scopeWithin(inner: Scope, outer: Scope[]): boolean {
  return outer.some(
    (o) =>
      o.permission === inner.permission &&
      inner.topics.every((t) => o.topics.includes(t)) &&
      inner.runs.every((r) => o.runs.includes(r)) &&
      inner.products.every((p) => o.products.includes(p)),
  );
}
