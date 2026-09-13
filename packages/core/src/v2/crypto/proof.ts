/**
 * P02 native Proof event lane — seal/verify plus body construction rules.
 *
 * Domains (spec §2.2, fixture `sealProof`):
 *  - hash preimage: `UTF8("LAGI-PROOF-EVENT/v1") || NUL || J(body)`
 *  - signature msg: `UTF8("LAGI-PROOF-EVENT-SIGN/v1") || NUL || raw(hash)`
 *
 * Body fields are exactly `v,workspace,source,stream,seq,prev,lamport,key,
 * parents,data`; seq starts at decimal "1" with a 64-zero genesis prev;
 * counts are canonical decimal strings ≤ 2^63−1; parents sort by
 * source/stream/numeric-seq/hash; an event serializes to ≤ 64 KiB.
 */
import { Buffer } from "node:buffer";
import { sign, timingSafeEqual, verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { Count, EventRef, Hash, Id, Signature } from "../protocol/refs.js";
import { canonicalJson, isCanonicalDomainValue } from "./canonical.js";
import {
  isB64uCanonical,
  requirePublicKeyArg,
} from "./ed25519.js";
import { CryptoError } from "./errors.js";
import { HASH64_RE, isHash64, sha256Hex } from "./hash.js";
import { ID_RE } from "./ids.js";

/** Hash preimage domain for Proof events (before the NUL separator). */
export const PROOF_EVENT_HASH_DOMAIN = "LAGI-PROOF-EVENT/v1";
/** Signature domain for Proof events (before the NUL separator). */
export const PROOF_EVENT_SIGN_DOMAIN = "LAGI-PROOF-EVENT-SIGN/v1";
/** Genesis `prev`: 64 ASCII zeroes. */
export const GENESIS_PREV = "0".repeat(64);
/** Native limit: a serialized Proof event is at most 64 KiB. */
export const MAX_PROOF_EVENT_BYTES = 64 * 1024;
/** Native limit: at most 64 parents per event. */
export const MAX_PROOF_PARENTS = 64;
/** Canonical unsigned decimal string, bounded by 2^63−1. */
export const COUNT_RE = /^(0|[1-9][0-9]*)$/;

const MAX_COUNT = (1n << 63n) - 1n;
const PROOF_BODY_KEYS = new Set([
  "v",
  "workspace",
  "source",
  "stream",
  "seq",
  "prev",
  "lamport",
  "key",
  "parents",
  "data",
]);
const EVENT_REF_KEYS = new Set(["source", "stream", "seq", "hash"]);
const PROOF_EVENT_KEYS = new Set(["body", "hash", "signature"]);

export type ProofEventBody = {
  v: 1;
  workspace: Id;
  source: Id;
  stream: Id;
  seq: Count;
  prev: Hash;
  lamport: Count;
  key: Hash;
  parents: EventRef[];
  data: unknown;
};

export type ProofEvent = {
  body: ProofEventBody;
  hash: Hash;
  signature: Signature;
};

/** True when `value` is a canonical decimal string bounded by 2^63−1. */
export function isCount(value: unknown): value is Count {
  return (
    typeof value === "string" &&
    COUNT_RE.test(value) &&
    BigInt(value) <= MAX_COUNT
  );
}

function fail(message: string): never {
  throw new CryptoError("PROOF_BODY_INVALID", message);
}

function hasExactly(obj: Record<string, unknown>, keys: Set<string>): boolean {
  const own = Object.keys(obj);
  return own.length === keys.size && own.every((k) => keys.has(k));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isEventRef(value: unknown): value is EventRef {
  return (
    isPlainObject(value) &&
    hasExactly(value, EVENT_REF_KEYS) &&
    typeof value.source === "string" &&
    ID_RE.test(value.source) &&
    typeof value.stream === "string" &&
    ID_RE.test(value.stream) &&
    isCount(value.seq) &&
    value.seq !== "0" &&
    isHash64(value.hash)
  );
}

/** Parent ordering: source, then stream, then numeric seq, then hash. */
export function compareEventRefs(a: EventRef, b: EventRef): number {
  if (a.source !== b.source) {
    return a.source < b.source ? -1 : 1;
  }
  if (a.stream !== b.stream) {
    return a.stream < b.stream ? -1 : 1;
  }
  const sa = BigInt(a.seq);
  const sb = BigInt(b.seq);
  if (sa !== sb) {
    return sa < sb ? -1 : 1;
  }
  if (a.hash !== b.hash) {
    return a.hash < b.hash ? -1 : 1;
  }
  return 0;
}

/** Return a new array sorted by the native Proof parent ordering. */
export function sortParents(parents: readonly EventRef[]): EventRef[] {
  return [...parents].sort(compareEventRefs);
}

/**
 * Validate a Proof event body. Throws CryptoError `PROOF_BODY_INVALID`
 * naming the violated field; returns the (typed) body on success.
 */
export function assertProofBody(body: unknown): asserts body is ProofEventBody {
  if (!isPlainObject(body) || !hasExactly(body, PROOF_BODY_KEYS)) {
    fail("body must be a closed object with exactly the 10 Proof fields");
  }
  if (body.v !== 1) {
    fail("body.v must be 1");
  }
  for (const field of ["workspace", "source", "stream"] as const) {
    const value = body[field];
    if (typeof value !== "string" || !ID_RE.test(value)) {
      fail(`body.${field} must match the Proof Id grammar`);
    }
  }
  if (!isCount(body.seq) || body.seq === "0") {
    fail("body.seq must be a canonical decimal string >= 1");
  }
  if (!isHash64(body.prev)) {
    fail("body.prev must be 64 lowercase hex");
  }
  // seq "1" is genesis iff prev is 64 zeroes — the biconditional holds
  // because every later seq in a lane must reference its predecessor hash.
  if (body.seq === "1" && body.prev !== GENESIS_PREV) {
    fail("genesis body (seq 1) must have prev of 64 zeroes");
  }
  if (body.seq !== "1" && body.prev === GENESIS_PREV) {
    fail("non-genesis body must not use the zero genesis prev");
  }
  if (!isCount(body.lamport) || body.lamport === "0") {
    fail("body.lamport must be a canonical decimal string >= 1");
  }
  if (!isHash64(body.key)) {
    fail("body.key must be a 64-hex key id");
  }
  if (!Array.isArray(body.parents) || body.parents.length > MAX_PROOF_PARENTS) {
    fail(`body.parents must be an array of at most ${MAX_PROOF_PARENTS} refs`);
  }
  const parents = body.parents as unknown[];
  for (const ref of parents) {
    if (!isEventRef(ref)) {
      fail("each parent must be a closed {source,stream,seq,hash} EventRef");
    }
    if (
      ref.source === body.source &&
      ref.stream === body.stream &&
      BigInt(ref.seq) >= BigInt(body.seq as string)
    ) {
      fail("a parent cannot be the event itself or a later slot in its lane");
    }
  }
  for (let i = 1; i < parents.length; i += 1) {
    const prev = parents[i - 1] as EventRef;
    const next = parents[i] as EventRef;
    if (compareEventRefs(prev, next) >= 0) {
      fail("body.parents must be strictly sorted by source/stream/seq/hash");
    }
  }
  if (!isCanonicalDomainValue(body)) {
    fail("body must be inside the strict canonical JSON domain");
  }
}

export type ProofBodyParts = {
  workspace: Id;
  source: Id;
  stream: Id;
  seq: Count;
  /** Optional only for genesis (`seq === "1"` → 64 zeroes). */
  prev?: Hash;
  lamport: Count;
  key: Hash;
  parents?: readonly EventRef[];
  data: unknown;
};

/**
 * Build and validate a Proof event body. Parents are copied into canonical
 * sort order. `prev` defaults to the 64-zero genesis hash when seq is "1".
 */
export function proofBody(parts: ProofBodyParts): ProofEventBody {
  const prev =
    parts.prev ?? (parts.seq === "1" ? GENESIS_PREV : undefined);
  if (prev === undefined) {
    fail("body.prev is required for non-genesis events");
  }
  const body: ProofEventBody = {
    v: 1,
    workspace: parts.workspace,
    source: parts.source,
    stream: parts.stream,
    seq: parts.seq,
    prev,
    lamport: parts.lamport,
    key: parts.key,
    parents: sortParents(parts.parents ?? []),
    data: parts.data,
  };
  assertProofBody(body);
  return body;
}

/**
 * Proof event hash: `H(UTF8(domain) || NUL || J(body))` — the preimage
 * carries the canonical JSON text of the body, not a nested digest.
 */
export function proofEventHash(body: unknown): Hash {
  const preimage = Buffer.concat([
    Buffer.from(`${PROOF_EVENT_HASH_DOMAIN}\0`, "utf8"),
    Buffer.from(canonicalJson(body), "utf8"),
  ]);
  return sha256Hex(preimage);
}

/** `UTF8(sign-domain) || NUL || raw(hash)` signature message. */
function signMessage(hashHex: Hash): Buffer {
  return Buffer.concat([
    Buffer.from(`${PROOF_EVENT_SIGN_DOMAIN}\0`, "utf8"),
    Buffer.from(hashHex, "hex"),
  ]);
}

/**
 * Seal a Proof body into `{body,hash,signature}` exactly as the fixture
 * `sealProof()` does. Validates the body and the 64 KiB serialized cap.
 */
export function sealProofEvent(
  body: ProofEventBody,
  secretKey: KeyObject,
): ProofEvent {
  assertProofBody(body);
  const hash = proofEventHash(body);
  const signature = sign(null, signMessage(hash), secretKey).toString(
    "base64url",
  );
  const event: ProofEvent = { body, hash, signature };
  if (Buffer.byteLength(canonicalJson(event), "utf8") > MAX_PROOF_EVENT_BYTES) {
    throw new CryptoError(
      "EVENT_LIMIT",
      `serialized Proof event exceeds ${MAX_PROOF_EVENT_BYTES} bytes`,
    );
  }
  return event;
}

/** The Proof EventRef of a sealed event: `{source,stream,seq,hash}`. */
export function eventRefOf(event: ProofEvent): EventRef {
  return {
    source: event.body.source,
    stream: event.body.stream,
    seq: event.body.seq,
    hash: event.hash,
  };
}

/**
 * Verify a sealed Proof event: closed shape, valid body, recomputed hash
 * equal to `event.hash` (constant-time), and a P05 signature under
 * `publicKey` (KeyObject or base64url raw key). False maps to
 * SIGNATURE_INVALID at the RPC layer.
 */
export function verifyProofEvent(
  event: unknown,
  publicKey: KeyObject | string,
): boolean {
  try {
    if (!isPlainObject(event) || !hasExactly(event, PROOF_EVENT_KEYS)) {
      return false;
    }
    if (!isHash64(event.hash)) {
      return false;
    }
    if (typeof event.signature !== "string" || !isB64uCanonical(event.signature)) {
      return false;
    }
    const signature = Buffer.from(event.signature, "base64url");
    if (signature.length !== 64) {
      return false;
    }
    assertProofBody(event.body);
    const computed = proofEventHash(event.body);
    const expected = Buffer.from(event.hash as string, "hex");
    const actual = Buffer.from(computed, "hex");
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return false;
    }
    if (
      Buffer.byteLength(canonicalJson(event), "utf8") > MAX_PROOF_EVENT_BYTES
    ) {
      return false;
    }
    return verify(
      null,
      signMessage(computed),
      requirePublicKeyArg(publicKey),
      signature,
    );
  } catch {
    return false;
  }
}
