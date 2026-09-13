/**
 * §4.2/§4.3 pairing-ceremony signature domains and proof bodies.
 *
 * Every proof uses the fixture `signed()` construction (see ed25519.ts):
 * `Ed25519( UTF8(domain) || NUL || raw(H(J(body))) )` → base64url.
 *
 *  - `LATTICEAG-GATEWAY-PAIR/1`    — signed registration (agent.register /
 *    agent.pair.propose), bound to `{pair,key,profiles,interfaces,
 *    capabilities}` via `proposalHash`.
 *  - `LATTICEAG-GATEWAY-RENEW/1`   — agent.renew refresh proof.
 *  - `LATTICEAG-GATEWAY-REQUEST/1` — per-request key proof carried in the
 *    X-LatticeAG-Key-Proof header; TTL/expiry checks (proof ≤60 s,
 *    issued_ms skew, now>=expires_ms) are the caller's concern — this
 *    module only authenticates the signed body.
 */
import type { KeyObject } from "node:crypto";
import type { Count, Hash, Id } from "../protocol/refs.js";
import { canonicalJson } from "./canonical.js";
import { signB64u, verifyB64u } from "./ed25519.js";
import { CryptoError } from "./errors.js";
import { isHash64, sha256Hex } from "./hash.js";
import { PAIR_CODE_RE } from "./ids.js";

/** Signed-registration domain (spec §4.2). */
export const PAIR_DOMAIN = "LATTICEAG-GATEWAY-PAIR/1";
/** Refresh-grant proof domain (spec §4.3). */
export const RENEW_DOMAIN = "LATTICEAG-GATEWAY-RENEW/1";
/** Per-request key-proof domain (spec §4.3). */
export const REQUEST_DOMAIN = "LATTICEAG-GATEWAY-REQUEST/1";

export type RegisterBodyParams = {
  gateway: Id;
  workspace: Id;
  epoch: Count;
  pair: Id;
  challenge: string;
  client_nonce: string;
  server_nonce: string;
  /** Key-material id (H of the raw public key) being registered. */
  key: Hash;
  profiles: string[];
  interfaces: string;
  capabilities: unknown[];
};

/** Closed signed-registration body `{v:1,kind:"register",…}`. */
export type RegisterBody = RegisterBodyParams & {
  v: 1;
  kind: "register";
};

/** Build the exact signed registration body of spec §4.2. */
export function registerBody(params: RegisterBodyParams): RegisterBody {
  const body: RegisterBody = { v: 1, kind: "register", ...params };
  return body;
}

/** Sign a registration body under `LATTICEAG-GATEWAY-PAIR/1`. */
export function signRegister(
  body: RegisterBody,
  secretKey: KeyObject,
): string {
  return signB64u(PAIR_DOMAIN, body, secretKey);
}

/** Verify a registration signature under `LATTICEAG-GATEWAY-PAIR/1`. */
export function verifyRegister(
  body: unknown,
  signatureB64u: string,
  publicKey: KeyObject | string,
): boolean {
  return verifyB64u(PAIR_DOMAIN, body, signatureB64u, publicKey);
}

export type RenewBodyParams = {
  gateway: Id;
  workspace: Id;
  epoch: Count;
  peer: Id;
  /** H(refresh token) — never the token plaintext. */
  refresh_hash: Hash;
  challenge: string;
  server_nonce: string;
};

/** Closed agent.renew body `{v:1,kind:"renew",…}`. */
export type RenewBody = RenewBodyParams & { v: 1; kind: "renew" };

/** Build the signed renew body of spec §4.3. */
export function renewBody(params: RenewBodyParams): RenewBody {
  return { v: 1, kind: "renew", ...params };
}

/** Sign a renew body under `LATTICEAG-GATEWAY-RENEW/1`. */
export function signRenew(body: RenewBody, secretKey: KeyObject): string {
  return signB64u(RENEW_DOMAIN, body, secretKey);
}

/** Verify a renew signature under `LATTICEAG-GATEWAY-RENEW/1`. */
export function verifyRenew(
  body: unknown,
  signatureB64u: string,
  publicKey: KeyObject | string,
): boolean {
  return verifyB64u(RENEW_DOMAIN, body, signatureB64u, publicKey);
}

export type RequestProofBodyParams = {
  gateway: Id;
  workspace: Id;
  epoch: Count;
  /** H(access token) — never the token plaintext. */
  token_hash: Hash;
  /** The RPC envelope id this proof authenticates. */
  id: Id;
  method: string;
  /** H(J(params)) of the RPC params. */
  params_sha256: Hash;
  /** Fresh 32-byte nonce (base64url), persisted until token expiry. */
  nonce: string;
  issued_ms: number;
  expires_ms: number;
};

/** Closed per-request key-proof body `{v:1,kind:"request",…}`. */
export type RequestProofBody = RequestProofBodyParams & {
  v: 1;
  kind: "request";
};

/**
 * Build the per-request key-proof body of spec §4.3. Lexical checks on
 * `token_hash`/`params_sha256`/timestamps run here; freshness (TTL ≤60 s,
 * clock skew, `now >= expires_ms`) is enforced by the transport caller.
 */
export function requestProofBody(
  params: RequestProofBodyParams,
): RequestProofBody {
  if (!isHash64(params.token_hash)) {
    throw new CryptoError(
      "REQUEST_PROOF_INVALID",
      "token_hash must be 64 lowercase hex",
    );
  }
  if (!isHash64(params.params_sha256)) {
    throw new CryptoError(
      "REQUEST_PROOF_INVALID",
      "params_sha256 must be 64 lowercase hex",
    );
  }
  if (
    !Number.isSafeInteger(params.issued_ms) ||
    !Number.isSafeInteger(params.expires_ms)
  ) {
    throw new CryptoError(
      "REQUEST_PROOF_INVALID",
      "issued_ms/expires_ms must be safe integers",
    );
  }
  return { v: 1, kind: "request", ...params };
}

/** Sign a request-proof body under `LATTICEAG-GATEWAY-REQUEST/1`. */
export function signRequest(
  body: RequestProofBody,
  secretKey: KeyObject,
): string {
  return signB64u(REQUEST_DOMAIN, body, secretKey);
}

/**
 * Verify a request key proof under `LATTICEAG-GATEWAY-REQUEST/1`.
 * A wrong key or tampered body returns false → AUTH_REQUIRED.
 */
export function verifyRequest(
  body: unknown,
  signatureB64u: string,
  publicKey: KeyObject | string,
): boolean {
  return verifyB64u(REQUEST_DOMAIN, body, signatureB64u, publicKey);
}

export type ProposalParams = {
  /** Key-material id (H of the raw public key). */
  key: Hash;
  profiles: string[];
  interfaces: string;
  capabilities: unknown[];
};

/**
 * Operator-approved proposal hash: `H(J({key,profiles,interfaces,
 * capabilities}))` (spec §4.2 step 4). Any change to the proposal
 * invalidates the approval.
 */
export function proposalHash(params: ProposalParams): Hash {
  return sha256Hex(canonicalJson(params));
}

/** Shape check for a 10-char Crockford-base32 invitation code. */
export function inviteCodeValid(code: unknown): code is string {
  return typeof code === "string" && PAIR_CODE_RE.test(code);
}
