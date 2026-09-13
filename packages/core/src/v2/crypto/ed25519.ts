/**
 * P05 Proof Ed25519 codec — ordinary Ed25519 with canonical unpadded
 * base64url on the wire.
 *
 * Implements the §13.1 fixture `signed()` construction exactly:
 *
 *   signed(domain, body, k) =
 *     Ed25519_sign( UTF8(domain) || NUL || RAW(H(J(body))) )
 *
 * where `Buffer.from(H(J(body)), "hex")` in the fixture takes the hex
 * *encoding* of the digest and decodes it back to the raw 32 hash bytes —
 * i.e. the signed payload is `domain || NUL || raw(hash)`, matching the
 * spec prose `UTF8(domain) || NUL || raw(H(J(body)))` (§4.2/§4.3). The
 * same raw-hash convention is used by the Proof event sign domain and
 * (in hex form) by the Sunlight signature domain.
 *
 * Keys may be carried as node:crypto KeyObjects or as canonical base64url
 * raw 32-byte public keys. All base64url inputs are strictly validated:
 * unpadded, canonical re-encode round-trip, exact decoded length.
 */
import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import type { KeyObject } from "node:crypto";
import { canonicalJson } from "./canonical.js";
import { CryptoError } from "./errors.js";
import { sha256Hex } from "./hash.js";

/** PKCS#8 DER prefix for an Ed25519 private key carrying a 32-byte seed. */
const PKCS8_ED25519_SEED_PREFIX = "302e020100300506032b657004220420";
/** SPKI DER prefix for an Ed25519 public key carrying the raw 32 bytes. */
const SPKI_ED25519_RAW_PREFIX = "302a300506032b6570032100";

const B64U_RE = /^[A-Za-z0-9_-]+$/;

/**
 * True when `value` is canonical unpadded base64url: only the base64url
 * alphabet, no `=` padding, and a lossless decode/re-encode round-trip
 * (which also rejects non-canonical trailing bits).
 */
export function isB64uCanonical(value: unknown): value is string {
  return (
    typeof value === "string" &&
    B64U_RE.test(value) &&
    Buffer.from(value, "base64url").toString("base64url") === value
  );
}

/** Strictly decode canonical base64url into bytes. */
function decodeB64u(value: string, what: string): Buffer {
  if (!isB64uCanonical(value)) {
    throw new CryptoError(
      "ENCODING_INVALID",
      `${what} must be canonical unpadded base64url`,
    );
  }
  return Buffer.from(value, "base64url");
}

function requireEd25519(key: KeyObject, what: string): KeyObject {
  if (
    key === null ||
    typeof key !== "object" ||
    (key as KeyObject).asymmetricKeyType !== "ed25519"
  ) {
    throw new CryptoError("KEY_INVALID", `${what} must be an Ed25519 key`);
  }
  return key;
}

function requireEd25519Private(key: KeyObject): KeyObject {
  requireEd25519(key, "secret key");
  if (key.type !== "private") {
    throw new CryptoError("KEY_INVALID", "secret key must be a private key");
  }
  return key;
}

/**
 * Normalize a KeyObject-or-base64url argument into a public Ed25519
 * KeyObject (private keys are derived to their public half).
 * @throws {CryptoError} `KEY_INVALID` for anything else.
 */
export function requirePublicKeyArg(key: KeyObject | string): KeyObject {
  const obj =
    typeof key === "string" ? publicKeyFromB64u(key) : key;
  requireEd25519(obj, "public key");
  if (obj.type === "private") {
    return createPublicKey(obj);
  }
  if (obj.type !== "public") {
    throw new CryptoError("KEY_INVALID", "key must be a public or private key");
  }
  return obj;
}

/**
 * Build an Ed25519 private KeyObject from a 32-byte seed given as 64 hex
 * chars, using the same PKCS#8 DER wrap as the fixture `makeKey()`.
 */
export function keyFromSeed32(seedHex: string): KeyObject {
  if (typeof seedHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(seedHex)) {
    throw new CryptoError(
      "KEY_INVALID",
      "seed must be exactly 64 hex characters (32 bytes)",
    );
  }
  const der = Buffer.from(
    PKCS8_ED25519_SEED_PREFIX + seedHex.toLowerCase(),
    "hex",
  );
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Derive the public KeyObject of an Ed25519 private KeyObject. */
export function publicKeyOf(secretKey: KeyObject): KeyObject {
  requireEd25519Private(secretKey);
  return createPublicKey(secretKey);
}

/** Raw 32-byte Ed25519 public key material (SPKI low-order bytes). */
export function rawPublicKeyBytes(key: KeyObject): Uint8Array {
  const pub = requirePublicKeyArg(key);
  return pub.export({ format: "der", type: "spki" }).subarray(-32);
}

/** Canonical base64url of the raw 32-byte public key (43 chars). */
export function publicKeyB64u(key: KeyObject): string {
  return Buffer.from(rawPublicKeyBytes(key)).toString("base64url");
}

/** Rebuild a public KeyObject from a canonical base64url raw 32-byte key. */
export function publicKeyFromB64u(publicKey: string): KeyObject {
  const raw = decodeB64u(publicKey, "public key");
  if (raw.length !== 32) {
    throw new CryptoError(
      "KEY_INVALID",
      "public key must decode to exactly 32 bytes",
    );
  }
  const der = Buffer.concat([
    Buffer.from(SPKI_ED25519_RAW_PREFIX, "hex"),
    raw,
  ]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/**
 * Key id: SHA-256 hex of the raw 32-byte public key (fixture
 * `material.id = H(raw)`). Accepts a KeyObject or a base64url raw key.
 */
export function keyIdOfPublic(key: KeyObject | string): string {
  const raw =
    typeof key === "string" ? decodeB64u(key, "public key") : rawPublicKeyBytes(key);
  if (raw.length !== 32) {
    throw new CryptoError(
      "KEY_INVALID",
      "public key must decode to exactly 32 bytes",
    );
  }
  return sha256Hex(raw);
}

/**
 * Domain-separated Ed25519 signature over a canonical JSON body, per the
 * fixture `signed()`: `sign(UTF8(domain) || NUL || RAW(H(J(body))))`,
 * emitted as canonical base64url (64 bytes → 86 chars).
 *
 * @throws {CryptoError} `CANONICAL_DOMAIN` when `body` is outside the
 *   strict canonical domain; `KEY_INVALID` for a non-Ed25519 private key.
 */
export function signB64u(
  domain: string,
  body: unknown,
  secretKey: KeyObject,
): string {
  requireEd25519Private(secretKey);
  const digestHex = sha256Hex(canonicalJson(body));
  const message = Buffer.concat([
    Buffer.from(`${domain}\0`, "utf8"),
    Buffer.from(digestHex, "hex"), // hex encoding → raw 32 digest bytes
  ]);
  return sign(null, message, secretKey).toString("base64url");
}

/**
 * Verify a `signB64u` signature. Returns false for a malformed signature,
 * malformed/mismatched public key, out-of-domain body, or any verification
 * failure — callers map false to `SIGNATURE_INVALID`.
 */
export function verifyB64u(
  domain: string,
  body: unknown,
  signatureB64u: string,
  publicKey: KeyObject | string,
): boolean {
  try {
    if (!isB64uCanonical(signatureB64u)) {
      return false;
    }
    const signature = Buffer.from(signatureB64u, "base64url");
    if (signature.length !== 64) {
      return false;
    }
    const pub = requirePublicKeyArg(publicKey);
    const digestHex = sha256Hex(canonicalJson(body));
    const message = Buffer.concat([
      Buffer.from(`${domain}\0`, "utf8"),
      Buffer.from(digestHex, "hex"),
    ]);
    return verify(null, message, pub, signature);
  } catch {
    return false;
  }
}
