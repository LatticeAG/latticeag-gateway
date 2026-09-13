/**
 * §5.1 Sunlight release signatures — native `sunlight.statement/1`
 * statements as used for release/provenance signing.
 *
 * Constructions (fixture `sunlight()`):
 *  - statement hash: `"sha256:" + H("sunlight.statement/1\n" || J(body))`
 *  - signature:      Ed25519 over
 *    `"sunlight.statement.signature/1\n" || raw(hash sans "sha256:")`,
 *    emitted as lowercase `signature_hex` — native Sunlight hex stays hex
 *    (spec §2.1 P05); it is never re-encoded to base64url.
 *
 * Threshold verification (spec §5.1 + TV-GW-47): every supplied signature
 * must verify under an authorized root key AND at least `quorum` distinct
 * authorized keys must have signed. A single malformed or unauthorized
 * statement fails the whole set — extras are never silently discarded.
 */
import { Buffer } from "node:buffer";
import { sign, timingSafeEqual, verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type {
  Hash,
  NativeRef,
  SunlightArtifact,
  SunlightDetails,
  SunlightEvidenceRef,
  SunlightParent,
  SunlightStatement,
  SunlightStatementBody,
} from "../protocol/refs.js";
import { canonicalJson, isCanonicalDomainValue } from "./canonical.js";
import {
  keyIdOfPublic,
  requirePublicKeyArg,
} from "./ed25519.js";
import { CryptoError } from "./errors.js";
import { isHash64, sha256Hex } from "./hash.js";

/** Statement profile (also the `\n`-terminated hash domain). */
export const SUNLIGHT_STATEMENT_PROFILE = "sunlight.statement/1";
/** Byte prefix of the statement-hash preimage. */
export const SUNLIGHT_STATEMENT_HASH_PREFIX = "sunlight.statement/1\n";
/** Byte prefix of the statement-signature message. */
export const SUNLIGHT_STATEMENT_SIGN_PREFIX = "sunlight.statement.signature/1\n";
/** `"sha256:"` + 64 lowercase hex. */
export const SUNLIGHT_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
/** `signature_hex`: 128 lowercase hex chars = 64 Ed25519 bytes. */
export const SIGNATURE_HEX_RE = /^[0-9a-f]{128}$/;

const SUNLIGHT_STATEMENT_KEYS = new Set(["body", "hash", "signature_hex"]);

/**
 * Authorized signer roots for Sunlight verification.
 *  - Map: signer identifier (the statement's `body.signer` value, e.g. a
 *    `slk_…` label or a key id) → Ed25519 public key (KeyObject or
 *    canonical base64url raw key).
 *  - Set: canonical base64url raw public keys; `body.signer` must equal a
 *    member or that member's key id (H of raw public key).
 */
export type SunlightTrustRoot =
  | ReadonlyMap<string, KeyObject | string>
  | ReadonlySet<string>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function fail(message: string): never {
  throw new CryptoError("SUNLIGHT_STATEMENT_INVALID", message);
}

/** Validate the lexical shape of a `bytes/1` Sunlight artifact. */
export function isSunlightArtifact(value: unknown): value is SunlightArtifact {
  return (
    isPlainObject(value) &&
    value.profile === "bytes/1" &&
    typeof value.digest === "string" &&
    SUNLIGHT_DIGEST_RE.test(value.digest) &&
    typeof value.bytes === "number" &&
    Number.isSafeInteger(value.bytes) &&
    value.bytes >= 0
  );
}

/** `bytes/1` artifact of raw bytes: `{profile,digest:"sha256:"+H,bytes}`. */
export function sunlightArtifact(data: string | Uint8Array): SunlightArtifact {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return {
    profile: "bytes/1",
    digest: `sha256:${sha256Hex(bytes)}`,
    bytes: bytes.length,
  };
}

export type SunlightStatementParams = {
  id: string;
  ledger: string;
  signer: string;
  claimed_at_ms: number;
  capture: "creation_hook" | "posthoc";
  /** `bytes/1` artifact the statement attests (e.g. raw manifest bytes). */
  artifact: SunlightArtifact;
  subjectKind?: "dataset" | "run" | "model" | "action" | "evidence";
  parents?: SunlightParent[];
  details?: SunlightDetails;
  evidence?: SunlightEvidenceRef[];
};

/**
 * Build a `sunlight.statement/1` body. Release/provenance statements use
 * the defaults: `subject.kind` "evidence", empty `parents`/`evidence`, and
 * `details` `{type:"creation"}`.
 */
export function sunlightStatement(
  params: SunlightStatementParams,
): SunlightStatementBody {
  if (
    !Number.isSafeInteger(params.claimed_at_ms) ||
    params.claimed_at_ms < 0
  ) {
    fail("claimed_at_ms must be a nonnegative safe integer");
  }
  if (!isSunlightArtifact(params.artifact)) {
    fail("subject artifact must be a valid bytes/1 artifact");
  }
  const body: SunlightStatementBody = {
    v: SUNLIGHT_STATEMENT_PROFILE,
    id: params.id,
    ledger: params.ledger,
    signer: params.signer,
    claimed_at_ms: params.claimed_at_ms,
    capture: params.capture,
    subject: { kind: params.subjectKind ?? "evidence", artifact: params.artifact },
    parents: params.parents ?? [],
    details: params.details ?? { type: "creation" },
    evidence: params.evidence ?? [],
  };
  if (!isCanonicalDomainValue(body)) {
    fail("statement body must be inside the strict canonical JSON domain");
  }
  return body;
}

/**
 * Statement hash: `"sha256:" + H("sunlight.statement/1\n" || J(body))`.
 */
export function sunlightHash(body: SunlightStatementBody): string {
  const preimage = Buffer.concat([
    Buffer.from(SUNLIGHT_STATEMENT_HASH_PREFIX, "utf8"),
    Buffer.from(canonicalJson(body), "utf8"),
  ]);
  return `sha256:${sha256Hex(preimage)}`;
}

/** Signature message: sign prefix || raw 32 digest bytes. */
function sunlightSignMessage(digestWithPrefix: string): Buffer {
  return Buffer.concat([
    Buffer.from(SUNLIGHT_STATEMENT_SIGN_PREFIX, "utf8"),
    Buffer.from(digestWithPrefix.slice("sha256:".length), "hex"),
  ]);
}

/**
 * Sign a statement body → `{body, hash, signature_hex}`. The signature is
 * Ed25519 over `"sunlight.statement.signature/1\n" || raw(hash)` rendered
 * as lowercase hex (native Sunlight convention — stays hex per P05).
 */
export function sunlightSign(
  body: SunlightStatementBody,
  secretKey: KeyObject,
): SunlightStatement {
  if (!isPlainObject(body) || body.v !== SUNLIGHT_STATEMENT_PROFILE) {
    fail('body.v must be "sunlight.statement/1"');
  }
  if (!isCanonicalDomainValue(body)) {
    fail("statement body must be inside the strict canonical JSON domain");
  }
  const hash = sunlightHash(body);
  const signatureHex = sign(
    null,
    sunlightSignMessage(hash),
    secretKey,
  ).toString("hex");
  return { body, hash, signature_hex: signatureHex };
}

/** Convenience: build a body with {@link sunlightStatement} and sign it. */
export function issueSunlightStatement(
  params: SunlightStatementParams,
  secretKey: KeyObject,
): SunlightStatement {
  return sunlightSign(sunlightStatement(params), secretKey);
}

/** Resolve `body.signer` to a public key under `roots`; null if unauthorized. */
function resolveSignerKey(
  signer: string,
  roots: SunlightTrustRoot,
): KeyObject | null {
  try {
    if (roots instanceof Map || typeof (roots as ReadonlyMap<string, unknown>).get === "function") {
      const mapped = (roots as ReadonlyMap<string, KeyObject | string>).get(signer);
      if (mapped === undefined) {
        return null;
      }
      return requirePublicKeyArg(mapped);
    }
    for (const element of roots as ReadonlySet<string>) {
      if (element === signer) {
        return requirePublicKeyArg(element);
      }
      try {
        if (keyIdOfPublic(element) === signer) {
          return requirePublicKeyArg(element);
        }
      } catch {
        // Not a parseable public-key element; skip.
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Verify one statement: closed shape, canonical `"sha256:"` hash that
 * recomputes from the body, an authorized signer resolving under `roots`,
 * and a valid Ed25519 `signature_hex`. Returns the verified signer's key
 * id, or null on any failure (caller maps null → SIGNATURE_INVALID).
 */
export function verifySunlightStatementKeyId(
  statement: unknown,
  roots: SunlightTrustRoot,
): string | null {
  try {
    if (
      !isPlainObject(statement) ||
      Object.keys(statement).length !== SUNLIGHT_STATEMENT_KEYS.size ||
      !Object.keys(statement).every((k) => SUNLIGHT_STATEMENT_KEYS.has(k))
    ) {
      return null;
    }
    const { body, hash, signature_hex: signatureHex } = statement as {
      body: unknown;
      hash: unknown;
      signature_hex: unknown;
    };
    if (typeof hash !== "string" || !SUNLIGHT_DIGEST_RE.test(hash)) {
      return null;
    }
    if (typeof signatureHex !== "string" || !SIGNATURE_HEX_RE.test(signatureHex)) {
      return null;
    }
    if (
      !isPlainObject(body) ||
      body.v !== SUNLIGHT_STATEMENT_PROFILE ||
      !isCanonicalDomainValue(body)
    ) {
      return null;
    }
    const computed = sunlightHash(body as SunlightStatementBody);
    const expected = Buffer.from(hash.slice("sha256:".length), "hex");
    const actual = Buffer.from(computed.slice("sha256:".length), "hex");
    if (!timingSafeEqual(expected, actual)) {
      return null;
    }
    const signer = (body as SunlightStatementBody).signer;
    if (typeof signer !== "string") {
      return null;
    }
    const publicKey = resolveSignerKey(signer, roots);
    if (publicKey === null) {
      return null;
    }
    const ok = verify(
      null,
      sunlightSignMessage(hash),
      publicKey,
      Buffer.from(signatureHex, "hex"),
    );
    return ok ? keyIdOfPublic(publicKey) : null;
  } catch {
    return null;
  }
}

/**
 * Verify one statement against authorized roots. Convenience boolean form
 * of {@link verifySunlightStatementKeyId}.
 */
export function verifySunlightStatement(
  statement: unknown,
  roots: SunlightTrustRoot,
): boolean {
  return verifySunlightStatementKeyId(statement, roots) !== null;
}

/**
 * Release threshold: every supplied statement must verify under `rootSet`
 * (a single malformed/unauthorized signature fails the whole set — never
 * discard extras), and at least `quorum` *distinct authorized keys* must
 * have signed. Returns true iff both hold.
 */
export function verifyReleaseThreshold(
  statements: readonly unknown[],
  rootSet: SunlightTrustRoot,
  quorum = 2,
): boolean {
  const distinctSigners = new Set<string>();
  for (const statement of statements) {
    const keyId = verifySunlightStatementKeyId(statement, rootSet);
    if (keyId === null) {
      return false;
    }
    distinctSigners.add(keyId);
  }
  return distinctSigners.size >= quorum;
}

/**
 * INTERFACES §1.5 lossless NativeRef of a statement (fixture `native()`):
 * namespace=ledger, object_id=id, commitment=native hash, plus the raw
 * SHA-256 and byte length of the statement's own canonical encoding.
 */
export function nativeRefOf(statement: SunlightStatement): NativeRef {
  const raw = canonicalJson(statement);
  return {
    profile: SUNLIGHT_STATEMENT_PROFILE,
    namespace: statement.body.ledger,
    object_id: statement.body.id,
    commitment: statement.hash,
    raw_sha256: sha256Hex(raw) as Hash,
    bytes: String(Buffer.byteLength(raw, "utf8")),
  };
}
