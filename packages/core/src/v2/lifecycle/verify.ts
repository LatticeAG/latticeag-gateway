/**
 * §5.1 release verification — zero code execution. The fetcher/verifier
 * reads bytes only; no `npx`, no npm lifecycle hooks, no package-provided
 * verifier, no imported JavaScript is ever run while checking a release.
 *
 * verifyRelease enforces, in order:
 *  1. wire-shape + Blob integrity (ref.digest/bytes == decoded content),
 *  2. trust-expiry for unpinned installs (TRUST_EXPIRED, TV-GW-45),
 *  3. manifest schema (SCHEMA_INVALID / UNSUPPORTED_COMPOSITION),
 *  4. every release signature verifies under authorized release roots
 *     with ≥2 distinct signers; a malformed extra fails the whole set
 *     (SIGNATURE_INVALID, TV-GW-05/TV-GW-47),
 *  5. archive digest declared by the manifest == supplied archive bytes
 *     (ARTIFACT_MISMATCH),
 *  6. provenance descriptor digest match, descriptor/manifest field
 *     equality, provenance signatures under trusted signers, and the
 *     builder allowlist (PROVENANCE_INVALID, TV-GW-06),
 *  7. revocation list (POLICY_DENIED, TV-GW-14),
 *  8. platform os/arch/node compatibility (UNSUPPORTED_COMPOSITION).
 */
import { Buffer } from "node:buffer";

import { RpcError } from "../protocol/errors.js";
import type { Hash, ObjectRef } from "../protocol/refs.js";
import type { ProductManifest, Release } from "../protocol/product.js";
import { PRODUCT_LIMITS } from "../protocol/product.js";
import { canonicalJson } from "../crypto/canonical.js";
import { isB64uCanonical, keyIdOfPublic } from "../crypto/ed25519.js";
import { isHash64, sha256Hex } from "../crypto/hash.js";
import {
  SUNLIGHT_DIGEST_RE,
  isSunlightArtifact,
  nativeRefOf,
  verifySunlightStatementKeyId,
} from "../crypto/sunlight.js";
import type { SunlightStatement } from "../protocol/refs.js";
import { parseProductManifest } from "./manifest.js";
import { satisfiesNode } from "./semver.js";

/**
 * Trusted roots for release verification.
 *  - `releaseKeys`: authorized release root keys — canonical base64url raw
 *    Ed25519 public keys, or bare 64-hex key ids (H of raw public key).
 *    Key-id-only entries authorize by identity; verification still needs
 *    the key material (supply b64u or a `signers` binding).
 *  - `signers`: signer-label → b64u public key / key id binding (the
 *    `slk_…` statement signer names). A statement's claimed signer must
 *    resolve to an authorized key.
 *  - `builders`: approved builder identities matched against the
 *    provenance descriptor/manifest builder.
 *  - `builderKeys`/`builderSigners`: independently trusted provenance
 *    statement signers; default to the release keys when omitted.
 *  - `revocations`: digests ("sha256:…" or bare 64-hex) revoked by an
 *    independently signed revocation set.
 *  - `keyMaterials`: ordered pinned key material for plan trust hashing.
 *  - `provenanceQuorum`: distinct provenance signers required (default 1;
 *    release signatures always require 2).
 */
export interface ReleaseTrust {
  readonly releaseKeys: ReadonlySet<string>;
  readonly signers?: ReadonlyMap<string, string>;
  readonly builders: ReadonlySet<string>;
  readonly builderKeys?: ReadonlySet<string>;
  readonly builderSigners?: ReadonlyMap<string, string>;
  readonly revocations: ReadonlySet<string>;
  readonly keyMaterials?: readonly unknown[];
  readonly provenanceQuorum?: number;
}

export interface VerifyContext {
  /** Platform checks; default to the running process. */
  readonly os?: string;
  readonly arch?: string;
  readonly node?: string;
  /** Archive bytes fetched for this release — digest-checked. */
  readonly archive?: Uint8Array;
  /** Clock + index expiry for TRUST_EXPIRED (TV-GW-45). */
  readonly now?: number;
  readonly indexExpiresMs?: number;
  /** Pinned installs survive index expiry (§9.4 offline pinned). */
  readonly pinned?: boolean;
}

export interface VerifiedRelease {
  readonly manifest: ProductManifest;
  /** Raw manifest blob bytes. */
  readonly manifestBytes: Uint8Array;
  /** sha256 hex of the manifest bytes (plan `manifest` field). */
  readonly manifestDigest: Hash;
  /** Parsed provenance descriptor (gateway.build/1). */
  readonly provenance: ProvenanceDescriptor;
  /** Raw provenance blob bytes. */
  readonly provenanceBytes: Uint8Array;
  /** "sha256:…" archive digest from the manifest. */
  readonly archiveDigest: string;
  /** Distinct release signer key ids. */
  readonly releaseSigners: string[];
}

export interface ProvenanceDescriptor {
  readonly schema: "gateway.build/1";
  readonly builder: string;
  readonly repository: string;
  readonly commit: string;
  readonly command: string;
  readonly materials: readonly unknown[];
  readonly sbom: ObjectRef;
  readonly outputs: readonly { profile: string; digest: string; bytes: number }[];
}

function fail(code: "SIGNATURE_INVALID" | "PROVENANCE_INVALID" | "ARTIFACT_MISMATCH", message: string, field?: string): never {
  throw new RpcError(code, message, { field: field ?? null });
}

function isPlain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Decode a {ref:{digest,bytes,media},content:b64u} blob to raw bytes. */
function decodeBlob(blob: unknown, field: string, maxBytes: number): Uint8Array {
  if (!isPlain(blob) || !isPlain(blob.ref)) {
    throw new RpcError("SCHEMA_INVALID", `${field} must be a Blob`, { field });
  }
  const { digest, bytes, media } = blob.ref as Record<string, unknown>;
  if (!isHash64(digest)) {
    throw new RpcError("SCHEMA_INVALID", `${field}.ref.digest must be 64 hex`, { field });
  }
  if (typeof bytes !== "string" || !/^(0|[1-9][0-9]*)$/.test(bytes)) {
    throw new RpcError("SCHEMA_INVALID", `${field}.ref.bytes must be a decimal string`, { field });
  }
  if (typeof media !== "string" || media.length === 0 || media.length > 128) {
    throw new RpcError("SCHEMA_INVALID", `${field}.ref.media invalid`, { field });
  }
  if (typeof blob.content !== "string" || !isB64uCanonical(blob.content)) {
    throw new RpcError("SCHEMA_INVALID", `${field}.content must be canonical base64url`, { field });
  }
  const raw = Buffer.from(blob.content, "base64url");
  if (raw.length > maxBytes) {
    throw new RpcError("OBJECT_LIMIT", `${field} exceeds ${maxBytes} bytes`, { field });
  }
  if (raw.length !== Number(bytes) || sha256Hex(raw) !== digest) {
    fail("ARTIFACT_MISMATCH", `${field} ref does not match content bytes`, field);
  }
  return raw;
}

/**
 * Build the Sunlight root map + authorized key-id set from a key set and
 * optional signer-label binding. Elements of `keys` are b64u raw public
 * keys or bare key ids; `signers` binds `slk_…` labels to those keys.
 */
function buildRootSet(
  keys: ReadonlySet<string>,
  signers: ReadonlyMap<string, string> | undefined,
  what: string,
): { roots: Map<string, string>; authorized: Set<string> } {
  const roots = new Map<string, string>();
  const authorized = new Set<string>();
  for (const element of keys) {
    if (isHash64(element)) {
      authorized.add(element);
      continue;
    }
    let keyId: string;
    try {
      keyId = keyIdOfPublic(element);
    } catch {
      throw new RpcError("SCHEMA_INVALID", `${what} root is not a key id or b64u public key`);
    }
    authorized.add(keyId);
    roots.set(element, element); // signer may literally name the key
    roots.set(keyId, element); // or its key id
  }
  if (signers) {
    for (const [label, bound] of signers) {
      let keyId: string | null = null;
      if (isHash64(bound)) keyId = bound;
      else {
        try {
          keyId = keyIdOfPublic(bound);
        } catch {
          keyId = null;
        }
      }
      if (keyId === null || !authorized.has(keyId)) {
        throw new RpcError(
          "SCHEMA_INVALID",
          `${what} signer "${label}" binds an unauthorized key`,
        );
      }
      roots.set(label, bound);
    }
  }
  return { roots, authorized };
}

/**
 * Verify one statement's binding to an expected subject artifact: the
 * subject must be exactly the raw bytes/1 artifact, subject.kind
 * "evidence", empty parents, creation details — the unchanged native
 * release-statement shape (§5.1).
 */
function statementBindsArtifact(
  statement: SunlightStatement,
  artifact: { digest: string; bytes: number },
): boolean {
  const body = statement.body;
  if (body.v !== "sunlight.statement/1") return false;
  if (body.subject?.kind !== "evidence") return false;
  if (!isSunlightArtifact(body.subject?.artifact)) return false;
  if (body.subject.artifact.profile !== "bytes/1") return false;
  if (body.subject.artifact.digest !== artifact.digest) return false;
  if (body.subject.artifact.bytes !== artifact.bytes) return false;
  if (!Array.isArray(body.parents) || body.parents.length !== 0) return false;
  if (!isPlain(body.details) || body.details.type !== "creation") return false;
  return true;
}

const MAX_SIGNATURES = 64;

function verifyStatementSet(
  statements: readonly unknown[],
  roots: Map<string, string>,
  authorized: ReadonlySet<string>,
  artifact: { digest: string; bytes: number },
  quorum: number,
  code: "SIGNATURE_INVALID" | "PROVENANCE_INVALID",
  field: string,
): string[] {
  if (!Array.isArray(statements) || statements.length === 0 || statements.length > MAX_SIGNATURES) {
    fail(code, `${field} must carry 1–${MAX_SIGNATURES} statements`, field);
  }
  const distinct = new Set<string>();
  for (const [i, statement] of statements.entries()) {
    const keyId = verifySunlightStatementKeyId(statement, roots);
    if (keyId === null || !authorized.has(keyId)) {
      fail(code, `${field}[${i}] does not verify under an authorized signer`, field);
    }
    // Every signature is an unchanged native Statement whose subject is
    // exactly the signed bytes — no rebinding, no parent baggage.
    if (!statementBindsArtifact(statement as SunlightStatement, artifact)) {
      fail(code, `${field}[${i}] subject does not bind the signed artifact`, field);
    }
    distinct.add(keyId!);
  }
  if (distinct.size < quorum) {
    fail(code, `${field} requires ${quorum} distinct authorized signers`, field);
  }
  return [...distinct];
}

function refEqual(a: ObjectRef, b: unknown): boolean {
  return (
    isPlain(b) &&
    a.digest === (b as { digest?: unknown }).digest &&
    a.bytes === (b as { bytes?: unknown }).bytes &&
    a.media === (b as { media?: unknown }).media
  );
}

function parseProvenanceDescriptor(
  raw: Uint8Array,
  manifest: ProductManifest,
): ProvenanceDescriptor {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(raw).toString("utf8"));
  } catch {
    fail("PROVENANCE_INVALID", "provenance descriptor is not valid JSON", "provenance");
  }
  if (!isPlain(value) || value.schema !== "gateway.build/1") {
    fail("PROVENANCE_INVALID", 'provenance schema must be "gateway.build/1"', "provenance.schema");
  }
  const d = value as Record<string, unknown>;
  if (
    typeof d.builder !== "string" ||
    typeof d.repository !== "string" ||
    typeof d.commit !== "string" ||
    typeof d.command !== "string" ||
    !Array.isArray(d.materials) ||
    !Array.isArray(d.outputs)
  ) {
    fail("PROVENANCE_INVALID", "provenance descriptor fields malformed", "provenance");
  }
  // Manifest/provenance field equality: builder identity, exact
  // repository/commit, SBOM ref, and lockfile material.
  if (
    d.builder !== manifest.provenance.builder ||
    d.repository !== manifest.provenance.repository ||
    d.commit !== manifest.provenance.commit
  ) {
    fail("PROVENANCE_INVALID", "descriptor does not match manifest provenance fields", "provenance");
  }
  if (!refEqual(manifest.provenance.sbom, d.sbom)) {
    fail("PROVENANCE_INVALID", "descriptor sbom ref does not match manifest", "provenance.sbom");
  }
  const lock = manifest.provenance.lockfile;
  const materials = d.materials as unknown[];
  const lockListed = materials.some(
    (m) => isPlain(m) && (m as { digest?: unknown }).digest === lock.digest,
  );
  if (!lockListed) {
    fail("PROVENANCE_INVALID", "descriptor materials lack the manifest lockfile", "provenance.materials");
  }
  const outputs = (d.outputs as unknown[]).map((o) => {
    if (!isSunlightArtifact(o)) {
      fail("PROVENANCE_INVALID", "descriptor output is not a bytes/1 artifact", "provenance.outputs");
    }
    return o;
  });
  return {
    schema: "gateway.build/1",
    builder: d.builder,
    repository: d.repository,
    commit: d.commit,
    command: d.command,
    materials,
    sbom: d.sbom as ObjectRef,
    outputs,
  };
}

/**
 * Verify a wire Release against the pinned trust roots. Returns the typed
 * manifest + descriptor on success; throws a coded RpcError otherwise.
 * Never executes any bytes from the release.
 */
export function verifyRelease(
  wire: Release,
  trust: ReleaseTrust,
  ctx: VerifyContext = {},
): VerifiedRelease {
  if (!isPlain(wire)) {
    throw new RpcError("SCHEMA_INVALID", "release must be an object");
  }
  // (2) trust expiry before any cryptographic work — expired catalog
  // metadata cannot authorize new unpinned installs (TV-GW-45); installed
  // pinned releases are unaffected because they verify without an index.
  if (
    ctx.indexExpiresMs !== undefined &&
    ctx.pinned !== true &&
    ctx.now !== undefined &&
    ctx.now >= ctx.indexExpiresMs
  ) {
    throw new RpcError("TRUST_EXPIRED", "catalog index validity window has ended", {
      field: "index",
    });
  }

  const manifestBytes = decodeBlob(wire.manifest, "manifest", PRODUCT_LIMITS.manifestBytes);
  const metadataBytes =
    manifestBytes.length +
    JSON.stringify(wire.signatures ?? null).length +
    JSON.stringify(wire.provenance ?? null).length +
    JSON.stringify(wire.provenance_signatures ?? null).length;
  if (metadataBytes > PRODUCT_LIMITS.releaseMetadataBytes + PRODUCT_LIMITS.manifestBytes) {
    throw new RpcError("OBJECT_LIMIT", "release metadata exceeds 1 MiB", { field: "signatures" });
  }

  const manifest = parseProductManifest(manifestBytes);
  const manifestDigest = sha256Hex(manifestBytes) as Hash;
  const manifestArtifact = {
    digest: `sha256:${manifestDigest}`,
    bytes: manifestBytes.length,
  };

  // (4) release signatures: all verify under authorized roots, subject is
  // exactly the manifest bytes, ≥2 distinct signers; a malformed extra
  // fails the set — extras are never discarded to meet threshold.
  const { roots, authorized } = buildRootSet(trust.releaseKeys, trust.signers, "release");
  const releaseSigners = verifyStatementSet(
    wire.signatures,
    roots,
    authorized,
    manifestArtifact,
    PRODUCT_LIMITS.releaseSignatureThreshold,
    "SIGNATURE_INVALID",
    "signatures",
  );

  // (5) archive digest == manifest.package.archive.digest.
  const archiveDigest = manifest.package.archive.digest;
  if (ctx.archive !== undefined) {
    const actual = `sha256:${sha256Hex(ctx.archive)}`;
    if (actual !== archiveDigest) {
      fail("ARTIFACT_MISMATCH", "archive bytes do not match manifest.package.archive.digest", "archive");
    }
    if (ctx.archive.length !== manifest.package.archive.bytes) {
      fail("ARTIFACT_MISMATCH", "archive length does not match manifest", "archive");
    }
    if (ctx.archive.length > PRODUCT_LIMITS.archiveCompressedBytes) {
      throw new RpcError("OBJECT_LIMIT", "archive exceeds 256 MiB compressed", { field: "archive" });
    }
  }

  // (6) provenance: descriptor digest match, field equality, signatures
  // under independently trusted signers, builder allowlist.
  const provenanceBytes = decodeBlob(
    wire.provenance,
    "provenance",
    PRODUCT_LIMITS.releaseMetadataBytes,
  );
  if (manifest.provenance.descriptor.digest !== sha256Hex(provenanceBytes)) {
    fail("PROVENANCE_INVALID", "manifest provenance.descriptor does not match descriptor bytes", "provenance");
  }
  const descriptor = parseProvenanceDescriptor(provenanceBytes, manifest);
  if (!trust.builders.has(descriptor.builder)) {
    fail("PROVENANCE_INVALID", `builder "${descriptor.builder}" is not in the trusted builder set`, "provenance.builder");
  }
  const archiveListed = descriptor.outputs.some((o) => o.digest === archiveDigest);
  if (!archiveListed) {
    fail("PROVENANCE_INVALID", "descriptor outputs do not include the manifest archive", "provenance.outputs");
  }
  const builderKeys = trust.builderKeys ?? trust.releaseKeys;
  const builderRoots = buildRootSet(builderKeys, trust.builderSigners ?? trust.signers, "provenance");
  verifyStatementSet(
    wire.provenance_signatures,
    builderRoots.roots,
    builderRoots.authorized,
    { digest: `sha256:${sha256Hex(provenanceBytes)}`, bytes: provenanceBytes.length },
    trust.provenanceQuorum ?? 1,
    "PROVENANCE_INVALID",
    "provenance_signatures",
  );
  // The manifest's declared statement set must be exactly the supplied
  // provenance signatures (native lossless refs).
  const expected = new Set(
    manifest.provenance.statements.map((s) => canonicalJson(s)),
  );
  const actual = new Set(
    wire.provenance_signatures.map((s) =>
      canonicalJson(nativeRefOf(s as SunlightStatement)),
    ),
  );
  if (expected.size !== actual.size || ![...expected].every((e) => actual.has(e))) {
    fail("PROVENANCE_INVALID", "provenance.statements do not match supplied signatures", "provenance.statements");
  }

  // (7) revocation: any revoked digest denies the release (TV-GW-14).
  const revoked =
    trust.revocations.has(archiveDigest) ||
    trust.revocations.has(manifestDigest) ||
    trust.revocations.has(`sha256:${manifestDigest}`) ||
    trust.revocations.has(archiveDigest.slice("sha256:".length));
  if (revoked) {
    throw new RpcError("POLICY_DENIED", "release digest is revoked", { field: "revocations" });
  }

  // (8) platform: only known os/arch values are legal; node range must be
  // satisfied before extraction.
  const os = ctx.os ?? process.platform;
  const arch = ctx.arch ?? process.arch;
  const node = ctx.node ?? process.version;
  if (!manifest.runtime.os.includes(os)) {
    throw new RpcError("UNSUPPORTED_COMPOSITION", `os "${os}" not in manifest runtime.os`, {
      field: "runtime.os",
    });
  }
  if (!manifest.runtime.arch.includes(arch)) {
    throw new RpcError("UNSUPPORTED_COMPOSITION", `arch "${arch}" not in manifest runtime.arch`, {
      field: "runtime.arch",
    });
  }
  if (!satisfiesNode(node, manifest.runtime.node)) {
    throw new RpcError(
      "UNSUPPORTED_COMPOSITION",
      `node ${node} does not satisfy "${manifest.runtime.node}"`,
      { field: "runtime.node" },
    );
  }

  return {
    manifest,
    manifestBytes,
    manifestDigest,
    provenance: descriptor,
    provenanceBytes,
    archiveDigest,
    releaseSigners,
  };
}

/** True when `digest` appears in the revocation set in either encoding. */
export function isRevoked(revocations: ReadonlySet<string>, digest: string): boolean {
  const bare = digest.startsWith("sha256:") ? digest.slice(7) : digest;
  return revocations.has(digest) || revocations.has(bare) || revocations.has(`sha256:${bare}`);
}
