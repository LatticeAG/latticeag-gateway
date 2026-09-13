/**
 * Gateway v2 control protocol — imported refinement types.
 *
 * These are the shared primitives the gateway spec imports verbatim:
 *  - PROOF_SPEC_EXTREME §1.1: Hash, Count, Id, Signature, PublicKey, Json,
 *    Media, ObjectRef, Blob, KeyMaterial, EventRef (spec §2.1 P01–P06).
 *  - INTERFACES.md §1.5: NativeRef, EvidenceJoin, AdapterResult
 *    (spec §2.1 line 151 requires verbatim import, closed fields).
 *  - SUNLIGHT_SPEC_EXTREME: Statement (release/provenance signatures).
 *
 * They are type aliases only; no parsing, IO, or validation is performed here.
 * Lexical bounds are documented on each alias and enforced by the owning
 * native validators, not reimplemented in this package.
 */

/** Canonical JSON value (RFC 8785-compatible domain). Depth is capped at 32. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** JSON object helper. */
export type JsonObject = { [key: string]: Json };

/** Exactly 64 lowercase hex characters (SHA-256 of raw bytes). */
export type Hash = string;

/** Canonical unsigned decimal string, `^(0|[1-9][0-9]*)$`, bounded by 2^63−1. */
export type Count = string;

/** `^[A-Za-z][A-Za-z0-9_-]{0,63}$`; workspace-scoped opaque name, never authority. */
export type Id = string;

/** Canonical unpadded base64url encoding of exactly 64 bytes (Ed25519). */
export type Signature = string;

/** Canonical unpadded base64url encoding of exactly 32 bytes (Ed25519). */
export type PublicKey = string;

/** Proof object media enum (closed). */
export type Media = "application/json" | "application/octet-stream" | "text/plain";

/**
 * Proof P04 raw evidence object reference: SHA-256 of raw object bytes,
 * decimal-string byte length. Never a substituted body-domain hash.
 */
export type ObjectRef = { digest: Hash; bytes: Count; media: Media };

/** Proof Blob: base64url content whose decoded length/digest equal ref. */
export type Blob = { ref: ObjectRef; content: string };

/** KeyMaterial.id = H(BASE64URL_DECODE(public)); importing a key does not trust it. */
export type KeyMaterial = { id: Hash; public: PublicKey };

/** Proof scoped event identity: `(source,stream,seq,hash)`. */
export type EventRef = { source: Id; stream: Id; seq: Count; hash: Hash };

/**
 * INTERFACES §1.5 lossless native reference (closed object, verbatim):
 * profile/namespace are ASCII 1–128 bytes, object_id 1–256 UTF-8 bytes,
 * commitment preserves the native lexical digest or null, raw_sha256 is
 * exactly 64 lowercase hex, bytes is a canonical decimal string ≤2^63−1.
 */
export type NativeRef = {
  profile: string;
  namespace: string;
  object_id: string;
  commitment: string | null;
  raw_sha256: Hash;
  bytes: Count;
};

/**
 * INTERFACES §1.5 adapter metadata join (closed, verbatim). `related` has
 * 0–64 distinct entries sorted by J(NativeRef) byte order.
 */
export type EvidenceJoin = {
  schema: "interfaces.evidence-join/1";
  subject: NativeRef;
  related: NativeRef[];
  relation: "reports" | "supports" | "identity_evidence" | "policy_evidence";
  assessment: "OPAQUE";
};

/**
 * INTERFACES §1.5 adapter result (closed, verbatim). No adapter may set
 * grants_authority=true; adapter_sha256/trust_sha256 are 64 lowercase hex.
 */
export type AdapterResult = {
  schema: "interfaces.adapter-result/1";
  adapter: string;
  adapter_sha256: string;
  source: NativeRef;
  trust_sha256: string;
  outcome: "STORED" | "REJECTED" | "NATIVE_VERIFIED";
  code: string;
  native_result: NativeRef | null;
  grants_authority: false;
};

/** Sunlight safe nonnegative integer (used as byte counts/timestamps). */
export type SunlightInt = number;

/** Sunlight digest: 64 lowercase hex (same lexical form as Hash). */
export type SunlightDigest = string;

/** Sunlight artifact refinement; Gateway manifests restrict profile to "bytes/1". */
export type SunlightArtifact = {
  profile: "bytes/1" | "jcs/1" | "tree/1";
  digest: SunlightDigest;
  bytes: SunlightInt;
};

export type SunlightParent = {
  statement: SunlightDigest;
  artifact: SunlightDigest;
  relation: "source" | "dataset" | "base_model" | "run" | "model";
};

export type SunlightForeignFormat =
  | "c2pa/opaque"
  | "fv.sunlight-export/1"
  | "vislineage-bundle/1"
  | "world/opaque"
  | "mint/opaque"
  | "treaty/opaque"
  | "generic/opaque";

export type SunlightEvidenceRef = {
  artifact: SunlightArtifact;
  format: SunlightForeignFormat;
  source_commitment: SunlightDigest | null;
  assessment: "OPAQUE";
};

export type SunlightDetails =
  | { type: "creation" }
  | { type: "transform"; procedure: SunlightDigest }
  | {
      type: "training";
      run_id: string;
      code: SunlightDigest;
      environment: SunlightDigest;
      parameters: SunlightDigest;
      seed: string | null;
    }
  | { type: "model" }
  | {
      type: "action";
      action_id: string;
      input: SunlightDigest;
      output: SunlightDigest | null;
      outcome: "attempted" | "completed" | "failed";
      context: SunlightDigest | null;
    };

/**
 * Sunlight `sunlight.statement/1` body. Release signatures are unchanged
 * native Statements: creation/evidence, empty parents, subject artifact
 * exactly the raw manifest bytes/1 (spec §5.1).
 */
export type SunlightStatementBody = {
  v: "sunlight.statement/1";
  id: string;
  ledger: string;
  signer: string;
  claimed_at_ms: SunlightInt;
  capture: "creation_hook" | "posthoc";
  subject: {
    kind: "dataset" | "run" | "model" | "action" | "evidence";
    artifact: SunlightArtifact;
  };
  parents: SunlightParent[];
  details: SunlightDetails;
  evidence: SunlightEvidenceRef[];
};

/** Sunlight Statement: signed body plus native hex signature (stays hex). */
export type SunlightStatement = {
  body: SunlightStatementBody;
  hash: SunlightDigest;
  signature_hex: string;
};
