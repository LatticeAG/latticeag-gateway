/**
 * E35 VisLineage→Sunlight handoff seam (spec §5.3 disposition table:
 * "Check SunlightHandoff; native body commitment distinct from raw
 * digest"; INTERFACES §4.3 C43; VisLineage §8 `SunlightHandoff`;
 * Sunlight §13.1 foreign-evidence contract).
 *
 * A SunlightHandoff carries the bundle's *native* body commitment —
 * `bundle.hash` = D("VL-BUNDLE/1", bundle.body) — while the Sunlight
 * EvidenceRef's `source_commitment` preserves it and the artifact digest
 * independently commits the whole raw bundle bytes. The two hash domains
 * are never collapsed: a handoff whose `bundle` commitment is anything
 * other than the bundle's own `hash` — e.g. the raw complete-bundle
 * digest — is rejected PROVENANCE_INVALID, and the mismatch is retained
 * as evidence (TV-GW-55). No Sunlight success acknowledgement may be
 * issued for a rejected handoff: the checker throws before producing a
 * result.
 */
import { Buffer } from "node:buffer";

import { RpcError } from "../protocol/errors.js";
import type { Hash } from "../protocol/refs.js";
import { sha256Hex } from "../crypto/hash.js";

/** `vislineage-bundle/1` — the only handoff format v1 accepts. */
export const VISLINEAGE_BUNDLE_FORMAT = "vislineage-bundle/1";

/**
 * The VisLineage §8 SunlightHandoff wire shape (verbatim fields). Every
 * field is a commitment/id string; `bundle` is the *native* bundle body
 * commitment, not a raw whole-file digest.
 */
export interface SunlightHandoff {
  readonly v: 1;
  readonly kind: "action-lineage";
  readonly format: string;
  readonly bundle: string;
  readonly action: string;
  readonly trace: string;
  readonly graph: string;
  readonly disclosure: string;
  readonly semantics: string;
}

export interface HandoffCheckInput {
  readonly handoff: SunlightHandoff;
  /** The received bundle's own native commitment (its `hash` field). */
  readonly bundleHash: string;
  /** The actual received whole-bundle bytes — hashed independently. */
  readonly bundleBytes: Uint8Array | string;
}

/** The retained mismatch record (INTERFACES §4.3: keep both digests). */
export interface HandoffMismatch {
  readonly edge: "E35";
  readonly format: string | null;
  /** `handoff.bundle` exactly as supplied (the claimed commitment). */
  readonly claimed_commitment: string | null;
  /** The bundle's own native commitment that should have been claimed. */
  readonly native_commitment: string;
  /** sha256:H of the actual whole-bundle bytes (independent digest). */
  readonly raw_digest: string;
}

/**
 * The Sunlight EvidenceRef produced by an accepted handoff — assessment
 * stays OPAQUE; no semantic-truth or acceptance claim is synthesized.
 */
export interface VislineageEvidenceRef {
  readonly artifact: {
    readonly profile: "bytes/1";
    readonly digest: string;
    readonly bytes: number;
  };
  readonly format: typeof VISLINEAGE_BUNDLE_FORMAT;
  /** Preserved native commitment — never the raw artifact digest. */
  readonly source_commitment: string;
  readonly assessment: "OPAQUE";
}

/**
 * Receive-side E35 consistency check (Sunlight §13.1: "Reject a handoff
 * whose format is not vislineage-bundle/1 or whose bundle commitment
 * differs from the bundle's own `hash`; this consistency check is not a
 * native proof verification"). On success returns the OPAQUE evidence
 * ref preserving `source_commitment` = the native bundle hash and an
 * artifact digest bound to the actual bytes. On failure the mismatch is
 * pushed to `retain` (when given) and PROVENANCE_INVALID is thrown —
 * callers must not emit a success ACK for the handoff.
 */
export function checkSunlightHandoff(
  input: HandoffCheckInput,
  retain?: (mismatch: HandoffMismatch) => void,
): VislineageEvidenceRef {
  const bytes =
    typeof input.bundleBytes === "string"
      ? Buffer.from(input.bundleBytes, "utf8")
      : input.bundleBytes;
  const rawDigest = `sha256:${sha256Hex(bytes)}`;
  const handoff = input.handoff;
  const format =
    handoff !== null && typeof handoff === "object" && typeof handoff.format === "string"
      ? handoff.format
      : null;
  const claimed =
    handoff !== null && typeof handoff === "object" && typeof handoff.bundle === "string"
      ? handoff.bundle
      : null;
  const reject = (field: string): never => {
    retain?.({
      edge: "E35",
      format,
      claimed_commitment: claimed,
      native_commitment: input.bundleHash,
      raw_digest: rawDigest,
    });
    throw new RpcError(
      "PROVENANCE_INVALID",
      `E35 SunlightHandoff ${field} does not bind the bundle's native commitment`,
      { field: `handoff.${field}` },
    );
  };
  if (format !== VISLINEAGE_BUNDLE_FORMAT) reject("format");
  // The claimed commitment must be the bundle's own native hash. A value
  // equal to `rawDigest` here is the hash-domain collapse the edge forbids.
  if (claimed !== input.bundleHash) reject("bundle");
  if (input.bundleHash === rawDigest) {
    // Defensive: the two commitment domains must stay distinct; a bundle
    // whose native hash equals the whole-file digest is malformed.
    reject("bundle");
  }
  return {
    artifact: {
      profile: "bytes/1",
      digest: rawDigest,
      bytes: bytes.length,
    },
    format: VISLINEAGE_BUNDLE_FORMAT,
    source_commitment: input.bundleHash as Hash,
    assessment: "OPAQUE",
  };
}
