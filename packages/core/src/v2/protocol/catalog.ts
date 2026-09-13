/**
 * Gateway v2 — signed dynamic catalog types, caps, and freshness
 * (spec §9.4, §8.1 pin definition).
 *
 * Index bytes are signed as native Sunlight creation/evidence Statements
 * under a separate two-of-three catalog-root role; roots do not come from
 * the index being verified.
 */

import type { Count, Hash, NativeRef, ObjectRef } from "./refs.js";
import type { Series } from "./product.js";

export type CatalogChannel = "stable" | "preview";

export const CATALOG_CHANNELS: readonly CatalogChannel[] = ["stable", "preview"];

/**
 * Catalog entry (closed): ProductManifest refinements apply to
 * slug/series/version/surfaces. `published_ms` is the signed
 * first-publication time, never reset by a mirror.
 */
export type CatalogEntry = {
  slug: string;
  series: Series;
  version: string;
  published_ms: number;
  manifest: ObjectRef;
  release_signatures: NativeRef[];
  adapter_status: "available" | "stub";
  surfaces: {
    local: "free" | "licensed";
    hosted: boolean;
    tier: "oss" | "hosted" | "enterprise";
    entitlement: string | null;
  };
};

/** Signed catalog index (closed). Entries sort by slug/version, unique. */
export type CatalogIndex = {
  schema: "gateway.catalog/1";
  revision: Count;
  issued_ms: number;
  expires_ms: number;
  channel: CatalogChannel;
  entries: CatalogEntry[];
  revocations: NativeRef[];
};

/**
 * A configured catalog pin (§8.1 `$defs.pin`): exact slug, exact SemVer
 * version, `sha256:`-prefixed archive digest, and the index commitment.
 * One pin per slug.
 */
export type CatalogPin = {
  slug: string;
  version: string;
  digest: string;
  index: string;
};

/** Catalog bounds (§9.4). */
export const CATALOG_LIMITS = {
  /** Signed index byte cap. */
  indexBytes: 8 * 1024 * 1024,
  /** Entry count cap. */
  maxEntries: 10_000,
  /** Signature count cap on an index. */
  maxSignatures: 16,
  /** Redirects allowed, each with full destination revalidation. */
  maxRedirects: 2,
  /** Operator refresh floor between fetches when a trusted update
   *  descriptor exists, ms (24 h). */
  fetchIntervalMs: 24 * 60 * 60 * 1000,
  /** Clock-skew allowance on issued_ms, ms. */
  issuedSkewMs: 5_000,
  /** Minimum published age for new npm dependencies, ms (7 days). */
  minPublishedAgeMs: 7 * 24 * 60 * 60 * 1000,
  /** Config max_age_s bounds (§8.1 catalog.max_age_s: 3600–2592000). */
  maxAgeSMin: 3_600,
  maxAgeSMax: 2_592_000,
} as const;

/**
 * Freshness verdict for a signed index (§9.4):
 *  - "CURRENT": issued_ms <= now+5000, now < expires_ms, and
 *    now < issued_ms + max_age_s*1000.
 *  - "STALE": signature-valid but past the configured max_age window —
 *    the index is too old by policy, not yet by its own expiry.
 *  - "TRUST_EXPIRED": future-dated issue time (beyond skew) or
 *    now >= expires_ms — the signed validity window itself has failed.
 * Expired metadata cannot authorize new unpinned releases; an
 * enterprise-approved offline snapshot shows OFFLINE_PINNED, never CURRENT.
 */
export type CatalogFreshness = "CURRENT" | "STALE" | "TRUST_EXPIRED";

export function catalogFresh(
  index: Pick<CatalogIndex, "issued_ms" | "expires_ms">,
  now: number,
  max_age_s: number,
): CatalogFreshness {
  if (index.issued_ms > now + CATALOG_LIMITS.issuedSkewMs) {
    return "TRUST_EXPIRED";
  }
  if (now >= index.expires_ms) {
    return "TRUST_EXPIRED";
  }
  if (now >= index.issued_ms + max_age_s * 1000) {
    return "STALE";
  }
  return "CURRENT";
}
