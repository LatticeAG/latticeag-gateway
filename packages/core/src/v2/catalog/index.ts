/**
 * Gateway v2 catalog — signed dynamic index store (spec §9.4).
 *
 * Verification:
 *  - closed `gateway.catalog/1` schema, ≤8 MiB, ≤10000 entries,
 *    ≤16 signatures;
 *  - entries sorted by slug/version and unique;
 *  - every supplied signature must verify under the configured
 *    catalog-root set AND bind the exact index bytes — a malformed or
 *    unauthorized extra fails the set (TV-GW-47), and at least `quorum`
 *    (two-of-three) distinct keys must sign. Roots come from trust
 *    config, never from the index itself.
 *
 * Refresh:
 *  - lower revision → CATALOG_ROLLBACK, prior verified cache and
 *    highest-seen byte-identical (TV-GW-44);
 *  - equal revision / different digest → retained equivocation,
 *    REVISION_CONFLICT;
 *  - an untrusted channel cannot switch stable to preview;
 *  - persistence is atomic: raw index + signatures + highest accepted
 *    revision/hash + freshness cut + revoked digests.
 *
 * Freshness (catalogFresh): now>=expires_ms → TRUST_EXPIRED for new
 * unpinned operations; installed exact-digest pinned releases keep
 * working under known revocations/local policy and show stale
 * (TV-GW-45). An enterprise-approved offline snapshot authorizes exact
 * pinned cached installs only and shows OFFLINE_PINNED, never CURRENT.
 * strict=true with an empty allowlist permits no new installs
 * (TV-GW-46).
 */

import { Buffer } from "node:buffer";
import type { Count, Hash, NativeRef, ObjectRef } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import {
  CATALOG_CHANNELS,
  CATALOG_LIMITS,
  catalogFresh,
} from "../protocol/catalog.js";
import type {
  CatalogEntry,
  CatalogFreshness,
  CatalogIndex,
} from "../protocol/catalog.js";
import { SLUG_RE, SEMVER_RE, isSeries } from "../protocol/product.js";
import { COUNT_RE } from "../crypto/proof.js";
import { canonicalJson, isCanonicalDomainValue } from "../crypto/canonical.js";
import { isHash64, sha256Hex } from "../crypto/hash.js";
import {
  verifySunlightStatementKeyId,
} from "../crypto/sunlight.js";
import type { SunlightStatement } from "../protocol/refs.js";
import type {
  CachedIndex,
  CatalogPorts,
  IndexFetch,
} from "./ports.js";

/** Freshness verdict including the offline-snapshot marker. */
export type IndexFreshness = CatalogFreshness | "OFFLINE_PINNED";

const INDEX_KEYS = new Set([
  "schema",
  "revision",
  "issued_ms",
  "expires_ms",
  "channel",
  "entries",
  "revocations",
]);

const ENTRY_KEYS = new Set([
  "slug",
  "series",
  "version",
  "published_ms",
  "manifest",
  "release_signatures",
  "adapter_status",
  "surfaces",
]);

const SURFACES_KEYS = new Set(["local", "hosted", "tier", "entitlement"]);
const NATIVEREF_KEYS = new Set([
  "profile",
  "namespace",
  "object_id",
  "commitment",
  "raw_sha256",
  "bytes",
]);
const OBJECTREF_KEYS = new Set(["digest", "bytes", "media"]);
const MEDIA = new Set([
  "application/json",
  "application/octet-stream",
  "text/plain",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hasExactly(obj: Record<string, unknown>, keys: ReadonlySet<string>): boolean {
  const own = Object.keys(obj);
  return own.length === keys.size && own.every((k) => keys.has(k));
}

function fail(code: "SCHEMA_INVALID" | "SCHEMA_UNSUPPORTED", field: string): never {
  throw new RpcError(code, `catalog index invalid at ${field}`, {
    retryable: false,
    field,
  });
}

function isClosedNativeRef(value: unknown): value is NativeRef {
  if (!isPlainObject(value) || !hasExactly(value, NATIVEREF_KEYS)) return false;
  return (
    typeof value.profile === "string" &&
    value.profile.length >= 1 &&
    value.profile.length <= 128 &&
    typeof value.namespace === "string" &&
    value.namespace.length >= 1 &&
    value.namespace.length <= 128 &&
    typeof value.object_id === "string" &&
    value.object_id.length >= 1 &&
    value.object_id.length <= 256 &&
    (typeof value.commitment === "string" || value.commitment === null) &&
    isHash64(value.raw_sha256) &&
    typeof value.bytes === "string" &&
    COUNT_RE.test(value.bytes)
  );
}

function isClosedObjectRef(value: unknown): value is ObjectRef {
  return (
    isPlainObject(value) &&
    hasExactly(value, OBJECTREF_KEYS) &&
    isHash64(value.digest) &&
    typeof value.bytes === "string" &&
    COUNT_RE.test(value.bytes) &&
    typeof value.media === "string" &&
    MEDIA.has(value.media)
  );
}

function isClosedEntry(value: unknown): value is CatalogEntry {
  if (!isPlainObject(value) || !hasExactly(value, ENTRY_KEYS)) return false;
  if (typeof value.slug !== "string" || !SLUG_RE.test(value.slug)) return false;
  if (typeof value.series !== "string" || !isSeries(value.series)) return false;
  if (typeof value.version !== "string" || !SEMVER_RE.test(value.version)) {
    return false;
  }
  if (
    typeof value.published_ms !== "number" ||
    !Number.isSafeInteger(value.published_ms) ||
    value.published_ms < 0
  ) {
    return false;
  }
  if (!isClosedObjectRef(value.manifest)) return false;
  if (
    !Array.isArray(value.release_signatures) ||
    !value.release_signatures.every(isClosedNativeRef)
  ) {
    return false;
  }
  if (value.adapter_status !== "available" && value.adapter_status !== "stub") {
    return false;
  }
  const surfaces = value.surfaces;
  if (!isPlainObject(surfaces) || !hasExactly(surfaces, SURFACES_KEYS)) {
    return false;
  }
  if (surfaces.local !== "free" && surfaces.local !== "licensed") return false;
  if (typeof surfaces.hosted !== "boolean") return false;
  if (
    surfaces.tier !== "oss" &&
    surfaces.tier !== "hosted" &&
    surfaces.tier !== "enterprise"
  ) {
    return false;
  }
  return typeof surfaces.entitlement === "string" || surfaces.entitlement === null;
}

export interface RefreshResult {
  readonly revision: Count;
  readonly entries: number;
  readonly freshness: IndexFreshness;
}

export interface InstallAuthorization {
  readonly ok: true;
  /** True when authorized by an exact pin rather than live freshness. */
  readonly pinned: boolean;
  /** Freshness of the authorizing metadata. */
  readonly freshness: IndexFreshness;
  /** True when the authorizing metadata is not CURRENT (or offline). */
  readonly stale: boolean;
}

export class CatalogStore {
  private readonly ports: CatalogPorts;

  constructor(ports: CatalogPorts) {
    this.ports = ports;
  }

  /** Persisted verified cache, or null. */
  cache(): CachedIndex | null {
    return this.ports.loadCache();
  }

  /** Freshness verdict of the current cache (OFFLINE_PINNED marker kept). */
  freshness(): IndexFreshness | null {
    const cache = this.ports.loadCache();
    if (cache === null) return null;
    if (cache.offline) return "OFFLINE_PINNED";
    return catalogFresh(
      cache.index,
      this.ports.now(),
      this.ports.trust().max_age_s,
    );
  }

  /**
   * Verify a candidate index: closed schema, caps, sorted-unique entries,
   * and the catalog-root signature quorum binding the exact index bytes.
   * @throws {RpcError} SCHEMA_INVALID / SCHEMA_UNSUPPORTED /
   *   SIGNATURE_INVALID / BODY_LIMIT.
   */
  verifyIndex(index: unknown, signatures: unknown[]): CatalogIndex {
    if (!isPlainObject(index) || !hasExactly(index, INDEX_KEYS)) {
      fail("SCHEMA_INVALID", "(root)");
    }
    if (index.schema !== "gateway.catalog/1") {
      fail("SCHEMA_UNSUPPORTED", "schema");
    }
    if (typeof index.revision !== "string" || !COUNT_RE.test(index.revision)) {
      fail("SCHEMA_INVALID", "revision");
    }
    for (const field of ["issued_ms", "expires_ms"] as const) {
      const v = index[field];
      if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
        fail("SCHEMA_INVALID", field);
      }
    }
    if ((index.expires_ms as number) <= (index.issued_ms as number)) {
      fail("SCHEMA_INVALID", "expires_ms");
    }
    if (
      typeof index.channel !== "string" ||
      !CATALOG_CHANNELS.includes(index.channel as never)
    ) {
      fail("SCHEMA_INVALID", "channel");
    }
    if (!Array.isArray(index.entries) || !Array.isArray(index.revocations)) {
      fail("SCHEMA_INVALID", "entries");
    }
    if (index.entries.length > CATALOG_LIMITS.maxEntries) {
      fail("SCHEMA_INVALID", "entries");
    }
    if (!index.revocations.every(isClosedNativeRef)) {
      fail("SCHEMA_INVALID", "revocations");
    }
    for (const entry of index.entries) {
      if (!isClosedEntry(entry)) fail("SCHEMA_INVALID", "entries");
    }
    // Entries sort by slug/version and are unique — a strictly increasing
    // sequence under the total order is both at once.
    for (let i = 1; i < index.entries.length; i += 1) {
      const prev = index.entries[i - 1]!;
      const next = index.entries[i]!;
      const cmp =
        prev.slug === next.slug
          ? prev.version < next.version
            ? -1
            : prev.version === next.version
              ? 0
              : 1
          : prev.slug < next.slug
            ? -1
            : 1;
      if (cmp >= 0) fail("SCHEMA_INVALID", "entries");
    }
    if (!isCanonicalDomainValue(index)) {
      fail("SCHEMA_INVALID", "(root)");
    }
    const raw = canonicalJson(index);
    if (Buffer.byteLength(raw, "utf8") > CATALOG_LIMITS.indexBytes) {
      throw new RpcError("BODY_LIMIT", "catalog index exceeds 8 MiB", {
        retryable: false,
        field: "entries",
      });
    }
    if (!Array.isArray(signatures)) {
      fail("SCHEMA_INVALID", "signatures");
    }
    if (signatures.length > CATALOG_LIMITS.maxSignatures) {
      fail("SCHEMA_INVALID", "signatures");
    }
    // Signature set: every statement must verify under the configured
    // catalog-root set AND bind the exact index bytes — extras are never
    // silently discarded to meet the threshold (TV-GW-47).
    const digest = `sha256:${sha256Hex(raw)}`;
    const roots = this.ports.trust().roots;
    const distinct = new Set<string>();
    for (const statement of signatures) {
      const keyId = verifySunlightStatementKeyId(statement, roots);
      const bound =
        isPlainObject(statement) &&
        isPlainObject(statement.body) &&
        isPlainObject(statement.body.subject) &&
        isPlainObject(statement.body.subject.artifact) &&
        statement.body.subject.artifact.digest === digest;
      if (keyId === null || !bound) {
        throw new RpcError(
          "SIGNATURE_INVALID",
          "catalog index signature failed verification or does not bind the index bytes",
          { retryable: false, field: "signatures" },
        );
      }
      distinct.add(keyId);
    }
    if (distinct.size < this.ports.trust().quorum) {
      throw new RpcError(
        "SIGNATURE_INVALID",
        `catalog index has ${distinct.size} distinct authorized signers, quorum is ${this.ports.trust().quorum}`,
        { retryable: false, field: "signatures" },
      );
    }
    return index as unknown as CatalogIndex;
  }

  /**
   * Refresh the verified cache from an injected fetch or the enrolled
   * offline snapshot. The prior verified cache is left untouched by any
   * invalid refresh (§9.4).
   */
  async refresh(options: {
    source: string;
    offline?: boolean;
    provided?: IndexFetch;
  }): Promise<RefreshResult> {
    const trust = this.ports.trust();
    let payload: IndexFetch | null;
    if (options.provided !== undefined) {
      payload = options.provided;
    } else if (options.offline === true) {
      payload = this.ports.offlineSnapshot();
      if (payload === null) {
        throw new RpcError("NOT_FOUND", "no offline snapshot enrolled", {
          retryable: false,
          field: "offline",
        });
      }
    } else {
      payload = await this.ports.fetchIndex(options.source);
    }
    const index = this.verifyIndex(payload.index, [...payload.signatures]);
    const raw = canonicalJson(index);
    const digest = sha256Hex(raw);
    // An untrusted channel cannot switch stable to preview (§9.4).
    if (index.channel !== trust.channel) {
      throw new RpcError(
        "POLICY_DENIED",
        `index channel ${index.channel} is not the trusted channel ${trust.channel}`,
        { retryable: false, field: "channel" },
      );
    }
    const high = this.ports.highestSeen();
    if (high !== null && BigInt(index.revision) < BigInt(high.revision)) {
      // TV-GW-44: cache and highest-seen remain byte-identical.
      throw new RpcError(
        "CATALOG_ROLLBACK",
        `index revision ${index.revision} is below highest seen ${high.revision}`,
        { retryable: false, field: "revision" },
      );
    }
    if (
      high !== null &&
      index.revision === high.revision &&
      digest !== high.digest
    ) {
      // Equal revision, different digest: retained equivocation (§9.4).
      this.ports.recordEquivocation({
        revision: index.revision,
        current: high.digest,
        candidate: digest,
        raw,
      });
      throw new RpcError(
        "REVISION_CONFLICT",
        `catalog revision ${index.revision} equivocated (digest differs from highest seen)`,
        { retryable: false, field: "revision" },
      );
    }
    // Atomic persist: raw index + signatures + highest accepted + the
    // trusted-time high-water mark (rollback detection).
    this.ports.saveCache({
      raw,
      digest,
      signatures: payload.signatures,
      index,
      offline: options.offline === true,
    });
    if (high === null || BigInt(index.revision) > BigInt(high.revision)) {
      this.ports.saveHighestSeen(index.revision, digest);
    }
    this.ports.saveTimeHighWater(this.ports.now());
    const freshness: IndexFreshness =
      options.offline === true
        ? "OFFLINE_PINNED"
        : catalogFresh(index, this.ports.now(), trust.max_age_s);
    return {
      revision: index.revision,
      entries: index.entries.length,
      freshness,
    };
  }

  /** Digests revoked by the current index (commitment or raw hash). */
  private revokedDigests(cache: CachedIndex): Set<string> {
    const revoked = new Set<string>();
    for (const ref of cache.index.revocations) {
      revoked.add(ref.raw_sha256);
      if (typeof ref.commitment === "string") {
        revoked.add(
          ref.commitment.startsWith("sha256:")
            ? ref.commitment.slice("sha256:".length)
            : ref.commitment,
        );
      }
    }
    return revoked;
  }

  /**
   * Authorize a new install against the trusted cache, pins, allowlist,
   * and freshness (§9.4). Exact pins survive refresh and keep working
   * under expired metadata; unpinned releases require CURRENT.
   * @throws {RpcError} POLICY_DENIED / TRUST_EXPIRED / NOT_FOUND.
   */
  authorizeInstall(input: {
    slug: string;
    version: string;
    digest: string;
  }): InstallAuthorization {
    const cache = this.ports.loadCache();
    if (cache === null) {
      throw new RpcError("TRUST_EXPIRED", "no trusted catalog index", {
        retryable: false,
        field: "source",
      });
    }
    const trust = this.ports.trust();
    const bareDigest = input.digest.startsWith("sha256:")
      ? input.digest.slice("sha256:".length)
      : input.digest;
    if (this.revokedDigests(cache).has(bareDigest)) {
      throw new RpcError(
        "POLICY_DENIED",
        `archive ${input.digest} is revoked`,
        { retryable: false, field: "digest" },
      );
    }
    if (trust.strict) {
      // strict=true: nonempty exact allowlist plus an exact pin for
      // every install — an empty allowlist permits nothing (TV-GW-46).
      if (trust.allowlist.length === 0 || !trust.allowlist.includes(input.slug)) {
        throw new RpcError(
          "POLICY_DENIED",
          "catalog.strict with an empty/nonmatching allowlist authorizes no installs",
          { retryable: false, field: "slug" },
        );
      }
    }
    const pin = this.ports.pins().find((p) => p.slug === input.slug);
    const pinned =
      pin !== undefined &&
      pin.version === input.version &&
      pin.digest === input.digest;
    if (pin !== undefined && !pinned) {
      throw new RpcError(
        "POLICY_DENIED",
        `${input.slug} is pinned to ${pin.version} ${pin.digest}`,
        { retryable: false, field: "digest" },
      );
    }
    if (trust.strict && !pinned) {
      throw new RpcError(
        "POLICY_DENIED",
        "catalog.strict requires an exact version/archive/index pin",
        { retryable: false, field: "slug" },
      );
    }
    const freshness: IndexFreshness = cache.offline
      ? "OFFLINE_PINNED"
      : catalogFresh(cache.index, this.ports.now(), trust.max_age_s);
    if (pinned) {
      // Pinned exact-digest releases keep working under expired metadata
      // and under an offline snapshot — flagged stale, never CURRENT.
      return { ok: true, pinned: true, freshness, stale: freshness !== "CURRENT" };
    }
    if (cache.offline) {
      // An offline snapshot authorizes exact pinned installs only.
      throw new RpcError(
        "POLICY_DENIED",
        "OFFLINE_PINNED snapshot authorizes pinned installs only",
        { retryable: false, field: "slug" },
      );
    }
    if (freshness !== "CURRENT") {
      throw new RpcError(
        "TRUST_EXPIRED",
        `catalog freshness is ${freshness}; new unpinned installs are not authorized`,
        { retryable: false, field: "source" },
      );
    }
    return { ok: true, pinned: false, freshness, stale: false };
  }

  /** Entries of the current cache (empty when none). */
  entries(): readonly CatalogEntry[] {
    return this.ports.loadCache()?.index.entries ?? [];
  }

  /** Current index commitment (`sha256:` + cache digest), if any. */
  indexCommitment(): string | null {
    const cache = this.ports.loadCache();
    return cache === null ? null : `sha256:${cache.digest}`;
  }

  /** Retained signature statements of the current cache. */
  signatures(): readonly unknown[] {
    return this.ports.loadCache()?.signatures ?? [];
  }
}

export type { SunlightStatement };
