/**
 * Gateway v2 — product packaging, release descriptors, and the adapter
 * process contract (spec §5.1–§5.2).
 *
 * The archive and release manifest are separate objects so the archive need
 * not contain its own digest. Slugs resolve through signed metadata, never
 * an invented npm name. Dependency ranges are bounded SemVer ranges only.
 */

import type {
  Count,
  Hash,
  Id,
  Json,
  NativeRef,
  ObjectRef,
  Blob,
  SunlightStatement,
} from "./refs.js";

// ── §5.1 verbatim types ──────────────────────────────────────────────────

/** Sunlight bytes/1 refinement: `sha256:` + 64 lowercase hex, safe int bytes. */
export type Artifact = { profile: "bytes/1"; digest: string; bytes: number };

export type Dependency = {
  slug: string;
  range: string;
  kind: "required" | "optional" | "evidence";
  edge: string | null;
  capability: string | null;
  pin: Hash | null;
};

export const SERIES = ["poly", "lex", "vek", "axi", "vis", "forge"] as const;
export type Series = (typeof SERIES)[number];

export function isSeries(s: string): s is Series {
  return (SERIES as readonly string[]).includes(s);
}

export type ProductManifest = {
  schema: "gateway.product/1";
  slug: string;
  version: string;
  series: Series;
  license: string;
  package: { kind: "npm" | "local"; name: string; archive: Artifact };
  runtime: {
    os: string[];
    arch: string[];
    node: string;
    sandbox: "linux-ns" | "oci" | "wasi";
  };
  adapter: {
    contract: "gateway-adapter/1";
    entry: string;
    config_schema: ObjectRef;
    health_timeout_ms: number;
    startup_timeout_ms: number;
  };
  provenance: {
    descriptor: ObjectRef;
    statements: NativeRef[];
    builder: string;
    repository: string;
    commit: string;
    lockfile: Artifact;
    sbom: ObjectRef;
  };
  dependencies: Dependency[];
  capabilities: {
    read_paths: string[];
    write_paths: string[];
    network_origins: string[];
    emit: string[];
    consume: string[];
    native_profiles: string[];
  };
  interfaces: { profile: "interfaces/1"; snapshot: Hash; edges: string[] };
  surfaces: {
    local: "free" | "licensed";
    hosted: boolean;
    tier: "oss" | "hosted" | "enterprise";
    entitlement: string | null;
  };
};

export type Release = {
  manifest: Blob;
  signatures: SunlightStatement[];
  provenance: Blob;
  provenance_signatures: SunlightStatement[];
};

// ── Bounds and lexical rules (§5.1) ──────────────────────────────────────

export const PRODUCT_LIMITS = {
  /** ProductManifest canonical bytes cap. */
  manifestBytes: 256 * 1024,
  /** Release metadata cap. */
  releaseMetadataBytes: 1024 * 1024,
  /** Compressed archive cap. */
  archiveCompressedBytes: 256 * 1024 * 1024,
  /** Expanded archive cap. */
  archiveExpandedBytes: 1024 * 1024 * 1024,
  /** Max files inside an archive. */
  archiveMaxFiles: 10_000,
  /** Official releases require two distinct authorized release keys. */
  releaseSignatureThreshold: 2,
  /** Independently pinned release root set size. */
  releaseRootKeys: 3,
} as const;

/** Known execution OS values (§5.1). */
export const OS_VALUES = ["linux", "darwin", "win32"] as const;
export type OsValue = (typeof OS_VALUES)[number];

/** Known execution arch values (§5.1). */
export const ARCH_VALUES = ["x64", "arm64"] as const;
export type ArchValue = (typeof ARCH_VALUES)[number];

/** Known sandbox backends (§5.1, §10.1). */
export const SANDBOX_KINDS = ["linux-ns", "oci", "wasi"] as const;
export type SandboxKind = (typeof SANDBOX_KINDS)[number];

/** Slug grammar: lowercase `[a-z][a-z0-9-]{0,63}` (§5.1). */
export const SLUG_RE = /^[a-z][a-z0-9-]{0,63}$/;

/** Exact SemVer 2.0.0 grammar (no ranges, no wildcards). */
export const SEMVER_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$/;

const SEMVER_IDENT = "(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)";
const SEMVER_PART =
  `(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)` +
  `(?:-${SEMVER_IDENT}(?:\\.${SEMVER_IDENT})*)?` +
  `(?:\\+[0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*)?`;
/** One comparator: an optional operator followed by an exact version. */
const COMPARATOR_RE = new RegExp(`^(?:>=|>|<=|<|=)?${SEMVER_PART}$`);
/** Hyphen range: `X.Y.Z - A.B.C` with exact versions on both ends. */
const HYPHEN_RE = new RegExp(`^${SEMVER_PART} - ${SEMVER_PART}$`);
/** Caret/tilde range on an exact version (implies an upper bound). */
const CARET_TILDE_RE = new RegExp(`^[~^]${SEMVER_PART}$`);

export type RangeValidation = { ok: true } | { ok: false; reason: string };

/**
 * Validate a dependency range (§5.1): bounded SemVer ranges only — an exact
 * version, a hyphen range `a.b.c - d.e.f`, a caret/tilde range on an exact
 * version, or a space/comma-separated comparator set. `*`, `x` wildcards,
 * `latest`, Git branches, tag names, and floating URLs are rejected. A
 * comparator set must include both a lower bound (`>`,`>=`,`=`, or an exact
 * version) and an upper bound (`<`,`<=`) — unbounded sets like `>=1.0.0`
 * are rejected.
 */
export function validateRange(range: unknown): RangeValidation {
  if (typeof range !== "string") return { ok: false, reason: "range must be a string" };
  const r = range.trim();
  if (r.length === 0) return { ok: false, reason: "range must be nonempty" };
  if (r.length > 256) return { ok: false, reason: "range exceeds 256 characters" };
  if (/[x*]/.test(r)) {
    return { ok: false, reason: "wildcards are not bounded ranges" };
  }
  if (/(?:^|[^a-z])latest(?:[^a-z]|$)/i.test(r) || r.includes("://") ||
      r.startsWith("git+") || r.startsWith("git:") || r.startsWith("github:") ||
      r.includes("#")) {
    return { ok: false, reason: "latest, URLs, and branch/commit refs are not bounded ranges" };
  }
  if (SEMVER_RE.test(r)) return { ok: true };
  if (HYPHEN_RE.test(r)) return { ok: true };
  if (CARET_TILDE_RE.test(r)) return { ok: true };

  const parts = r.split(/[\s,]+/).filter((p) => p.length > 0);
  if (parts.length === 0 || !parts.every((p) => COMPARATOR_RE.test(p))) {
    return { ok: false, reason: "range must be exact versions, comparators, or a hyphen range" };
  }
  // A comparator set must be bounded on both sides; an "=x.y.z" pin
  // supplies both bounds, while ">=1.0.0" alone is unbounded above.
  let lower = false;
  let upper = false;
  for (const p of parts) {
    if (p.startsWith(">")) lower = true;
    else if (p.startsWith("<")) upper = true;
    else {
      lower = true;
      upper = true;
    }
  }
  if (!(lower && upper)) {
    return { ok: false, reason: "comparator set needs a lower and an upper bound" };
  }
  return { ok: true };
}

// ── §5.2 adapter process contract ────────────────────────────────────────

/**
 * Supervisor ↔ adapter control is `gateway-adapter/1`: LF-delimited bounded
 * JSON on private pipes, one outstanding request per adapter, 64 KiB
 * maximum line, schema-checked request IDs. No generic shell/exec method.
 */
export const ADAPTER_METHODS = [
  "describe",
  "configure",
  "start",
  "health",
  "drain",
  "snapshot",
  "stop",
] as const;

export type AdapterMethod = (typeof ADAPTER_METHODS)[number];

export function isAdapterMethod(name: string): name is AdapterMethod {
  return (ADAPTER_METHODS as readonly string[]).includes(name);
}

/** Adapter wire request: `{v:1,id,method,params}`. */
export type AdapterRequest = {
  v: 1;
  id: Id;
  method: AdapterMethod;
  params: Json;
};

export type AdapterSuccess = { v: 1; id: Id; ok: true; result: Json };

export type AdapterFailure = {
  v: 1;
  id: Id;
  ok: false;
  error: { code: string; retryable: boolean };
};

export type AdapterResponse = AdapterSuccess | AdapterFailure;

/** Wire and health bounds (§5.2). */
export const ADAPTER_LIMITS = {
  /** Max LF-delimited JSON line, bytes. */
  maxLineBytes: 64 * 1024,
  /** Outstanding requests per adapter pipe. */
  maxOutstandingRequests: 1,
  /** Default health probe timeout, ms. */
  healthTimeoutMs: 2_000,
  /** Readiness successes required for activation. */
  readinessSuccesses: 3,
  /** Spacing between readiness checks, ms. */
  readinessIntervalMs: 1_000,
  /** Default startup_timeout_ms when the manifest does not set one. */
  startupTimeoutDefaultMs: 30_000,
  /** Maximum startup_timeout_ms. */
  startupTimeoutMaxMs: 120_000,
  /** Live probe interval, ms. */
  probeIntervalMs: 10_000,
  /** Consecutive live-probe failures before DEGRADED. */
  probeFailureLimit: 3,
} as const;
