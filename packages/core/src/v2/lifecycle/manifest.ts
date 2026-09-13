/**
 * §5.1 ProductManifest bytes → typed manifest, or a coded RpcError.
 *
 * Enforces the closed `gateway.product/1` schema: 256 KiB byte cap, slug
 * grammar, exact SemVer version, series/license/sandbox enums, known
 * os/arch values, the pinned `gateway-adapter/1` contract, bounded
 * dependency ranges via `validateRange`, Sunlight tree-path restrictions
 * on entry/config paths, and the interfaces/1 edge registry (E01–E53).
 * Parsing never executes package code.
 */
import { Buffer } from "node:buffer";

import { RpcError } from "../protocol/errors.js";
import { jsonDepth, isJson, ENVELOPE_LIMITS } from "../protocol/envelope.js";
import {
  ARCH_VALUES,
  OS_VALUES,
  PRODUCT_LIMITS,
  SANDBOX_KINDS,
  SEMVER_RE,
  SERIES,
  SLUG_RE,
  validateRange,
} from "../protocol/product.js";
import type {
  Dependency,
  ProductManifest,
} from "../protocol/product.js";
import type { Count, Hash, Media, NativeRef, ObjectRef } from "../protocol/refs.js";
import { isHash64, sha256Hex } from "../crypto/hash.js";
import { isSunlightArtifact } from "../crypto/sunlight.js";
import { validateNodeRange } from "./semver.js";

const MEDIA = new Set<Media>([
  "application/json",
  "application/octet-stream",
  "text/plain",
]);

const COUNT_RE = /^(0|[1-9][0-9]*)$/;
const EDGE_RE = /^E(0[1-9]|[1-4][0-9]|5[0-3])$/;
const MAX_STRING = ENVELOPE_LIMITS.maxStringBytes;
const MAX_DEPS = 128;
const MAX_LIST = 256;

function fail(message: string, field: string | null = null): never {
  throw new RpcError("SCHEMA_INVALID", message, { field });
}

function unsupported(message: string, field: string | null = null): never {
  throw new RpcError("UNSUPPORTED_COMPOSITION", message, { field });
}

function isPlain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Closed-object check: exactly `keys`, all present, no extras. */
function closed(
  obj: unknown,
  keys: readonly string[],
  field: string,
): Record<string, unknown> {
  if (!isPlain(obj)) fail(`${field} must be an object`, field);
  for (const key of Object.keys(obj)) {
    if (!keys.includes(key)) fail(`${field}.${key} is not in the schema`, `${field}.${key}`);
  }
  for (const key of keys) {
    if (!(key in obj)) fail(`${field}.${key} is required`, `${field}.${key}`);
  }
  return obj;
}

function str(value: unknown, field: string, max: number = MAX_STRING): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    fail(`${field} must be a nonempty string ≤${max} chars`, field);
  }
  return value;
}

function strOrNull(value: unknown, field: string, max: number = MAX_STRING): string | null {
  if (value === null) return null;
  return str(value, field, max);
}

function safeInt(value: unknown, field: string, min: number, max: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < min ||
    value > max
  ) {
    fail(`${field} must be a safe integer in [${min},${max}]`, field);
  }
  return value;
}

function bool(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") fail(`${field} must be a boolean`, field);
  return value;
}

function count(value: unknown, field: string): Count {
  if (typeof value !== "string" || !COUNT_RE.test(value)) {
    fail(`${field} must be a canonical decimal string`, field);
  }
  const n = BigInt(value);
  if (n > (BigInt(1) << BigInt(63)) - BigInt(1)) {
    fail(`${field} exceeds 2^63-1`, field);
  }
  return value;
}

function stringList(value: unknown, field: string, maxLen: number = MAX_LIST): string[] {
  if (!Array.isArray(value) || value.length > maxLen) {
    fail(`${field} must be an array of ≤${maxLen} strings`, field);
  }
  const out: string[] = [];
  for (const [i, item] of value.entries()) {
    out.push(str(item, `${field}[${i}]`));
  }
  return out;
}

function enumOf<T extends string>(
  value: unknown,
  allowed: readonly T[],
  field: string,
): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    fail(`${field} must be one of ${allowed.join("|")}`, field);
  }
  return value as T;
}

/**
 * Sunlight tree-path restriction for in-archive paths (entry, config
 * schema): relative, `/`-separated, no `.`/`..`/empty segments, no
 * backslashes, no control chars or NUL, segment ≤255 bytes, total ≤1024.
 */
function treePath(value: unknown, field: string): string {
  const p = str(value, field, 1024);
  if (
    p.startsWith("/") ||
    p.includes("\\") ||
    p.includes("\0") ||
    p.endsWith("/") ||
    /^[A-Za-z]:/.test(p)
  ) {
    fail(`${field} must be a relative /-separated tree path`, field);
  }
  for (const seg of p.split("/")) {
    if (seg.length === 0 || seg === "." || seg === "..") {
      fail(`${field} contains an illegal path segment`, field);
    }
    if (Buffer.byteLength(seg, "utf8") > 255) {
      fail(`${field} segment exceeds 255 bytes`, field);
    }
    if (/[\u0000-\u001f\u007f]/.test(seg)) {
      fail(`${field} contains control characters`, field);
    }
  }
  return p;
}

function objectRef(value: unknown, field: string): ObjectRef {
  const o = closed(value, ["digest", "bytes", "media"], field);
  const digest = o.digest;
  if (!isHash64(digest)) fail(`${field}.digest must be 64 lowercase hex`, `${field}.digest`);
  const b = count(o.bytes, `${field}.bytes`);
  const media = enumOf(o.media, [...MEDIA], `${field}.media`);
  return { digest: digest as Hash, bytes: b, media };
}

function artifactRef(value: unknown, field: string): ProductManifest["package"]["archive"] {
  if (!isSunlightArtifact(value) || value.profile !== "bytes/1") {
    fail(`${field} must be a bytes/1 artifact (sha256: digest, safe bytes)`, field);
  }
  return { ...value, profile: "bytes/1" };
}

function nativeRef(value: unknown, field: string): NativeRef {
  const o = closed(
    value,
    ["profile", "namespace", "object_id", "commitment", "raw_sha256", "bytes"],
    field,
  );
  const profile = str(o.profile, `${field}.profile`, 128);
  const namespace = str(o.namespace, `${field}.namespace`, 128);
  const objectId = str(o.object_id, `${field}.object_id`, 256);
  const commitment = strOrNull(o.commitment, `${field}.commitment`, 256);
  if (!isHash64(o.raw_sha256)) {
    fail(`${field}.raw_sha256 must be 64 lowercase hex`, `${field}.raw_sha256`);
  }
  const b = count(o.bytes, `${field}.bytes`);
  return {
    profile,
    namespace,
    object_id: objectId,
    commitment,
    raw_sha256: o.raw_sha256 as Hash,
    bytes: b,
  };
}

function dependency(value: unknown, field: string): Dependency {
  const o = closed(
    value,
    ["slug", "range", "kind", "edge", "capability", "pin"],
    field,
  );
  const slug = str(o.slug, `${field}.slug`, 64);
  if (!SLUG_RE.test(slug)) fail(`${field}.slug must match ${SLUG_RE}`, `${field}.slug`);
  const range = str(o.range, `${field}.range`, 256);
  const vr = validateRange(range);
  if (!vr.ok) {
    fail(`${field}.range is not a bounded SemVer range: ${vr.reason}`, `${field}.range`);
  }
  const kind = enumOf(o.kind, ["required", "optional", "evidence"] as const, `${field}.kind`);
  const edge = strOrNull(o.edge, `${field}.edge`, 8);
  if (edge !== null && !EDGE_RE.test(edge)) {
    fail(`${field}.edge must be null or a registered E01–E53 edge`, `${field}.edge`);
  }
  const capability = strOrNull(o.capability, `${field}.capability`, 128);
  if (o.pin !== null && !isHash64(o.pin)) {
    fail(`${field}.pin must be null or 64 lowercase hex`, `${field}.pin`);
  }
  return {
    slug,
    range,
    kind,
    edge,
    capability,
    pin: (o.pin as Hash | null) ?? null,
  };
}

/**
 * Parse and validate ProductManifest bytes. On any violation throws
 * RpcError with SCHEMA_INVALID (shape/lexical), UNSUPPORTED_COMPOSITION
 * (a contract or composition this gateway cannot run), or OBJECT_LIMIT
 * (byte cap).
 */
export function parseProductManifest(data: Uint8Array | string): ProductManifest {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  if (bytes.length > PRODUCT_LIMITS.manifestBytes) {
    throw new RpcError("OBJECT_LIMIT", "manifest exceeds 256 KiB", {
      field: "manifest",
    });
  }
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    fail("manifest is not valid JSON", "manifest");
  }
  if (!isJson(raw) || jsonDepth(raw) > ENVELOPE_LIMITS.maxJsonDepth) {
    fail("manifest is outside the JSON domain or exceeds depth 32", "manifest");
  }
  const m = closed(raw, [
    "schema",
    "slug",
    "version",
    "series",
    "license",
    "package",
    "runtime",
    "adapter",
    "provenance",
    "dependencies",
    "capabilities",
    "interfaces",
    "surfaces",
  ], "manifest");

  if (m.schema !== "gateway.product/1") {
    if (typeof m.schema === "string" && m.schema.startsWith("gateway.product/")) {
      throw new RpcError("SCHEMA_UNSUPPORTED", `unsupported manifest schema ${m.schema}`, {
        field: "schema",
      });
    }
    fail(`schema must be "gateway.product/1"`, "schema");
  }

  const slug = str(m.slug, "slug", 64);
  if (!SLUG_RE.test(slug)) fail(`slug must match ${SLUG_RE}`, "slug");

  const version = str(m.version, "version", 64);
  if (!SEMVER_RE.test(version)) fail("version must be exact SemVer", "version");

  const series = enumOf(m.series, SERIES, "series");
  const license = str(m.license, "license", 128);

  const pkg = closed(m.package, ["kind", "name", "archive"], "package");
  const pkgKind = enumOf(pkg.kind, ["npm", "local"] as const, "package.kind");
  const pkgName = str(pkg.name, "package.name", 256);
  const archive = artifactRef(pkg.archive, "package.archive");

  const rt = closed(m.runtime, ["os", "arch", "node", "sandbox"], "runtime");
  const os = stringList(rt.os, "runtime.os", 8);
  if (os.length === 0 || new Set(os).size !== os.length) {
    fail("runtime.os must be a nonempty unique list", "runtime.os");
  }
  for (const o of os) enumOf(o, OS_VALUES, "runtime.os");
  const arch = stringList(rt.arch, "runtime.arch", 8);
  if (arch.length === 0 || new Set(arch).size !== arch.length) {
    fail("runtime.arch must be a nonempty unique list", "runtime.arch");
  }
  for (const a of arch) enumOf(a, ARCH_VALUES, "runtime.arch");
  const node = str(rt.node, "runtime.node", 256);
  const nr = validateNodeRange(node);
  if (!nr.ok) fail(`runtime.node is not a bounded node range: ${nr.reason}`, "runtime.node");
  const sandbox = enumOf(rt.sandbox, SANDBOX_KINDS, "runtime.sandbox");

  const ad = closed(
    m.adapter,
    ["contract", "entry", "config_schema", "health_timeout_ms", "startup_timeout_ms"],
    "adapter",
  );
  if (ad.contract !== "gateway-adapter/1") {
    unsupported(
      `adapter.contract must be "gateway-adapter/1", got ${JSON.stringify(ad.contract)}`,
      "adapter.contract",
    );
  }
  const entry = treePath(ad.entry, "adapter.entry");
  const configSchema = objectRef(ad.config_schema, "adapter.config_schema");
  const healthTimeout = safeInt(ad.health_timeout_ms, "adapter.health_timeout_ms", 1, 120_000);
  const startupTimeout = safeInt(
    ad.startup_timeout_ms,
    "adapter.startup_timeout_ms",
    1,
    120_000,
  );

  const pv = closed(
    m.provenance,
    ["descriptor", "statements", "builder", "repository", "commit", "lockfile", "sbom"],
    "provenance",
  );
  const descriptor = objectRef(pv.descriptor, "provenance.descriptor");
  if (!Array.isArray(pv.statements) || pv.statements.length > 64) {
    fail("provenance.statements must be an array of ≤64 NativeRefs", "provenance.statements");
  }
  const statements = (pv.statements as unknown[]).map((s, i) =>
    nativeRef(s, `provenance.statements[${i}]`),
  );
  const builder = str(pv.builder, "provenance.builder", 128);
  const repository = str(pv.repository, "provenance.repository", 256);
  const commit = str(pv.commit, "provenance.commit", 128);
  const lockfile = artifactRef(pv.lockfile, "provenance.lockfile");
  const sbom = objectRef(pv.sbom, "provenance.sbom");

  if (!Array.isArray(m.dependencies) || m.dependencies.length > MAX_DEPS) {
    fail(`dependencies must be an array of ≤${MAX_DEPS}`, "dependencies");
  }
  const dependencies = (m.dependencies as unknown[]).map((d, i) =>
    dependency(d, `dependencies[${i}]`),
  );

  const caps = closed(
    m.capabilities,
    ["read_paths", "write_paths", "network_origins", "emit", "consume", "native_profiles"],
    "capabilities",
  );
  const capabilities = {
    read_paths: stringList(caps.read_paths, "capabilities.read_paths"),
    write_paths: stringList(caps.write_paths, "capabilities.write_paths"),
    network_origins: stringList(caps.network_origins, "capabilities.network_origins"),
    emit: stringList(caps.emit, "capabilities.emit"),
    consume: stringList(caps.consume, "capabilities.consume"),
    native_profiles: stringList(caps.native_profiles, "capabilities.native_profiles"),
  };
  for (const [i, p] of capabilities.read_paths.entries()) {
    treePathCheck(p, `capabilities.read_paths[${i}]`);
  }
  for (const [i, p] of capabilities.write_paths.entries()) {
    treePathCheck(p, `capabilities.write_paths[${i}]`);
  }

  const itf = closed(m.interfaces, ["profile", "snapshot", "edges"], "interfaces");
  if (itf.profile !== "interfaces/1") {
    fail(`interfaces.profile must be "interfaces/1"`, "interfaces.profile");
  }
  if (!isHash64(itf.snapshot)) {
    fail("interfaces.snapshot must be 64 lowercase hex", "interfaces.snapshot");
  }
  const edges = stringList(itf.edges, "interfaces.edges", 53);
  for (const [i, e] of edges.entries()) {
    if (!EDGE_RE.test(e)) fail(`interfaces.edges[${i}] must be E01–E53`, `interfaces.edges[${i}]`);
  }

  const sf = closed(
    m.surfaces,
    ["local", "hosted", "tier", "entitlement"],
    "surfaces",
  );
  const surfaces = {
    local: enumOf(sf.local, ["free", "licensed"] as const, "surfaces.local"),
    hosted: bool(sf.hosted, "surfaces.hosted"),
    tier: enumOf(sf.tier, ["oss", "hosted", "enterprise"] as const, "surfaces.tier"),
    entitlement: strOrNull(sf.entitlement, "surfaces.entitlement", 256),
  };

  return {
    schema: "gateway.product/1",
    slug,
    version,
    series,
    license,
    package: { kind: pkgKind, name: pkgName, archive },
    runtime: {
      os: os as ProductManifest["runtime"]["os"],
      arch: arch as ProductManifest["runtime"]["arch"],
      node,
      sandbox,
    },
    adapter: {
      contract: "gateway-adapter/1",
      entry,
      config_schema: configSchema,
      health_timeout_ms: healthTimeout,
      startup_timeout_ms: startupTimeout,
    },
    provenance: {
      descriptor,
      statements,
      builder,
      repository,
      commit,
      lockfile,
      sbom,
    },
    dependencies,
    capabilities,
    interfaces: {
      profile: "interfaces/1",
      snapshot: itf.snapshot as Hash,
      edges,
    },
    surfaces,
  };
}

/** Capability path entries allow absolute paths too but never `..`/`\`. */
function treePathCheck(p: string, field: string): void {
  if (p.includes("\\") || p.includes("\0")) {
    fail(`${field} must not contain backslashes or NUL`, field);
  }
  for (const seg of p.split("/")) {
    if (seg === "..") fail(`${field} must not contain ".."`, field);
  }
}

/** Digest of raw manifest bytes → the hex digest used in plan manifests. */
export function manifestDigestOf(bytes: Uint8Array | string): string {
  const b = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes;
  return sha256Hex(b);
}
