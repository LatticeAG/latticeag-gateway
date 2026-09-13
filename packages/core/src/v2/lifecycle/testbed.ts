/**
 * Shared test wiring: fixture trust roots, memory ports loaded with the
 * §13.1 releases, and manifest helpers. Test-only module — the daemon
 * binds real ports instead.
 */
import {
  F,
  artifact,
  auditor,
  blob,
  J,
  native,
  now,
  origin,
  release as mkRelease,
  schema,
  tar,
} from "@latticeag/testkit";

import type { CatalogEntry, CatalogIndex } from "../protocol/catalog.js";
import type { Blob, Count, NativeRef } from "../protocol/refs.js";
import type { Dependency, ProductManifest, Release } from "../protocol/product.js";

import { parseProductManifest } from "./manifest.js";
import type { ReleaseTrust } from "./verify.js";
import { createMemoryPorts, retainedRow } from "./testing.js";
import type { MemoryPorts, MemoryPortsOptions } from "./testing.js";
import type { GenerationRow } from "./ports.js";

/** A real NativeRef usable as the commit `review` argument. */
export const REVIEW: NativeRef = F.nativeRef as NativeRef;

/** Trust roots: the two fixture release keys, builder allowlist, no revocations. */
export function fixtureTrust(patch: Partial<ReleaseTrust> = {}): ReleaseTrust {
  return {
    releaseKeys: new Set([origin.material.public, auditor.material.public]),
    signers: new Map<string, string>([
      [origin.sunlight, origin.material.public],
      [auditor.sunlight, auditor.material.public],
    ]),
    builders: new Set(["fixture-builder"]),
    revocations: new Set<string>(),
    keyMaterials: [origin.material, auditor.material],
    ...patch,
  };
}

/** Catalog entry for a fixture release (same shape as F.catalogEntry). */
export function entryFor(rel: typeof F.release1): CatalogEntry {
  return {
    ...(F.catalogEntry as CatalogEntry),
    version: rel.manifest.version,
    manifest: rel.wire.manifest.ref,
    release_signatures: rel.wire.signatures.map(native),
    surfaces: rel.manifest.surfaces,
  } as CatalogEntry;
}

/** Index containing both fixture releases (needed for update/rollback). */
export const INDEX2 = {
  ...(F.index as object),
  entries: [F.catalogEntry, entryFor(F.release2)],
} as CatalogIndex;

export interface FixtureOptions extends MemoryPortsOptions {
  readonly index?: CatalogIndex | null;
  readonly trust?: Partial<ReleaseTrust>;
}

/** Memory ports pre-loaded with release1 + release2 and the trust roots. */
export function fixturePorts(opts: FixtureOptions = {}): MemoryPorts {
  const ports = createMemoryPorts({
    ...opts,
    index: opts.index === undefined ? (INDEX2 as CatalogIndex) : opts.index,
    trust: fixtureTrust(opts.trust),
    fakeClock: { startMs: now },
  });
  ports.putRelease(F.release1.wire as Release, F.release1.archive);
  ports.putRelease(F.release2.wire as Release, F.release2.archive);
  return ports;
}

/** Parse the manifest blob of a fixture release. */
export function manifestOf(rel: typeof F.release1): ProductManifest {
  return parseProductManifest(
    Buffer.from(rel.wire.manifest.content, "base64url"),
  );
}

/** Clone a manifest with shallow patches (for resolver-only fixtures). */
export function manifestPatched(
  rel: typeof F.release1,
  patch: Partial<ProductManifest>,
): ProductManifest {
  return { ...manifestOf(rel), ...patch };
}

/** A required/optional/evidence dependency record. */
export function dep(
  slug: string,
  range: string,
  kind: Dependency["kind"] = "required",
  edge: string | null = null,
): Dependency {
  return { slug, range, kind, edge, capability: null, pin: null };
}

/** Re-exported fixture helpers the tests use directly. */
export { F, artifact, auditor, blob, J, mkRelease, native, now, origin, schema, tar };
export type { Release };
export { retainedRow };
export type { GenerationRow, MemoryPorts };
export type { Count };
export type { Blob };
