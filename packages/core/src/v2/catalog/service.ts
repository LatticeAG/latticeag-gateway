/**
 * Gateway v2 catalog — CatalogService implementation (spec §3.2/§3.3).
 *
 * Exchange shapes (§3.3):
 *  - catalog.refresh {source,offline?} → {revision,entries,freshness}
 *    (offline:true → OFFLINE_PINNED)
 *  - catalog.search  {q,series,after,limit} → {items,next} — cached
 *    signed entries only, q ≤128 bytes, series enum or null
 *  - catalog.show    {slug,version} → {entry} — entry carries trust
 *    freshness plus adapter_status/surfaces
 *  - catalog.pin     {slug,version,digest,expected_revision} →
 *    {revision,pin} — CAS on the pins revision
 *  - catalog.unpin   {slug,expected_revision} → {revision}
 */

import { Buffer } from "node:buffer";
import type { Count } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type { CatalogService } from "../protocol/services.js";
import type {
  CatalogEntry,
  CatalogPin,
} from "../protocol/catalog.js";
import { SEMVER_RE, SLUG_RE, isSeries } from "../protocol/product.js";
import type { Series } from "../protocol/product.js";
import { CatalogStore } from "./index.js";
import type { CatalogPorts } from "./ports.js";

/** Search page bound (service-side cap; §3.2 leaves it to the handler). */
const SEARCH_LIMIT_MAX = 200;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

function fail(field: string, message: string): never {
  throw new RpcError("SCHEMA_INVALID", message, {
    retryable: false,
    field,
  });
}

function requireSlug(value: unknown): string {
  if (typeof value !== "string" || !SLUG_RE.test(value)) {
    fail("slug", "slug must match the §5.1 slug grammar");
  }
  return value;
}

function requireVersion(value: unknown): string {
  if (typeof value !== "string" || !SEMVER_RE.test(value)) {
    fail("version", "version must be exact SemVer 2.0.0");
  }
  return value;
}

function requireRevision(value: unknown): Count {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    fail("expected_revision", "expected_revision must be a canonical Count");
  }
  return value;
}

export function createCatalogService(ports: CatalogPorts): CatalogService {
  const store = new CatalogStore(ports);

  return {
    async refresh(params: { source: "configured" | string; offline?: boolean }) {
      if (typeof params.source !== "string" || params.source.length === 0) {
        fail("source", "source must be a nonempty string");
      }
      const result = await store.refresh({
        source: params.source,
        offline: params.offline === true,
      });
      return {
        revision: result.revision,
        entries: result.entries,
        freshness: result.freshness,
      };
    },

    async search(params: {
      q: string;
      series: Series | null;
      after: string | null;
      limit: number;
    }) {
      const { q, series, after, limit } = params;
      if (typeof q !== "string" || Buffer.byteLength(q, "utf8") > 128) {
        fail("q", "q must be a string of at most 128 bytes");
      }
      if (series !== null && (typeof series !== "string" || !isSeries(series))) {
        fail("series", "series must be poly/lex/vek/axi/vis/forge or null");
      }
      if (
        typeof limit !== "number" ||
        !Number.isSafeInteger(limit) ||
        limit < 1 ||
        limit > SEARCH_LIMIT_MAX
      ) {
        fail("limit", `limit must be an integer in 1..${SEARCH_LIMIT_MAX}`);
      }
      let offset = 0;
      if (after !== null) {
        if (typeof after !== "string" || !/^[0-9]+$/.test(after)) {
          fail("after", "after must be an opaque page cursor or null");
        }
        offset = Number(after);
      }
      const needle = q.toLowerCase();
      const matched = store
        .entries()
        .filter(
          (entry) =>
            (needle.length === 0 ||
              entry.slug.toLowerCase().includes(needle) ||
              entry.version.toLowerCase().includes(needle)) &&
            (series === null || entry.series === series),
        );
      const items = matched.slice(offset, offset + limit);
      const next = offset + limit < matched.length ? String(offset + limit) : null;
      return { items, next };
    },

    async show(params: { slug: string; version: string }) {
      const slug = requireSlug(params.slug);
      const version = requireVersion(params.version);
      const entry = store
        .entries()
        .find((e) => e.slug === slug && e.version === version);
      if (entry === undefined) {
        throw new RpcError("NOT_FOUND", `no catalog entry ${slug}@${version}`, {
          retryable: false,
          field: "slug",
        });
      }
      // The entry carries its trust freshness beside adapter_status and
      // surfaces (§3.2 catalog.show row).
      const freshness = store.freshness() ?? "TRUST_EXPIRED";
      return { entry: { ...entry, freshness } as CatalogEntry };
    },

    async pin(params: {
      slug: string;
      version: string;
      digest: string;
      expected_revision: Count;
    }) {
      const slug = requireSlug(params.slug);
      const version = requireVersion(params.version);
      if (typeof params.digest !== "string" || !DIGEST_RE.test(params.digest)) {
        fail("digest", 'digest must be "sha256:" + 64 lowercase hex');
      }
      const expected = requireRevision(params.expected_revision);
      const current = ports.pinsRevision();
      if (current !== expected) {
        throw new RpcError(
          "REVISION_CONFLICT",
          `pins revision is ${current}, expected ${expected}`,
          { retryable: false, field: "expected_revision" },
        );
      }
      const index = store.indexCommitment();
      if (index === null) {
        throw new RpcError(
          "NOT_FOUND",
          "no verified catalog index to pin against",
          { retryable: false, field: "index" },
        );
      }
      // One pin per slug: an existing pin is replaced under the same CAS.
      const pin: CatalogPin = { slug, version, digest: params.digest, index };
      const pins = ports.pins().filter((p) => p.slug !== slug);
      pins.push(pin);
      const next = (BigInt(current) + 1n).toString();
      ports.setPins(pins, next);
      return { revision: next, pin };
    },

    async unpin(params: { slug: string; expected_revision: Count }) {
      const slug = requireSlug(params.slug);
      const expected = requireRevision(params.expected_revision);
      const current = ports.pinsRevision();
      if (current !== expected) {
        throw new RpcError(
          "REVISION_CONFLICT",
          `pins revision is ${current}, expected ${expected}`,
          { retryable: false, field: "expected_revision" },
        );
      }
      const pins = ports.pins();
      if (!pins.some((p) => p.slug === slug)) {
        throw new RpcError("NOT_FOUND", `no pin for ${slug}`, {
          retryable: false,
          field: "slug",
        });
      }
      const next = (BigInt(current) + 1n).toString();
      ports.setPins(
        pins.filter((p) => p.slug !== slug),
        next,
      );
      return { revision: next };
    },
  };
}
