/**
 * Gateway v2 catalog — injected ports (spec §9.4).
 *
 * Index bytes are signed as native Sunlight creation/evidence Statements
 * under a separate two-of-three catalog-root role; roots come from the
 * trust configuration, never from the index being verified. All
 * persistence and fetching is injected — `fetchIndex` is a port, never a
 * real network call inside this package.
 */

import type { Count, Hash } from "../protocol/refs.js";
import type {
  CatalogChannel,
  CatalogIndex,
  CatalogPin,
} from "../protocol/catalog.js";
import type { SunlightTrustRoot } from "../crypto/sunlight.js";
import type { CatalogEntry } from "../protocol/catalog.js";

/** Trust configuration view for catalog verification (§9.4). */
export interface CatalogTrustView {
  /** Catalog-root key set from trust config — never from the index. */
  readonly roots: SunlightTrustRoot;
  /** Distinct authorized keys required (two-of-three). */
  readonly quorum: number;
  /** Trusted channel; an untrusted channel cannot switch it. */
  readonly channel: CatalogChannel;
  /** strict=true requires a nonempty allowlist + pins for installs. */
  readonly strict: boolean;
  readonly allowlist: readonly string[];
  /** Config catalog.max_age_s (3600–2592000). */
  readonly max_age_s: number;
}

/** A verified index as persisted (raw bytes + signatures + parsed form). */
export interface CachedIndex {
  /** Persisted canonical index bytes. */
  readonly raw: string;
  /** sha256Hex(raw) — the persisted index digest. */
  readonly digest: Hash;
  /** The retained Sunlight statements that authorized it. */
  readonly signatures: unknown[];
  readonly index: CatalogIndex;
  /** True for an enterprise-approved offline snapshot import. */
  readonly offline: boolean;
}

/** Fetched index payload: parsed index value plus its statements. */
export interface IndexFetch {
  readonly index: unknown;
  readonly signatures: unknown[];
}

/** Retained equal-revision/different-digest evidence (§9.4). */
export interface Equivocation {
  readonly revision: Count;
  readonly current: Hash;
  readonly candidate: Hash;
  readonly raw: string;
}

export interface CatalogPorts {
  now(): number;
  trust(): CatalogTrustView;
  /** Prior verified cache — invalid refreshes never touch it. */
  loadCache(): CachedIndex | null;
  saveCache(cache: CachedIndex): void;
  /** Highest accepted revision/hash — monotonic (§9.4). */
  highestSeen(): { revision: Count; digest: Hash } | null;
  saveHighestSeen(revision: Count, digest: Hash): void;
  /** Retain equivocation evidence; both candidates kept. */
  recordEquivocation(e: Equivocation): void;
  equivocations(): readonly Equivocation[];
  /** Config pins (one per slug) plus their CAS revision. */
  pins(): CatalogPin[];
  pinsRevision(): Count;
  setPins(pins: CatalogPin[], revision: Count): void;
  /**
   * Injected bounded fetch of a signed index from a trusted configured
   * source (≤8 MiB/10000 entries/16 sigs/≤2 redirects are enforced by the
   * caller chain; the port itself never performs IO here).
   */
  fetchIndex(source: string): Promise<IndexFetch>;
  /** Enterprise-approved offline snapshot; null when none is enrolled. */
  offlineSnapshot(): IndexFetch | null;
  /**
   * Trusted-time high-water mark (§9.4): persisted to detect clock
   * rollback. Monotonic — a lower `now` is retained, never applied.
   */
  timeHighWater(): number;
  saveTimeHighWater(ms: number): void;
}

/** Deterministic in-memory CatalogPorts. */
export interface MemoryCatalogPorts extends CatalogPorts {
  readonly clock: { value: number };
  trustView: CatalogTrustView;
  cache: CachedIndex | null;
  highest: { revision: Count; digest: Hash } | null;
  readonly equivocationLog: Equivocation[];
  pinList: CatalogPin[];
  pinRev: bigint;
  /** source name → payload the injected fetch returns. */
  readonly fetchPayloads: Map<string, IndexFetch>;
  snapshot: IndexFetch | null;
  timeHigh: number;
  advance(ms: number): void;
}

export function createMemoryCatalogPorts(opts?: {
  now?: number;
  trust?: Partial<CatalogTrustView>;
}): MemoryCatalogPorts {
  const clock = { value: opts?.now ?? 0 };
  const ports: MemoryCatalogPorts = {
    clock,
    trustView: {
      roots: new Set<string>(),
      quorum: 2,
      channel: "stable",
      strict: false,
      allowlist: [],
      max_age_s: 604_800,
      ...opts?.trust,
    },
    cache: null,
    highest: null,
    equivocationLog: [],
    pinList: [],
    pinRev: 1n,
    fetchPayloads: new Map(),
    snapshot: null,
    timeHigh: 0,
    now: () => clock.value,
    advance(ms: number) {
      clock.value += ms;
    },
    trust: () => ports.trustView,
    loadCache: () => ports.cache,
    saveCache: (cache) => {
      ports.cache = cache;
    },
    highestSeen: () => ports.highest,
    saveHighestSeen: (revision, digest) => {
      ports.highest = { revision, digest };
    },
    recordEquivocation: (e) => {
      ports.equivocationLog.push(e);
    },
    equivocations: () => ports.equivocationLog,
    pins: () => ports.pinList,
    pinsRevision: () => ports.pinRev.toString(),
    setPins: (pins, revision) => {
      ports.pinList = pins;
      ports.pinRev = BigInt(revision);
    },
    async fetchIndex(source) {
      const payload = ports.fetchPayloads.get(source);
      if (payload === undefined) {
        throw new Error(`NETWORK_UNAVAILABLE: no payload for ${source}`);
      }
      return payload;
    },
    offlineSnapshot: () => ports.snapshot,
    timeHighWater: () => ports.timeHigh,
    saveTimeHighWater: (ms) => {
      if (ms > ports.timeHigh) ports.timeHigh = ms;
    },
  };
  return ports;
}

export type { CatalogEntry };
