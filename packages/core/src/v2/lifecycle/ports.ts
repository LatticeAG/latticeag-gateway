/**
 * LifecyclePorts — the seam the daemon implements. Everything the
 * lifecycle engine touches outside pure computation flows through these
 * ports so tests can inject in-memory fakes, a scripted clock, fault
 * injection, and recording sinks. See testing.ts `createMemoryPorts`.
 */
import type { CatalogIndex } from "../protocol/catalog.js";
import type { ProductState, TransitionEvent } from "../protocol/lifecycle.js";
import type { Count, Hash, Id, Json } from "../protocol/refs.js";
import type { Dependency, Release, SandboxKind } from "../protocol/product.js";
import type { AdapterChild } from "./adapter-client.js";
import type { ClockOps } from "./health.js";
import type { ReleaseTrust } from "./verify.js";

/** Exact release locator (slug + exact version). */
export interface SourceRef {
  readonly slug: string;
  readonly version: string;
}

/** A fetched release: wire object plus the archive bytes it names. */
export interface FetchedRelease {
  readonly release: Release;
  readonly archive: Uint8Array;
}

/** Catalog port — the registry fetcher downloads bytes only. */
export interface CatalogPort {
  fetch(sref: SourceRef): Promise<FetchedRelease>;
  /** Signed index snapshot used at plan time (null = local-only). */
  index(): Promise<CatalogIndex | null>;
  /** All versions of a slug the catalog knows (dependency resolution). */
  versions(slug: string): Promise<string[]>;
}

/** Registry generation row — per immutable candidate/version. */
export interface GenerationRow {
  slug: string;
  version: string;
  /** Monotonic generation id (decimal string). */
  generation: Count;
  state: ProductState;
  /** The active pointer targets this generation. */
  active: boolean;
  manifest_digest: Hash;
  archive_digest: string;
  staged_dir: string | null;
  data_dir: string | null;
  /** OS pid of the owned adapter process when live. */
  pid: number | null;
  /** Dependencies carried from the signed manifest (dependents checks). */
  dependencies: Dependency[];
  /** Activation projection indexed exactly once (TV-GW-12). */
  activation_indexed: boolean;
  /** Post-commit projection applied. */
  projected: boolean;
  /** Verified rollback snapshot exists for this generation's data. */
  snapshot_verified: boolean;
  /** Data migrated without a verified inverse. */
  irreversible_data: boolean;
  /** Executable discovery entries withdrawn (DEGRADED). */
  capabilities_withdrawn: boolean;
  /** Restart-budget start timestamps (ms). */
  starts: number[];
}

/** Registry port: generation rows plus the atomic active pointer. */
export interface ProductRegistryPort {
  generations(slug: string): GenerationRow[];
  all(): GenerationRow[];
  get(slug: string, generation: Count): GenerationRow | undefined;
  create(row: GenerationRow): GenerationRow;
  update(slug: string, generation: Count, patch: Partial<GenerationRow>): void;
  active(slug: string): GenerationRow | undefined;
  /** Compare-and-set the active pointer; false on expected mismatch. */
  casActive(slug: string, expected: Count | null, next: Count | null): boolean;
  nextGeneration(slug: string): Count;
  /** CAS revision of the registry document (plan staleness). */
  revision(): Count;
}

/** Filesystem layout the engine stages/extracts into. */
export interface PathsPort {
  /** Staging root for a candidate generation. */
  stageDir(slug: string, generation: Count): string;
  /** Private versioned data dir for a generation. */
  dataDir(slug: string, generation: Count): string;
  /** Remove a staged tree after REJECTED/REMOVED (package links only). */
  removeStage?(dir: string): void;
}

/** Operator/catalog policy view consulted at plan + activation time. */
export interface PolicyView {
  readonly strict: boolean;
  readonly allowlist: readonly string[];
  /** Sandboxes this host can actually enforce. */
  readonly sandboxes: readonly SandboxKind[];
}

/** A journal mutation the engine asks the daemon to commit. */
export interface JournalMutation {
  readonly type:
    | "operation"
    | "transition"
    | "start_intent"
    | "active_pointer"
    | "projection"
    | "tombstone";
  readonly operation?: Id;
  readonly slug?: string;
  readonly generation?: Count;
  readonly detail?: Json;
}

/** Transition receipt emitted to the sink (spec §5.4 named events). */
export interface TransitionReceipt {
  readonly event: TransitionEvent;
  readonly operation: Id;
  readonly slug: string;
  readonly generation: Count;
  readonly from: ProductState;
  readonly to: ProductState;
  readonly at_ms: number;
  readonly detail?: Json;
}

/**
 * All ports are injectable. `spawnAdapter` receives the full argv and env
 * — adapter secrets never travel on argv/env; they are delivered on a
 * private inherited descriptor arranged by the daemon implementation.
 */
export interface LifecyclePorts {
  readonly catalog: CatalogPort;
  trustStore(): ReleaseTrust;
  readonly productRegistry: ProductRegistryPort;
  spawnAdapter(
    cmd: readonly string[],
    dir: string,
    env: Record<string, string>,
  ): AdapterChild | Promise<AdapterChild>;
  readonly clock: ClockOps;
  journalMutation(m: JournalMutation): void | Promise<void>;
  receiptSink(e: TransitionReceipt): void | Promise<void>;
  readonly paths: PathsPort;
  platform(): { os: string; arch: string; node: string };
  policy(): PolicyView;
  /** Current CAS revisions bound into every plan. */
  revisions(): { config: Count; catalog: Count; registry: Count };
  /**
   * Optional post-crash probe: verify an owned process is alive/healthy
   * when the engine has no live client handle (recovery path).
   */
  probeGeneration?(row: GenerationRow): Promise<boolean>;
  /** Optional liveness check for a pid retained across restart. */
  pidAlive?(pid: number): boolean;
}
