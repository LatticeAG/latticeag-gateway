/**
 * createProductService — the ProductService facade over LifecycleEngine.
 *
 * Plan → review → commit flow (§5.4):
 *  - product.plan resolves + binds inputs into a content-addressed plan
 *    (hash-bound to manifest + archive bytes, pinned to CAS revisions).
 *  - Mutations carry the plan hash plus a native `review` ref (the
 *    operator review matched to the plan); a wrong kind, stale revision,
 *    unknown hash, or moved `from` rejects PLAN_STALE.
 *  - Mutations return `{operation, state:"QUEUED"}`; the engine runs the
 *    transition sequence asynchronously and operation.get observes it.
 */
import { RpcError } from "../protocol/errors.js";
import type { ErrorCode } from "../protocol/errors.js";
import type { Accepted, Page } from "../protocol/envelope.js";
import type { Hash, Json, NativeRef } from "../protocol/refs.js";
import { SLUG_RE, SEMVER_RE } from "../protocol/product.js";
import type { ProductManifest } from "../protocol/product.js";
import type {
  OperationKind,
  OperationService,
  ProductService,
} from "../protocol/services.js";

import { LifecycleEngine } from "./engine.js";
import type {
  EngineOptions,
  OperationKind as EngineOperationKind,
  OperationRecord,
  RunContext,
} from "./engine.js";
import { manifestDigestOf, parseProductManifest } from "./manifest.js";
import { resolvePlan } from "./resolve.js";
import type { InstalledProduct, PlanSummary } from "./resolve.js";
import type { LifecyclePorts, SourceRef } from "./ports.js";

interface StoredPlan {
  readonly summary: PlanSummary;
  readonly sref: SourceRef | null;
  /** `pinned` was requested at plan time (offline/pinned installs). */
  readonly pinned: boolean;
}

export interface ServiceOptions {
  readonly engine?: EngineOptions;
  /** Plan-time manifest fetch bound (default 64). */
  readonly planFetchBound?: number;
}

export interface ProductServiceBundle {
  readonly product: ProductService;
  readonly operation: OperationService;
  readonly engine: LifecycleEngine;
  /** Await an operation's terminal record (test/daemon helper). */
  waitOperation(id: string): Promise<OperationRecord>;
  readonly plans: ReadonlyMap<Hash, StoredPlan>;
}

const SREF_RE = /^([a-z][a-z0-9-]{0,63})(?:@([^\s]+))?$/;
const MAX_PLAN_FETCHES = 64;

/** Decode a wire `{ref,content}` manifest blob to raw bytes. */
function manifestBlobBytes(manifest: unknown): Uint8Array {
  const content = (manifest as { content?: unknown }).content;
  if (typeof content === "string") {
    return new Uint8Array(Buffer.from(content, "base64url"));
  }
  if (manifest instanceof Uint8Array) return manifest;
  throw new RpcError("SCHEMA_INVALID", "release manifest is not a blob", {
    field: "manifest",
  });
}

/** plan() accepts the wire params plus a local `pinned` review flag. */
type PlanParams = Parameters<ProductService["plan"]>[0] & { pinned?: boolean };
type CommitParams = { plan: Hash; review: NativeRef };

export function createProductService(
  ports: LifecyclePorts,
  opts: ServiceOptions = {},
): ProductServiceBundle {
  const engine = new LifecycleEngine(ports, opts.engine);
  const plans = new Map<Hash, StoredPlan>();
  const runs = new Map<string, Promise<OperationRecord>>();

  const parseSref = (source: string, version?: string): SourceRef => {
    const m = SREF_RE.exec(source);
    if (!m) {
      throw new RpcError("SCHEMA_INVALID", `bad source "${source}"`, { field: "source" });
    }
    const v = version ?? m[2];
    if (v === undefined || !SEMVER_RE.test(v)) {
      throw new RpcError("SCHEMA_INVALID", `source "${source}" needs an exact version`, {
        field: "version",
      });
    }
    return { slug: m[1]!, version: v };
  };

  const installedView = (): InstalledProduct[] =>
    ports.productRegistry
      .all()
      .filter((g) => g.state !== "REMOVED")
      .map((g) => ({
        slug: g.slug,
        version: g.version,
        state: g.state,
        active: g.active,
        dependencies: g.dependencies,
      }));

  /**
   * Gather every manifest version the resolver can see for `slugs`,
   * bounded; catalog fetches only (no execution).
   */
  const gatherManifests = async (
    target: SourceRef,
    firstManifest: ProductManifest,
  ): Promise<Map<string, ProductManifest[]>> => {
    const manifests = new Map<string, ProductManifest[]>();
    const add = (m: ProductManifest): void => {
      const arr = manifests.get(m.slug) ?? [];
      if (!arr.some((x) => x.version === m.version)) arr.push(m);
      manifests.set(m.slug, arr);
    };
    add(firstManifest);
    const queue: ProductManifest[] = [firstManifest];
    let fetched = 0;
    const bound = opts.planFetchBound ?? MAX_PLAN_FETCHES;
    const seen = new Set<string>([target.slug]);
    while (queue.length > 0) {
      const mf = queue.shift()!;
      for (const d of mf.dependencies) {
        if (d.kind === "evidence") continue;
        if (seen.has(d.slug)) continue;
        seen.add(d.slug);
        const versions = await ports.catalog.versions(d.slug);
        for (const v of versions) {
          if (++fetched > bound) {
            throw new RpcError(
              "DEPENDENCY_CONFLICT",
              "dependency manifest fetch bound exceeded",
              { field: "dependencies" },
            );
          }
          const f = await ports.catalog.fetch({ slug: d.slug, version: v });
          const dep = parseProductManifest(manifestBlobBytes(f.release.manifest));
          add(dep);
          queue.push(dep);
        }
      }
    }
    return manifests;
  };

  const checkReview = (review: NativeRef): void => {
    if (typeof review !== "object" || review === null) {
      throw new RpcError(
        "POLICY_DENIED",
        "commit requires an explicit review ref matched to the plan",
        { field: "review" },
      );
    }
  };

  const commitChecks = (
    plan: Hash,
    want: "install" | "update" | "uninstall" | "rollback",
    review: NativeRef,
  ): StoredPlan => {
    const stored = plans.get(plan);
    if (!stored) {
      throw new RpcError("PLAN_STALE", "plan hash was never issued by product.plan", {
        field: "plan",
      });
    }
    if (stored.summary.kind !== want) {
      throw new RpcError(
        "PLAN_STALE",
        `plan kind "${stored.summary.kind}" cannot commit ${want}`,
        { field: "plan" },
      );
    }
    const rev = ports.revisions();
    if (
      stored.summary.revisions.config !== rev.config ||
      stored.summary.revisions.catalog !== rev.catalog ||
      stored.summary.revisions.registry !== rev.registry
    ) {
      throw new RpcError("PLAN_STALE", "plan revisions no longer match", {
        field: "revisions",
      });
    }
    checkReview(review);
    return stored;
  };

  const start = (
    kind: EngineOperationKind,
    stored: StoredPlan,
    extra?: Partial<RunContext>,
  ): Accepted => {
    const op = engine.createOperation(kind, stored.summary.slug, stored.summary.from, stored.summary.to);
    const ctx: RunContext = {
      plan: stored.summary,
      pinned: stored.pinned,
      ...(stored.sref ? { sref: stored.sref } : {}),
      ...extra,
    };
    const done =
      kind === "install"
        ? engine.install(ctx, op)
        : kind === "update"
          ? engine.update(ctx, op)
          : kind === "rollback"
            ? engine.rollback(ctx, op)
            : engine.uninstall(ctx, op);
    runs.set(
      op.id,
      done.catch(() => op),
    );
    return { operation: op.id, state: "QUEUED" };
  };

  const product: ProductService = {
    plan: async (p) => {
      const params = p as PlanParams;
      if (
        params.kind !== "install" &&
        params.kind !== "update" &&
        params.kind !== "uninstall" &&
        params.kind !== "rollback"
      ) {
        throw new RpcError("SCHEMA_INVALID", `unknown plan kind "${String(params.kind)}"`, {
          field: "kind",
        });
      }
      const index = await ports.catalog.index();
      const policy = ports.policy();
      const installed = installedView();
      const revisions = ports.revisions();
      const trust = ports.trustStore();
      const resolveOpts = {
        now: ports.clock.now(),
        pinned: params.pinned === true,
        strict: policy.strict,
        allowlist: policy.allowlist,
        cascade: params.cascade === true,
        keep_data: params.keep_data !== false,
        revisions,
        trustMaterials: trust.keyMaterials ?? [...trust.releaseKeys].sort(),
      };

      if (params.kind === "uninstall") {
        const m = SREF_RE.exec(params.source);
        if (!m || !SLUG_RE.test(m[1]!)) {
          throw new RpcError("SCHEMA_INVALID", `bad source "${params.source}"`, {
            field: "source",
          });
        }
        const resolved = resolvePlan({
          kind: "uninstall",
          source: m[1]!,
          manifests: new Map(),
          index,
          installed,
          opts: resolveOpts,
        });
        plans.set(resolved.plan, { summary: resolved.summary, sref: null, pinned: false });
        return { plan: resolved.plan, summary: resolved.summary as unknown as Json };
      }

      const sref = parseSref(params.source, params.version);
      if (params.kind === "update" && !ports.productRegistry.active(sref.slug)) {
        throw new RpcError("NOT_FOUND", `"${sref.slug}" is not installed`, {
          field: "source",
        });
      }
      const fetched = await ports.catalog.fetch(sref);
      const manifestBytes = manifestBlobBytes(fetched.release.manifest);
      const manifest = parseProductManifest(manifestBytes);
      const manifests = await gatherManifests(sref, manifest);
      const resolved = resolvePlan({
        kind: params.kind,
        source: sref.slug,
        version: sref.version,
        target: {
          manifest,
          manifestDigest: manifestDigestOf(manifestBytes) as Hash,
        },
        manifests,
        index,
        installed,
        opts: resolveOpts,
      });
      plans.set(resolved.plan, {
        summary: resolved.summary,
        sref,
        pinned: params.pinned === true,
      });
      return { plan: resolved.plan, summary: resolved.summary as unknown as Json };
    },

    install: async (p: CommitParams) => {
      const stored = commitChecks(p.plan, "install", p.review);
      return start("install", stored);
    },

    update: async (p: CommitParams) => {
      const stored = commitChecks(p.plan, "update", p.review);
      const active = ports.productRegistry.active(stored.summary.slug);
      if (!active || active.version !== stored.summary.from) {
        throw new RpcError("PLAN_STALE", "plan.from no longer matches the active version", {
          field: "from",
        });
      }
      return start("update", stored);
    },

    rollback: async (p: CommitParams) => {
      const stored = commitChecks(p.plan, "rollback", p.review);
      const active = ports.productRegistry.active(stored.summary.slug);
      if (!active || active.version !== stored.summary.from) {
        throw new RpcError("PLAN_STALE", "plan.from no longer matches the active version", {
          field: "from",
        });
      }
      return start("rollback", stored);
    },

    uninstall: async (p: CommitParams) => {
      const stored = commitChecks(p.plan, "uninstall", p.review);
      return start("uninstall", stored);
    },

    list: (p) => {
      const rows: Json[] = [];
      const bySlug = new Map<string, { slug: string; gens: { version: string; state: string; active: boolean; generation: string }[] }>();
      for (const g of ports.productRegistry.all()) {
        if (g.state === "REMOVED") continue;
        const bucket = bySlug.get(g.slug) ?? { slug: g.slug, gens: [] };
        bucket.gens.push({
          version: g.version,
          state: g.state,
          active: g.active,
          generation: g.generation,
        });
        bySlug.set(g.slug, bucket);
      }
      for (const { slug, gens } of bySlug.values()) {
        const active = gens.find((g) => g.active) ?? gens[gens.length - 1]!;
        rows.push({
          slug,
          version: active.version,
          state: active.state,
          active: active.active,
          generations: gens.map((g) => g.generation),
        } as unknown as Json);
      }
      const offset = p.after !== null ? Number(p.after) : 0;
      const limit = Math.min(Math.max(p.limit, 1), 200);
      const items = rows.slice(offset, offset + limit);
      const page: Page<Json> = {
        items,
        next: offset + limit < rows.length ? String(offset + limit) : null,
      };
      return Promise.resolve(page);
    },

    health: async (p) => {
      const gen = ports.productRegistry
        .generations(p.slug)
        .filter((g) => g.state !== "REMOVED")
        .sort((a, b) => Number(BigInt(b.generation) - BigInt(a.generation)))
        .find((g) => g.active) ??
        ports.productRegistry
          .generations(p.slug)
          .filter((g) => g.state !== "REMOVED")
          .sort((a, b) => Number(BigInt(b.generation) - BigInt(a.generation)))[0];
      if (!gen) {
        throw new RpcError("NOT_FOUND", `"${p.slug}" is not installed`, { field: "slug" });
      }
      let liveness = false;
      let readiness = false;
      let native: Json = null;
      const client = engine.clientFor(p.slug);
      if (client !== undefined) {
        try {
          const h = await client.health({ generation: gen.generation });
          liveness = h.liveness;
          readiness = h.readiness;
          native = h.native;
        } catch {
          /* reported as dead below */
        }
      }
      const manifest = engine.manifestFor(p.slug, gen.generation);
      return {
        slug: p.slug,
        state: gen.state,
        liveness,
        readiness,
        sandbox: manifest?.runtime.sandbox ?? "linux-ns",
        native,
      };
    },
  };

  const operation: OperationService = {
    get: (p) => {
      const op = engine.getOperation(p.operation);
      if (!op) {
        return Promise.reject(
          new RpcError("NOT_FOUND", `operation "${p.operation}" unknown`),
        );
      }
      return Promise.resolve({
        operation: op.id,
        kind: op.kind as OperationKind,
        state: op.state,
        slug: op.slug,
        from: op.from,
        to: op.to,
        cursor: op.cursor,
        error: op.error
          ? {
              code: op.error.code as ErrorCode,
              retryable: op.error.retryable,
              field: op.error.field,
            }
          : null,
      });
    },
    cancel: async (p) => {
      const op = await engine.cancelOperation(p.operation);
      return { operation: op.id, state: op.state };
    },
  };

  return {
    product,
    operation,
    engine,
    plans,
    waitOperation: (id) => {
      const run = runs.get(id);
      if (!run) {
        return Promise.reject(new RpcError("NOT_FOUND", `operation "${id}" unknown`));
      }
      return run;
    },
  };
}
