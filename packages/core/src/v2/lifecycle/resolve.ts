/**
 * §5.3 dependency resolver — topological resolution of required packages
 * plus the complete E01–E53 edge-disposition table binding Gateway's
 * operational interpretation of the interfaces/1 registry.
 *
 * A dependency edge is not automatically a hard package dependency: only
 * the consumer's signed manifest can mark a required capability, and
 * evidence-only relationships never trigger installs. Cycles reject with
 * DEPENDENCY_CONFLICT carrying the exact cycle path. Blocked edges fail
 * pre-allocation with the edge's specific code — E17/E21/E49
 * UNSUPPORTED_COMPOSITION, E28 CAP_ADAPTER_UNAVAILABLE, E38
 * MINT_EXCLUSIVE_HOLD_UNAVAILABLE; E35 carries PROVENANCE_INVALID for its
 * handoff-mismatch check without blocking plan resolution.
 */
import { RpcError } from "../protocol/errors.js";
import type { RegistryErrorCode } from "../protocol/errors.js";
import type { CatalogIndex } from "../protocol/catalog.js";
import type { Dependency, ProductManifest } from "../protocol/product.js";
import { SEMVER_RE, SLUG_RE } from "../protocol/product.js";
import type { Count, Hash } from "../protocol/refs.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import { compareSemver, parseSemver, satisfiesSemver } from "./semver.js";
import type { SemVer } from "./semver.js";

// ── Edge dispositions (§5.3 table, verbatim rule text) ───────────────────

export interface EdgeDisposition {
  /** Registry edge id, E01–E53. */
  readonly edge: string;
  /** Producer product name (left of → in the spec Boundary column). */
  readonly producer: string;
  /** Consumer product name (right of →). */
  readonly consumer: string;
  /** Verbatim Gateway disposition rule text from spec §5.3. */
  readonly rule: string;
  /**
   * The error code this edge's failures map to. When `blocksRequired` is
   * true a manifest marking this edge `required` fails resolution with
   * this code pre-allocation; otherwise the code applies when the edge's
   * own runtime/handoff check fails (e.g. E35 SunlightHandoff mismatch →
   * PROVENANCE_INVALID, E26 oversized stream → OBJECT_LIMIT).
   */
  readonly code: RegistryErrorCode | null;
  /** Whether a required dependency on this edge fails resolution. */
  readonly blocksRequired: boolean;
}

export const EDGE_DISPOSITIONS: readonly EdgeDisposition[] = [
  { edge: "E01", producer: "LexTier", consumer: "VekQuorum", rule: "Pinned enrichment adapter; advisory card, zero votes.", code: null, blocksRequired: false },
  { edge: "E02", producer: "LexScope", consumer: "LexTier", rule: "Direct chaining blocked; exact tool/authority mapping absent.", code: "UNSUPPORTED_COMPOSITION", blocksRequired: true },
  { edge: "E03", producer: "LexTier", consumer: "LexSieve", rule: "Pinned candidate binding before every model/cache/log return.", code: null, blocksRequired: false },
  { edge: "E04", producer: "LexScope", consumer: "LexSieve", rule: "Credential scrub before screening; both bounds/checks retained.", code: null, blocksRequired: false },
  { edge: "E05", producer: "LexShield", consumer: "LexTier", rule: "Required compatible native check; absence blocks readiness.", code: "CAP_ADAPTER_UNAVAILABLE", blocksRequired: false },
  { edge: "E06", producer: "LexShield", consumer: "LexSieve", rule: "Separate return-policy port; only its permitted pinned static fallback.", code: null, blocksRequired: false },
  { edge: "E07", producer: "VekInbox", consumer: "LexTier", rule: "Upsert/ack projection; authenticated native callbacks, no reviewer authority from service possession.", code: null, blocksRequired: false },
  { edge: "E08", producer: "Herald", consumer: "LexScope", rule: "Native challenge/card/sub/key binding; ≤5 s fresh, cache ≤60 s, fail closed.", code: null, blocksRequired: false },
  { edge: "E09", producer: "Herald", consumer: "World", rule: "Key-control evidence plus approved local UID mapping; creates no World capability.", code: null, blocksRequired: false },
  { edge: "E10", producer: "Herald", consumer: "Mint", rule: "Key-control evidence; no new principal_group from key rotation.", code: null, blocksRequired: false },
  { edge: "E11", producer: "Herald", consumer: "Treaty", rule: "Original evidence alongside treaty identity; no DID/signature substitution.", code: null, blocksRequired: false },
  { edge: "E12", producer: "VekQuorum", consumer: "Charter", rule: "Independent gate only; never translate votes into Charter signatures.", code: null, blocksRequired: false },
  { edge: "E13", producer: "VekQuorum", consumer: "Bedrock", rule: "Independent gate; Bedrock deny wins and publication remains native.", code: null, blocksRequired: false },
  { edge: "E14", producer: "Bedrock", consumer: "Charter", rule: "Explicit newly signed translation and differential corpus; not a byte alias.", code: null, blocksRequired: false },
  { edge: "E15", producer: "Bedrock", consumer: "World", rule: "Pure evaluator inside World's actual dispatch barrier.", code: null, blocksRequired: false },
  { edge: "E16", producer: "Charter", consumer: "World", rule: "Embedded evaluator; no remote amendment ceremony supplied.", code: null, blocksRequired: false },
  { edge: "E17", producer: "Charter", consumer: "Mint", rule: "Block real-money authority; Charter supplies no court/precedent law.", code: "UNSUPPORTED_COMPOSITION", blocksRequired: true },
  { edge: "E18", producer: "World", consumer: "Proof", rule: "Exact world-lineage/1 EvidenceAttached; inner NOT_EVALUATED.", code: null, blocksRequired: false },
  { edge: "E19", producer: "Mint", consumer: "World", rule: "Opaque join, not a World cause or invented SlashApplied event.", code: null, blocksRequired: false },
  { edge: "E20", producer: "Mint", consumer: "Treaty", rule: "Advisory offline artifacts; no automatic penalty or netting.", code: null, blocksRequired: false },
  { edge: "E21", producer: "Treaty", consumer: "Covenant", rule: "Prepared refund execution forbidden under current pair-2pc profile.", code: "UNSUPPORTED_COMPOSITION", blocksRequired: true },
  { edge: "E22", producer: "VekQuorum", consumer: "Commit", rule: "Evidence only; separate payer, custody, policy, and approvals.", code: null, blocksRequired: false },
  { edge: "E23", producer: "Commit", consumer: "Proof", rule: "Pinned AuditDelivery collector into import API; no invented native audit-ingest endpoint.", code: null, blocksRequired: false },
  { edge: "E24", producer: "Seatbelt", consumer: "Proof", rule: "Ordinary observation object; retain FULL/METADATA and HOST_ATTESTED.", code: null, blocksRequired: false },
  { edge: "E25", producer: "Watch", consumer: "Proof", rule: "Original watch-proof/1 objects; preserve facts_verified=false.", code: null, blocksRequired: false },
  { edge: "E26", producer: "Charter", consumer: "Proof", rule: "Bounded objects only; reject oversized 12 GiB stream under current profile.", code: "OBJECT_LIMIT", blocksRequired: false },
  { edge: "E27", producer: "VisLineage", consumer: "Proof", rule: "Exact vislineage-bundle/1 ≤1 MiB; NORMALIZED_ONLY unchanged.", code: null, blocksRequired: false },
  { edge: "E28", producer: "LexWatt", consumer: "Trellis", rule: "CAP_ADAPTER_UNAVAILABLE until joint lifetime/FD/containment certification.", code: "CAP_ADAPTER_UNAVAILABLE", blocksRequired: true },
  { edge: "E29", producer: "Trellis", consumer: "Weather", rule: "Pinned native export projection; arrival time is not heartbeat safety.", code: null, blocksRequired: false },
  { edge: "E30", producer: "VisLineage", consumer: "Weather", rule: "Source-scoped projection; no invented cost or timestamp.", code: null, blocksRequired: false },
  { edge: "E31", producer: "Weather", consumer: "Watch", rule: "Operator-visible advisory evidence only; no clearance or policy command.", code: null, blocksRequired: false },
  { edge: "E32", producer: "Watch", consumer: "Weather", rule: "Native collector gate; no invented watch-export/1 profile.", code: null, blocksRequired: false },
  { edge: "E33", producer: "Watch", consumer: "Seatbelt", rule: "Enrolled stop/tighten controller only; no latch reset/capacity refill.", code: null, blocksRequired: false },
  { edge: "E34", producer: "ForgeVerity", consumer: "Sunlight", rule: "Canonical raw export; durable ack uses whole canonical-byte hash.", code: null, blocksRequired: false },
  { edge: "E35", producer: "VisLineage", consumer: "Sunlight", rule: "Check SunlightHandoff; native body commitment distinct from raw digest.", code: "PROVENANCE_INVALID", blocksRequired: false },
  { edge: "E36", producer: "EvalSeal", consumer: "Weather", rule: "Dated baseline evidence; expiry never becomes a detector threshold.", code: null, blocksRequired: false },
  { edge: "E37", producer: "Weather", consumer: "EvalSeal", rule: "No conversion to official suite, band, or certificate.", code: null, blocksRequired: false },
  { edge: "E38", producer: "Mint", consumer: "Bond", rule: "MINT_EXCLUSIVE_HOLD_UNAVAILABLE; task.fund is not exclusive liability hold.", code: "MINT_EXCLUSIVE_HOLD_UNAVAILABLE", blocksRequired: true },
  { edge: "E39", producer: "Bedrock", consumer: "Bond", rule: "Pure exact-pin evaluator; deny wins at native dispatch barrier.", code: null, blocksRequired: false },
  { edge: "E40", producer: "Trellis", consumer: "Bond", rule: "Bound run/task/host evidence; retrospective kill does not reverse effects.", code: null, blocksRequired: false },
  { edge: "E41", producer: "VekRevert", consumer: "Bond", rule: "Native inverse/lookup release required; no World-replay replacement.", code: "CAP_ADAPTER_UNAVAILABLE", blocksRequired: false },
  { edge: "E42", producer: "GhostSession", consumer: "Proof", rule: "Opaque receipt; never cookies, vault plaintext, login or retry authority.", code: null, blocksRequired: false },
  { edge: "E43", producer: "PolyCite", consumer: "Proof", rule: "Private claim/source bytes; preserve sequence zero and final outcome.", code: null, blocksRequired: false },
  { edge: "E44", producer: "EvalSeal", consumer: "Proof", rule: "Whole signed objects; no automatic ZIP unpack or current certification.", code: null, blocksRequired: false },
  { edge: "E45", producer: "LexWatt", consumer: "Proof", rule: "Preserve coverage and wide quantities; never narrow into Proof Count.", code: null, blocksRequired: false },
  { edge: "E46", producer: "ForgeVerity", consumer: "Proof", rule: "Original gate/release evidence; no semantic-truth assertion.", code: null, blocksRequired: false },
  { edge: "E47", producer: "Sunlight", consumer: "Proof", rule: "Original profiles/objects; storage is not provenance re-verification.", code: null, blocksRequired: false },
  { edge: "E48", producer: "CIS Guardian", consumer: "Proof", rule: "Explicit private consent and compatible deletion only; no MIT/public inheritance.", code: null, blocksRequired: false },
  { edge: "E49", producer: "LexTier", consumer: "GhostSession", rule: "Direct browser dispatch blocked; outside the native six-tool registry.", code: "UNSUPPORTED_COMPOSITION", blocksRequired: true },
  { edge: "E50", producer: "PolyCite", consumer: "PolyBrain/VisBoard", rule: "Validated render only; no blocked final text or automatic URL retrieval.", code: null, blocksRequired: false },
  { edge: "E51", producer: "ForgeDistill", consumer: "ForgeVerity", rule: "Signed candidate assertion, not trusted gate decision.", code: null, blocksRequired: false },
  { edge: "E52", producer: "EvalHarness", consumer: "EvalSeal", rule: "Licensed pinned actual suites/runner/oracle; fixtures cannot certify.", code: "ENTITLEMENT_REQUIRED", blocksRequired: false },
  { edge: "E53", producer: "World", consumer: "Seatbelt", rule: "One actual dispatcher/lifetime boundary; independent check-then-act calls rejected.", code: "UNSUPPORTED_COMPOSITION", blocksRequired: false },
];

const EDGE_MAP: ReadonlyMap<string, EdgeDisposition> = new Map(
  EDGE_DISPOSITIONS.map((d) => [d.edge, d]),
);

/** Look up the disposition for a registry edge id. */
export function edgeDisposition(edge: string): EdgeDisposition | undefined {
  return EDGE_MAP.get(edge);
}

// ── Resolver input/output shapes ─────────────────────────────────────────

/** A product row visible to the resolver (installed registry view). */
export interface InstalledProduct {
  readonly slug: string;
  readonly version: string;
  readonly state: string;
  readonly active: boolean;
  /** Signed manifest dependencies carried on the installed generation. */
  readonly dependencies: readonly Dependency[];
}

/** Locked dependency entry embedded in a plan. */
export interface PlanDependency {
  readonly slug: string;
  readonly version: string;
  readonly kind: "required" | "optional" | "evidence" | "cascade-remove";
  readonly edge: string | null;
  readonly capability: string | null;
  readonly pin: Hash | null;
  /** Locked manifest digest when known (64 hex). */
  readonly manifest: Hash | null;
  /** Locked "sha256:…" archive digest when known. */
  readonly archive: string | null;
}

/** Plan summary — the shape `planFor` builds in the fixture prelude. */
export interface PlanSummary {
  readonly kind: "install" | "update" | "uninstall" | "rollback";
  readonly slug: string;
  readonly from: string | null;
  readonly to: string | null;
  readonly manifest: Hash;
  readonly archive: string;
  readonly dependencies: readonly PlanDependency[];
  readonly grants: ProductManifest["capabilities"] | null;
  readonly revisions: { config: Count; catalog: Count; registry: Count };
  readonly trust: Hash;
  readonly keep_data: boolean;
  readonly cascade: boolean;
}

export interface ResolveOptions {
  readonly now?: number;
  /** Pinned/offline installs survive index expiry (TV-GW-45). */
  readonly pinned?: boolean;
  /** catalog.strict — empty allowlist authorizes zero installs (TV-GW-46). */
  readonly strict?: boolean;
  readonly allowlist?: readonly string[];
  readonly cascade?: boolean;
  readonly keep_data?: boolean;
  readonly revisions?: { config: Count; catalog: Count; registry: Count };
  /** Ordered pinned release-key material hashed into `summary.trust`. */
  readonly trustMaterials?: readonly unknown[];
}

export interface ResolveInput {
  readonly kind: "install" | "update" | "uninstall" | "rollback";
  /** Signed catalog slug (or `slug@version`), npm selector, local locator. */
  readonly source: string;
  readonly version?: string;
  /**
   * Target manifest + locked digests for install/update/rollback. For
   * uninstall the installed generation supplies the digests.
   */
  readonly target?: {
    readonly manifest: ProductManifest;
    readonly manifestDigest: Hash;
  };
  /** All manifests visible to resolution, keyed by slug. */
  readonly manifests:
    | ReadonlyMap<string, readonly ProductManifest[]>
    | ((slug: string) => readonly ProductManifest[]);
  readonly index?: CatalogIndex | null;
  readonly installed?: readonly InstalledProduct[];
  readonly opts?: ResolveOptions;
}

export interface ResolvedPlan {
  /** sha256 of the canonical plan summary (the `plan` hash). */
  readonly plan: Hash;
  readonly summary: PlanSummary;
  /** Resolved dependency list (locked), in install order. */
  readonly dependencies: PlanDependency[];
  /** Exact cycle path when resolution failed, e.g. ["a","b","a"]. */
  readonly cycle?: string[];
}

/** Cycle-aware conflict error carrying the exact path. */
export class DependencyConflictError extends RpcError {
  readonly cycle: string[] | null;
  constructor(message: string, cycle: string[] | null = null) {
    super("DEPENDENCY_CONFLICT", message, { field: "dependencies" });
    this.name = "DependencyConflictError";
    this.cycle = cycle;
  }
}

// ── helpers ──────────────────────────────────────────────────────────────

function manifestsOf(
  input: ResolveInput["manifests"],
  slug: string,
): readonly ProductManifest[] {
  if (typeof input === "function") return input(slug);
  return input.get(slug) ?? [];
}

/** Highest version in `candidates` satisfying `range` (null if none). */
export function selectVersion(
  candidates: readonly ProductManifest[],
  range: string,
): ProductManifest | null {
  let best: ProductManifest | null = null;
  let bestV: SemVer | null = null;
  for (const c of candidates) {
    const v = parseSemver(c.version);
    if (v === null || !satisfiesSemver(v, range)) continue;
    if (bestV === null || compareSemver(v, bestV) > 0) {
      best = c;
      bestV = v;
    }
  }
  return best;
}

/**
 * True when an installed (or stopping) product `other` still requires the
 * product `slug` — live dependents block uninstall/update (§5.4).
 */
export function dependentsPresent(
  installed: readonly InstalledProduct[],
  slug: string,
): string[] {
  const out: string[] = [];
  for (const p of installed) {
    if (p.slug === slug) continue;
    if (p.state === "REMOVED" || p.state === "REJECTED" || p.state === "CANCELLED") continue;
    const requires = p.dependencies.some(
      (d) => d.kind === "required" && d.slug === slug,
    );
    if (requires) out.push(p.slug);
  }
  return out;
}

interface Node {
  slug: string;
  manifest: ProductManifest;
}

/**
 * Topo-sort the required-dependency closure of `root`. Optional deps are
 * included only when already installed; evidence deps are recorded but
 * never resolved for install. Returns install order (leaves first) plus
 * the evidence-only records. Throws DependencyConflictError with the exact
 * cycle path on a required-dependency cycle.
 */
export function resolveGraph(
  root: ProductManifest,
  input: Pick<ResolveInput, "manifests" | "installed">,
): { order: Node[]; evidence: Dependency[]; optional: Node[] } {
  const order: Node[] = [];
  const evidence: Dependency[] = [];
  const optional: Node[] = [];
  const installedSlugs = new Map(
    (input.installed ?? []).map((p) => [p.slug, p]),
  );
  const state = new Map<string, "visiting" | "done">();
  const stack: string[] = [];

  const visit = (slug: string, manifest: ProductManifest): void => {
    const mark = state.get(slug);
    if (mark === "done") return;
    if (mark === "visiting") {
      const start = stack.indexOf(slug);
      const cycle = [...stack.slice(start), slug];
      throw new DependencyConflictError(
        `required dependency cycle: ${cycle.join("→")}`,
        cycle,
      );
    }
    state.set(slug, "visiting");
    stack.push(slug);
    for (const dep of manifest.dependencies) {
      if (dep.kind === "evidence") {
        // Evidence-only relationships never trigger installs.
        evidence.push(dep);
        continue;
      }
      if (dep.edge !== null) {
        const disp = EDGE_MAP.get(dep.edge);
        if (dep.kind === "required" && disp?.blocksRequired) {
          throw new RpcError(disp.code ?? "UNSUPPORTED_COMPOSITION", `${dep.edge} ${disp.producer}→${disp.consumer}: ${disp.rule}`, { field: "dependencies" });
        }
      }
      const candidates = manifestsOf(input.manifests, dep.slug);
      // `pin` locks the selected manifest digest at plan time (carried into
      // the plan); candidate choice is still the best satisfying version.
      const selected = selectVersion(candidates, dep.range);
      if (dep.kind === "required") {
        if (selected === null) {
          const installedHit = installedSlugs.get(dep.slug);
          if (installedHit && satisfiesSemver(installedHit.version, dep.range)) {
            continue; // already satisfied by an installed instance
          }
          throw new DependencyConflictError(
            `required dependency "${dep.slug}@${dep.range}" has no satisfying manifest`,
          );
        }
        visit(dep.slug, selected);
      } else if (dep.kind === "optional") {
        const installedHit = installedSlugs.get(dep.slug);
        if (installedHit && satisfiesSemver(installedHit.version, dep.range)) continue;
        if (selected !== null) {
          optional.push({ slug: dep.slug, manifest: selected });
          visit(dep.slug, selected);
        }
      }
    }
    stack.pop();
    state.set(slug, "done");
    order.push({ slug, manifest });
  };

  visit(root.slug, root);
  return { order, evidence, optional };
}

/** Compute the plan hash exactly as the fixture: H(J(summary)). */
export function planHashOf(summary: PlanSummary): Hash {
  return sha256Hex(canonicalJson(summary)) as Hash;
}

function toPlanDependency(
  slug: string,
  manifest: ProductManifest | null,
  kind: PlanDependency["kind"],
  dep: Dependency | null,
  manifestDigests: ReadonlyMap<string, Hash>,
): PlanDependency {
  return {
    slug,
    version: manifest?.version ?? dep?.range ?? "",
    kind,
    edge: dep?.edge ?? null,
    capability: dep?.capability ?? null,
    pin: dep?.pin ?? null,
    manifest: manifest !== null ? manifestDigests.get(manifestDigestKey(manifest)) ?? null : null,
    archive: manifest?.package.archive.digest ?? null,
  };
}

function manifestDigestKey(manifest: ProductManifest): string {
  return `${manifest.slug}@${manifest.version}`;
}

/**
 * Resolve a plan (§5.3). Performs no fetch and runs no code — selection
 * locks manifest/archive digests supplied by the caller, checks index
 * membership/expiry, strict allowlist policy, edge dispositions, cycles,
 * and live dependents.
 */
export function resolvePlan(input: ResolveInput): ResolvedPlan {
  const opts = input.opts ?? {};
  const installed = input.installed ?? [];
  const now = opts.now;

  const target = input.target?.manifest ?? null;
  const slug = target?.slug ?? input.source.split("@")[0]!;
  if (!SLUG_RE.test(slug)) {
    throw new RpcError("SCHEMA_INVALID", `source slug "${slug}" is invalid`, { field: "source" });
  }
  const version = input.version ?? target?.version;
  if (input.kind !== "uninstall") {
    if (typeof version !== "string" || !SEMVER_RE.test(version)) {
      throw new RpcError("SCHEMA_INVALID", "an exact version is required", { field: "version" });
    }
  }

  // Strict catalog policy: an empty allowlist authorizes zero installs.
  if (opts.strict === true) {
    const allow = new Set(opts.allowlist ?? []);
    if (!allow.has(slug)) {
      throw new RpcError("POLICY_DENIED", `strict catalog: "${slug}" is not in the allowlist`, {
        field: "source",
      });
    }
  }

  // Index membership + freshness for catalog-sourced installs.
  if (input.index != null && input.kind !== "uninstall" && input.kind !== "rollback") {
    const entry = input.index.entries.find(
      (e) => e.slug === slug && e.version === version,
    );
    if (!entry) {
      throw new RpcError("NOT_FOUND", `no catalog entry for ${slug}@${version}`, {
        field: "source",
      });
    }
    if (now !== undefined && opts.pinned !== true && now >= input.index.expires_ms) {
      throw new RpcError("TRUST_EXPIRED", "catalog index has expired for new installs", {
        field: "index",
      });
    }
  }

  const active = installed.find((p) => p.slug === slug && p.active);

  // from/to per kind.
  let from: string | null = null;
  let to: string | null = null;
  if (input.kind === "install") {
    if (active) {
      throw new DependencyConflictError(
        `"${slug}" is already installed at ${active.version}; use update`,
      );
    }
    to = version!;
  } else if (input.kind === "update") {
    if (!active) {
      throw new RpcError("NOT_FOUND", `"${slug}" is not installed`, { field: "source" });
    }
    from = active.version;
    to = version!;
  } else if (input.kind === "rollback") {
    if (!active) {
      throw new RpcError("NOT_FOUND", `"${slug}" is not installed`, { field: "source" });
    }
    from = active.version;
    to = version!;
    const retained = installed.find(
      (p) => p.slug === slug && p.version === to && p.state === "STOPPED_RETAINED",
    );
    if (!retained) {
      throw new RpcError("NOT_FOUND", `no retained ${slug}@${to} generation to roll back to`, {
        field: "version",
      });
    }
  } else {
    // uninstall
    if (!active && !installed.some((p) => p.slug === slug && p.state === "STOPPED_RETAINED")) {
      throw new RpcError("NOT_FOUND", `"${slug}" is not installed`, { field: "source" });
    }
    from = active?.version ?? installed.find((p) => p.slug === slug)?.version ?? null;
    to = null;
  }

  // Live dependents block update/uninstall unless cascade is reviewed.
  const dependents = dependentsPresent(installed, slug);
  if ((input.kind === "uninstall" || input.kind === "update") && dependents.length > 0) {
    if (input.kind === "uninstall" && opts.cascade !== true) {
      throw new RpcError(
        "DEPENDENTS_PRESENT",
        `live dependents require "${slug}": ${dependents.join(", ")}`,
        { field: "dependencies" },
      );
    }
    if (input.kind === "update") {
      // Incompatible installed dependents block the update: a dependent
      // whose required range excludes the new version cannot be left live.
      for (const depSlug of dependents) {
        const dependent = installed.find((p) => p.slug === depSlug)!;
        const dep = dependent.dependencies.find((d) => d.slug === slug)!;
        if (!satisfiesSemver(to!, dep.range)) {
          throw new RpcError(
            "DEPENDENTS_PRESENT",
            `installed dependent "${depSlug}" requires ${slug}@${dep.range}`,
            { field: "dependencies" },
          );
        }
      }
    }
  }

  // Dependency resolution (install/update/rollback have a target manifest).
  const manifestDigests = new Map<string, Hash>();
  if (input.target) {
    manifestDigests.set(manifestDigestKey(input.target.manifest), input.target.manifestDigest);
  }
  const dependencies: PlanDependency[] = [];
  if (target !== null) {
    const { order, evidence } = resolveGraph(target, input);
    // order includes the root last; every other entry is a required/optional
    // dependency in install order (leaves first).
    for (const node of order) {
      if (node.slug === slug && node.manifest.version === version) continue;
      const dep = findDep(target, order, node.slug);
      dependencies.push(
        toPlanDependency(node.slug, node.manifest, dep?.kind === "optional" ? "optional" : "required", dep ?? null, manifestDigests),
      );
    }
    for (const dep of evidence) {
      dependencies.push(toPlanDependency(dep.slug, null, "evidence", dep, manifestDigests));
    }
  }

  const summary: PlanSummary = {
    kind: input.kind,
    slug,
    from,
    to,
    manifest: input.target?.manifestDigest ?? ("0".repeat(64) as Hash),
    archive: target?.package.archive.digest ?? "",
    dependencies,
    grants: target?.capabilities ?? null,
    revisions: opts.revisions ?? { config: "1", catalog: "1", registry: "1" },
    trust: sha256Hex(canonicalJson([...(opts.trustMaterials ?? [])])) as Hash,
    keep_data: opts.keep_data ?? true,
    cascade: opts.cascade ?? false,
  };
  return { plan: planHashOf(summary), summary, dependencies };
}

/** Find the dependency record that selected `slug` anywhere in the graph. */
function findDep(
  root: ProductManifest,
  order: readonly Node[],
  slug: string,
): Dependency | null {
  const all = [root, ...order.map((n) => n.manifest)];
  for (const m of all) {
    const dep = m.dependencies.find((d) => d.slug === slug);
    if (dep) return dep;
  }
  return null;
}
