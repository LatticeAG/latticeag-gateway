/**
 * LifecycleEngine — executes the §5.4 transition relation end to end.
 *
 * States are per immutable candidate/version (generation rows); the active
 * pointer, operation status, and retained prior versions are separate
 * registry fields behind the ProductRegistryPort. Every listed transition
 * emits its named event object — recorded on the operation record and
 * pushed to the receipt sink. Unlisted moves never happen here.
 *
 * Semantics (§5.4):
 *  - install: ABSENT→PLANNED→FETCHING→VERIFIED→STAGED→STARTING→
 *    HEALTHCHECKING→READY; any pre-start failure → REJECTED; a start or
 *    health failure → DRAINING (ProductCandidateAbortRequested) →
 *    STOPPED_RETAINED, never activating or publishing capabilities.
 *  - update: candidate verified while the old version stays active; the
 *    active pointer switches atomically only after candidate health; then
 *    the old generation drains to STOPPED_RETAINED.
 *  - rollback: selects an exact retained generation, re-verifies current
 *    trust/dependencies, then walks the same stage/start/health/activate
 *    path; revoked targets → POLICY_DENIED, irreversible data without a
 *    verified snapshot → UNSUPPORTED_COMPOSITION before any pointer move.
 *  - uninstall: keep-data default; refuses live dependents; drains, stops,
 *    unwires, removes.
 *  - restart budget: ≤5 starts/60 s with 1/2/4/8/16 s delays; exhaustion
 *    quarantines the generation.
 *  - recoverAfterCrash reconciles the marker-fsync/pre-projection window:
 *    a committed pointer is preserved, activation is indexed exactly once,
 *    and the generation is probed before readiness.
 */
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { RpcError } from "../protocol/errors.js";
import type { ErrorCode } from "../protocol/errors.js";
import { transitionFor } from "../protocol/lifecycle.js";
import { GRACE, RESTART_BUDGET } from "../protocol/lifecycle.js";
import type {
  ProductState,
  TransitionEvent,
} from "../protocol/lifecycle.js";
import type { Count, Hash, Id, Json } from "../protocol/refs.js";
import type { ProductManifest, Release, SandboxKind } from "../protocol/product.js";

import { AdapterClient, describeChecked } from "./adapter-client.js";
import type { AdapterChild } from "./adapter-client.js";
import { extractArchive } from "./extract.js";
import type { ExtractedEntry } from "./extract.js";
import { awaitReadiness, startLiveProbes } from "./health.js";
import type { LiveProbeHandle } from "./health.js";
import { isRevoked, verifyRelease } from "./verify.js";
import { dependentsPresent } from "./resolve.js";
import type { InstalledProduct, PlanSummary } from "./resolve.js";
import type {
  GenerationRow,
  JournalMutation,
  LifecyclePorts,
  SourceRef,
  TransitionReceipt,
} from "./ports.js";

/** Thrown by an injected crash fault — a crash is not an orderly rejection. */
export class InjectedCrash extends Error {
  constructor(message = "injected crash") {
    super(message);
    this.name = "InjectedCrash";
  }
}

export function isInjectedCrash(e: unknown): e is InjectedCrash {
  return e instanceof InjectedCrash || (e instanceof Error && e.name === "InjectedCrash");
}

export type OperationKind = "install" | "update" | "uninstall" | "rollback" | "restart" | "recover";

/** Operation record: {id,kind,state,slug,from,to,cursor,error} + evidence. */
export interface OperationRecord {
  id: Id;
  kind: OperationKind;
  /** QUEUED → terminal product state, or the failure code (HEALTH_FAILED…). */
  state: string;
  slug: string;
  from: string | null;
  to: string | null;
  cursor: string;
  error: { code: string; retryable: boolean; field: string | null } | null;
  /** Ordered transition events emitted by this operation. */
  events: TransitionReceipt[];
  /** Set by operation.cancel; the engine checks at stage boundaries. */
  cancelRequested: boolean;
}

export interface EngineOptions {
  readonly readinessIntervalMs?: number;
  readonly readinessSuccesses?: number;
  readonly readinessFailureLimit?: number;
  readonly probeIntervalMs?: number;
  readonly probeFailureLimit?: number;
  /** Start the 10 s live-probe loop after READY (default true). */
  readonly liveProbes?: boolean;
  /** Restart crashed generations within budget (default true). */
  readonly autoRestart?: boolean;
}

export interface RunContext {
  readonly plan: PlanSummary;
  readonly sref?: SourceRef;
  readonly instance?: string;
  readonly config?: Json;
  /** Pinned/offline installs survive index expiry (TV-GW-45). */
  readonly pinned?: boolean;
  /** Destructive purge needs a separate confirmation (§5.4). */
  readonly purgeConfirmed?: boolean;
}

const CANCELABLE = new Set<ProductState>([
  "PLANNED",
  "FETCHING",
  "VERIFIED",
  "STAGED",
]);

const LIVE = new Set<ProductState>([
  "READY",
  "DEGRADED",
  "HEALTHCHECKING",
  "STARTING",
]);

function key(slug: string, generation: Count): string {
  return `${slug}:${generation}`;
}

export class LifecycleEngine {
  private readonly ports: LifecyclePorts;
  private readonly opts: EngineOptions;
  private readonly ops = new Map<Id, OperationRecord>();
  private readonly clients = new Map<string, AdapterClient>();
  private readonly probes = new Map<string, LiveProbeHandle>();
  private readonly manifests = new Map<string, ProductManifest>();
  private readonly draining = new Set<string>();
  private opSeq = 0;
  private closed = false;

  constructor(ports: LifecyclePorts, opts: EngineOptions = {}) {
    this.ports = ports;
    this.opts = opts;
  }

  // ── operation records ──────────────────────────────────────────────────

  listOperations(): OperationRecord[] {
    return [...this.ops.values()];
  }

  getOperation(id: Id): OperationRecord | undefined {
    return this.ops.get(id);
  }

  /** Live adapter client for a slug's active generation (null if none). */
  clientFor(slug: string): AdapterClient | undefined {
    const active = this.ports.productRegistry.active(slug);
    if (!active) return undefined;
    return this.clients.get(key(slug, active.generation));
  }

  /** Verified manifest retained for a generation (null if unknown). */
  manifestFor(slug: string, generation: Count): ProductManifest | undefined {
    return this.manifests.get(key(slug, generation));
  }

  /**
   * Public operation factory — the service needs the operation id before
   * the (async) run completes, so it creates the record then passes it to
   * install/update/rollback/uninstall as `op`.
   */
  createOperation(
    kind: OperationKind,
    slug: string,
    from: string | null,
    to: string | null,
  ): OperationRecord {
    return this.newOperation(kind, slug, from, to);
  }

  private newOperation(
    kind: OperationKind,
    slug: string,
    from: string | null,
    to: string | null,
  ): OperationRecord {
    const id = `op${++this.opSeq}`;
    const op: OperationRecord = {
      id,
      kind,
      state: "QUEUED",
      slug,
      from,
      to,
      cursor: `c${String(this.opSeq).padStart(16, "0")}:0`,
      error: null,
      events: [],
      cancelRequested: false,
    };
    this.ops.set(id, op);
    return op;
  }

  // ── plumbing ───────────────────────────────────────────────────────────

  private async journal(m: JournalMutation): Promise<void> {
    await this.ports.journalMutation(m);
  }

  private now(): number {
    return this.ports.clock.now();
  }

  private sleep(ms: number): Promise<void> {
    return this.ports.clock.sleep(ms);
  }

  /**
   * Perform a listed §5.4 transition: journal it, move the generation
   * state, record the named event on the operation, and emit the receipt.
   * Unlisted transitions are STATE_TRANSITION — refused with the
   * STATE_TRANSITION code.
   */
  private async transition(
    gen: GenerationRow,
    to: ProductState,
    op: OperationRecord,
    detail?: Json,
  ): Promise<TransitionEvent> {
    const event = transitionFor(gen.state, to);
    if (event === "STATE_TRANSITION") {
      throw new RpcError(
        "STATE_TRANSITION",
        `unlisted transition ${gen.state}→${to} for ${gen.slug}#${gen.generation}`,
      );
    }
    const from = gen.state;
    await this.journal({
      type: "transition",
      operation: op.id,
      slug: gen.slug,
      generation: gen.generation,
      detail: { from, to, event },
    });
    this.ports.productRegistry.update(gen.slug, gen.generation, { state: to });
    gen.state = to;
    const receipt: TransitionReceipt = {
      event,
      operation: op.id,
      slug: gen.slug,
      generation: gen.generation,
      from,
      to,
      at_ms: this.now(),
      ...(detail !== undefined ? { detail } : {}),
    };
    op.events.push(receipt);
    op.cursor = `c${op.id.slice(2).padStart(16, "0")}:${op.events.length}`;
    await this.ports.receiptSink(receipt);
    return event;
  }

  /** Cancel check run at each pre-start stage boundary. */
  private checkCancel(op: OperationRecord, gen: GenerationRow): void {
    if (op.cancelRequested && CANCELABLE.has(gen.state)) {
      throw new RpcError("STATE_TRANSITION", "operation cancelled by operator", {
        field: "operation",
      });
    }
  }

  private async failOperation(
    op: OperationRecord,
    gen: GenerationRow | null,
    err: unknown,
  ): Promise<never> {
    if (isInjectedCrash(err)) throw err;
    const code: ErrorCode =
      err instanceof RpcError ? err.code : "OUTCOME_UNKNOWN";
    op.error = {
      code,
      retryable: err instanceof RpcError ? err.retryable : false,
      field: err instanceof RpcError ? err.field : null,
    };
    op.state = code;
    if (gen !== null) {
      if (op.cancelRequested && CANCELABLE.has(gen.state)) {
        await this.transition(gen, "CANCELLED", op);
        op.state = "CANCELLED";
      } else if (CANCELABLE.has(gen.state)) {
        await this.transition(gen, "REJECTED", op, { code });
      } else if (gen.state === "STARTING" || gen.state === "HEALTHCHECKING") {
        // Candidate abort: never activate, never publish capabilities.
        await this.transition(gen, "DRAINING", op, { code });
        try {
          await this.stopChild(gen, "candidate_abort");
          await this.transition(gen, "STOPPED_RETAINED", op, { code });
        } catch {
          await this.transition(gen, "QUARANTINED", op, { code: "OUTCOME_UNKNOWN" });
        }
      }
    }
    throw err;
  }

  // ── shared stages ─────────────────────────────────────────────────────

  private async fetchStage(
    gen: GenerationRow,
    op: OperationRecord,
    sref: SourceRef,
  ): Promise<{ release: Release; archive: Uint8Array }> {
    this.checkCancel(op, gen);
    await this.transition(gen, "FETCHING", op);
    return await this.ports.catalog.fetch(sref);
  }

  private async verifyStage(
    gen: GenerationRow,
    op: OperationRecord,
    fetched: { release: Release; archive: Uint8Array },
    pinned: boolean,
  ): Promise<ProductManifest> {
    this.checkCancel(op, gen);
    const platform = this.ports.platform();
    const index = await this.ports.catalog.index();
    const verified = verifyRelease(fetched.release, this.ports.trustStore(), {
      archive: fetched.archive,
      os: platform.os,
      arch: platform.arch,
      node: platform.node,
      now: this.now(),
      indexExpiresMs: index?.expires_ms,
      pinned,
    });
    this.ports.productRegistry.update(gen.slug, gen.generation, {
      manifest_digest: verified.manifestDigest,
      archive_digest: verified.archiveDigest,
      dependencies: [...verified.manifest.dependencies],
    });
    gen.manifest_digest = verified.manifestDigest;
    gen.archive_digest = verified.archiveDigest;
    gen.dependencies = [...verified.manifest.dependencies];
    this.manifests.set(key(gen.slug, gen.generation), verified.manifest);
    await this.transition(gen, "VERIFIED", op, {
      manifest: verified.manifestDigest,
      archive: verified.archiveDigest,
    });
    return verified.manifest;
  }

  private async stageGeneration(
    gen: GenerationRow,
    op: OperationRecord,
    manifest: ProductManifest,
    archive: Uint8Array,
  ): Promise<void> {
    this.checkCancel(op, gen);
    const stageDir = this.ports.paths.stageDir(gen.slug, gen.generation);
    // Re-staging a retained generation replaces its tree — 'wx' writes
    // refuse to overwrite, so clear a prior stage dir first.
    if (existsSync(stageDir)) {
      this.ports.paths.removeStage?.(stageDir);
    }
    const entries = extractArchive(archive, stageDir);
    this.bindStagedPackage(stageDir, entries, manifest);
    const dataDir = this.ports.paths.dataDir(gen.slug, gen.generation);
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.ports.productRegistry.update(gen.slug, gen.generation, {
      staged_dir: stageDir,
      data_dir: dataDir,
    });
    gen.staged_dir = stageDir;
    gen.data_dir = dataDir;
    await this.transition(gen, "STAGED", op, { staged_dir: stageDir });
  }

  /**
   * The internal `package/gateway-adapter.json` binds adapter entry and
   * config-schema filenames; both must equal the signed manifest, and the
   * staged config schema's digest must equal `adapter.config_schema`.
   */
  private bindStagedPackage(
    stageDir: string,
    entries: readonly ExtractedEntry[],
    manifest: ProductManifest,
  ): void {
    const bindingPath = join(stageDir, "package", "gateway-adapter.json");
    if (!existsSync(bindingPath)) {
      throw new RpcError("ARTIFACT_MISMATCH", "package/gateway-adapter.json missing", {
        field: "adapter",
      });
    }
    let binding: { contract?: unknown; entry?: unknown; config_schema?: unknown };
    try {
      binding = JSON.parse(readFileSync(bindingPath, "utf8"));
    } catch {
      throw new RpcError("ARTIFACT_MISMATCH", "gateway-adapter.json is not valid JSON", {
        field: "adapter",
      });
    }
    if (
      binding.contract !== "gateway-adapter/1" ||
      binding.entry !== manifest.adapter.entry ||
      typeof binding.config_schema !== "string"
    ) {
      throw new RpcError(
        "ARTIFACT_MISMATCH",
        "gateway-adapter.json does not bind the manifest entry/contract",
        { field: "adapter" },
      );
    }
    const schemaEntry = entries.find(
      (e) => e.kind === "file" && e.path === `package/${binding.config_schema as string}`,
    );
    if (!schemaEntry || schemaEntry.digest !== manifest.adapter.config_schema.digest) {
      throw new RpcError(
        "ARTIFACT_MISMATCH",
        "staged config schema digest != manifest adapter.config_schema",
        { field: "adapter.config_schema" },
      );
    }
    const entryFile = entries.find(
      (e) => e.kind === "file" && e.path === `package/${manifest.adapter.entry}`,
    );
    if (!entryFile) {
      throw new RpcError("ARTIFACT_MISMATCH", "adapter entry not present in package", {
        field: "adapter.entry",
      });
    }
  }

  private async spawnAndStart(
    gen: GenerationRow,
    op: OperationRecord,
    manifest: ProductManifest,
    ctx: RunContext,
  ): Promise<AdapterClient> {
    this.checkCancel(op, gen);
    const sandboxes = this.ports.policy().sandboxes;
    if (!sandboxes.includes(manifest.runtime.sandbox as SandboxKind)) {
      throw new RpcError(
        "SANDBOX_UNAVAILABLE",
        `sandbox "${manifest.runtime.sandbox}" is not available on this host`,
        { field: "runtime.sandbox" },
      );
    }
    const stageDir = gen.staged_dir;
    if (stageDir === null) {
      throw new RpcError("STATE_TRANSITION", "generation was never staged");
    }
    const pkgDir = join(stageDir, "package");
    await this.journal({
      type: "start_intent",
      operation: op.id,
      slug: gen.slug,
      generation: gen.generation,
      detail: { entry: manifest.adapter.entry },
    });
    await this.transition(gen, "STARTING", op);
    const client = await this.spawnClient(gen, op, manifest, ctx, pkgDir);
    await this.transition(gen, "HEALTHCHECKING", op);
    return client;
  }

  /** Spawn + describe/configure/start handshake; shared by start+restart. */
  private async spawnClient(
    gen: GenerationRow,
    op: OperationRecord,
    manifest: ProductManifest,
    ctx: RunContext,
    pkgDir: string,
  ): Promise<AdapterClient> {
    gen.starts = [...gen.starts, this.now()];
    this.ports.productRegistry.update(gen.slug, gen.generation, { starts: gen.starts });
    const child: AdapterChild = await this.ports.spawnAdapter(
      [process.execPath, manifest.adapter.entry],
      pkgDir,
      {},
    );
    this.ports.productRegistry.update(gen.slug, gen.generation, {
      pid: child.pid ?? null,
    });
    gen.pid = child.pid ?? null;
    const client = new AdapterClient(child, {
      timeoutMs: manifest.adapter.health_timeout_ms,
    });
    this.clients.set(key(gen.slug, gen.generation), client);
    client.onExit((code, signal) => {
      void this.onChildExit(gen, code, signal);
    });
    try {
      // Describe is checked against signed manifest metadata, never trusted
      // because a process claims a capability (§5.2).
      await describeChecked(client, manifest);
      const conf = await client.configure({
        instance: ctx.instance ?? `${gen.slug}-${gen.generation}`,
        config: ctx.config ?? {},
        generation: gen.generation,
      });
      if (!conf.accepted) {
        throw new RpcError("SCHEMA_INVALID", "adapter rejected its configuration", {
          field: "config",
        });
      }
      const started = await client.start({
        operation: op.id,
        generation: gen.generation,
      });
      if (started.state !== "RUNNING") {
        throw new RpcError("HEALTH_FAILED", "adapter did not reach RUNNING");
      }
    } catch (e) {
      this.clients.delete(key(gen.slug, gen.generation));
      client.close();
      throw e;
    }
    return client;
  }

  /** Health gate + atomic activation commit (the crash-critical window). */
  private async activate(
    gen: GenerationRow,
    op: OperationRecord,
    manifest: ProductManifest,
    client: AdapterClient,
    expectedActive: Count | null,
  ): Promise<void> {
    await awaitReadiness(
      () => client.health({ generation: gen.generation }),
      {
        clock: this.ports.clock,
        successes: this.opts.readinessSuccesses,
        intervalMs: this.opts.readinessIntervalMs,
        startupTimeoutMs: manifest.adapter.startup_timeout_ms,
        failureLimit: this.opts.readinessFailureLimit,
      },
    );
    // Atomic active/config/registry commit (§5.4): pointer CAS, marker
    // fsync, then the projection — the crash window TV-GW-12 recovers.
    const ok = this.ports.productRegistry.casActive(
      gen.slug,
      expectedActive,
      gen.generation,
    );
    if (!ok) {
      throw new RpcError("REVISION_CONFLICT", "active pointer moved during activation", {
        field: "registry",
      });
    }
    gen.active = true;
    await this.journal({
      type: "active_pointer",
      operation: op.id,
      slug: gen.slug,
      generation: gen.generation,
      detail: { from: expectedActive, to: gen.generation },
    });
    // ── crash window: marker fsynced, projection not yet applied ──
    // The activation index is written at most once per generation.
    if (!gen.activation_indexed) {
      this.ports.productRegistry.update(gen.slug, gen.generation, {
        activation_indexed: true,
      });
      gen.activation_indexed = true;
      await this.journal({
        type: "projection",
        operation: op.id,
        slug: gen.slug,
        generation: gen.generation,
      });
    }
    this.ports.productRegistry.update(gen.slug, gen.generation, { projected: true });
    gen.projected = true;
    await this.transition(gen, "READY", op, { digest: gen.manifest_digest });
    this.startProbes(gen, client);
  }

  private startProbes(gen: GenerationRow, client: AdapterClient): void {
    if (this.opts.liveProbes === false) return;
    const k = key(gen.slug, gen.generation);
    this.probes.get(k)?.stop();
    const handle = startLiveProbes(
      () => client.health({ generation: gen.generation }),
      {
        clock: this.ports.clock,
        intervalMs: this.opts.probeIntervalMs,
        failureLimit: this.opts.probeFailureLimit,
      },
      () => {
        void this.degrade(gen);
      },
    );
    this.probes.set(k, handle);
  }

  private async degrade(gen: GenerationRow): Promise<void> {
    if (gen.state !== "READY") return;
    const op = this.newOperation("recover", gen.slug, gen.version, gen.version);
    this.ports.productRegistry.update(gen.slug, gen.generation, {
      capabilities_withdrawn: true,
    });
    gen.capabilities_withdrawn = true;
    await this.transition(gen, "DEGRADED", op);
  }

  /** Drain + stop + detach the adapter child. */
  private async stopChild(gen: GenerationRow, reason: string): Promise<void> {
    const k = key(gen.slug, gen.generation);
    this.probes.get(k)?.stop();
    this.probes.delete(k);
    const client = this.clients.get(k);
    this.clients.delete(k);
    if (client === undefined) return;
    this.draining.add(k);
    try {
      const d = await client.drain({ deadline_ms: GRACE.adapterStopDeadlineMs });
      if (d.uncertain.length > 0) {
        throw new RpcError(
          "OUTCOME_UNKNOWN",
          `drain reports ${d.uncertain.length} uncertain effects`,
        );
      }
      await client.stop({ reason, deadline_ms: GRACE.adapterStopDeadlineMs });
    } finally {
      client.close();
      this.draining.delete(k);
      this.ports.productRegistry.update(gen.slug, gen.generation, { pid: null });
      gen.pid = null;
    }
  }

  private async drainGeneration(
    gen: GenerationRow,
    op: OperationRecord,
    reason: string,
  ): Promise<void> {
    await this.transition(gen, "DRAINING", op, { reason });
    try {
      await this.stopChild(gen, reason);
    } catch (e) {
      // Cannot prove containment/termination, or drain reported uncertain
      // effects → quarantine rather than claim a clean stop (§5.4).
      await this.transition(gen, "QUARANTINED", op, {
        code: e instanceof RpcError ? e.code : "OUTCOME_UNKNOWN",
      });
      throw e;
    }
    await this.transition(gen, "STOPPED_RETAINED", op);
  }

  // ── crash watch + restart budget ──────────────────────────────────────

  private async onChildExit(
    gen: GenerationRow,
    code: number | null,
    signal: string | null,
  ): Promise<void> {
    const k = key(gen.slug, gen.generation);
    if (this.closed || this.draining.has(k) || !LIVE.has(gen.state)) return;
    const op = this.newOperation("restart", gen.slug, gen.version, gen.version);
    await this.transition(gen, "CRASHED", op, { code, signal });
    if (this.opts.autoRestart === false) return;
    const windowStart = this.now() - RESTART_BUDGET.windowMs;
    const recent = gen.starts.filter((t) => t >= windowStart);
    if (recent.length >= RESTART_BUDGET.maxStarts) {
      await this.transition(gen, "QUARANTINED", op, {
        reason: "restart_budget_exhausted",
      });
      return;
    }
    const delay = RESTART_BUDGET.delaysMs[Math.max(0, recent.length - 1)] ?? 16_000;
    await this.sleep(delay);
    if (this.closed) return;
    try {
      const manifest = this.manifests.get(k);
      if (!manifest) {
        throw new RpcError("STORAGE_UNAVAILABLE", "manifest record lost", {
          field: "manifest",
        });
      }
      await this.transition(gen, "STARTING", op, { restart: true, delay_ms: delay });
      const client = await this.spawnClient(
        gen,
        op,
        manifest,
        { plan: emptyPlan(gen) },
        join(gen.staged_dir!, "package"),
      );
      await this.transition(gen, "HEALTHCHECKING", op);
      await this.activate(gen, op, manifest, client, gen.generation);
      op.state = "READY";
    } catch (e) {
      if (isInjectedCrash(e)) throw e;
      await this.transition(gen, "QUARANTINED", op, {
        code: e instanceof RpcError ? e.code : "OUTCOME_UNKNOWN",
      });
    }
  }

  // ── public operations ─────────────────────────────────────────────────

  /**
   * Shared candidate path: PLANNED → FETCHING → VERIFIED → STAGED →
   * STARTING → HEALTHCHECKING → READY, then drain the superseded
   * generation when the pointer moved.
   */
  private async runCandidate(
    kind: "install" | "update" | "rollback",
    op: OperationRecord,
    gen: GenerationRow,
    ctx: RunContext,
    prev: GenerationRow | null,
  ): Promise<OperationRecord> {
    const sref = ctx.sref ?? { slug: gen.slug, version: gen.version };
    try {
      const fetched = await this.fetchStage(gen, op, sref);
      const manifest = await this.verifyStage(gen, op, fetched, ctx.pinned === true);
      await this.stageGeneration(gen, op, manifest, fetched.archive);
      const client = await this.spawnAndStart(gen, op, manifest, ctx);
      await this.activate(gen, op, manifest, client, prev?.generation ?? null);
      if (
        prev &&
        prev.generation !== gen.generation &&
        (prev.state === "READY" || prev.state === "DEGRADED")
      ) {
        await this.drainGeneration(prev, op, "activated_replacement");
      }
      op.state = "READY";
      return op;
    } catch (e) {
      return await this.failOperation(op, gen, e);
    }
  }

  private planGen(ctx: RunContext, version: string): GenerationRow {
    return this.ports.productRegistry.create({
      slug: ctx.plan.slug,
      version,
      generation: this.ports.productRegistry.nextGeneration(ctx.plan.slug),
      state: "ABSENT",
      active: false,
      manifest_digest: ctx.plan.manifest,
      archive_digest: ctx.plan.archive,
      staged_dir: null,
      data_dir: null,
      pid: null,
      dependencies: [],
      activation_indexed: false,
      projected: false,
      snapshot_verified: false,
      irreversible_data: false,
      capabilities_withdrawn: false,
      starts: [],
    });
  }

  /** install: ABSENT→…→READY on a fresh generation. */
  async install(ctx: RunContext, op?: OperationRecord): Promise<OperationRecord> {
    const rec = op ?? this.newOperation("install", ctx.plan.slug, ctx.plan.from, ctx.plan.to);
    const gen = this.planGen(ctx, ctx.plan.to!);
    await this.transition(gen, "PLANNED", rec, { plan: planDetail(ctx.plan) });
    return this.runCandidate("install", rec, gen, ctx, null);
  }

  /**
   * update: candidate while the old version remains active; pointer
   * switches only after health; the old generation then drains.
   */
  async update(ctx: RunContext, op?: OperationRecord): Promise<OperationRecord> {
    const rec = op ?? this.newOperation("update", ctx.plan.slug, ctx.plan.from, ctx.plan.to);
    const prev = this.ports.productRegistry.active(ctx.plan.slug) ?? null;
    if (!prev || prev.version !== ctx.plan.from) {
      rec.state = "PLAN_STALE";
      rec.error = { code: "PLAN_STALE", retryable: false, field: "from" };
      throw new RpcError("PLAN_STALE", "active version does not match plan.from");
    }
    const gen = this.planGen(ctx, ctx.plan.to!);
    await this.transition(gen, "PLANNED", rec, { plan: planDetail(ctx.plan) });
    return this.runCandidate("update", rec, gen, ctx, prev);
  }

  /**
   * rollback: explicit operation on a retained generation — re-verifies
   * trust/dependencies, then runs the same stage/start/health path.
   * Emits ProductRollbackPlanned first; revoked targets and irreversible
   * data without a verified snapshot are refused before any pointer move.
   */
  async rollback(ctx: RunContext, existing?: OperationRecord): Promise<OperationRecord> {
    const plan = ctx.plan;
    const op = existing ?? this.newOperation("rollback", plan.slug, plan.from, plan.to);
    const current = this.ports.productRegistry.active(plan.slug) ?? null;
    const target = this.ports.productRegistry
      .generations(plan.slug)
      .find((g) => g.version === plan.to && g.state === "STOPPED_RETAINED");
    if (!current || !target) {
      op.state = "NOT_FOUND";
      op.error = { code: "NOT_FOUND", retryable: false, field: "version" };
      throw new RpcError("NOT_FOUND", "no active/retained generation pair for rollback");
    }
    // Storage reversibility first — refuse before any pointer move when the
    // data migration lacks a verified inverse/snapshot (TV-GW-15).
    if (current.irreversible_data && !target.snapshot_verified) {
      op.state = "UNSUPPORTED_COMPOSITION";
      op.error = { code: "UNSUPPORTED_COMPOSITION", retryable: false, field: "version" };
      throw new RpcError(
        "UNSUPPORTED_COMPOSITION",
        "rollback data migration has no verified inverse/snapshot",
      );
    }
    try {
      // The rollback plan transition applies to the retained generation.
      await this.transition(target, "PLANNED", op, { plan: planDetail(plan) });
      // Revoked releases cannot roll back into execution (TV-GW-14).
      const trust = this.ports.trustStore();
      if (isRevoked(trust.revocations, target.archive_digest)) {
        throw new RpcError("POLICY_DENIED", "rollback target digest is revoked", {
          field: "revocations",
        });
      }
      return await this.runCandidate("rollback", op, target, ctx, current);
    } catch (e) {
      return await this.failOperation(op, target, e);
    }
  }

  /**
   * uninstall: keep-data default; refuses live dependents; drains, stops,
   * unwires config/registry atomically, removes package links; receipts
   * and tombstones are retained.
   */
  async uninstall(ctx: RunContext, existing?: OperationRecord): Promise<OperationRecord> {
    const plan = ctx.plan;
    const op = existing ?? this.newOperation("uninstall", plan.slug, plan.from, plan.to);
    const deps = dependentsPresent(this.installedView(), plan.slug);
    if (deps.length > 0 && plan.cascade !== true) {
      op.state = "DEPENDENTS_PRESENT";
      op.error = { code: "DEPENDENTS_PRESENT", retryable: false, field: "dependencies" };
      throw new RpcError(
        "DEPENDENTS_PRESENT",
        `live dependents require "${plan.slug}": ${deps.join(", ")}`,
      );
    }
    if (plan.keep_data !== true && ctx.purgeConfirmed !== true) {
      op.state = "POLICY_DENIED";
      op.error = { code: "POLICY_DENIED", retryable: false, field: "keep_data" };
      throw new RpcError(
        "POLICY_DENIED",
        "--purge-data requires a separate destructive confirmation",
      );
    }
    const gen =
      this.ports.productRegistry.active(plan.slug) ??
      this.ports.productRegistry
        .generations(plan.slug)
        .find((g) => g.state === "STOPPED_RETAINED");
    if (!gen) {
      op.state = "NOT_FOUND";
      op.error = { code: "NOT_FOUND", retryable: false, field: "slug" };
      throw new RpcError("NOT_FOUND", `"${plan.slug}" is not installed`);
    }
    try {
      if (gen.state === "READY" || gen.state === "DEGRADED") {
        await this.drainGeneration(gen, op, "operator_uninstall");
      }
      await this.transition(gen, "UNINSTALLING", op, {
        keep_data: plan.keep_data,
      });
      if (gen.active) {
        this.ports.productRegistry.casActive(plan.slug, gen.generation, null);
        gen.active = false;
      }
      // Remove package links; retain data unless a confirmed purge.
      if (gen.staged_dir && this.ports.paths.removeStage) {
        this.ports.paths.removeStage(gen.staged_dir);
      }
      if (plan.keep_data !== true && ctx.purgeConfirmed === true && gen.data_dir) {
        this.ports.paths.removeStage?.(gen.data_dir);
      }
      await this.journal({
        type: "tombstone",
        operation: op.id,
        slug: plan.slug,
        generation: gen.generation,
      });
      await this.transition(gen, "REMOVED", op);
      op.state = "REMOVED";
      return op;
    } catch (e) {
      return await this.failOperation(op, gen, e);
    }
  }

  /**
   * Recover after a daemon crash. For the marker-fsync/pre-projection
   * window (TV-GW-12): the committed active pointer is preserved, the
   * activation is indexed exactly once, and the generation is probed
   * before readiness — never blindly dispatched twice.
   */
  async recoverAfterCrash(point?: string): Promise<void> {
    void point;
    for (const gen of this.ports.productRegistry.all()) {
      if (gen.state === "HEALTHCHECKING" && gen.active && !gen.projected) {
        // Pointer committed; projection torn — index the activation
        // exactly once (only when it was not already indexed), then probe
        // before readiness.
        const op = this.newOperation("recover", gen.slug, gen.version, gen.version);
        if (!gen.activation_indexed) {
          this.ports.productRegistry.update(gen.slug, gen.generation, {
            activation_indexed: true,
          });
          gen.activation_indexed = true;
          await this.journal({
            type: "projection",
            operation: op.id,
            slug: gen.slug,
            generation: gen.generation,
            detail: { recovered: true },
          });
        }
        this.ports.productRegistry.update(gen.slug, gen.generation, { projected: true });
        gen.projected = true;
        const ok = this.ports.probeGeneration
          ? await this.ports.probeGeneration(gen)
          : true;
        if (ok) {
          await this.transition(gen, "READY", op, { recovered: true });
        }
        op.state = gen.state;
      } else if (
        (gen.state === "STARTING" || gen.state === "HEALTHCHECKING") &&
        !gen.active
      ) {
        // Candidate crashed before pointer commit — abort without ever
        // activating or dispatching twice.
        const op = this.newOperation("recover", gen.slug, gen.version, gen.version);
        await this.transition(gen, "DRAINING", op, { recovered: true });
        await this.stopChild(gen, "crash_recovery");
        await this.transition(gen, "STOPPED_RETAINED", op);
        op.state = gen.state;
      } else if (CANCELABLE.has(gen.state)) {
        // Never started — reject cleanly; nothing executed.
        const op = this.newOperation("recover", gen.slug, gen.version, gen.version);
        await this.transition(gen, "REJECTED", op, { recovered: true });
        op.state = gen.state;
      }
    }
  }

  /** Registry rows projected into the resolver's installed view. */
  private installedView(): InstalledProduct[] {
    return this.ports.productRegistry
      .all()
      .filter((g) => g.state !== "REMOVED")
      .map((g) => ({
        slug: g.slug,
        version: g.version,
        state: g.state,
        active: g.active,
        dependencies: g.dependencies,
      }));
  }

  /** operation.cancel — before start/activation only (§3.2). */
  async cancelOperation(id: Id): Promise<OperationRecord> {
    const op = this.ops.get(id);
    if (!op) throw new RpcError("NOT_FOUND", `operation "${id}" unknown`);
    op.cancelRequested = true;
    const gen = this.ports.productRegistry
      .generations(op.slug)
      .find((g) => g.version === (op.to ?? op.from ?? ""));
    if (gen && (gen.state === "READY" || gen.state === "REMOVED" || gen.state === "DRAINING")) {
      throw new RpcError("CANCEL_UNSAFE", "operation is past safe cancellation", {
        field: "operation",
      });
    }
    if (gen && CANCELABLE.has(gen.state)) {
      await this.transition(gen, "CANCELLED", op);
      op.state = "CANCELLED";
    }
    return op;
  }

  /** Stop probe loops and adapter children; engine shutdown. */
  async close(): Promise<void> {
    this.closed = true;
    for (const p of this.probes.values()) p.stop();
    this.probes.clear();
    for (const c of this.clients.values()) c.close();
    this.clients.clear();
  }
}

function planDetail(plan: PlanSummary): Json {
  return {
    kind: plan.kind,
    slug: plan.slug,
    from: plan.from,
    to: plan.to,
    manifest: plan.manifest,
    archive: plan.archive,
  } as Json;
}

function emptyPlan(gen: GenerationRow): PlanSummary {
  return {
    kind: "install",
    slug: gen.slug,
    from: null,
    to: gen.version,
    manifest: gen.manifest_digest as Hash,
    archive: gen.archive_digest,
    dependencies: [],
    grants: null,
    revisions: { config: "1", catalog: "1", registry: "1" },
    trust: "0".repeat(64) as Hash,
    keep_data: true,
    cascade: false,
  };
}
