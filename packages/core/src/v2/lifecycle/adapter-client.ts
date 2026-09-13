/**
 * `gateway-adapter/1` supervisor-side client (spec §5.2): LF-delimited
 * bounded JSON over private pipes, one outstanding request per adapter,
 * 64 KiB maximum line, schema-checked request ids, bounded+redacted
 * stderr capture. There is no shell/exec method — unknown method names
 * are rejected client-side with METHOD_UNKNOWN and never reach the pipe.
 *
 * Secrets/credentials must arrive on a private inherited descriptor; the
 * client never places them on argv or in the ambient environment (the
 * spawn port takes the full argv/env explicitly).
 */
import { Buffer } from "node:buffer";
import type { Readable, Writable } from "node:stream";

import { RpcError } from "../protocol/errors.js";
import { ERROR_CODES } from "../protocol/errors.js";
import type { RegistryErrorCode } from "../protocol/errors.js";
import type { Json } from "../protocol/refs.js";
import {
  ADAPTER_LIMITS,
  isAdapterMethod,
} from "../protocol/product.js";
import type { AdapterMethod, ProductManifest } from "../protocol/product.js";
import { isHash64 } from "../crypto/hash.js";

/** The ChildProcess surface the adapter client needs. */
export interface AdapterChild {
  readonly stdin: Writable | null;
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;
  readonly pid?: number | undefined;
  kill(signal?: string | number): unknown;
  on(event: "exit", cb: (code: number | null, signal: string | null) => void): unknown;
  once(event: "exit", cb: (code: number | null, signal: string | null) => void): unknown;
  off?(event: "exit", cb: (code: number | null, signal: string | null) => void): unknown;
}

export interface AdapterClientOptions {
  /** Per-request timeout, ms (default health timeout 2000 per §5.2). */
  readonly timeoutMs?: number;
  /** LF-delimited line cap in bytes (default 64 KiB). */
  readonly maxLineBytes?: number;
  /** Bounded stderr capture cap in bytes (default 64 KiB). */
  readonly stderrBytes?: number;
  /** Injectable timer for deterministic tests. */
  readonly setTimeout?: (fn: () => void, ms: number) => unknown;
  readonly clearTimeout?: (t: unknown) => void;
}

// ── Result shapes (spec §5.2 table) ─────────────────────────────────────

export interface DescribeResult {
  contract: "gateway-adapter/1";
  product: string;
  config_schema_digest: string;
  profiles: string[];
}

export interface ConfigureResult {
  generation: string;
  accepted: boolean;
}

export interface StartResult {
  state: "RUNNING";
  generation: string;
}

export interface HealthResult {
  liveness: boolean;
  readiness: boolean;
  dependencies: Json[];
  native: Json;
}

export interface DrainResult {
  in_flight: number;
  uncertain: Json[];
}

export interface SnapshotResult {
  supported: boolean;
  objects: Json[];
}

export interface StopResult {
  state: "STOPPED";
  uncertain: Json[];
}

const REDACTED = "[redacted]";

/** Redact credential-looking tokens from captured stderr text. */
function redactStderr(text: string): string {
  return text
    .replace(/(token|secret|password|authorization|api[_-]?key)(=|: ?)\S+/gi, `$1$2${REDACTED}`)
    .replace(/Bearer\s+\S+/gi, `Bearer ${REDACTED}`);
}

const REGISTRY_CODES: ReadonlySet<string> = new Set(ERROR_CODES);

interface Pending {
  id: string;
  method: AdapterMethod;
  resolve: (v: Json) => void;
  reject: (e: Error) => void;
  timer: unknown;
}

/**
 * One adapter pipe. Reads LF-delimited replies, enforces the single
 * outstanding-request rule, and type-checks per-method results.
 */
export class AdapterClient {
  private readonly child: AdapterChild;
  private readonly timeoutMs: number;
  private readonly maxLine: number;
  private readonly stderrCap: number;
  private readonly setT: (fn: () => void, ms: number) => unknown;
  private readonly clearT: (t: unknown) => void;

  private buf = Buffer.alloc(0);
  private pending: Pending | null = null;
  private counter = 0;
  private stderrBuf = Buffer.alloc(0);
  private closed = false;
  private exitInfo: { code: number | null; signal: string | null } | null = null;
  private exitListeners = new Set<(code: number | null, signal: string | null) => void>();
  private readonly onData = (chunk: Buffer | string): void => {
    this.feed(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk);
  };
  private readonly onErrData = (chunk: Buffer | string): void => {
    const b = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
    if (this.stderrBuf.length >= this.stderrCap) return; // bounded
    this.stderrBuf = Buffer.concat([
      this.stderrBuf,
      b.subarray(0, this.stderrCap - this.stderrBuf.length),
    ]);
  };
  private readonly handleExit = (code: number | null, signal: string | null): void => {
    this.exitInfo = { code, signal };
    this.closed = true;
    const pending = this.pending;
    this.pending = null;
    if (pending) {
      this.clearT(pending.timer);
      pending.reject(
        new RpcError("OUTCOME_UNKNOWN", `adapter exited (code ${code}) mid-request`),
      );
    }
    for (const l of this.exitListeners) l(code, signal);
  };

  constructor(child: AdapterChild, opts: AdapterClientOptions = {}) {
    if (!child.stdin || !child.stdout) {
      throw new RpcError("SANDBOX_UNAVAILABLE", "adapter child lacks stdio pipes");
    }
    this.child = child;
    this.timeoutMs = opts.timeoutMs ?? ADAPTER_LIMITS.healthTimeoutMs;
    this.maxLine = opts.maxLineBytes ?? ADAPTER_LIMITS.maxLineBytes;
    this.stderrCap = opts.stderrBytes ?? 64 * 1024;
    this.setT = opts.setTimeout ?? ((fn, ms) => setTimeout(fn, ms));
    this.clearT = opts.clearTimeout ?? ((t) => clearTimeout(t as never));
    child.stdout.on("data", this.onData);
    child.stderr?.on("data", this.onErrData);
    child.on("exit", this.handleExit);
  }

  /** Bounded, redacted stderr tail captured so far. */
  stderrTail(): string {
    return redactStderr(this.stderrBuf.toString("utf8"));
  }

  /** Exit info once the process has exited, else null. */
  exited(): { code: number | null; signal: string | null } | null {
    return this.exitInfo;
  }

  /** Subscribe to process exit (used by the engine's crash watch). */
  onExit(cb: (code: number | null, signal: string | null) => void): () => void {
    this.exitListeners.add(cb);
    if (this.exitInfo) cb(this.exitInfo.code, this.exitInfo.signal);
    return () => this.exitListeners.delete(cb);
  }

  /** Kill the adapter and stop reading. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.child.kill("SIGTERM");
    } catch {
      /* already dead */
    }
  }

  private feed(chunk: Buffer): void {
    this.buf = Buffer.concat([this.buf, chunk]);
    for (;;) {
      const nl = this.buf.indexOf(0x0a);
      if (nl === -1) {
        if (this.buf.length > this.maxLine) {
          this.protocolBreach(`adapter line exceeds ${this.maxLine} bytes`);
        }
        return;
      }
      const line = this.buf.subarray(0, nl);
      this.buf = this.buf.subarray(nl + 1);
      if (line.length > this.maxLine) {
        this.protocolBreach(`adapter line exceeds ${this.maxLine} bytes`);
        return;
      }
      if (line.length === 0) continue;
      this.dispatch(line);
      if (this.closed) return;
    }
  }

  private protocolBreach(why: string): void {
    const pending = this.pending;
    this.pending = null;
    this.close();
    if (pending) {
      this.clearT(pending.timer);
      pending.reject(
        new RpcError("BODY_LIMIT", `adapter protocol breach: ${why}`),
      );
    }
  }

  private dispatch(line: Buffer): void {
    let value: unknown;
    try {
      value = JSON.parse(line.toString("utf8"));
    } catch {
      this.protocolBreach("reply is not valid JSON");
      return;
    }
    const pending = this.pending;
    if (!pending) return; // unsolicited line — ignored (protocol only)
    if (
      value === null ||
      typeof value !== "object" ||
      (value as { v?: unknown }).v !== 1
    ) {
      this.clearT(pending.timer);
      this.pending = null;
      pending.reject(new RpcError("SCHEMA_INVALID", "adapter reply missing v:1"));
      return;
    }
    const id = (value as { id?: unknown }).id;
    if (id !== pending.id) {
      // Schema-checked ids: a mismatched id is a protocol violation.
      this.clearT(pending.timer);
      this.pending = null;
      pending.reject(new RpcError("SCHEMA_INVALID", "adapter reply id mismatch"));
      return;
    }
    this.clearT(pending.timer);
    this.pending = null;
    const ok = (value as { ok?: unknown }).ok;
    if (ok === true) {
      pending.resolve((value as { result: Json }).result);
      return;
    }
    if (ok === false) {
      const err = (value as { error?: unknown }).error;
      const code =
        err !== null &&
        typeof err === "object" &&
        typeof (err as { code?: unknown }).code === "string" &&
        REGISTRY_CODES.has((err as { code: string }).code)
          ? ((err as { code: string }).code as RegistryErrorCode)
          : "SCHEMA_INVALID";
      const retryable =
        err !== null &&
        typeof err === "object" &&
        (err as { retryable?: unknown }).retryable === true;
      pending.reject(
        new RpcError(code, `adapter error ${code}`, { retryable }),
      );
      return;
    }
    pending.reject(new RpcError("SCHEMA_INVALID", "adapter reply missing ok"));
  }

  /**
   * Send `{v:1,id,method,params}` and await the reply. Enforces one
   * outstanding request; unknown methods are rejected without any write.
   */
  request(method: string, params: Json): Promise<Json> {
    if (!isAdapterMethod(method)) {
      return Promise.reject(
        new RpcError("METHOD_UNKNOWN", `adapter method "${method}" does not exist`, {
          field: "method",
        }),
      );
    }
    if (this.closed || this.exitInfo) {
      return Promise.reject(
        new RpcError("OUTCOME_UNKNOWN", "adapter process is not running"),
      );
    }
    if (this.pending) {
      return Promise.reject(
        new RpcError("BUSY", "one outstanding request per adapter"),
      );
    }
    const id = `r${++this.counter}`;
    const line = JSON.stringify({ v: 1, id, method, params }) + "\n";
    return new Promise<Json>((resolve, reject) => {
      const timer = this.setT(() => {
        this.pending = null;
        reject(
          new RpcError("OUTCOME_UNKNOWN", `adapter ${method} timed out after ${this.timeoutMs}ms`),
        );
      }, this.timeoutMs);
      this.pending = { id, method, resolve, reject, timer };
      try {
        this.child.stdin!.write(line);
      } catch (e) {
        this.clearT(timer);
        this.pending = null;
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  // ── Typed methods (spec §5.2 result shapes) ────────────────────────────

  async describe(): Promise<DescribeResult> {
    const r = await this.request("describe", {});
    return requireShape<DescribeResult>(r, "describe", (v) => {
      const o = asObject(v, "describe");
      if (o.contract !== "gateway-adapter/1") bad("describe.contract");
      if (typeof o.product !== "string" || o.product.length === 0) bad("describe.product");
      if (!isHash64(o.config_schema_digest)) bad("describe.config_schema_digest");
      if (!Array.isArray(o.profiles) || !o.profiles.every((p) => typeof p === "string")) {
        bad("describe.profiles");
      }
      return {
        contract: "gateway-adapter/1",
        product: o.product,
        config_schema_digest: o.config_schema_digest,
        profiles: o.profiles,
      };
    });
  }

  async configure(params: {
    instance: string;
    config: Json;
    generation: string;
  }): Promise<ConfigureResult> {
    const r = await this.request("configure", {
      instance: params.instance,
      config: params.config,
      generation: params.generation,
    });
    return requireShape<ConfigureResult>(r, "configure", (v) => {
      const o = asObject(v, "configure");
      if (typeof o.generation !== "string") bad("configure.generation");
      if (typeof o.accepted !== "boolean") bad("configure.accepted");
      return { generation: o.generation, accepted: o.accepted };
    });
  }

  async start(params: { operation: string; generation: string }): Promise<StartResult> {
    const r = await this.request("start", {
      operation: params.operation,
      generation: params.generation,
    });
    return requireShape<StartResult>(r, "start", (v) => {
      const o = asObject(v, "start");
      if (o.state !== "RUNNING") bad("start.state");
      if (typeof o.generation !== "string") bad("start.generation");
      return { state: "RUNNING", generation: o.generation };
    });
  }

  async health(params: { generation: string }): Promise<HealthResult> {
    const r = await this.request("health", { generation: params.generation });
    return requireShape<HealthResult>(r, "health", (v) => {
      const o = asObject(v, "health");
      if (typeof o.liveness !== "boolean") bad("health.liveness");
      if (typeof o.readiness !== "boolean") bad("health.readiness");
      if (!Array.isArray(o.dependencies)) bad("health.dependencies");
      return {
        liveness: o.liveness,
        readiness: o.readiness,
        dependencies: o.dependencies,
        native: (o.native ?? null) as Json,
      };
    });
  }

  async drain(params: { deadline_ms: number }): Promise<DrainResult> {
    const r = await this.request("drain", { deadline_ms: params.deadline_ms });
    return requireShape<DrainResult>(r, "drain", (v) => {
      const o = asObject(v, "drain");
      if (typeof o.in_flight !== "number" || !Number.isSafeInteger(o.in_flight)) {
        bad("drain.in_flight");
      }
      if (!Array.isArray(o.uncertain)) bad("drain.uncertain");
      return { in_flight: o.in_flight, uncertain: o.uncertain };
    });
  }

  async snapshot(params: { generation: string }): Promise<SnapshotResult> {
    const r = await this.request("snapshot", { generation: params.generation });
    return requireShape<SnapshotResult>(r, "snapshot", (v) => {
      const o = asObject(v, "snapshot");
      if (typeof o.supported !== "boolean") bad("snapshot.supported");
      if (!Array.isArray(o.objects)) bad("snapshot.objects");
      return { supported: o.supported, objects: o.objects };
    });
  }

  async stop(params: { reason: string; deadline_ms: number }): Promise<StopResult> {
    const r = await this.request("stop", {
      reason: params.reason,
      deadline_ms: params.deadline_ms,
    });
    return requireShape<StopResult>(r, "stop", (v) => {
      const o = asObject(v, "stop");
      if (o.state !== "STOPPED") bad("stop.state");
      if (!Array.isArray(o.uncertain)) bad("stop.uncertain");
      return { state: "STOPPED", uncertain: o.uncertain };
    });
  }
}

function asObject(v: unknown, what: string): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new RpcError("SCHEMA_INVALID", `adapter ${what} result must be an object`);
  }
  return v as Record<string, unknown>;
}

function bad(field: string): never {
  throw new RpcError("SCHEMA_INVALID", `adapter result field ${field} invalid`, { field });
}

function requireShape<T>(value: Json, what: string, check: (v: unknown) => T): T {
  try {
    return check(value);
  } catch (e) {
    if (e instanceof RpcError) throw e;
    throw new RpcError("SCHEMA_INVALID", `adapter ${what} result malformed`);
  }
}

/**
 * describe() cross-checked against the signed manifest (§5.2): the
 * contract, product slug, and config schema digest must equal the signed
 * metadata — a process claiming a different capability is not trusted.
 */
export async function describeChecked(
  client: AdapterClient,
  manifest: ProductManifest,
): Promise<DescribeResult> {
  const d = await client.describe();
  if (d.contract !== manifest.adapter.contract) {
    throw new RpcError("ARTIFACT_MISMATCH", "adapter contract does not match manifest", {
      field: "adapter.contract",
    });
  }
  if (d.product !== manifest.slug) {
    throw new RpcError(
      "ARTIFACT_MISMATCH",
      `adapter product "${d.product}" != manifest slug "${manifest.slug}"`,
      { field: "slug" },
    );
  }
  if (d.config_schema_digest !== manifest.adapter.config_schema.digest) {
    throw new RpcError(
      "ARTIFACT_MISMATCH",
      "adapter config_schema_digest does not match manifest",
      { field: "adapter.config_schema" },
    );
  }
  return d;
}
