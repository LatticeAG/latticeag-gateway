/**
 * Test-only harness for the Gateway v2 CLI e2e suite.
 *
 * `runCliInProcess` executes the real in-process `runCli` (src/run-cli.ts)
 * — never the child-process launcher in src/test-spawn.ts — while capturing
 * everything the command surface can use to talk to its operator:
 *
 *  - process.stdout.write / process.stderr.write → captured strings
 *  - process.exit(code)                        → recorded, then throws a
 *    CliExit sentinel so control returns to the test exactly as the real
 *    process would have terminated at that point
 *  - process.exitCode                          → reset per run, captured
 *  - process.cwd() / process.env               → saved and restored
 *  - process.argv[1]                           → optionally stubbed so the
 *    detached-spawn path (cliBinPath fallback) launches a fast no-op stub
 *    instead of whatever runner hosts vitest
 *
 * Also included: a real HTTP-over-unix-socket RPC client for POST /v2/rpc
 * (the control protocol is HTTP/1.1, not line-delimited JSON), plus config
 * writers and a daemon starter used by the e2e tests.
 */
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import http from "node:http";
import { createServer } from "node:net";
import { runCli } from "../run-cli.js";
import {
  createDefaultConfig,
  migrateConfig,
  type LatticeagConfig,
} from "@latticeag/config";

// ── process-exit sentinel ────────────────────────────────────────────────

/** Thrown by the mocked process.exit; carries the requested exit code. */
export class CliExit extends Error {
  readonly code: number;
  constructor(code: number) {
    super(`process.exit(${code})`);
    this.name = "CliExit";
    this.code = code;
  }
}

export interface CliRunResult {
  /**
   * The exit code the process would have used: the first process.exit(n)
   * call, else a numeric process.exitCode left by the command, else the
   * value runCli resolved with. `null` when runCli rejected with an
   * uncaught error (the real binary would crash with an unhandled
   * rejection — a defect, not a mapped exit).
   */
  code: number | null;
  stdout: string;
  stderr: string;
  /** Non-null when runCli rejected instead of resolving/exiting. */
  threw: unknown;
}

export interface RunCliOptions {
  /**
   * Environment overrides applied for the duration of the call:
   * `undefined` values delete the variable. Restored afterwards.
   */
  env?: Record<string, string | undefined>;
  /**
   * Replace process.argv[1] for the call. Used to point cliBinPath()'s
   * fallback at a no-op stub so on-demand autostart never spawns the
   * test runner as a child.
   */
  argv1?: string;
  /**
   * When true (default), argv[1] is pointed at a generated stub script
   * that exits 0 immediately — detached `gateway start` spawns succeed
   * but no daemon ever appears, so unavailable paths stay deterministic.
   * Pass false to leave argv[1] untouched.
   */
  stubBin?: boolean;
  /** Directory for the generated stub (defaults to a fresh temp dir). */
  stubDir?: string;
}

type WriteFn = (
  chunk: string | Uint8Array,
  encoding?: BufferEncoding | ((err?: Error) => void),
  cb?: (err?: Error) => void,
) => boolean;

function captureWrite(
  target: NodeJS.WriteStream,
  sink: { text: string },
): WriteFn {
  const write: WriteFn = (chunk, encoding, cb) => {
    const enc = typeof encoding === "string" ? encoding : "utf8";
    sink.text +=
      typeof chunk === "string" ? chunk : Buffer.from(chunk).toString(enc);
    const done = typeof encoding === "function" ? encoding : cb;
    done?.();
    return true;
  };
  target.write = write as typeof target.write;
  return write;
}

/**
 * Run the real commander program in-process. `args` excludes the node and
 * script argv slots (e.g. ["gateway", "status", "--json"]).
 */
export async function runCliInProcess(
  args: string[],
  opts: RunCliOptions = {},
): Promise<CliRunResult> {
  const stdout = { text: "" };
  const stderr = { text: "" };

  const savedStdoutWrite = process.stdout.write;
  const savedStderrWrite = process.stderr.write;
  const savedExit = process.exit;
  const savedExitCode = process.exitCode;
  const savedCwd = process.cwd();
  const savedArgv1 = process.argv[1];
  const savedEnv = { ...process.env };

  // Deterministic daemon discovery: no ambient XDG runtime dir or stale
  // control-socket override leaks into a test unless it asks for them.
  if (!("XDG_RUNTIME_DIR" in (opts.env ?? {}))) {
    delete process.env.XDG_RUNTIME_DIR;
  }
  if (!("LATTICEAG_CONTROL_SOCKET" in (opts.env ?? {}))) {
    delete process.env.LATTICEAG_CONTROL_SOCKET;
  }
  for (const [key, value] of Object.entries(opts.env ?? {})) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }

  if (opts.argv1 !== undefined) {
    process.argv[1] = opts.argv1;
  } else if (opts.stubBin !== false) {
    process.argv[1] = opts.stubDir
      ? ensureStubIn(opts.stubDir)
      : stubBinPath();
  }

  captureWrite(process.stdout, stdout);
  captureWrite(process.stderr, stderr);
  let exitCode: number | null = null;
  process.exit = ((code?: number) => {
    const c = typeof code === "number" ? code : 0;
    if (exitCode === null) exitCode = c;
    throw new CliExit(c);
  }) as typeof process.exit;
  process.exitCode = undefined;

  let threw: unknown = null;
  let resolved: number | undefined;
  let postExitCode: number | undefined;
  try {
    resolved = await runCli([process.execPath, "latticeag", ...args]);
  } catch (err) {
    if (err instanceof CliExit) {
      // exitCode already recorded
    } else {
      threw = err;
    }
  } finally {
    postExitCode =
      typeof process.exitCode === "number" ? process.exitCode : undefined;
    process.stdout.write = savedStdoutWrite;
    process.stderr.write = savedStderrWrite;
    process.exit = savedExit;
    if (savedArgv1 !== undefined) process.argv[1] = savedArgv1;
    // Restore env wholesale: delete added keys, reset mutated ones.
    for (const key of Object.keys(process.env)) {
      if (!(key in savedEnv)) delete process.env[key];
    }
    for (const [key, value] of Object.entries(savedEnv)) {
      if (process.env[key] !== value) process.env[key] = value;
    }
    process.exitCode = savedExitCode;
    process.chdir(savedCwd);
  }

  const code =
    exitCode ??
    (typeof postExitCode === "number" ? postExitCode : null) ??
    (typeof resolved === "number" ? resolved : null);
  return { code, stdout: stdout.text, stderr: stderr.text, threw };
}

// ── unix-socket control RPC (HTTP/1.1 over the socket, spec §1.2/§3.1) ────

export interface UnixRpcResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  text: string;
  /** Parsed body when it is JSON, else undefined. */
  json: Record<string, unknown> | undefined;
}

/**
 * POST raw bytes to a control socket path. `body` may be a value (JSON
 * stringified here) or a Buffer/string sent verbatim — malformed-input
 * tests need the latter.
 */
export function unixRpc(
  socketPath: string,
  body: unknown,
  opts: { contentType?: string; headers?: Record<string, string> } = {},
): Promise<UnixRpcResult> {
  const payload = Buffer.isBuffer(body)
    ? body
    : typeof body === "string"
      ? Buffer.from(body, "utf8")
      : Buffer.from(JSON.stringify(body), "utf8");
  return new Promise((resolveP, reject) => {
    const req = http.request(
      {
        socketPath,
        method: "POST",
        path: "/v2/rpc",
        headers: {
          "content-type": opts.contentType ?? "application/json",
          "content-length": payload.length,
          ...opts.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: Record<string, unknown> | undefined;
          try {
            json = JSON.parse(text) as Record<string, unknown>;
          } catch {
            json = undefined;
          }
          resolveP({
            status: res.statusCode ?? 0,
            headers: res.headers,
            text,
            json,
          });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

/** GET a control-socket endpoint (healthz/metrics). */
export function unixGet(
  socketPath: string,
  urlPath: string,
): Promise<UnixRpcResult> {
  return new Promise((resolveP, reject) => {
    const req = http.request(
      { socketPath, method: "GET", path: urlPath },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: Record<string, unknown> | undefined;
          try {
            json = JSON.parse(text) as Record<string, unknown>;
          } catch {
            json = undefined;
          }
          resolveP({
            status: res.statusCode ?? 0,
            headers: res.headers,
            text,
            json,
          });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

/** §3.1 request envelope: exact {v,id,workspace,method,params} shape. */
export function rpcEnvelope(
  method: string,
  params: unknown,
  opts: { id?: string; workspace?: string } = {},
): Record<string, unknown> {
  return {
    v: 2,
    id: opts.id ?? `e2e${Math.floor(Math.random() * 1e6).toString(36)}`,
    workspace: opts.workspace ?? "default",
    method,
    params: params ?? {},
  };
}

export interface RpcResponse {
  ok: boolean;
  result?: unknown;
  receipt?: unknown;
  error?: { code?: string; retryable?: boolean; field?: string | null };
}

/** Parse one JSON envelope line off captured stdout. */
export function jsonLines(stdout: string): Record<string, unknown>[] {
  return stdout
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

// ── filesystem fixtures ──────────────────────────────────────────────────

export function tempDir(prefix = "latticeag-e2e-"): string {
  return mkdtempSync(path.join(tmpdir(), prefix));
}

/** One shared no-op bin stub per test process (for cliBinPath fallback). */
let sharedStub: string | null = null;
function stubBinPath(): string {
  if (sharedStub === null) {
    const dir = mkdtempSync(path.join(tmpdir(), "latticeag-stub-"));
    sharedStub = path.join(dir, "stub-bin.js");
    writeFileSync(sharedStub, "process.exit(0);\n", "utf8");
  }
  return sharedStub;
}

function ensureStubIn(dir: string): string {
  const stub = path.join(dir, "stub-bin.js");
  if (!existsSync(stub)) {
    writeFileSync(stub, "process.exit(0);\n", "utf8");
  }
  return stub;
}

export function cleanTemp(dir: string): Promise<void> {
  return rm(dir, { recursive: true, force: true });
}

/** A free loopback port for the v1 ingest listener. */
export function freePort(): Promise<number> {
  return new Promise((resolveP, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      server.close((err) => (err ? reject(err) : resolveP(port)));
    });
  });
}

/** Write a schema_version 1 latticeag.json (the `run` surface's input). */
export async function writeV1Config(
  dir: string,
  opts: { ingestPort?: number; name?: string } = {},
): Promise<LatticeagConfig> {
  const config = createDefaultConfig(opts.name ?? "e2e-project", []);
  if (opts.ingestPort !== undefined) {
    config.ingest.port = opts.ingestPort;
  }
  await mkdir(dir, { recursive: true });
  await writeFile(
    path.join(dir, "latticeag.json"),
    `${JSON.stringify(config, null, 2)}\n`,
    "utf8",
  );
  return config;
}

/**
 * Write a schema_version 2 latticeag.json by running the real §8.2
 * migration over a generated v1 document. Returns the v2 document as
 * written (so tests can point the daemon at it via config_path or
 * in-memory `config`).
 */
export async function writeV2Config(
  dir: string,
  opts: {
    workspace?: string;
    instance?: string;
    autostart?: "on-demand" | "never";
    uiPort?: number;
    uiEnabled?: boolean;
  } = {},
): Promise<Record<string, unknown>> {
  const v1 = createDefaultConfig("e2e-project", []);
  const doc = migrateConfig(
    v1 as unknown as Record<string, unknown>,
    opts.workspace ?? "default",
    opts.instance ?? "e2e1",
  ) as unknown as Record<string, unknown>;
  const gateway = doc.gateway as Record<string, unknown>;
  if (opts.autostart !== undefined) gateway.autostart = opts.autostart;
  const ui = gateway.ui as Record<string, unknown>;
  if (opts.uiPort !== undefined) ui.port = opts.uiPort;
  if (opts.uiEnabled !== undefined) ui.enabled = opts.uiEnabled;
  await mkdir(dir, { recursive: true });
  await writeFile(
    path.join(dir, "latticeag.json"),
    `${JSON.stringify(doc, null, 2)}\n`,
    "utf8",
  );
  return doc;
}

/** Read the daemon's published endpoints.json once it exists. */
export async function readEndpoints(
  configDir: string,
): Promise<Record<string, unknown>> {
  const file = path.join(configDir, ".latticeag", "runtime", "endpoints.json");
  return JSON.parse(await readFile(file, "utf8")) as Record<string, unknown>;
}

export function endpointsPath(configDir: string): string {
  return path.join(configDir, ".latticeag", "runtime", "endpoints.json");
}

/** Poll a predicate until true or the deadline passes (ms). */
export async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  timeoutMs = 8000,
  stepMs = 50,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return predicate();
}
