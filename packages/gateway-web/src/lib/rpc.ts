/**
 * Typed client for the loopback control bridge (spec §3.1/§7.2).
 *
 * Every call is `POST /v2/rpc` with the closed v2 envelope
 * `{v:2,id,workspace,method,params}` and, once a session exists, the
 * memory-only `X-LatticeAG-CSRF` secret. `ui.session.exchange` is the one
 * CSRF-exempt call: it authenticates with the one-use `#bootstrap=`
 * fragment token instead.
 *
 * Nothing is persisted — no Web Storage, no cookie writes from JS (the
 * session cookie is HttpOnly and set by the bridge on exchange).
 */

export const CSRF_HEADER = "X-LatticeAG-CSRF";
export const RPC_PATH = "/v2/rpc";

/** Closed-registry RPC failure surfaced to callers (spec §3.1). */
export class RpcError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly field: string | null;
  constructor(code: string, message: string, opts: { retryable?: boolean; field?: string | null } = {}) {
    super(message);
    this.name = "RpcError";
    this.code = code;
    this.retryable = opts.retryable ?? false;
    this.field = opts.field ?? null;
  }
}

/** In-memory browser session returned by ui.session.exchange. */
export interface Session {
  session: string;
  role: "viewer" | "operator";
  csrf: string;
  expires_ms?: number;
  /** Workspace binding used on every subsequent envelope. */
  workspace: string;
}

interface RequestEnvelope {
  v: 2;
  id: string;
  workspace: string;
  method: string;
  params: unknown;
}

/** `Id` grammar: `^[A-Za-z][A-Za-z0-9_-]{0,63}$` — 128 random bits. */
export function newRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let s = "r";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export interface RpcClientOptions {
  /** Current workspace id bound into every envelope. */
  workspace: () => string;
  /** Current CSRF secret (null pre-session → exchange only). */
  csrf?: () => string | null;
  fetchFn?: typeof fetch;
  /** Milliseconds before the request is aborted (default 15000). */
  timeoutMs?: number;
}

function toError(value: unknown): RpcError {
  if (value instanceof RpcError) return value;
  const e = value as { code?: unknown; message?: unknown };
  return new RpcError(
    typeof e.code === "string" ? e.code : "NETWORK_UNAVAILABLE",
    typeof e.message === "string" ? e.message : "request failed",
    { retryable: true },
  );
}

export class RpcClient {
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
  private readonly workspaceOf: () => string;
  private readonly csrfOf: () => string | null;

  constructor(opts: RpcClientOptions) {
    this.fetchFn = opts.fetchFn ?? fetch.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    this.workspaceOf = opts.workspace;
    this.csrfOf = opts.csrf ?? (() => null);
  }

  /**
   * One control RPC. Resolves with the Success envelope's `result`;
   * rejects with RpcError {code,retryable,field} on a Failure envelope or
   * a transport failure.
   */
  async call<T = unknown>(method: string, params: unknown = {}, opts: { signal?: AbortSignal } = {}): Promise<T> {
    const env: RequestEnvelope = {
      v: 2,
      id: newRequestId(),
      workspace: this.workspaceOf(),
      method,
      params: params as RequestEnvelope["params"],
    };
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    const csrf = this.csrfOf();
    if (csrf !== null && method !== "ui.session.exchange") headers[CSRF_HEADER] = csrf;

    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), this.timeoutMs);
    const link = opts.signal;
    const onAbort = () => timeout.abort();
    link?.addEventListener("abort", onAbort, { once: true });
    let res: Response;
    try {
      res = await this.fetchFn(RPC_PATH, {
        method: "POST",
        headers,
        body: JSON.stringify(env),
        signal: timeout.signal,
        credentials: "same-origin",
        referrerPolicy: "no-referrer",
      });
    } catch (e) {
      throw toError(e);
    } finally {
      clearTimeout(timer);
      link?.removeEventListener("abort", onAbort);
    }

    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new RpcError("JSON_INVALID", `HTTP ${res.status} with non-JSON body`);
    }
    const env2 = body as {
      ok?: unknown;
      result?: unknown;
      error?: { code?: unknown; retryable?: unknown; field?: unknown };
    };
    if (env2.ok === true) return env2.result as T;
    const err = env2.error ?? {};
    throw new RpcError(
      typeof err.code === "string" ? err.code : `HTTP_${res.status}`,
      `RPC ${method} failed (${typeof err.code === "string" ? err.code : res.status})`,
      {
        retryable: err.retryable === true,
        field: typeof err.field === "string" ? err.field : null,
      },
    );
  }
}

/** Parsed `#bootstrap=…` (plus optional forward-compatible params). */
export interface BootstrapParams {
  bootstrap: string;
  workspace?: string;
}

/**
 * Parse the bootstrap fragment. Accepts `#bootstrap=<token>` and the
 * forward-compatible `#bootstrap=<token>&workspace=<id>` form so the
 * daemon/CLI can add the workspace binding without a format change.
 */
export function parseBootstrapFragment(hash: string): BootstrapParams | null {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (raw === "") return null;
  const params = new URLSearchParams(raw);
  const bootstrap = params.get("bootstrap");
  if (bootstrap === null || bootstrap === "") return null;
  const workspace = params.get("workspace");
  return { bootstrap, workspace: workspace === null || workspace === "" ? undefined : workspace };
}

export interface BootstrapExchangeResult {
  session: Session;
}

/**
 * §7.2 bootstrap: read `#bootstrap=` → same-origin `ui.session.exchange`
 * → keep {session,role,csrf,workspace} in memory → replaceState clears the
 * fragment. The fragment is cleared even on failure — the one-use token
 * must never linger in history or be sent as Referer.
 */
export async function bootstrapFromLocation(opts: {
  location: Pick<Location, "hash" | "pathname" | "search">;
  history: Pick<History, "replaceState">;
  fetchFn?: typeof fetch;
  /** Fallback workspace when the fragment carries none. */
  defaultWorkspace?: string;
}): Promise<BootstrapExchangeResult | null> {
  const parsed = parseBootstrapFragment(opts.location.hash);
  // Clear the fragment immediately — before the network call resolves.
  if (parsed !== null) {
    opts.history.replaceState(null, "", `${opts.location.pathname}${opts.location.search}`);
  }
  if (parsed === null) return null;
  const workspace = parsed.workspace ?? opts.defaultWorkspace ?? "default";

  const client = new RpcClient({ workspace: () => workspace, fetchFn: opts.fetchFn });
  const result = await client.call<{
    session: string;
    role: "viewer" | "operator";
    csrf: string;
    expires_ms?: number;
  }>("ui.session.exchange", { bootstrap: parsed.bootstrap });
  return { session: { ...result, workspace } };
}
