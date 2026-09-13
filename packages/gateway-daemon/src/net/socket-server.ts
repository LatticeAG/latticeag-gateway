/**
 * Control listener: HTTP/1.1 over a Unix domain socket (spec §1.2, §3.1).
 *
 * Path: `$XDG_RUNTIME_DIR/latticeag/<instance>/control.sock` when the XDG
 * runtime directory exists and is owner-private; otherwise
 * `<stateRoot>/runtime/control.sock`. The socket's parent directory is
 * 0700 and the socket itself is chmod 0600.
 *
 * Caller authentication (spec §3.1: "Socket/pipe callers are authenticated
 * as the OS user"): the platform mechanisms are `SO_PEERCRED` (Linux) and
 * `getpeereid` (macOS). Pure Node exposes neither, so this implementation
 * enforces the equivalent through filesystem permissions — an owner-only
 * directory chain plus a 0600 socket means only the owning UID (or root)
 * can connect — and every accepted connection is bound to the
 * `local_operator` (L) principal. If a native helper later exposes peer
 * credentials, it must *re-verify* uid==euid here; this code must not trust
 * a caller-supplied uid.
 *
 * A stale socket path is replaced only while holding the instance lock
 * (the caller guarantees lock order), and only after the old path is
 * validated as a socket owned by this uid — never unlink anything else.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { lstat, unlink, chmod, stat } from "node:fs/promises";
import { join } from "node:path";
import { ensureDir, pathExists } from "../store/util.js";
import { ENVELOPE_LIMITS } from "../core-v2.js";
import {
  applyBaseSecurityHeaders,
  closeServer,
  readBody,
  sendError,
  sendJson,
} from "./http-util.js";

/** Serialized RPC outcome produced by the dispatch pipeline (§3.1). */
export interface RpcHttpResult {
  status: number;
  response: unknown;
  headers?: Record<string, string>;
}

/** The transport hook every listener drives into the dispatch pipeline. */
export type RpcHandler = (req: {
  body: Buffer;
  transport: "socket" | "bridge";
}) => Promise<RpcHttpResult>;

export class UnsafeSocketPathError extends Error {
  readonly code = "SOCKET_PATH_UNSAFE" as const;
  constructor(message: string) {
    super(message);
    this.name = "UnsafeSocketPathError";
  }
}

function euid(): number | null {
  return typeof process.geteuid === "function" ? process.geteuid() : null;
}

/**
 * §1.2 ancestor check: walk `dir` and every ancestor to the filesystem
 * root; reject symlinks, non-owned non-root owners, and group/world
 * writable entries lacking the sticky bit (a world-writable *sticky*
 * directory such as /tmp cannot be abused to replace our socket).
 */
export async function assertSafeSocketAncestors(dir: string): Promise<void> {
  if (process.platform === "win32") return;
  const uid = euid();
  let cur = dir;
  for (;;) {
    const st = await lstat(cur);
    if (st.isSymbolicLink()) {
      throw new UnsafeSocketPathError(`socket ancestor ${cur} is a symlink`);
    }
    if (uid !== null && st.uid !== uid && st.uid !== 0) {
      throw new UnsafeSocketPathError(
        `socket ancestor ${cur} is owned by uid ${st.uid}`,
      );
    }
    const writable = (st.mode & 0o022) !== 0;
    const sticky = (st.mode & 0o1000) !== 0;
    if (writable && !sticky) {
      throw new UnsafeSocketPathError(
        `socket ancestor ${cur} is group/world-writable without sticky bit`,
      );
    }
    const parent = join(cur, "..");
    const resolved = new URL(`file://${cur}/..`).pathname;
    if (resolved === cur || parent === cur) return;
    cur = resolved;
  }
}

/**
 * Resolve the control socket path (spec §1.2): the XDG runtime dir when it
 * exists and is owner-private; otherwise the state runtime directory.
 */
export async function resolveControlSocketPath(
  stateRoot: string,
  instance: string,
): Promise<{ path: string; dir: string; source: "xdg" | "state" }> {
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (
    typeof xdg === "string" &&
    xdg.length > 0 &&
    process.platform !== "win32"
  ) {
    try {
      const st = await stat(xdg);
      const uid = euid();
      if (
        st.isDirectory() &&
        (uid === null || st.uid === uid || st.uid === 0) &&
        (st.mode & 0o077) === 0
      ) {
        const dir = join(xdg, "latticeag", instance);
        await ensureDir(dir);
        return { path: join(dir, "control.sock"), dir, source: "xdg" };
      }
    } catch {
      /* fall through to state dir */
    }
  }
  const dir = join(stateRoot, "runtime");
  await ensureDir(dir);
  return { path: join(dir, "control.sock"), dir, source: "state" };
}

export interface ControlServerOptions {
  /** Fully resolved socket path (see resolveControlSocketPath). */
  socketPath: string;
  /** RPC handler; invoked only for POST /v2/rpc. */
  onRpc: RpcHandler;
  /** Liveness for GET /healthz; default always alive. */
  healthz?: () => { alive: boolean };
  /** Optional §11 metrics handler (local-operator authenticated socket). */
  metrics?: () => string;
  /**
   * Set true by the caller (daemon) once it holds the instance lock — the
   * only state in which replacing a stale socket is permitted.
   */
  holdsLock: boolean;
}

export interface ControlServer {
  readonly path: string;
  readonly server: Server;
  close(): Promise<void>;
}

/**
 * Replace a stale socket file: the old path must exist, be a socket, and be
 * owned by this uid. Anything else is refused — the lock holder never
 * deletes an unexpected file type or another user's socket.
 */
async function replaceStaleSocket(socketPath: string): Promise<void> {
  if (!(await pathExists(socketPath))) return;
  const st = await lstat(socketPath);
  const uid = euid();
  if (!st.isSocket()) {
    throw new UnsafeSocketPathError(
      `refusing to replace non-socket path ${socketPath}`,
    );
  }
  if (uid !== null && st.uid !== uid) {
    throw new UnsafeSocketPathError(
      `refusing to replace socket ${socketPath} owned by uid ${st.uid}`,
    );
  }
  await unlink(socketPath);
}

/** Create and bind the unix-socket control server. */
export async function createControlServer(
  opts: ControlServerOptions,
): Promise<ControlServer> {
  const { socketPath } = opts;
  const parent = join(socketPath, "..");
  await ensureDir(parent);
  await chmod(parent, 0o700).catch(() => {});
  await assertSafeSocketAncestors(parent);
  if (opts.holdsLock) {
    await replaceStaleSocket(socketPath);
  } else if (await pathExists(socketPath)) {
    throw new UnsafeSocketPathError(
      "socket path exists and the instance lock is not held",
    );
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void route(req, res).catch(() => {
      if (!res.headersSent) sendError(res, null, "STORAGE_UNAVAILABLE");
      if (!res.writableEnded) res.end();
    });
  });

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    applyBaseSecurityHeaders(res);
    const url = req.url ?? "/";
    if (req.method === "GET" && url === "/healthz") {
      const h = opts.healthz?.() ?? { alive: true };
      if (h.alive) {
        sendJson(res, 200, { alive: true });
      } else {
        sendJson(res, 503, { alive: false });
      }
      return;
    }
    if (req.method === "GET" && url === "/metrics" && opts.metrics !== undefined) {
      const body = Buffer.from(opts.metrics(), "utf8");
      res.setHeader("Content-Type", "text/plain; version=0.0.4");
      res.setHeader("Content-Length", body.length);
      res.writeHead(200);
      res.end(body);
      return;
    }
    if (req.method !== "POST" || url !== "/v2/rpc") {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    // §3.1: application/json + identity content encoding only.
    const ctype = req.headers["content-type"];
    if (
      typeof ctype !== "string" ||
      !ctype.toLowerCase().startsWith("application/json")
    ) {
      sendError(res, null, "SCHEMA_INVALID", { field: "content-type" });
      return;
    }
    const encoding = req.headers["content-encoding"];
    if (
      encoding !== undefined &&
      encoding.toLowerCase() !== "identity"
    ) {
      sendError(res, null, "SCHEMA_INVALID", { field: "content-encoding" });
      return;
    }
    const body = await readBody(req, ENVELOPE_LIMITS.requestBodyBytes);
    if (!body.ok) {
      res.setHeader("Connection", "close");
      res.once("finish", () => req.socket.destroy());
      sendError(res, null, body.code);
      return;
    }
    const out = await opts.onRpc({ body: body.body, transport: "socket" });
    for (const [k, v] of Object.entries(out.headers ?? {})) {
      res.setHeader(k, v);
    }
    sendJson(res, out.status, out.response);
  }

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  await chmod(socketPath, 0o600);

  return {
    path: socketPath,
    server,
    close: () => closeServer(server),
  };
}
