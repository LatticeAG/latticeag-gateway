/**
 * §6 loopback bridge — HTTP/1.1 on `127.0.0.1:<port>` (default 9848) plus
 * an optional literal `::1` listener when `config.ui.ipv6` is true.
 *
 * Security posture (spec §6/§7.3):
 *  - `Host` must equal `127.0.0.1:<port>` (or `[::1]:<port>`) byte-for-byte;
 *    anything else is FORBIDDEN — DNS-rebinding defense.
 *  - `Origin`, when present, must equal `http://<expected host>` exactly.
 *  - No CORS and no OPTIONS pre-flight: cross-origin requests die at the
 *    Host/Origin checks.
 *  - Every non-bootstrap request carries `X-LatticeAG-CSRF`; for session
 *    callers the value must equal the session's memory-only CSRF secret.
 *    Session auth is the host-only `latticeag_session_<instance>_<port>`
 *    cookie (HttpOnly, SameSite=Strict, no Domain, no Secure on loopback).
 *  - `ui.session.exchange` is the one bootstrap call: it authenticates via
 *    the one-use 60 s bootstrap token, and the response sets the cookie.
 *  - Bearer peers may also POST /v2/rpc (Authorization + X-LatticeAG-*
 *    proof headers); CSRF presence is still enforced as a transport guard.
 *  - Static assets come only from packages/gateway-web/dist when it exists;
 *    otherwise every static route is 404.
 *  - CSP + nosniff + Referrer-Policy on every response; token-bearing
 *    responses are `Cache-Control: no-store`.
 *  - Never binds 0.0.0.0/:: — an EADDRINUSE bind surfaces PORT_IN_USE and
 *    the existing occupant is never killed.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { ENVELOPE_LIMITS, HTTP_STATUS, RETRYABLE, RpcError, type RegistryErrorCode } from "../core-v2.js";
import {
  applyBaseSecurityHeaders,
  closeServer,
  failureEnvelope,
  parseCookies,
  readBody,
  sendJson,
  CSP_HEADER,
} from "./http-util.js";
import { parseStrictJson } from "./strict-json.js";
import {
  extractPeerProofHeaders,
  type SessionRecord,
  type TransportCredentials,
} from "../rpc/auth.js";
import type { DispatchOutcome } from "../rpc/dispatch.js";
import { parseLastEventId, serveSse, type SseRegistry, type SseSource } from "./sse.js";

export const BRIDGE_CSP = CSP_HEADER;
export const CSRF_HEADER = "x-latticeag-csrf";

const MIME: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

export interface BridgeSse {
  registry: SseRegistry;
  source: SseSource;
  /** Metrics hooks (optional). */
  onOpen?: () => void;
  onClose?: () => void;
}

export interface BridgeOptions {
  /** Gateway instance id (for the default session-cookie name). */
  instance: string;
  /**
   * Expected Host byte-for-byte. Defaults to `127.0.0.1:<bound port>` /
   * `[::1]:<bound port>` computed from the bind address + actual port.
   */
  host?: string;
  /**
   * Session cookie name. Defaults to
   * `latticeag_session_<instance>_<bound port>` (§6).
   */
  sessionCookie?: string;
  /**
   * Session token resolver (`peek` does not slide idle; `resolve` does).
   * The concrete `SessionStore` satisfies this; the daemon substitutes a
   * durable registry-backed resolver.
   */
  sessions: {
    peek(id: string): SessionRecord | null;
    resolve(id: string): SessionRecord | null;
  };
  /** SSE wiring; null disables GET /v2/events (404). */
  sse?: BridgeSse | null;
  /** gateway-web dist directory; null/undefined → static 404. */
  staticDir?: string | null;
  /** Bound dispatch — receives parsed body + resolved transport creds. */
  onRpc: (
    body: Buffer | unknown,
    creds: TransportCredentials,
    session: SessionRecord | null,
  ) => Promise<DispatchOutcome>;
  onHealth?: () => Record<string, unknown>;
  onReady?: () => { ok: boolean; body: Record<string, unknown> };
  onMetrics?: () => string;
}

function sendOutcome(res: ServerResponse, out: DispatchOutcome): void {
  sendJson(res, out.status, out.response, out.headers);
}

function bridgeFail(
  res: ServerResponse,
  code: RegistryErrorCode,
  field: string | null = null,
): void {
  const headers: Record<string, string> = {};
  if (RETRYABLE.has(code)) headers["Retry-After"] = "1";
  sendJson(res, HTTP_STATUS[code], failureEnvelope(null, code, { field }), headers);
}

async function serveStatic(
  res: ServerResponse,
  dist: string,
  urlPath: string,
): Promise<boolean> {
  let rel: string;
  try {
    const decoded = decodeURIComponent(urlPath);
    rel = decoded === "/" ? "index.html" : decoded.replace(/^\/+/, "");
  } catch {
    return false;
  }
  const abs = normalize(join(dist, rel));
  if (abs !== dist && !abs.startsWith(dist + sep)) return false;
  try {
    const st = await stat(abs);
    if (!st.isFile()) return false;
  } catch {
    return false;
  }
  const ext = abs.slice(abs.lastIndexOf("."));
  const body = await readFile(abs);
  sendJsonRaw(res, 200, body, MIME[ext] ?? "application/octet-stream");
  return true;
}

function sendJsonRaw(
  res: ServerResponse,
  status: number,
  body: Buffer,
  contentType: string,
): void {
  res.setHeader("Content-Type", contentType);
  res.setHeader("Content-Length", body.length);
  res.writeHead(status);
  res.end(body);
}

export interface BridgeHandle {
  server: Server;
  /** Actual bound port (when 0 was requested, the ephemeral port). */
  port: number;
  close(): Promise<void>;
}

/**
 * `ui.session.exchange` is the one call a browser makes before it holds a
 * session: its credential is the `params.bootstrap` token itself, consumed
 * by the service. Until then the caller is the bootstrap principal (role
 * P), modelled by the `anonymous` transport credential — a live session
 * still takes precedence when one is already held.
 */

/**
 * Bind one loopback HTTP server on `bind` ("127.0.0.1" or "::1").
 * `opts.host` is the expected Host header byte-for-byte.
 */
export async function createBridgeListener(
  bind: "127.0.0.1" | "::1",
  port: number,
  opts: BridgeOptions,
): Promise<BridgeHandle> {
  // Loopback-only is a runtime invariant, not just a type: a cast or a
  // non-TS caller must never open a non-loopback listener (spec §6).
  if (bind !== "127.0.0.1" && bind !== "::1") {
    throw new RpcError("SCHEMA_INVALID", "bridge bind must be a loopback address", {
      field: "bind",
    });
  }
  // Resolved after listen() so an ephemeral port produces the real values.
  let host = "";
  let sessionCookie = "";
  const dist = opts.staticDir !== undefined && opts.staticDir !== null
    ? resolve(opts.staticDir)
    : null;
  const staticDir =
    dist !== null &&
    (await stat(dist).then(
      (s) => s.isDirectory(),
      () => false,
    ))
      ? dist
      : null;

  const server = createServer((req, res) => {
    void route(req, res).catch(() => {
      if (!res.headersSent) {
        bridgeFail(res, "STORAGE_UNAVAILABLE");
      } else if (!res.writableEnded) {
        res.end();
      }
    });
  });

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "";
    const url = new URL(req.url ?? "/", "http://localhost");

    // ── Host / Origin (spec §6): exact byte match, FORBIDDEN otherwise ──
    const reqHost = req.headers.host ?? "";
    if (reqHost !== host) {
      applyBaseSecurityHeaders(res);
      res.setHeader("Content-Security-Policy", CSP_HEADER);
      bridgeFail(res, "FORBIDDEN");
      return;
    }
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== `http://${host}`) {
      applyBaseSecurityHeaders(res);
      res.setHeader("Content-Security-Policy", CSP_HEADER);
      bridgeFail(res, "FORBIDDEN");
      return;
    }

    applyBaseSecurityHeaders(res);
    res.setHeader("Content-Security-Policy", CSP_HEADER);

    if (method === "GET" && url.pathname === "/healthz") {
      sendJson(res, 200, opts.onHealth?.() ?? { ok: true });
      return;
    }
    if (method === "GET" && url.pathname === "/readyz") {
      const r = opts.onReady?.() ?? { ok: true, body: { ok: true, state: "READY" } };
      sendJson(res, r.ok ? 200 : 503, r.body);
      return;
    }
    if (method === "GET" && url.pathname === "/metrics") {
      const text = opts.onMetrics?.() ?? "";
      res.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Length", Buffer.byteLength(text));
      res.writeHead(200);
      res.end(text);
      return;
    }

    if (method === "GET" && url.pathname === "/v2/events") {
      if (opts.sse == null) {
        sendJson(res, 404, { error: "not found" });
        return;
      }
      const cookies = parseCookies(req.headers.cookie);
      const sessionId = cookies.get(sessionCookie);
      const session =
        sessionId !== undefined ? opts.sessions.peek(sessionId) : null;
      if (session === null) {
        bridgeFail(res, "AUTH_REQUIRED");
        return;
      }
      const csrf = req.headers[CSRF_HEADER];
      if (typeof csrf !== "string" || csrf !== session.csrf) {
        bridgeFail(res, "FORBIDDEN");
        return;
      }
      const subId = url.searchParams.get("subscription") ?? "";
      const sub = opts.sse.registry.lookup(subId);
      if (sub === null) {
        bridgeFail(res, "NOT_FOUND");
        return;
      }
      const lastEventId = parseLastEventId(
        typeof req.headers["last-event-id"] === "string"
          ? req.headers["last-event-id"]
          : undefined,
      );
      opts.sse.onOpen?.();
      try {
        await serveSse(res, sub, opts.sse.source, { lastEventId });
      } catch (e) {
        if ((e as { code?: string }).code === "CURSOR_GONE") {
          if (!res.headersSent) {
            bridgeFail(res, "CURSOR_GONE");
          } else if (!res.writableEnded) {
            res.end();
          }
        } else if (!res.writableEnded) {
          res.end();
        }
      } finally {
        opts.sse.onClose?.();
      }
      return;
    }

    if (method === "POST" && url.pathname === "/v2/rpc") {
      // application/json + identity only (same contract as the socket).
      const ctype = req.headers["content-type"];
      if (
        typeof ctype !== "string" ||
        !ctype.toLowerCase().startsWith("application/json")
      ) {
        bridgeFail(res, "SCHEMA_INVALID", "content-type");
        return;
      }
      const encoding = req.headers["content-encoding"];
      if (encoding !== undefined && encoding.toLowerCase() !== "identity") {
        bridgeFail(res, "SCHEMA_INVALID", "content-encoding");
        return;
      }
      const body = await readBody(req, ENVELOPE_LIMITS.requestBodyBytes);
      if (!body.ok) {
        res.setHeader("Connection", "close");
        res.once("finish", () => req.socket.destroy());
        bridgeFail(res, body.code);
        return;
      }
      // Peek at the parsed method for the bootstrap/CSRF decision; the
      // strict-parse outcome still flows through dispatch (JSON_INVALID).
      const parsed = parseStrictJson(body.body);
      const rpcMethod =
        parsed.ok &&
        parsed.value !== null &&
        typeof parsed.value === "object" &&
        !Array.isArray(parsed.value)
          ? (parsed.value as Record<string, unknown>).method
          : undefined;
      const isBootstrap = rpcMethod === "ui.session.exchange";

      const cookies = parseCookies(req.headers.cookie);
      const sessionId = cookies.get(sessionCookie);
      const session =
        sessionId !== undefined ? opts.sessions.resolve(sessionId) : null;

      let creds: TransportCredentials;
      if (isBootstrap) {
        // Bootstrap is CSRF-exempt (no session exists yet): the params token
        // is the credential; the anonymous/bootstrap principal (P) reaches
        // the service which consumes it or answers AUTH_REQUIRED.
        creds =
          session !== null
            ? { kind: "session", session }
            : { kind: "anonymous" };
      } else if (session !== null) {
        const csrf = req.headers[CSRF_HEADER];
        if (typeof csrf !== "string" || csrf !== session.csrf) {
          bridgeFail(res, "FORBIDDEN");
          return;
        }
        creds = { kind: "session", session };
      } else {
        const proof = extractPeerProofHeaders(
          (n) => req.headers[n] as string | undefined,
        );
        if (proof !== null) {
          const csrf = req.headers[CSRF_HEADER];
          if (typeof csrf !== "string" || csrf === "") {
            bridgeFail(res, "FORBIDDEN");
            return;
          }
          creds = { kind: "peer", headers: proof };
        } else {
          bridgeFail(res, "AUTH_REQUIRED");
          return;
        }
      }

      const outcome = await opts.onRpc(
        parsed.ok ? parsed.value : body.body,
        creds,
        session,
      );
      if (isBootstrap && outcome.status === 200) {
        const result = (outcome.response as Record<string, unknown>).result;
        if (
          result !== null &&
          typeof result === "object" &&
          typeof (result as Record<string, unknown>).session === "string"
        ) {
          res.setHeader(
            "Set-Cookie",
            `${sessionCookie}=${(result as Record<string, unknown>).session}; Path=/; HttpOnly; SameSite=Strict`,
          );
        }
      }
      sendOutcome(res, outcome);
      return;
    }

    if ((method === "GET" || method === "HEAD") && staticDir !== null) {
      if (await serveStatic(res, staticDir, url.pathname)) return;
    }
    sendJson(res, 404, { error: "not found" });
  }

  await new Promise<void>((resolveBind, reject) => {
    server.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        reject(
          new RpcError(
            "PORT_IN_USE",
            `loopback port ${port} is already in use; the occupant is not killed`,
          ),
        );
      } else {
        reject(err);
      }
    });
    server.listen(port, bind, () => resolveBind());
  });

  const actualPort = (server.address() as { port: number }).port;
  host =
    opts.host ??
    (bind === "::1" ? `[::1]:${actualPort}` : `127.0.0.1:${actualPort}`);
  sessionCookie =
    opts.sessionCookie ??
    `latticeag_session_${opts.instance}_${actualPort}`;
  return { server, port: actualPort, close: () => closeServer(server) };
}

/** Default dist location of packages/gateway-web inside the repo. */
export function defaultStaticDir(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  return resolve(join(here, "../../gateway-web/dist"));
}
