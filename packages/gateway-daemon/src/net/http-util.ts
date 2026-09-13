/**
 * Shared HTTP/1.1 plumbing for the control socket and loopback bridge.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { HTTP_STATUS, type RegistryErrorCode } from "../core-v2.js";
import type { Json } from "../store/util.js";

/** Spec-mandated browser-facing response headers (§7.6). */
export const CSP_HEADER =
  "default-src 'none'; script-src 'self'; style-src 'self'; " +
  "img-src 'self' data:; connect-src 'self'; font-src 'self'; " +
  "frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

export function applyBaseSecurityHeaders(res: ServerResponse): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
}

export function applyBridgeSecurityHeaders(res: ServerResponse): void {
  applyBaseSecurityHeaders(res);
  res.setHeader("Content-Security-Policy", CSP_HEADER);
}

/** Result of a bounded request-body read. */
export type BodyRead =
  | { ok: true; body: Buffer }
  | { ok: false; code: "BODY_LIMIT" | "JSON_INVALID" };

/**
 * Read a request body with a hard byte cap. Exceeding the cap destroys the
 * request stream and resolves to BODY_LIMIT (§3.1 transport cap).
 */
export function readBody(req: IncomingMessage, capBytes: number): Promise<BodyRead> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    const finish = (r: BodyRead): void => {
      if (done) return;
      done = true;
      resolve(r);
    };
    req.on("data", (chunk: Buffer) => {
      if (done) return;
      total += chunk.length;
      if (total > capBytes) {
        // Pause (do NOT destroy) so the 413 response can still flush on this
        // socket; the caller should then close the connection.
        finish({ ok: false, code: "BODY_LIMIT" });
        req.removeAllListeners("data");
        req.pause();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => finish({ ok: true, body: Buffer.concat(chunks) }));
    req.on("error", () => finish({ ok: false, code: "JSON_INVALID" }));
    req.on("close", () => finish({ ok: false, code: "JSON_INVALID" }));
  });
}

/** The closed failure envelope shape (§3.1). */
export function failureEnvelope(
  id: string | null,
  code: RegistryErrorCode,
  opts: { retryable?: boolean; field?: string | null; receipt?: unknown } = {},
): Record<string, unknown> {
  return {
    v: 2,
    id,
    ok: false,
    error: {
      code,
      retryable: opts.retryable ?? false,
      field: opts.field ?? null,
    },
    receipt: (opts.receipt ?? null) as Json,
  };
}

export function sendJson(
  res: ServerResponse,
  status: number,
  value: unknown,
  headers: Record<string, string> = {},
): void {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", body.length);
  res.writeHead(status);
  res.end(body);
}

/** Send a closed-registry error as a §3.1 failure envelope. */
export function sendError(
  res: ServerResponse,
  id: string | null,
  code: RegistryErrorCode,
  opts: { retryable?: boolean; field?: string | null; headers?: Record<string, string>; retryAfterMs?: number } = {},
): void {
  const headers = { ...(opts.headers ?? {}) };
  if (opts.retryAfterMs !== undefined) {
    headers["Retry-After"] = String(Math.ceil(opts.retryAfterMs / 1000));
  }
  sendJson(
    res,
    HTTP_STATUS[code],
    failureEnvelope(id, code, { retryable: opts.retryable, field: opts.field }),
    headers,
  );
}

/** Parse the Cookie header into a name→value map (first occurrence wins). */
export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (header === undefined) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (name.length === 0 || out.has(name)) continue;
    out.set(name, part.slice(eq + 1).trim());
  }
  return out;
}

/** Best-effort socket close used by stop/drain paths. */
export function closeServer(server: { close(cb?: (err?: Error) => void): void; closeAllConnections?(): void }): Promise<void> {
  return new Promise((resolve) => {
    try {
      server.closeAllConnections?.();
    } catch {
      /* unsupported */
    }
    server.close(() => resolve());
    // Never hang a shutdown on a stuck listener.
    setTimeout(resolve, 1500).unref();
  });
}
