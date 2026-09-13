/**
 * Unix control-socket tests (spec §1.2/§3.1): real HTTP/1.1 over the socket,
 * route table, body cap, security headers.
 */
import { describe, expect, test } from "vitest";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import { createControlServer, type ControlServer } from "./socket-server.js";

function unixRequest(
  socketPath: string,
  opts: { method?: string; path?: string; body?: string | Buffer; headers?: Record<string, string> },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        method: opts.method ?? "POST",
        path: opts.path ?? "/v2/rpc",
        headers: opts.headers ?? { "content-type": "application/json" },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    req.on("error", reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

async function withServer(
  fn: (s: ControlServer, dir: string) => Promise<void>,
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "gw-sock-test-"));
  const socketPath = join(dir, "control.sock");
  const server = await createControlServer({
    socketPath,
    holdsLock: true,
    onRpc: async ({ body }) => ({
      status: 200,
      response: { v: 2, ok: true, echo: body.toString("utf8") },
    }),
  });
  try {
    await fn(server, dir);
  } finally {
    await server.close();
    await rm(dir, { recursive: true, force: true });
  }
}

describe("createControlServer", () => {
  test("POST /v2/rpc round trip", async () => {
    await withServer(async (s, _dir) => {
      const r = await unixRequest(s.path, {
        body: JSON.stringify({ v: 2, id: "q1", method: "x" }),
      });
      expect(r.status).toBe(200);
      const body = JSON.parse(r.body) as { echo: string };
      expect(body.echo).toContain('"method":"x"');
      // §7.6 base headers on every response.
      expect(r.headers["x-content-type-options"]).toBe("nosniff");
      expect(r.headers["referrer-policy"]).toBe("no-referrer");
      // Socket file is owner-only.
      const st = await stat(s.path);
      expect(st.mode & 0o777).toBe(0o600);
    });
  });

  test("GET /healthz answers alive", async () => {
    await withServer(async (s) => {
      const r = await unixRequest(s.path, { method: "GET", path: "/healthz" });
      expect(r.status).toBe(200);
      expect(JSON.parse(r.body)).toEqual({ alive: true });
    });
  });

  test("wrong path is 404", async () => {
    await withServer(async (s) => {
      const r = await unixRequest(s.path, { method: "GET", path: "/nope" });
      expect(r.status).toBe(404);
      const r2 = await unixRequest(s.path, { method: "POST", path: "/other" });
      expect(r2.status).toBe(404);
    });
  });

  test("oversized body is 413 BODY_LIMIT", async () => {
    await withServer(async (s) => {
      const big = Buffer.alloc(2 * 1024 * 1024 + 1, 0x61);
      const r = await unixRequest(s.path, { body: big });
      expect(r.status).toBe(413);
      const env = JSON.parse(r.body) as { error: { code: string } };
      expect(env.error.code).toBe("BODY_LIMIT");
    });
  });

  test("non-JSON content type is rejected", async () => {
    await withServer(async (s) => {
      const r = await unixRequest(s.path, {
        body: "{}",
        headers: { "content-type": "text/plain" },
      });
      expect(r.status).toBe(400);
      const env = JSON.parse(r.body) as { error: { code: string } };
      expect(env.error.code).toBe("SCHEMA_INVALID");
    });
  });
});
