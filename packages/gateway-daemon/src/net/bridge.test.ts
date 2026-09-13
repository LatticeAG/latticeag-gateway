/**
 * Loopback bridge tests (spec §6): Host/Origin checks, CSRF, session
 * cookie, security headers, PORT_IN_USE, static fallback.
 */
import { describe, expect, test } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBridgeListener, type BridgeHandle } from "./bridge.js";
import { SessionStore } from "../rpc/auth.js";
import { RpcError } from "../core-v2.js";
import type { DispatchOutcome } from "../rpc/dispatch.js";
import http from "node:http";

function rawRequest(
  port: number,
  opts: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    body?: string;
  },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolveP, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: opts.method ?? "GET",
        path: opts.path ?? "/healthz",
        headers: opts.headers ?? {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolveP({
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

const okOutcome: DispatchOutcome = {
  status: 200,
  response: { v: 2, id: "q1", ok: true, result: {}, receipt: null },
  headers: {},
};

async function withBridge(
  fn: (b: BridgeHandle, base: string, sessions: SessionStore) => Promise<void>,
  opts: { sse?: boolean } = {},
): Promise<void> {
  const sessions = new SessionStore();
  const bridge = await createBridgeListener("127.0.0.1", 0, {
    instance: "gw1",
    sessions,
    staticDir: null,
    onRpc: async () => okOutcome,
  });
  try {
    await fn(bridge, `http://127.0.0.1:${bridge.port}`, sessions);
  } finally {
    await bridge.close();
  }
}

describe("createBridgeListener", () => {
  test("wrong Host header → 403 FORBIDDEN envelope", async () => {
    await withBridge(async (b) => {
      const r = await rawRequest(b.port, {
        headers: { Host: "evil.example:9848" },
      });
      expect(r.status).toBe(403);
      const env = JSON.parse(r.body) as { ok: boolean; error: { code: string } };
      expect(env.ok).toBe(false);
      expect(env.error.code).toBe("FORBIDDEN");
    });
  });

  test("missing CSRF on a session request → 403 FORBIDDEN", async () => {
    await withBridge(async (b, base, sessions) => {
      // Create a real session via the store's internal path.
      const { bootstrap } = sessions.createBootstrap("viewer");
      const session = sessions.exchange(bootstrap)!;
      const cookie = `latticeag_session_gw1_${b.port}=${session.id}`;
      const r = await fetch(`${base}/v2/rpc`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          // no X-LatticeAG-CSRF
        },
        body: JSON.stringify({ v: 2, id: "q1", workspace: "ws1", method: "daemon.status", params: {} }),
      });
      expect(r.status).toBe(403);
      const env = (await r.json()) as { error: { code: string } };
      expect(env.error.code).toBe("FORBIDDEN");
      // Wrong CSRF too.
      const r2 = await fetch(`${base}/v2/rpc`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          "x-latticeag-csrf": "wrong",
        },
        body: JSON.stringify({ v: 2, id: "q1", workspace: "ws1", method: "daemon.status", params: {} }),
      });
      expect(r2.status).toBe(403);
      // Correct CSRF passes the transport gate.
      const r3 = await fetch(`${base}/v2/rpc`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          "x-latticeag-csrf": session.csrf,
        },
        body: JSON.stringify({ v: 2, id: "q1", workspace: "ws1", method: "daemon.status", params: {} }),
      });
      expect(r3.status).toBe(200);
    });
  });

  test("no credentials at all → 401 AUTH_REQUIRED", async () => {
    await withBridge(async (_b, base) => {
      const r = await fetch(`${base}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ v: 2, id: "q1", workspace: "ws1", method: "daemon.status", params: {} }),
      });
      expect(r.status).toBe(401);
      const env = (await r.json()) as { error: { code: string } };
      expect(env.error.code).toBe("AUTH_REQUIRED");
    });
  });

  test("wrong Origin → 403; exact Origin → ok", async () => {
    await withBridge(async (b, base, sessions) => {
      const { bootstrap } = sessions.createBootstrap("viewer");
      const session = sessions.exchange(bootstrap)!;
      const cookie = `latticeag_session_gw1_${b.port}=${session.id}`;
      const headers = {
        "content-type": "application/json",
        cookie,
        "x-latticeag-csrf": session.csrf,
      };
      const bad = await fetch(`${base}/v2/rpc`, {
        method: "POST",
        headers: { ...headers, origin: "http://evil.example" },
        body: JSON.stringify({ v: 2, id: "q1", workspace: "ws1", method: "daemon.status", params: {} }),
      });
      expect(bad.status).toBe(403);
      const good = await fetch(`${base}/v2/rpc`, {
        method: "POST",
        headers: { ...headers, origin: `http://127.0.0.1:${b.port}` },
        body: JSON.stringify({ v: 2, id: "q1", workspace: "ws1", method: "daemon.status", params: {} }),
      });
      expect(good.status).toBe(200);
    });
  });

  test("CSP + nosniff + referrer headers are present", async () => {
    await withBridge(async (_b, base) => {
      const r = await fetch(`${base}/healthz`);
      expect(r.headers.get("content-security-policy")).toContain(
        "default-src 'none'",
      );
      expect(r.headers.get("content-security-policy")).toContain(
        "frame-ancestors 'none'",
      );
      expect(r.headers.get("x-content-type-options")).toBe("nosniff");
      expect(r.headers.get("referrer-policy")).toBe("no-referrer");
    });
  });

  test("EADDRINUSE → PORT_IN_USE and the occupant is untouched", async () => {
    const sessions = new SessionStore();
    const first = await createBridgeListener("127.0.0.1", 0, {
      instance: "gw1",
      sessions,
      onRpc: async () => okOutcome,
    });
    try {
      await expect(
        createBridgeListener("127.0.0.1", first.port, {
          instance: "gw1",
          sessions,
          onRpc: async () => okOutcome,
        }),
      ).rejects.toMatchObject({ code: "PORT_IN_USE" });
      // First listener still serves.
      const r = await fetch(`http://127.0.0.1:${first.port}/healthz`);
      expect(r.status).toBe(200);
    } finally {
      await first.close();
    }
  });

  test("static 404 without gateway-web dist; served when present", async () => {
    await withBridge(async (_b, base) => {
      const r = await fetch(`${base}/`);
      expect(r.status).toBe(404);
    });
    const dir = await mkdtemp(join(tmpdir(), "gw-web-dist-"));
    try {
      await writeFile(join(dir, "index.html"), "<h1>ui</h1>");
      const sessions = new SessionStore();
      const b = await createBridgeListener("127.0.0.1", 0, {
        instance: "gw1",
        sessions,
        staticDir: dir,
        onRpc: async () => okOutcome,
      });
      try {
        const r = await fetch(`http://127.0.0.1:${b.port}/`);
        expect(r.status).toBe(200);
        expect(await r.text()).toBe("<h1>ui</h1>");
        // Path traversal is refused.
        const trav = await fetch(
          `http://127.0.0.1:${b.port}/..%2f..%2fetc%2fpasswd`,
        );
        expect(trav.status).toBe(404);
      } finally {
        await b.close();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("OPTIONS pre-flight gets no CORS authorization", async () => {
    await withBridge(async (_b, base) => {
      const r = await fetch(`${base}/v2/rpc`, { method: "OPTIONS" });
      expect(r.status).toBe(404);
      expect(r.headers.get("access-control-allow-origin")).toBeNull();
    });
  });

  test("PORT_IN_USE error is an RpcError", () => {
    const e = new RpcError("PORT_IN_USE", "x");
    expect(e.code).toBe("PORT_IN_USE");
  });
});
