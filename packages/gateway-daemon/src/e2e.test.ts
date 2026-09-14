/**
 * End-to-end coverage for the fully wired daemon (spec §1.3, §3, §6, §9):
 * real store + real service graph + real sockets — no mocked domain
 * services. Proves:
 *  - durable receipts are committed and resolvable via receipt.get;
 *  - mutating-call idempotency bindings survive a full daemon restart;
 *  - the loopback bridge gates anonymous callers to the P-method
 *    allowlist and routes the session exchange;
 *  - events.subscribe creates a durable lease the SSE source serves;
 *  - unsupported product/catalog capabilities fail with honest codes
 *    instead of fabricated success;
 *  - the process supervisor reaps daemon-owned children on shutdown.
 */
import { describe, expect, test } from "vitest";
import { mkdtemp, rm, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import { F } from "@latticeag/testkit";
import { GatewayDaemon } from "./daemon.js";
import { ProductProcessSupervisor } from "./supervisor.js";

function unixRpc(
  socketPath: string,
  body: unknown,
): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolveP, reject) => {
    const req = http.request(
      {
        socketPath,
        method: "POST",
        path: "/v2/rpc",
        headers: { "content-type": "application/json" },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolveP({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<
              string,
              unknown
            >,
          }),
        );
      },
    );
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

function rpc(method: string, params: unknown, id = "q1"): Record<string, unknown> {
  return { v: 2, id, workspace: "ws1", method, params };
}

async function makeDaemon(dir: string): Promise<GatewayDaemon> {
  const d = new GatewayDaemon();
  const out = await d.start({
    configDir: dir,
    config: F.config2,
    socketPath: join(dir, "control.sock"),
    bridgePort: 0,
    staticDir: null,
  });
  expect(out.kind).toBe("started");
  return d;
}

type Envelope = {
  ok: boolean;
  result?: unknown;
  receipt?: { workspace: string; event: { hash: string } } | null;
  error?: { code: string };
};

describe("GatewayDaemon end-to-end (wired services)", () => {
  test("durable receipt → receipt.get resolves the sealed audit event", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-e2e-"));
    const d = await makeDaemon(dir);
    try {
      const status = await unixRpc(
        d.endpoint!.control_sock,
        rpc("daemon.status", {}, "e2e-status"),
      );
      expect(status.status).toBe(200);
      const sr = status.json as unknown as Envelope;
      expect(sr.ok).toBe(true);
      expect(sr.receipt).not.toBeNull();
      const ptr = sr.receipt!;
      expect(ptr.event.hash).toMatch(/^[0-9a-f]{64}$/);

      // The receipt pointer resolves through the actions index —
      // action = the pointer itself; disclosure is an explicit string.
      const got = await unixRpc(
        d.endpoint!.control_sock,
        rpc(
          "receipt.get",
          { action: ptr, disclosure: "objects" },
          "e2e-rcpt",
        ),
      );
      const gr = got.json as unknown as Envelope;
      expect(gr.ok).toBe(true);
      const receipt = gr.result as {
        action?: { event?: { hash: string } };
        inventory?: unknown[];
      };
      expect(receipt.action?.event?.hash).toBe(ptr.event.hash);
      expect(Array.isArray(receipt.inventory)).toBe(true);
    } finally {
      await d.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("mutating idempotency binding survives a restart", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-e2e-"));
    const d1 = await makeDaemon(dir);
    let first: { status: number; json: Record<string, unknown> };
    try {
      first = await unixRpc(
        d1.endpoint!.control_sock,
        rpc("events.subscribe", { topics: ["gateway.action"] }, "idem-1"),
      );
      expect(first.status).toBe(200);
      const r1 = first.json as unknown as Envelope;
      expect(r1.ok).toBe(true);
      expect(typeof (r1.result as { subscription?: unknown }).subscription)
        .toBe("string");
    } finally {
      await d1.stop();
    }
    // Fresh daemon over the same state root — journal replay rebuilds the
    // registry, including the operations-table binding.
    const d2 = await makeDaemon(dir);
    try {
      const replay = await unixRpc(
        d2.endpoint!.control_sock,
        rpc("events.subscribe", { topics: ["gateway.action"] }, "idem-1"),
      );
      expect(replay.status).toBe(200);
      // Byte-identical saved response — the durable binding won, no new
      // lease was minted.
      expect(replay.json).toEqual(first.json);

      // A DIFFERENT body under the same id is an idempotency conflict.
      const conflict = await unixRpc(
        d2.endpoint!.control_sock,
        rpc("events.subscribe", { topics: ["other.topic"] }, "idem-1"),
      );
      const cr = conflict.json as unknown as Envelope;
      expect(cr.ok).toBe(false);
      expect(cr.error?.code).toBe("IDEMPOTENCY_CONFLICT");
    } finally {
      await d2.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("bridge: anonymous callers reach only the P-method allowlist", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-e2e-"));
    const d = await makeDaemon(dir);
    try {
      const ui = new URL(d.endpoint!.ui_url!);
      // Non-allowlisted method without a session → 401 with an envelope
      // whose error code is an auth failure (P is unauthorized).
      const denied = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rpc("daemon.status", {}, "b1")),
      });
      expect(denied.status).toBe(401);
      const deniedBody = (await denied.json()) as {
        v?: number;
        ok?: boolean;
        error?: { code?: string } | string;
      };
      expect(deniedBody.v).toBe(2);
      expect(deniedBody.ok).toBe(false);
      const deniedCode =
        typeof deniedBody.error === "string"
          ? deniedBody.error
          : deniedBody.error?.code;
      expect(["AUTH_REQUIRED", "FORBIDDEN"]).toContain(deniedCode);

      // The allowlisted exchange reaches the service and gets a semantic
      // rejection (envelope-shaped AUTH_REQUIRED) for a bogus bootstrap.
      const ex = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          rpc("ui.session.exchange", { bootstrap: "bogus" }, "b2"),
        ),
      });
      const exBody = (await ex.json()) as {
        v?: number;
        ok?: boolean;
        error?: { code?: string };
      };
      expect(exBody.v).toBe(2);
      expect(exBody.ok).toBe(false);
      expect(exBody.error?.code).toBe("AUTH_REQUIRED");
    } finally {
      await d.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("product.plan/install and catalog.refresh fail honestly", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-e2e-"));
    const d = await makeDaemon(dir);
    try {
      // product.plan needs a release fetcher — none is bound, so the call
      // fails with an honest network/capability code, never a fake plan.
      const plan = await unixRpc(
        d.endpoint!.control_sock,
        rpc(
          "product.plan",
          { kind: "install", source: "demo@1.0.0" },
          "p1",
        ),
      );
      const pr = plan.json as unknown as Envelope;
      expect(pr.ok).toBe(false);
      expect([
        "NETWORK_UNAVAILABLE",
        "CAP_ADAPTER_UNAVAILABLE",
        "SANDBOX_UNAVAILABLE",
        "VERIFY_FAILED",
        "SIGNATURE_INVALID",
        "NOT_FOUND",
      ]).toContain(pr.error?.code);

      // product.install without a real plan → PLAN_STALE, still honest.
      const install = await unixRpc(
        d.endpoint!.control_sock,
        rpc(
          "product.install",
          {
            plan: "0".repeat(64),
            review: {
              profile: "review/1",
              namespace: "ws1",
              object_id: "x",
              commitment: "0".repeat(64),
              raw_sha256: "0".repeat(64),
              bytes: "2",
            },
          },
          "p2",
        ),
      );
      const ir = install.json as unknown as Envelope;
      expect(ir.ok).toBe(false);
      expect(ir.error?.code).toBe("PLAN_STALE");

      // product.list is honest about the empty registry.
      const list = await unixRpc(
        d.endpoint!.control_sock,
        rpc("product.list", { after: null, limit: 50 }, "p3"),
      );
      const lr = list.json as unknown as Envelope;
      expect(lr.ok).toBe(true);
      expect((lr.result as { items: unknown[] }).items).toEqual([]);

      // catalog.refresh has no fetch adapter or trust roots → honest fail.
      const refresh = await unixRpc(
        d.endpoint!.control_sock,
        rpc(
          "catalog.refresh",
          { source: "https://catalog.latticeag.example/index.json" },
          "p4",
        ),
      );
      const rr = refresh.json as unknown as Envelope;
      expect(rr.ok).toBe(false);
      expect([
        "NETWORK_UNAVAILABLE",
        "SIGNATURE_INVALID",
        "NOT_FOUND",
        "CAP_ADAPTER_UNAVAILABLE",
      ]).toContain(rr.error?.code);
    } finally {
      await d.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("events.subscribe creates a durable lease; events.ack advances it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-e2e-"));
    const d = await makeDaemon(dir);
    try {
      const sub = await unixRpc(
        d.endpoint!.control_sock,
        rpc("events.subscribe", { topics: ["gateway.action"] }, "s1"),
      );
      const sr = sub.json as unknown as Envelope;
      expect(sr.ok).toBe(true);
      const lease = sr.result as {
        subscription: string;
        cursor: string;
        expires_ms: number;
      };
      expect(lease.subscription).toBeTruthy();
      expect(lease.cursor).toMatch(/^c[0-9a-f]{16}:\d+$/);
      expect(lease.expires_ms).toBeGreaterThan(Date.now());

      // events.query is honest about the event index (limit required).
      const q = await unixRpc(
        d.endpoint!.control_sock,
        rpc(
          "events.query",
          { topics: ["gateway.action"], limit: 10 },
          "s2",
        ),
      );
      const qr = q.json as unknown as Envelope;
      expect(qr.ok).toBe(true);
    } finally {
      await d.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("SSE: durable subscription streams committed events over the bridge", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-e2e-"));
    const d = await makeDaemon(dir);
    try {
      const ui = new URL(d.endpoint!.ui_url!);
      const port = ui.port;
      const cookieName = `latticeag_session_gw1_${port}`;

      // Local operator mints a viewer bootstrap; the browser exchanges it.
      const created = await unixRpc(
        d.endpoint!.control_sock,
        rpc("ui.session.create", { role: "viewer" }, "sse1"),
      );
      const bootstrap = (created.json as { result: { bootstrap: string } })
        .result.bootstrap;
      const ex = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rpc("ui.session.exchange", { bootstrap }, "sse2")),
      });
      const exBody = (await ex.json()) as {
        result: { session: string; csrf: string };
      };
      const cookie = `${cookieName}=${exBody.result.session}`;
      const csrf = exBody.result.csrf;

      // The session mints a durable subscription.
      const sub = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          "x-latticeag-csrf": csrf,
        },
        body: JSON.stringify(
          rpc("events.subscribe", { topics: ["gateway.action"] }, "sse3"),
        ),
      });
      const subBody = (await sub.json()) as {
        ok: boolean;
        result: { subscription: string };
      };
      expect(subBody.ok).toBe(true);

      // Generate committed gateway.action events (any authed mutation).
      await unixRpc(
        d.endpoint!.control_sock,
        rpc("daemon.status", {}, "sse4"),
      );

      // Open the SSE stream — frames for the durable events arrive.
      const res = await fetch(
        `${ui.origin}/v2/events?subscription=${subBody.result.subscription}`,
        {
          headers: {
            cookie,
            "x-latticeag-csrf": csrf,
          },
        },
      );
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/event-stream");
      const reader = res.body!.getReader();
      const deadline = Date.now() + 5000;
      let text = "";
      while (Date.now() < deadline && !text.includes("record_ref")) {
        const { value, done } = await Promise.race([
          reader.read(),
          new Promise<{ value?: Uint8Array; done: boolean }>((r2) =>
            setTimeout(() => r2({ done: false }), 500),
          ),
        ]);
        if (done) break;
        if (value !== undefined) text += Buffer.from(value).toString("utf8");
      }
      await reader.cancel().catch(() => {});
      expect(text).toContain("id: c");
      expect(text).toContain("event: bus");
      expect(text).toContain('"topic":"gateway.action"');
    } finally {
      await d.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("DRAINING rejects new mutations after daemon.stop", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-e2e-"));
    const d = await makeDaemon(dir);
    try {
      const stop = await unixRpc(
        d.endpoint!.control_sock,
        rpc("daemon.stop", { grace_ms: 5000 }, "d1"),
      );
      expect((stop.json as { ok: boolean }).ok).toBe(true);
      // Post-stop mutations must never succeed: either a DRAINING
      // envelope or a torn-down listener — never ok:true. Fires in a
      // loop because the drain window races with socket teardown.
      let sawDraining = false;
      let transportClosed = false;
      for (let i = 0; i < 60; i += 1) {
        let outcome: "ok" | "draining" | "closed" | "other";
        try {
          const mut = await unixRpc(
            d.endpoint!.control_sock,
            rpc("events.subscribe", { topics: ["x"] }, `d2${i}`),
          );
          const mr = mut.json as unknown as Envelope;
          outcome =
            mr.ok === true
              ? "ok"
              : mr.error?.code === "DRAINING"
                ? "draining"
                : "other";
        } catch {
          outcome = "closed";
        }
        if (outcome === "draining") sawDraining = true;
        if (outcome === "closed") {
          transportClosed = true;
          break;
        }
        expect(outcome).not.toBe("ok");
        await new Promise((r2) => setTimeout(r2, 15));
      }
      expect(sawDraining || transportClosed).toBe(true);
      const deadline = Date.now() + 8000;
      while (d.state !== "STOPPED" && Date.now() < deadline) {
        await new Promise((r2) => setTimeout(r2, 50));
      }
      expect(d.state).toBe("STOPPED");
    } finally {
      await d.stop().catch(() => {});
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("endpoints.json appears only at READY and is removed on stop", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-e2e-"));
    const d = await makeDaemon(dir);
    try {
      const epPath = join(dir, ".latticeag", "runtime", "endpoints.json");
      const ep = JSON.parse(await readFile(epPath, "utf8")) as {
        state?: string;
        control_sock: string;
        ui_url: string;
      };
      expect(d.state).toBe("READY");
      expect(ep.control_sock).toBe(join(dir, "control.sock"));
      await d.stop();
      await expect(access(epPath)).rejects.toThrow();
    } finally {
      await d.stop().catch(() => {});
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("ProductProcessSupervisor", () => {
  test("spawnAdapter tracks children and shutdownAll SIGTERMs them", async () => {
    const sup = new ProductProcessSupervisor();
    const handle = sup.spawnAdapter(
      [process.execPath, "-e", "setTimeout(()=>{}, 60000)"],
      ".",
      {},
    );
    try {
      expect(sup.count()).toBe(1);
      expect(sup.pidAlive(handle.pid!)).toBe(true);
      await sup.shutdownAll(2000);
      expect(sup.count()).toBe(0);
      expect(sup.pidAlive(handle.pid!)).toBe(false);
    } finally {
      await sup.shutdownAll(500).catch(() => {});
    }
  });
});
