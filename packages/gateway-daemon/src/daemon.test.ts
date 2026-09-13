/**
 * Lifecycle tests (spec §1.2/§1.3/§8): start → READY marker + endpoints.json
 * → RPC over the control socket → stop → STOPPED; a second start hands back
 * the incumbent endpoint.
 */
import { describe, expect, test } from "vitest";
import { mkdtemp, rm, readFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import { F } from "@latticeag/testkit";
import { GatewayDaemon, type StartOutcome } from "./daemon.js";

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

describe("GatewayDaemon lifecycle", () => {
  test("start → READY marker + endpoints.json; stop → STOPPED", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-daemon-test-"));
    const d = new GatewayDaemon();
    try {
      const out = await d.start({
        configDir: dir,
        config: F.config2,
        socketPath: join(dir, "control.sock"),
        bridgePort: 0,
        staticDir: null,
      });
      expect(out.kind).toBe("started");
      if (out.kind !== "started") return;
      expect(d.state).toBe("READY");

      // endpoints.json under <stateRoot>/runtime/ is the READY marker.
      const epRaw = await readFile(
        join(dir, ".latticeag", "runtime", "endpoints.json"),
        "utf8",
      );
      const ep = JSON.parse(epRaw) as {
        pid: number;
        instance: string;
        control_sock: string;
        ui_url: string;
      };
      expect(ep.instance).toBe("gw1");
      expect(ep.control_sock).toBe(join(dir, "control.sock"));
      expect(ep.ui_url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/$/);

      // daemon.hello over the unix socket (L caller, no receipt).
      const hello = await unixRpc(ep.control_sock, rpc("daemon.hello", {
        profiles: ["proof-evidence/1"],
        interfaces: "interfaces/1",
      }));
      expect(hello.status).toBe(200);
      const hr = hello.json as { ok: boolean; receipt: unknown; result: { protocol: string } };
      expect(hr.ok).toBe(true);
      expect(hr.receipt).toBeNull();
      expect(hr.result.protocol).toBe("latticeag-gateway/2");

      // daemon.status carries a receipt + state.
      const status = await unixRpc(ep.control_sock, rpc("daemon.status", {}));
      const sr = status.json as { ok: boolean; result: { state: string }; receipt: unknown };
      expect(sr.ok).toBe(true);
      expect(sr.result.state).toBe("READY");
      expect(sr.receipt).not.toBeNull();

      await d.stop();
      expect(d.state).toBe("STOPPED");
      // endpoints.json removed on clean stop.
      await expect(
        access(join(dir, ".latticeag", "runtime", "endpoints.json")),
      ).rejects.toThrow();
    } finally {
      await d.stop().catch(() => {});
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("second start returns the incumbent endpoint", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-daemon-test-"));
    const d1 = await makeDaemon(dir);
    try {
      const d2 = new GatewayDaemon();
      const out: StartOutcome = await d2.start({
        configDir: dir,
        config: F.config2,
        socketPath: join(dir, "control.sock"),
        bridgePort: 0,
        staticDir: null,
      });
      expect(out.kind).toBe("running");
      if (out.kind !== "running") return;
      expect(out.endpoint?.control_sock).toBe(join(dir, "control.sock"));
    } finally {
      await d1.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("daemon.stop RPC drains then reaches STOPPED", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-daemon-test-"));
    const d = await makeDaemon(dir);
    try {
      const res = await unixRpc(d.endpoint!.control_sock, rpc("daemon.stop", { grace_ms: 500 }));
      expect(res.status).toBe(200);
      const r = res.json as { ok: boolean; result: { state: string } };
      expect(r.ok).toBe(true);
      expect(r.result.state).toBe("DRAINING");
      // The scheduled stop completes quickly (grace 500 ms, no inflight).
      const deadline = Date.now() + 8000;
      while (d.state !== "STOPPED" && Date.now() < deadline) {
        await new Promise((r2) => setTimeout(r2, 50));
      }
      expect(d.state).toBe("STOPPED");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("bootstrap flow: session.create → bridge exchange → session+CSRF call", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-daemon-test-"));
    const d = await makeDaemon(dir);
    try {
      const ui = new URL(d.endpoint!.ui_url!);
      const port = ui.port;
      const cookieName = `latticeag_session_gw1_${port}`;

      // 1. Local operator mints a viewer bootstrap over the unix socket.
      const created = await unixRpc(
        d.endpoint!.control_sock,
        rpc("ui.session.create", { role: "viewer" }),
      );
      expect(created.status).toBe(200);
      const cres = created.json as { result: { bootstrap: string; url: string } };
      const bootstrap = cres.result.bootstrap;
      expect(cres.result.url).toContain(`#bootstrap=${bootstrap}`);

      // 2. Browser exchanges it at the loopback bridge (no CSRF — the one
      //    bootstrap-exempt call).
      const ex = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          rpc("ui.session.exchange", { bootstrap }, "q2"),
        ),
      });
      expect(ex.status).toBe(200);
      const setCookie = ex.headers.get("set-cookie") ?? "";
      expect(setCookie).toContain(`${cookieName}=`);
      expect(setCookie).toContain("HttpOnly");
      expect(setCookie).toContain("SameSite=Strict");
      const exBody = (await ex.json()) as {
        result: { session: string; csrf: string; role: string };
      };
      expect(exBody.result.role).toBe("viewer");

      // 3. The session + CSRF then reach viewer-role methods.
      const status = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: `${cookieName}=${exBody.result.session}`,
          "x-latticeag-csrf": exBody.result.csrf,
        },
        body: JSON.stringify(rpc("daemon.status", {}, "q3")),
      });
      expect(status.status).toBe(200);
      const sb = (await status.json()) as { ok: boolean; result: { state: string } };
      expect(sb.ok).toBe(true);
      expect(sb.result.state).toBe("READY");

      // 4. The consumed bootstrap cannot be replayed.
      const replay = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rpc("ui.session.exchange", { bootstrap }, "q4")),
      });
      expect(replay.status).toBe(401);
    } finally {
      await d.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("invalid config → ConfigValidationError, nothing left behind", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gw-daemon-test-"));
    const d = new GatewayDaemon();
    await expect(
      d.start({ configDir: dir, config: { schema_version: 2 }, socketPath: join(dir, "c.sock") }),
    ).rejects.toMatchObject({ name: "ConfigValidationError" });
    await rm(dir, { recursive: true, force: true });
  });
});
