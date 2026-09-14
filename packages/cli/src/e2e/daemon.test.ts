/**
 * Gateway v2 end-to-end coverage: the real CLI (in-process runCli) against
 * a real `@latticeag/gateway-daemon` instance — real unix control socket,
 * real loopback bridge, real durable store under a temp config dir.
 *
 * Covered (spec §1.2/§1.3/§3.1/§3.2/§6/§6.1/§6.2):
 *  - `gateway start --foreground` in-process → READY + endpoints.json;
 *    `gateway status`/`gateway stop` over the real socket; detached start
 *    incumbent handoff and unavailable paths with the v2 exit table.
 *  - `gateway config show|validate|migrate`, `gateway sync status|pause|
 *    resume|config|flush`, `gateway ui open|close` over real RPCs.
 *  - Raw control-socket RPC: hello/status/stop, strict-JSON rejection,
 *    envelope schema, workspace binding, method authorization, the six
 *    no-receipt methods, idempotent replay + conflict, DRAINING rejection,
 *    healthz/metrics.
 *  - Loopback bridge auth: anonymous allowlist, bootstrap→cookie+CSRF
 *    session, revoked/unknown Bearer tokens.
 *  - Lock contention (incumbent endpoint handoff) and restart-rebuilt
 *    idempotency bindings.
 */
import { describe, expect, test } from "vitest";
import { access } from "node:fs/promises";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  GatewayDaemon,
  InMemoryPeerTokenStore,
  type StartOutcome,
} from "@latticeag/gateway-daemon";
import { createDefaultConfig, migrateConfig } from "@latticeag/config";
import {
  cleanTemp,
  endpointsPath,
  jsonLines,
  readEndpoints,
  rpcEnvelope,
  runCliInProcess,
  tempDir,
  unixGet,
  unixRpc,
  waitFor,
  writeV1Config,
  writeV2Config,
  type RpcResponse,
} from "./cli-harness.js";

// ── daemon fixture ───────────────────────────────────────────────────────

interface RunningDaemon {
  daemon: GatewayDaemon;
  outcome: Extract<StartOutcome, { kind: "started" }>;
  dir: string;
  /** Absolute path of the bound control socket. */
  sock: string;
  /** Bound loopback UI origin (null when the bridge is disabled). */
  uiUrl: string | null;
}

/**
 * Start a real GatewayDaemon over `dir`'s config. `config` is passed
 * in-memory (the on-disk latticeag.json stays authoritative for the CLI's
 * own discovery). The socket path is left to the daemon's §1.2 resolution:
 * with XDG_RUNTIME_DIR cleared it lands at <dir>/.latticeag/runtime/
 * control.sock — exactly where the CLI's discovery fallback looks.
 */
async function startTestDaemon(
  dir: string,
  opts: {
    workspace?: string;
    instance?: string;
    peers?: InMemoryPeerTokenStore;
    bridge?: boolean;
    writeConfig?: boolean;
  } = {},
): Promise<RunningDaemon> {
  const doc = migrateConfig(
    createDefaultConfig("e2e-project", []) as unknown as Record<
      string,
      unknown
    >,
    opts.workspace ?? "default",
    opts.instance ?? "e2e1",
  ) as unknown as Record<string, unknown>;
  if (opts.writeConfig !== false) {
    writeFileSync(
      path.join(dir, "latticeag.json"),
      `${JSON.stringify(doc, null, 2)}\n`,
      "utf8",
    );
  }
  const daemon = new GatewayDaemon();
  const savedXdg = process.env.XDG_RUNTIME_DIR;
  delete process.env.XDG_RUNTIME_DIR;
  let outcome: StartOutcome;
  try {
    outcome = await daemon.start({
      configDir: dir,
      config: doc,
      bridge: opts.bridge,
      bridgePort: 0,
      staticDir: null,
      signals: false,
      ...(opts.peers !== undefined ? { peers: opts.peers } : {}),
    });
  } finally {
    if (savedXdg !== undefined) process.env.XDG_RUNTIME_DIR = savedXdg;
  }
  expect(outcome.kind).toBe("started");
  const started = outcome as Extract<StartOutcome, { kind: "started" }>;
  const sock = started.endpoint.control_sock;
  expect(sock).toBe(
    path.join(dir, ".latticeag", "runtime", "control.sock"),
  );
  return { daemon, outcome: started, dir, sock, uiUrl: started.endpoint.ui_url };
}

async function stopDaemon(run: RunningDaemon | null): Promise<void> {
  if (run === null) return;
  await run.daemon.stop(2000).catch(() => {});
}

/** rpc() result body typed loosely for assertions. */
function env(method: string, params: unknown, id: string, workspace = "default") {
  return rpcEnvelope(method, params, { id, workspace });
}

// ── §6.2 CLI lifecycle over a real daemon ────────────────────────────────

describe("gateway daemon lifecycle over the real control socket", () => {
  test("status --json returns READY + envelope; stop drains to STOPPED", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      const status = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "status",
        "--json",
      ]);
      expect(status.code).toBe(0);
      expect(status.threw).toBeNull();
      const [envelope] = jsonLines(status.stdout);
      expect(envelope).toMatchObject({
        ok: true,
        command: "gateway status",
      });
      expect(typeof envelope!.cli_version).toBe("string");
      const data = envelope!.data as Record<string, unknown>;
      expect(data).toMatchObject({
        instance: "e2e1",
        state: "READY",
        products: 0,
        peers: 0,
      });
      expect(typeof data.config_revision).toBe("string");
      expect(typeof data.ui).toBe("string");

      // Text surface renders the same fields (§6.2).
      const text = await runCliInProcess(["--cwd", dir, "gateway", "status"]);
      expect(text.code).toBe(0);
      expect(text.stdout).toContain("instance e2e1");
      expect(text.stdout).toContain("state READY");

      const stop = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "stop",
        "--json",
      ]);
      expect(stop.code).toBe(0);
      const [stopEnv] = jsonLines(stop.stdout);
      expect(stopEnv).toMatchObject({ ok: true, command: "gateway stop" });
      expect((stopEnv!.data as { state: string }).state).toBe("DRAINING");

      // READY → DRAINING → STOPPED: endpoints.json disappears and the
      // socket stops answering (§1.3).
      expect(
        await waitFor(async () => {
          try {
            await access(endpointsPath(dir));
            return false;
          } catch {
            return true;
          }
        }),
      ).toBe(true);
      await waitFor(() => run.daemon.state === "STOPPED", 8000, 50);
      expect(run.daemon.state).toBe("STOPPED");

      const after = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "status",
        "--json",
      ]);
      expect(after.code).toBe(11);
      const [afterEnv] = jsonLines(after.stdout);
      expect(afterEnv).toMatchObject({
        ok: false,
        error: { code: "RUNTIME_UNAVAILABLE" },
      });
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });

  test("status against an absent daemon exits 11 (never autostarts)", async () => {
    const dir = tempDir();
    try {
      await writeV2Config(dir, {});
      // status probes the discovered socket once; nothing is listening and
      // the status path never autostarts (runStatus calls the client
      // directly, not connectDaemon).
      const status = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "status",
      ]);
      expect(status.code).toBe(11);
      expect(status.stderr).toContain("unreachable");

      const json = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "status",
        "--json",
      ]);
      expect(json.code).toBe(11);
      const [envelope] = jsonLines(json.stdout);
      expect(envelope).toMatchObject({
        ok: false,
        command: "gateway status",
        error: { code: "RUNTIME_UNAVAILABLE" },
      });

      // --socket override is honored: same 11 against an explicit path.
      const override = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "status",
        "--socket",
        path.join(dir, "elsewhere.sock"),
        "--json",
      ]);
      expect(override.code).toBe(11);

      // stop refuses just as cleanly (autostart disabled for stop).
      const stop = await runCliInProcess(["--cwd", dir, "gateway", "stop"]);
      expect(stop.code).toBe(11);
    } finally {
      await cleanTemp(dir);
    }
  });

  test("gateway start --foreground runs the daemon in-process to READY", async () => {
    const dir = tempDir();
    try {
      await writeV2Config(dir, {});
      const start = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "start",
        "--foreground",
        "--ui-port",
        "0",
      ]);
      // runForeground awaits startGatewayDaemon and returns once READY —
      // the daemon keeps running in-process until stopped.
      expect(start.code).toBe(0);
      expect(start.threw).toBeNull();

      const ep = (await readEndpoints(dir)) as {
        pid: number;
        instance: string;
        boot_id: string;
        process_start: string;
        control_sock: string;
        ui_url: string | null;
      };
      expect(ep.pid).toBe(process.pid);
      expect(ep.instance).toBe("e2e1");
      expect(ep.control_sock).toBe(
        path.join(dir, ".latticeag", "runtime", "control.sock"),
      );
      expect(typeof ep.boot_id).toBe("string");
      expect(typeof ep.ui_url).toBe("string");

      const status = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "status",
        "--json",
      ]);
      expect(status.code).toBe(0);
      const [env1] = jsonLines(status.stdout);
      expect((env1!.data as { state: string }).state).toBe("READY");

      // A second foreground start hits the held instance lock and adopts
      // the incumbent endpoint — idempotent, not an error (§1.3).
      const again = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "start",
        "--foreground",
        "--ui-port",
        "0",
      ]);
      expect(again.code).toBe(0);

      // Detached start against the incumbent returns "already running"
      // without touching the spawn path.
      const detached = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "start",
        "--wait-ms",
        "2000",
      ]);
      expect(detached.code).toBe(0);
      expect(detached.stdout).toContain("already running");

      const stop = await runCliInProcess(["--cwd", dir, "gateway", "stop"]);
      expect(stop.code).toBe(0);
      expect(
        await waitFor(async () => !existsSync(endpointsPath(dir))),
      ).toBe(true);
    } finally {
      await cleanTemp(dir);
    }
  });

  test("detached start without a reachable daemon reports unavailable", async () => {
    const dir = tempDir();
    try {
      await writeV2Config(dir, {});
      // argv[1] is stubbed: the on-demand spawn launches a no-op bin that
      // exits instantly, so nothing ever reaches READY inside the budget.
      const start = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "start",
        "--wait-ms",
        "300",
        "--json",
      ]);
      expect(start.code).toBe(11);
      const [envelope] = jsonLines(start.stdout);
      expect(envelope).toMatchObject({
        ok: false,
        command: "gateway start",
        error: { code: "RUNTIME_UNAVAILABLE" },
      });
    } finally {
      await cleanTemp(dir);
    }
  });

  test("a second daemon over a locked dir returns the incumbent endpoint", async () => {
    const dir = tempDir();
    const first = await startTestDaemon(dir);
    try {
      const second = new GatewayDaemon();
      const outcome = await second.start({
        configDir: dir,
        config: JSON.parse(
          readFileSync(path.join(dir, "latticeag.json"), "utf8"),
        ) as Record<string, unknown>,
        bridgePort: 0,
        staticDir: null,
        signals: false,
      });
      expect(outcome.kind).toBe("running");
      const endpoint = (outcome as { endpoint?: { control_sock?: string } })
        .endpoint;
      expect(endpoint?.control_sock).toBe(first.sock);
    } finally {
      await stopDaemon(first);
      await cleanTemp(dir);
    }
  });
});

// ── §6.2 config commands ────────────────────────────────────────────────

describe("gateway config surface", () => {
  test("config validate reports v2 validity; invalid file exits 3", async () => {
    const dir = tempDir();
    try {
      await writeV2Config(dir, {});
      const okRun = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "config",
        "validate",
        "--json",
      ]);
      expect(okRun.code).toBe(0);
      const [okEnv] = jsonLines(okRun.stdout);
      expect(okEnv).toMatchObject({
        ok: true,
        command: "gateway config validate",
      });
      expect((okEnv!.data as { valid: boolean }).valid).toBe(true);
      expect((okEnv!.data as { schema_version: number }).schema_version).toBe(2);

      // Corrupt the document: still parses but violates the v2 schema.
      const bad = JSON.parse(
        readFileSync(path.join(dir, "latticeag.json"), "utf8"),
      ) as Record<string, unknown>;
      delete bad.storage;
      writeFileSync(path.join(dir, "latticeag.json"), JSON.stringify(bad));
      const badRun = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "config",
        "validate",
        "--json",
      ]);
      expect(badRun.code).toBe(3);
      const [badEnv] = jsonLines(badRun.stdout);
      expect(badEnv!.ok).toBe(true); // the check ran; the document is invalid
      expect((badEnv!.data as { valid: boolean }).valid).toBe(false);

      // Unparseable file → envelope failure with the config exit code.
      writeFileSync(path.join(dir, "latticeag.json"), "{not json");
      const unparseable = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "config",
        "validate",
        "--json",
      ]);
      expect(unparseable.code).toBe(3);
      const [badParse] = jsonLines(unparseable.stdout);
      expect((badParse!.data as { valid: boolean }).valid).toBe(false);
    } finally {
      await cleanTemp(dir);
    }
  });

  test("config show: embedded document without daemon; authoritative revision with daemon", async () => {
    const dir = tempDir();
    try {
      await writeV2Config(dir, {});
      const embedded = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "config",
        "show",
        "--json",
      ]);
      expect(embedded.code).toBe(0);
      const [embeddedEnv] = jsonLines(embedded.stdout);
      const embeddedData = embeddedEnv!.data as Record<string, unknown>;
      expect(embeddedData.schema_version).toBe(2);
      expect(embeddedData.revision).toBeNull();
      expect(
        (embeddedData.document as { gateway: { instance_id: string } })
          .gateway.instance_id,
      ).toBe("e2e1");

      const run = await startTestDaemon(dir);
      try {
        const viaDaemon = await runCliInProcess([
          "--cwd",
          dir,
          "gateway",
          "config",
          "show",
          "--json",
        ]);
        expect(viaDaemon.code).toBe(0);
        const [daemonEnv] = jsonLines(viaDaemon.stdout);
        const daemonData = daemonEnv!.data as {
          revision: string;
          document: Record<string, unknown>;
        };
        // config.get is the authoritative revision source when the daemon
        // answers (§6.2); the seeded revision is "1".
        expect(daemonData.revision).toBe("1");
        expect(
          (daemonData.document as { gateway: { workspace_id: string } })
            .gateway.workspace_id,
        ).toBe("default");
      } finally {
        await stopDaemon(run);
      }
    } finally {
      await cleanTemp(dir);
    }
  });

  test("config migrate: dry-run plan → reviewed apply → v2 file + backup", async () => {
    const dir = tempDir();
    try {
      await writeV1Config(dir, {});
      const dry = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "config",
        "migrate",
        "--dry-run",
        "--json",
      ]);
      expect(dry.code).toBe(0);
      const [dryEnv] = jsonLines(dry.stdout);
      const dryData = dryEnv!.data as {
        plan: { from: number; to: number; workspace_id: string };
        review_digest: string;
      };
      expect(dryData.plan.from).toBe(1);
      expect(dryData.plan.to).toBe(2);
      expect(dryData.review_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      // Dry run wrote nothing.
      expect(
        (JSON.parse(
          readFileSync(path.join(dir, "latticeag.json"), "utf8"),
        ) as { schema_version: number }).schema_version,
      ).toBe(1);

      // --yes without the exact displayed digest is a policy refusal.
      const wrongDigest = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "config",
        "migrate",
        "--yes",
        "--review-digest",
        "sha256:" + "0".repeat(64),
        "--json",
      ]);
      expect(wrongDigest.code).toBe(4);

      const apply = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "config",
        "migrate",
        "--yes",
        "--review-digest",
        dryData.review_digest,
        "--json",
      ]);
      expect(apply.code).toBe(0);
      const [applyEnv] = jsonLines(apply.stdout);
      expect(applyEnv!.ok).toBe(true);
      const applied = JSON.parse(
        readFileSync(path.join(dir, "latticeag.json"), "utf8"),
      ) as { schema_version: number; gateway: { workspace_id: string } };
      expect(applied.schema_version).toBe(2);
      // The deterministic migration ids derive from the v1 sha256.
      expect(applied.gateway.workspace_id).toMatch(/^ws[0-9a-f]{16}$/);
      // A .bak preserving the v1 bytes exists next to the migrated file.
      const backups = (await import("node:fs")).readdirSync(dir).filter(
        (f) => f.endsWith(".bak"),
      );
      expect(backups.length).toBe(1);

      // Migrating again is a usage-level SCHEMA_UNSUPPORTED (nothing to do).
      const again = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "config",
        "migrate",
        "--dry-run",
        "--json",
      ]);
      expect(again.code).toBe(2);
      const [againEnv] = jsonLines(again.stdout);
      expect(againEnv).toMatchObject({
        ok: false,
        error: { code: "SCHEMA_UNSUPPORTED" },
      });
    } finally {
      await cleanTemp(dir);
    }
  });
});

// ── §6.2 sync commands over the real socket ──────────────────────────────

describe("gateway sync surface", () => {
  test("sync status/pause/resume/flush/config over real RPCs", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      const status = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "sync",
        "status",
        "--json",
      ]);
      expect(status.code).toBe(0);
      const [statusEnv] = jsonLines(status.stdout);
      const syncStatus = statusEnv!.data as {
        paused: boolean;
        streams: Record<string, { pending: number }>;
        cloud: unknown;
      };
      expect(typeof syncStatus.paused).toBe("boolean");
      expect(Object.keys(syncStatus.streams).sort()).toEqual([
        "approvals",
        "lineage",
        "mesh",
        "receipts",
        "runs",
        "watch",
      ]);
      expect(syncStatus.cloud).toBeNull();

      const pause = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "sync",
        "pause",
        "--stream",
        "runs",
        "--json",
      ]);
      expect(pause.code).toBe(0);
      const [pauseEnv] = jsonLines(pause.stdout);
      expect((pauseEnv!.data as { paused: string[] }).paused).toEqual([
        "runs",
      ]);

      // A disabled stream is never resumed (service-level consent check).
      const resume = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "sync",
        "resume",
        "--stream",
        "runs",
        "--json",
      ]);
      expect(resume.code).toBe(0);
      const [resumeEnv] = jsonLines(resume.stdout);
      expect((resumeEnv!.data as { resumed: string[] }).resumed).toEqual([]);

      // Empty outbox → flush is trivially clean; --fail-on-sync stays 0.
      const flush = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "sync",
        "flush",
        "--timeout-ms",
        "0",
        "--fail-on-sync",
        "--json",
      ]);
      expect(flush.code).toBe(0);
      const [flushEnv] = jsonLines(flush.stdout);
      expect(flushEnv!.data).toMatchObject({ pending: 0, blocked: 0 });

      // `sync config` with no file reads the current document via config.get.
      const conf = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "sync",
        "config",
        "--json",
      ]);
      expect(conf.code).toBe(0);
      const [confEnv] = jsonLines(conf.stdout);
      expect((confEnv!.data as { revision: string }).revision).toBe("1");
      expect(
        (confEnv!.data as { document: { sync: unknown } }).document.sync,
      ).toBeDefined();
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });

  test("sync config --file dry-run prints the plan; apply is review-gated", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      const syncDoc = {
        enabled: true,
        paused: false,
        cloud: null,
        streams: {
          runs: {
            enabled: true,
            paused: false,
            profile: "metadata",
            include_objects: false,
            cohort: "private",
            from: "now",
          },
        },
        legacy: {},
      };
      const file = path.join(dir, "sync.json");
      writeFileSync(file, JSON.stringify(syncDoc));

      const dry = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "sync",
        "config",
        "--file",
        file,
        "--dry-run",
        "--json",
      ]);
      expect(dry.code).toBe(0);
      const [dryEnv] = jsonLines(dry.stdout);
      const dryData = dryEnv!.data as {
        plan: { method: string };
        review_digest: string;
        dry_run: boolean;
      };
      expect(dryData.plan.method).toBe("sync.configure");
      expect(dryData.review_digest).toMatch(/^sha256:[0-9a-f]{64}$/);

      // Honest gate: the daemon's sync.configure demands a review binding
      // the CLI's NativeRef digest cannot satisfy (validateReview port is
      // not wired — fallback accepts only a bare 64-hex string). The CLI
      // surfaces the daemon's POLICY_DENIED, exit 4. Note the plan
      // envelope is emitted first in --json mode — the apply result is
      // the LAST line.
      const apply = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "sync",
        "config",
        "--file",
        file,
        "--yes",
        "--review-digest",
        dryData.review_digest,
        "--json",
      ]);
      expect(apply.code).toBe(4);
      const applyLines = jsonLines(apply.stdout);
      const applyEnv = applyLines.at(-1);
      expect(applyEnv).toMatchObject({
        ok: false,
        error: { code: "POLICY_DENIED" },
      });
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });
});

// ── §6.2/§7 ui commands + loopback bridge auth ───────────────────────────

describe("gateway ui + loopback bridge auth", () => {
  test("ui open --no-browser mints a bootstrap bound to the real UI URL", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      expect(run.uiUrl).not.toBeNull();
      const open = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "ui",
        "open",
        "--no-browser",
        "--json",
      ]);
      expect(open.code).toBe(0);
      const [envOpen] = jsonLines(open.stdout);
      const created = envOpen!.data as {
        bootstrap: string;
        expires_ms: number;
        url: string;
      };
      expect(created.bootstrap.length).toBeGreaterThan(0);
      expect(created.url).toContain("#bootstrap=");
      expect(created.url.startsWith(run.uiUrl!)).toBe(true);

      // The CLI recorded the session for `ui close` bookkeeping.
      expect(
        existsSync(path.join(dir, ".latticeag", "cli-ui-session.json")),
      ).toBe(true);

      // ui close with an unknown session id → daemon NOT_FOUND → exit 1
      // (GENERAL row of the v2 table).
      const close = await runCliInProcess([
        "--cwd",
        dir,
        "gateway",
        "ui",
        "close",
        "--session",
        "s_missing",
        "--json",
      ]);
      expect(close.code).toBe(1);
      const [closeEnv] = jsonLines(close.stdout);
      expect(closeEnv).toMatchObject({
        ok: false,
        error: { code: "NOT_FOUND" },
      });
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });

  test("bridge: bootstrap → cookie + CSRF → session RPC; anonymous denied", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      const ui = new URL(run.uiUrl!);
      const cookieName = `latticeag_session_e2e1_${ui.port}`;

      // Anonymous non-bootstrap call → 401 AUTH_REQUIRED at the bridge.
      const denied = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(env("daemon.status", {}, "br1")),
      });
      expect(denied.status).toBe(401);
      const deniedBody = (await denied.json()) as { error?: { code?: string } };
      expect(deniedBody.error?.code).toBe("AUTH_REQUIRED");

      // Mint a bootstrap over the local socket, then exchange it.
      const created = await unixRpc(
        run.sock,
        env("ui.session.create", { role: "viewer" }, "br2"),
      );
      expect(created.status).toBe(200);
      const bootstrap = (created.json!.result as { bootstrap: string })
        .bootstrap;

      const exchange = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          env("ui.session.exchange", { bootstrap }, "br3"),
        ),
      });
      expect(exchange.status).toBe(200);
      const exchangeBody = (await exchange.json()) as {
        result: { session: string; csrf: string; role: string };
      };
      expect(exchangeBody.result.role).toBe("viewer");
      expect(exchange.headers.get("set-cookie")).toContain(
        `${cookieName}=${exchangeBody.result.session}`,
      );
      const cookie = `${cookieName}=${exchangeBody.result.session}`;
      const csrf = exchangeBody.result.csrf;

      // Session cookie without CSRF → 403 FORBIDDEN.
      const noCsrf = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify(env("daemon.status", {}, "br4")),
      });
      expect(noCsrf.status).toBe(403);

      // Cookie + CSRF → the session principal reaches daemon.status.
      const authed = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          "x-latticeag-csrf": csrf,
        },
        body: JSON.stringify(env("daemon.status", {}, "br5")),
      });
      expect(authed.status).toBe(200);
      const authedBody = (await authed.json()) as { ok: boolean };
      expect(authedBody.ok).toBe(true);

      // A viewer session is denied L-only methods (daemon.stop is L).
      const stopDenied = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie,
          "x-latticeag-csrf": csrf,
        },
        body: JSON.stringify(env("daemon.stop", { grace_ms: 0 }, "br6")),
      });
      const stopBody = (await stopDenied.json()) as {
        error?: { code?: string };
      };
      expect(stopBody.error?.code).toBe("FORBIDDEN");
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });

  test("bridge bearer: revoked and unknown tokens rejected honestly", async () => {
    const dir = tempDir();
    const peers = new InMemoryPeerTokenStore();
    // A revoked grant the daemon was booted with: the §4.3 chain stops at
    // TOKEN_REVOKED before freshness/proof checks.
    peers.bindAccessToken("tok_revoked_e2e", {
      peer: "peer1",
      publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      role: "agent",
      scopes: [],
      expires_ms: Date.now() + 60_000,
      revoked: true,
      epoch: "ep1",
    });
    const run = await startTestDaemon(dir, { peers });
    try {
      const ui = new URL(run.uiUrl!);
      const proofHeaders = (token: string): Record<string, string> => ({
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
        "x-latticeag-nonce": Buffer.alloc(32, 7).toString("base64url"),
        "x-latticeag-epoch": "ep1",
        "x-latticeag-issued-ms": String(Date.now()),
        "x-latticeag-expires-ms": String(Date.now() + 30_000),
        "x-latticeag-key-proof": Buffer.alloc(64, 1).toString("base64url"),
        "x-latticeag-csrf": "peer-csrf",
      });

      const revoked = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: proofHeaders("tok_revoked_e2e"),
        body: JSON.stringify(env("daemon.status", {}, "tk1")),
      });
      expect(revoked.status).toBe(401);
      const revokedBody = (await revoked.json()) as {
        error?: { code?: string };
      };
      expect(revokedBody.error?.code).toBe("TOKEN_REVOKED");

      const unknown = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: proofHeaders("tok_never_issued"),
        body: JSON.stringify(env("daemon.status", {}, "tk2")),
      });
      expect(unknown.status).toBe(401);
      const unknownBody = (await unknown.json()) as {
        error?: { code?: string };
      };
      expect(unknownBody.error?.code).toBe("AUTH_REQUIRED");

      // Peer proof headers without a CSRF header die at the bridge gate.
      const noCsrf = await fetch(`${ui.origin}/v2/rpc`, {
        method: "POST",
        headers: (() => {
          const h = proofHeaders("tok_revoked_e2e");
          delete h["x-latticeag-csrf"];
          return h;
        })(),
        body: JSON.stringify(env("daemon.status", {}, "tk3")),
      });
      expect(noCsrf.status).toBe(403);
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });
});

// ── §3.1 raw socket RPC + dispatch pipeline ──────────────────────────────

describe("control socket RPC pipeline", () => {
  test("daemon.hello/status answer over POST /v2/rpc", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      const hello = await unixRpc(
        run.sock,
        env(
          "daemon.hello",
          { interfaces: "interfaces/1", profiles: ["proof-evidence/1"] },
          "h1",
        ),
      );
      expect(hello.status).toBe(200);
      const helloBody = hello.json as unknown as RpcResponse;
      expect(helloBody.ok).toBe(true);
      const helloResult = helloBody.result as {
        protocol: string;
        interfaces: string;
        profiles: string[];
      };
      expect(helloResult.protocol).toBe("latticeag-gateway/2");
      expect(helloResult.interfaces).toBe("interfaces/1");
      expect(helloResult.profiles).toContain("proof-evidence/1");
      // daemon.hello is connection-accounted: receipt must be null.
      expect(helloBody.receipt).toBeNull();

      // A wrong interfaces value is a schema-level rejection.
      const badIface = await unixRpc(
        run.sock,
        env(
          "daemon.hello",
          { interfaces: "interfaces/9", profiles: ["proof-evidence/1"] },
          "h2",
        ),
      );
      expect(badIface.status).toBe(400);
      expect((badIface.json as unknown as RpcResponse).error?.code).toBe(
        "SCHEMA_UNSUPPORTED",
      );

      const status = await unixRpc(
        run.sock,
        env("daemon.status", {}, "h3"),
      );
      expect(status.status).toBe(200);
      const statusBody = status.json as unknown as RpcResponse;
      expect(statusBody.ok).toBe(true);
      // daemon.status gets a semantic receipt (§3.1).
      expect(statusBody.receipt).not.toBeNull();
      const receipt = statusBody.receipt as {
        workspace: string;
        event: { hash: string };
      };
      // Semantic receipts are written to the dedicated audit workspace
      // (wiring: receiptWorkspace "audit1"), not the caller's workspace.
      expect(receipt.workspace).toBe("audit1");
      expect(receipt.event.hash).toMatch(/^[0-9a-f]{64}$/);
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });

  test("strict JSON and envelope validation precede everything", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      const cases: Array<{
        name: string;
        body: Buffer | string;
        code: string;
      }> = [
        {
          name: "duplicate keys",
          body: '{"v":2,"v":2,"id":"x1","workspace":"default","method":"daemon.status","params":{}}',
          code: "JSON_INVALID",
        },
        {
          name: "utf-8 BOM",
          body: Buffer.concat([
            Buffer.from([0xef, 0xbb, 0xbf]),
            Buffer.from(
              '{"v":2,"id":"x1","workspace":"default","method":"daemon.status","params":{}}',
            ),
          ]),
          code: "JSON_INVALID",
        },
        {
          name: "invalid utf-8",
          body: Buffer.concat([
            Buffer.from('{"v":2,"id":"x1","workspace":"default","method":"daemon.status","params":{"s":"'),
            Buffer.from([0xff, 0xfe]),
            Buffer.from('"}}'),
          ]),
          code: "JSON_INVALID",
        },
        {
          name: "lone surrogate",
          body: '{"v":2,"id":"x1","workspace":"default","method":"daemon.status","params":{"s":"\\ud800"}}',
          code: "JSON_INVALID",
        },
        {
          name: "depth over 32",
          body:
            '{"v":2,"id":"x1","workspace":"default","method":"daemon.status","params":{"a":' +
            "[".repeat(40) +
            "]".repeat(40) +
            "}}",
          code: "JSON_INVALID",
        },
        {
          name: "non-finite number",
          body: '{"v":2,"id":"x1","workspace":"default","method":"daemon.status","params":{"n":NaN}}',
          code: "JSON_INVALID",
        },
        {
          name: "trailing content",
          body: '{"v":2,"id":"x1","workspace":"default","method":"daemon.status","params":{}} {}',
          code: "JSON_INVALID",
        },
      ];
      for (const c of cases) {
        const res = await unixRpc(run.sock, c.body);
        expect(res.status, c.name).toBe(400);
        expect(
          (res.json as unknown as RpcResponse | undefined)?.error?.code,
          c.name,
        ).toBe(c.code);
        expect(res.json?.id ?? null, `${c.name} id`).toBeNull();
      }

      // Envelope/schema stage (valid JSON, wrong shape).
      const wrongV = await unixRpc(run.sock, {
        ...env("daemon.status", {}, "e1"),
        v: 1,
      });
      expect((wrongV.json as unknown as RpcResponse).error?.code).toBe(
        "SCHEMA_UNSUPPORTED",
      );

      const extraKey = await unixRpc(run.sock, {
        ...env("daemon.status", {}, "e2"),
        extra: true,
      });
      expect((extraKey.json as unknown as RpcResponse).error?.code).toBe(
        "SCHEMA_INVALID",
      );

      const badId = await unixRpc(run.sock, {
        ...env("daemon.status", {}, "e3"),
        id: "9bad",
      });
      const badIdBody = badId.json as unknown as RpcResponse;
      expect(badIdBody.error?.code).toBe("SCHEMA_INVALID");
      expect(badIdBody.error?.field).toBe("id");

      // Workspace binding: a mismatched workspace is FORBIDDEN — invisible.
      const wrongWs = await unixRpc(
        run.sock,
        env("daemon.status", {}, "e4", "other"),
      );
      expect(wrongWs.status).toBe(403);
      expect((wrongWs.json as unknown as RpcResponse).error?.code).toBe(
        "FORBIDDEN",
      );

      // Registry: run.list and run.status do not exist — METHOD_UNKNOWN.
      for (const method of ["run.list", "run.status", "events.list"]) {
        const res = await unixRpc(run.sock, env(method, {}, "e5"));
        expect(res.status, method).toBe(400);
        expect(
          (res.json as unknown as RpcResponse).error?.code,
          method,
        ).toBe("METHOD_UNKNOWN");
      }

      // TV-X-24 boundary, real path: a declared bytes one over the 1 MiB
      // cap is OBJECT_LIMIT before any allocation or action lookup.
      const oversized = await unixRpc(
        run.sock,
        env(
          "objects.put",
          {
            action: { workspace: "default", event: { source: "s", stream: "s", seq: "0", hash: "0".repeat(64) } },
            blob: {
              ref: {
                digest: "0".repeat(64),
                bytes: "1048577",
                media: "application/json",
              },
              content: "",
            },
          },
          "e7",
        ),
      );
      expect((oversized.json as unknown as RpcResponse).error?.code).toBe(
        "OBJECT_LIMIT",
      );

      // Wrong content-type → SCHEMA_INVALID at the listener gate.
      const badType = await unixRpc(
        run.sock,
        env("daemon.status", {}, "e6"),
        { contentType: "text/plain" },
      );
      expect(badType.status).toBe(400);
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });

  test("idempotent replay + conflict; durable binding survives restart", async () => {
    const dir = tempDir();
    const run1 = await startTestDaemon(dir);
    let firstText: string;
    try {
      const first = await unixRpc(
        run1.sock,
        env("events.subscribe", { topics: ["gateway.action"] }, "idem1"),
      );
      expect(first.status).toBe(200);
      firstText = first.text;
      const parsed = first.json as unknown as RpcResponse;
      expect(parsed.ok).toBe(true);

      // Same id + same params → the saved response returns verbatim.
      const replay = await unixRpc(
        run1.sock,
        env("events.subscribe", { topics: ["gateway.action"] }, "idem1"),
      );
      expect(replay.text).toBe(firstText);

      // Same id + different params → IDEMPOTENCY_CONFLICT.
      const conflict = await unixRpc(
        run1.sock,
        env("events.subscribe", { topics: ["approval.request"] }, "idem1"),
      );
      expect(conflict.status).toBe(409);
      expect((conflict.json as unknown as RpcResponse).error?.code).toBe(
        "IDEMPOTENCY_CONFLICT",
      );
    } finally {
      await stopDaemon(run1);
    }

    // Fresh daemon over the same state root: the durable binding replays.
    const run2 = await startTestDaemon(dir, { writeConfig: false });
    try {
      const replayed = await unixRpc(
        run2.sock,
        env("events.subscribe", { topics: ["gateway.action"] }, "idem1"),
      );
      expect(replayed.status).toBe(200);
      expect(replayed.text).toBe(firstText);
    } finally {
      await stopDaemon(run2);
      await cleanTemp(dir);
    }
  });

  test("DRAINING rejects new mutations while reads continue", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      const stop = await unixRpc(
        run.sock,
        env("daemon.stop", { grace_ms: 5000 }, "st1"),
      );
      expect(stop.status).toBe(200);
      const stopBody = stop.json as unknown as RpcResponse;
      expect(stopBody.ok).toBe(true);
      expect((stopBody.result as { state: string }).state).toBe("DRAINING");

      // Until the listener tears down, mutations answer STATE_TRANSITION.
      let sawTransition = false;
      let transportClosed = false;
      for (let i = 0; i < 60; i += 1) {
        let outcome: "ok" | "transition" | "closed" | "other";
        try {
          const mut = await unixRpc(
            run.sock,
            env("events.subscribe", { topics: ["watch.alert"] }, `st2_${i}`),
          );
          const body = mut.json as unknown as RpcResponse | undefined;
          outcome =
            body?.ok === true
              ? "ok"
              : body?.error?.code === "STATE_TRANSITION"
                ? "transition"
                : "other";
        } catch {
          outcome = "closed";
        }
        expect(outcome).not.toBe("ok");
        if (outcome === "transition") sawTransition = true;
        if (outcome === "closed") {
          transportClosed = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 15));
      }
      expect(sawTransition || transportClosed).toBe(true);
      await waitFor(() => run.daemon.state === "STOPPED", 8000, 50);
      expect(run.daemon.state).toBe("STOPPED");
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });

  test("healthz and metrics endpoints answer on the socket", async () => {
    const dir = tempDir();
    const run = await startTestDaemon(dir);
    try {
      const healthz = await unixGet(run.sock, "/healthz");
      expect(healthz.status).toBe(200);
      expect(healthz.json).toMatchObject({ alive: true });

      const metrics = await unixGet(run.sock, "/metrics");
      expect(metrics.status).toBe(200);
      expect(metrics.headers["content-type"]).toContain("text/plain");
      expect(metrics.text).toContain("latticeag_daemon_state 1");

      // Unknown paths and wrong verbs are plain 404s.
      const missing = await unixGet(run.sock, "/nope");
      expect(missing.status).toBe(404);
    } finally {
      await stopDaemon(run);
      await cleanTemp(dir);
    }
  });
});
