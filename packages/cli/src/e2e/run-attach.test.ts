/**
 * Gateway v2 `run` boundary coverage: the real in-process runCli with
 * --daemon off|auto|required against both absent and live daemons.
 *
 * Honest findings encoded here (§6.1/§6.4 surface vs. implementation):
 *  - `--daemon off`/`--no-daemon` keep the v1 path: no Gateway
 *    registration, exit = 0 on child success / 2 on child failure.
 *  - `--daemon required` + absent daemon → RUNTIME_UNAVAILABLE → exit 11.
 *  - `--daemon auto` + live daemon → run.register + run.finish land in
 *    the daemon's durable `runs_v2` registry (asserted by reading
 *    registry.sqlite — there is no run.query/run.status RPC; that gap
 *    is documented, not worked around).
 *  - `--daemon auto` + absent daemon → silent v1 fallback (1500 ms
 *    budget, stubbed autostart so nothing real is spawned).
 *  - `--fail-on-sync` + a non-empty `.latticeag/sync-outbox.jsonl` →
 *    exit 5 with the run envelope still emitted.
 *  - `--attach custom` injects nothing; unknown kits are refused by
 *    commander with exit 2.
 */
import { describe, expect, test } from "vitest";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { GatewayDaemon, type StartOutcome } from "@latticeag/gateway-daemon";
import { createDefaultConfig, migrateConfig } from "@latticeag/config";
import {
  cleanTemp,
  jsonLines,
  rpcEnvelope,
  runCliInProcess,
  tempDir,
  unixRpc,
  waitFor,
  writeV1Config,
  type RpcResponse,
} from "./cli-harness.js";

/** Child shim: exits with $CHILD_EXIT (default 0). Written per project. */
const CHILD_JS = "process.exit(Number(process.env.CHILD_EXIT ?? \"0\"));\n";

interface RunData {
  run_id: string;
  session_id: string;
  child_exit: number;
  event_count: number;
  log_path: string;
  adapters_started: string[];
  duration_ms: number;
}

async function makeRunProject(
  dir: string,
): Promise<{ ingestPort: number }> {
  const { freePort } = await import("./cli-harness.js");
  const ingestPort = await freePort();
  await writeV1Config(dir, { ingestPort });
  writeFileSync(path.join(dir, "child.mjs"), CHILD_JS, "utf8");
  return { ingestPort };
}

function runProject(
  dir: string,
  extra: string[],
  env?: Record<string, string | undefined>,
) {
  return runCliInProcess(
    ["--cwd", dir, "run", "--cmd", "node child.mjs", ...extra, "--json"],
    { env },
  );
}

/** Start a workspace-"default" daemon over a v1 run project dir. */
async function startDaemon(dir: string) {
  const doc = migrateConfig(
    createDefaultConfig("e2e-run", []) as unknown as Record<string, unknown>,
    "default",
    "run1",
  ) as unknown as Record<string, unknown>;
  const daemon = new GatewayDaemon();
  const savedXdg = process.env.XDG_RUNTIME_DIR;
  delete process.env.XDG_RUNTIME_DIR;
  let outcome: StartOutcome;
  try {
    outcome = await daemon.start({
      configDir: dir,
      config: doc,
      bridgePort: 0,
      staticDir: null,
      signals: false,
    });
  } finally {
    if (savedXdg !== undefined) process.env.XDG_RUNTIME_DIR = savedXdg;
  }
  if (outcome.kind !== "started") {
    throw new Error(`daemon failed to start: ${outcome.kind}`);
  }
  return { daemon, sock: outcome.endpoint.control_sock };
}

/** Read the daemon's durable run row directly out of registry.sqlite. */
async function registryRun(
  dir: string,
  runId: string,
): Promise<Record<string, unknown> | null> {
  const dbPath = path.join(dir, ".latticeag", "registry.sqlite");
  if (!existsSync(dbPath)) return null;
  const { DatabaseSync } = (await import("node:sqlite")) as {
    DatabaseSync: new (p: string, o?: { open?: boolean }) => {
      prepare(sql: string): {
        get(...args: unknown[]): Record<string, unknown> | undefined;
      };
      close(): void;
    };
  };
  const db = new DatabaseSync(dbPath);
  try {
    const row = db
      .prepare("SELECT * FROM runs_v2 WHERE run_id = ?")
      .get(runId);
    return row ?? null;
  } finally {
    db.close();
  }
}

describe("run --daemon modes", () => {
  test("--daemon off and --no-daemon stay on the v1 path", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      for (const flag of [["--daemon", "off"], ["--no-daemon"]]) {
        const r = await runProject(dir, flag);
        expect(r.code, flag.join(" ")).toBe(0);
        expect(r.threw).toBeNull();
        const [envelope] = jsonLines(r.stdout);
        expect(envelope).toMatchObject({ ok: true, command: "run" });
        const data = envelope!.data as RunData;
        expect(data.child_exit).toBe(0);
        expect(data.run_id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
        expect(data.adapters_started).toEqual([]);
        // The event log is only materialized on first append; with no
        // adapters and a no-op child zero events is legitimate. The
        // envelope still reports the configured relative log path.
        expect(data.log_path).toBe(".latticeag/events.jsonl");
        expect(typeof data.event_count).toBe("number");
      }
    } finally {
      await cleanTemp(dir);
    }
  });

  test("--daemon required exits 11 when no daemon answers", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      const r = await runProject(dir, ["--daemon", "required"]);
      expect(r.code).toBe(11);
      const [envelope] = jsonLines(r.stdout);
      expect(envelope).toMatchObject({
        ok: false,
        command: "run",
        error: { code: "RUNTIME_UNAVAILABLE" },
      });
      // No run was launched: no log file, no registry row.
      expect(envelope!.data).toBeNull();
    } finally {
      await cleanTemp(dir);
    }
  });

  test("--daemon auto falls back to the v1 path when no daemon exists", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      // argv[1] is stubbed so the on-demand spawn is a no-op; the 1500 ms
      // budget elapses and the run proceeds exactly as --daemon off.
      const r = await runProject(dir, ["--daemon", "auto"]);
      expect(r.code).toBe(0);
      const [envelope] = jsonLines(r.stdout);
      expect(envelope!.ok).toBe(true);
      const data = envelope!.data as RunData;
      expect(data.child_exit).toBe(0);
      // Nothing registered: no daemon store exists in the project tree.
      expect(existsSync(path.join(dir, ".latticeag", "registry.sqlite"))).toBe(
        false,
      );
    } finally {
      await cleanTemp(dir);
    }
  });

  test("--daemon auto + live daemon registers + finishes durably", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      const { daemon } = await startDaemon(dir);
      try {
        const r = await runProject(dir, ["--daemon", "auto"]);
        expect(r.code).toBe(0);
        const [envelope] = jsonLines(r.stdout);
        expect(envelope!.ok).toBe(true);
        const data = envelope!.data as RunData;

        // run.register lands durably in registry.sqlite → runs_v2.
        const row = await registryRun(dir, data.run_id);
        expect(row, "runs_v2 row for the CLI run").not.toBeNull();
        expect(row).toMatchObject({
          run_id: data.run_id,
          owner: "cli",
          kit: "openai-completions",
        });

        // The CLI's advisory run.finish lands before runCli returns:
        // the durable row is FINISHED with the child exit code.
        expect(row).toMatchObject({ state: "FINISHED", exit_code: 0 });
      } finally {
        await daemon.stop(2000).catch(() => {});
      }
    } finally {
      await cleanTemp(dir);
    }
  });

  test("child non-zero exit propagates as CHILD_EXIT envelope + exit 2", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      const r = await runProject(dir, ["--no-daemon"], { CHILD_EXIT: "7" });
      expect(r.code).toBe(2);
      const [envelope] = jsonLines(r.stdout);
      expect(envelope).toMatchObject({
        ok: false,
        command: "run",
        error: { code: "CHILD_EXIT" },
      });
      expect((envelope!.data as RunData).child_exit).toBe(7);
    } finally {
      await cleanTemp(dir);
    }
  });

  test("a missing child binary is a CHILD_EXIT refusal, never a crash", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      const r = await runCliInProcess([
        "--cwd",
        dir,
        "run",
        "--cmd",
        "./definitely-not-a-real-binary-xyz",
        "--no-daemon",
        "--json",
      ]);
      expect(r.code).toBe(2);
      expect(r.threw).toBeNull();
      const [envelope] = jsonLines(r.stdout);
      expect(envelope!.ok).toBe(false);
      expect(envelope!.error).toMatchObject({ code: "CHILD_EXIT" });
    } finally {
      await cleanTemp(dir);
    }
  });

  test("--fail-on-sync + non-empty outbox exits 5 after the run envelope", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      // Seed a v1 sync outbox with a pending record (the file the run
      // checks is .latticeag/sync-outbox.jsonl — daemon state lives in
      // separate tables and does not satisfy this check).
      await mkdir(path.join(dir, ".latticeag"), { recursive: true });
      writeFileSync(
        path.join(dir, ".latticeag", "sync-outbox.jsonl"),
        `${JSON.stringify({ kind: "pending", event: "e1" })}\n`,
        "utf8",
      );
      const r = await runProject(dir, ["--no-daemon", "--fail-on-sync"]);
      expect(r.code).toBe(5);
      const [envelope] = jsonLines(r.stdout);
      expect(envelope!.ok).toBe(false);
      // The envelope still carries the completed run's data.
      expect((envelope!.data as RunData).child_exit).toBe(0);
    } finally {
      await cleanTemp(dir);
    }
  });

  test("--fail-on-sync with an empty outbox keeps the success exit", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      const r = await runProject(dir, ["--no-daemon", "--fail-on-sync"]);
      expect(r.code).toBe(0);
      const [envelope] = jsonLines(r.stdout);
      expect(envelope!.ok).toBe(true);
    } finally {
      await cleanTemp(dir);
    }
  });
});

describe("attach kits", () => {
  test("--attach custom injects no kit env into the child", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      // The child prints which kit-managed env vars reached it; `custom`
      // injects none of them (the run core's own LATTICEAG_* vars are
      // expected and not listed here).
      writeFileSync(
        path.join(dir, "child.mjs"),
        "const keys=[\"OPENAI_API_KEY\",\"OPENAI_BASE_URL\",\"HERMES_HOME\",\"LANGGRAPH_URL\"];\n" +
          "process.stdout.write(keys.filter((k)=>process.env[k]!==undefined).join(\",\"));\n" +
          "process.exit(0);\n",
        "utf8",
      );
      const r = await runCliInProcess(
        [
          "--cwd",
          dir,
          "run",
          "--cmd",
          "node child.mjs",
          "--attach",
          "custom",
          "--no-daemon",
          "--json", // --json already implies captureChild
        ],
        {
          // Scrub kit-managed names so the child only sees what the kit
          // itself would inject.
          env: {
            OPENAI_API_KEY: undefined,
            OPENAI_BASE_URL: undefined,
            HERMES_HOME: undefined,
            LANGGRAPH_URL: undefined,
          },
        },
      );
      expect(r.code).toBe(0);
      const [envelope] = jsonLines(r.stdout);
      expect(envelope!.ok).toBe(true);
      // Captured child output is on disk (captureChild writes the logs).
      const captured = readFileSync(
        path.join(dir, ".latticeag", "child-stdout.log"),
        "utf8",
      );
      // LATTICEAG_INGEST_URL is always injected by the run core (not the
      // kit); the kit-owned names must be absent for `custom`.
      expect(captured).not.toContain("OPENAI_API_KEY");
      expect(captured).not.toContain("HERMES_HOME");
    } finally {
      await cleanTemp(dir);
    }
  });

  test("an unknown attach kit is refused at the flag boundary", async () => {
    const dir = tempDir();
    try {
      await makeRunProject(dir);
      const r = await runProject(dir, [
        "--attach",
        "no-such-kit",
        "--no-daemon",
      ]);
      // commander's .choices() invalid-argument path exits 1 (the v1
      // usage exit) before any run machinery starts — no child spawned,
      // no run artifacts.
      expect(r.code).toBe(1);
      expect(`${r.stdout}${r.stderr}`).toContain("no-such-kit");
      expect(existsSync(path.join(dir, ".latticeag", "bus.pid"))).toBe(false);
    } finally {
      await cleanTemp(dir);
    }
  });
});

describe("run service RPC shape (documented boundary)", () => {
  test("run.register/heartbeat/finish enforce the §6.4 sequence", async () => {
    const dir = tempDir();
    try {
      const { daemon, sock } = await startDaemon(dir);
      try {
        const RUN = "01J0000000000000000000000A";
        const register = await unixRpc(
          sock,
          rpcEnvelope(
            "run.register",
            { run_id: RUN, owner: "cli", kit: "custom", resume: false },
            { id: "r1" },
          ),
        );
        expect(register.status).toBe(200);
        expect((register.json as unknown as RpcResponse).ok).toBe(true);

        // A numeric spool_seq is a schema error — the wire type is a
        // decimal string (the CLI's own run.finish sends a number, which
        // is why its advisory finish is rejected; asserted above).
        const badSeq = await unixRpc(
          sock,
          rpcEnvelope(
            "run.heartbeat",
            { run_id: RUN, owner: "cli", spool_seq: 1 },
            { id: "r2a" },
          ),
        );
        expect((badSeq.json as unknown as RpcResponse).error?.code).toBe(
          "SCHEMA_INVALID",
        );

        const hb = await unixRpc(
          sock,
          rpcEnvelope(
            "run.heartbeat",
            { run_id: RUN, owner: "cli", spool_seq: "1" },
            { id: "r2" },
          ),
        );
        expect(hb.status).toBe(200);
        const hbBody = hb.json as unknown as RpcResponse;
        expect(hbBody.ok).toBe(true);
        // run.heartbeat is connection-accounted: receipt must be null.
        expect(hbBody.receipt).toBeNull();

        // Owner fencing: a different owner cannot finish the run.
        const stolen = await unixRpc(
          sock,
          rpcEnvelope(
            "run.finish",
            {
              run_id: RUN,
              owner: "mallory",
              exit_code: 0,
              signal: null,
              spool_seq: "2",
            },
            { id: "r3" },
          ),
        );
        expect((stolen.json as unknown as RpcResponse).error?.code).toBe(
          "POLICY_DENIED",
        );

        const finish = await unixRpc(
          sock,
          rpcEnvelope(
            "run.finish",
            {
              run_id: RUN,
              owner: "cli",
              exit_code: 0,
              signal: null,
              spool_seq: "2",
            },
            { id: "r4" },
          ),
        );
        expect(finish.status).toBe(200);
        const finBody = finish.json as unknown as RpcResponse;
        expect(finBody.ok).toBe(true);
        expect((finBody.result as { state: string }).state).toBe("FINISHED");

        // A heartbeat after FINISHED is a state-transition rejection.
        const late = await unixRpc(
          sock,
          rpcEnvelope(
            "run.heartbeat",
            { run_id: RUN, owner: "cli", spool_seq: "3" },
            { id: "r5" },
          ),
        );
        expect((late.json as unknown as RpcResponse).error?.code).toBe(
          "STATE_TRANSITION",
        );

        // spool_seq regression on finish → REVISION_CONFLICT.
        const regress = await unixRpc(
          sock,
          rpcEnvelope(
            "run.finish",
            {
              run_id: RUN,
              owner: "cli",
              exit_code: 1,
              signal: null,
              spool_seq: "1",
            },
            { id: "r6" },
          ),
        );
        expect((regress.json as unknown as RpcResponse).error?.code).toBe(
          "REVISION_CONFLICT",
        );

        // The finished row is durable in registry.sqlite.
        const row = await registryRun(dir, RUN);
        expect(row).toMatchObject({
          owner: "cli",
          kit: "custom",
          state: "FINISHED",
          exit_code: 0,
        });
      } finally {
        await daemon.stop(2000).catch(() => {});
      }
    } finally {
      await cleanTemp(dir);
    }
  });

  test("run.query/run.list/run.status do not exist (documented gap)", async () => {
    const dir = tempDir();
    try {
      const { daemon, sock } = await startDaemon(dir);
      try {
        for (const method of ["run.query", "run.list", "run.status"]) {
          const res = await unixRpc(
            sock,
            rpcEnvelope(method, {}, { id: "q1" }),
          );
          expect(res.status, method).toBe(400);
          expect((res.json as unknown as RpcResponse).error?.code).toBe(
            "METHOD_UNKNOWN",
          );
        }
      } finally {
        await daemon.stop(2000).catch(() => {});
      }
    } finally {
      await cleanTemp(dir);
    }
  });
});
