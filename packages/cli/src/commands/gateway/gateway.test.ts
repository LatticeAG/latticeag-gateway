import { createServer, type Server, type Socket } from "node:net";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  DUMMY_ADAPTER_ENV,
  initRunProject,
  runCli,
} from "../../test-spawn.js";

const here = path.dirname(fileURLToPath(import.meta.url));

function tempDir(): string {
  return mkdtempSync(path.join(tmpdir(), "latticeag-gw-"));
}

function snapshot(rel: string): string {
  return readFileSync(path.join(here, rel), "utf8");
}

/** The §8.2 fixture v1 document (all seven adapter entries required). */
const V1_CONFIG = {
  schema_version: 1,
  project: { name: "demo", run_id_prefix: "run" },
  bus: {},
  ingest: { bind: "127.0.0.1", port: 9847, path: "/v1/ingest" },
  adapters: {
    axion: {
      enabled: false,
      base_url: "http://127.0.0.1:9001",
      webhook_path: "/v1/ingest/axion",
    },
    visreplay: { enabled: false, session_dir: ".latticeag/sessions" },
    lexverdict: { enabled: true, base_url_env: "LEXVERDICT_URL" },
    vekinbox: {
      enabled: false,
      base_url_env: "VEKINBOX_URL",
      api_key_env: "VEKINBOX_API_KEY",
      workspace_id_env: "VEKINBOX_WORKSPACE_ID",
      agent_id_env: "VEKINBOX_AGENT_ID",
    },
    viscompile: { enabled: false, bin: "lattice", baseline: "baseline.json" },
    lexshield: { enabled: false, bin: "lexshield" },
    polymesh: {
      enabled: false,
      gateway_url_env: "POLYMESH_GATEWAY_URL",
      mesh_id_env: "POLYMESH_MESH_ID",
      capability: "latticeag.events.relay",
    },
  },
  redaction: { keys: ["authorization", "api_key"], include_raw_text: false },
  sync: {
    enabled: false,
    gateway_url_env: "LEXGATEWAY_URL",
    token_env: "LEXGATEWAY_TOKEN",
    mode: "replicate",
    local_port: 8788,
    polymesh: { enabled: false },
  },
  doctor: {},
};

interface FakeControl {
  sockPath: string;
  server: Server;
  requests: Array<{ method: string; params: unknown }>;
  close: () => Promise<void>;
}

/**
 * Minimal §3.1 fake: HTTP/1.1 over a unix socket; responds to POST /v2/rpc
 * with a canned Success result per method (or Failure when configured).
 */
async function fakeControl(
  dir: string,
  handler: (method: string, params: unknown) => { ok: true; result: unknown } | { ok: false; code: string },
): Promise<FakeControl> {
  const sockPath = path.join(dir, "control.sock");
  const requests: FakeControl["requests"] = [];
  const server = createServer((conn: Socket) => {
    let buf = Buffer.alloc(0);
    conn.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const headerEnd = buf.indexOf("\r\n\r\n");
      if (headerEnd < 0) {
        return;
      }
      const head = buf.subarray(0, headerEnd).toString("utf8");
      const m = /content-length:\s*(\d+)/i.exec(head);
      const len = m ? Number(m[1]) : 0;
      const bodyStart = headerEnd + 4;
      if (buf.length < bodyStart + len) {
        return;
      }
      const body = JSON.parse(buf.subarray(bodyStart, bodyStart + len).toString("utf8")) as {
        id: string;
        method: string;
        params: unknown;
      };
      requests.push({ method: body.method, params: body.params });
      const out = handler(body.method, body.params);
      const resp =
        out.ok === true
          ? { v: 2, id: body.id, ok: true, result: out.result, receipt: null }
          : {
              v: 2,
              id: body.id,
              ok: false,
              error: { code: out.code, retryable: false, field: null },
              receipt: null,
            };
      const payload = Buffer.from(JSON.stringify(resp), "utf8");
      conn.end(
        Buffer.concat([
          Buffer.from(
            `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${payload.length}\r\nconnection: close\r\n\r\n`,
            "utf8",
          ),
          payload,
        ]),
      );
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(sockPath, () => resolve());
  });
  return {
    sockPath,
    server,
    requests,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

describe("latticeag gateway status", () => {
  it("unreachable daemon exits 11 with a JSON error envelope", async () => {
    const dir = tempDir();
    const missing = path.join(dir, "absent.sock");
    const result = await runCli(["gateway", "status", "--json"], {
      cwd: dir,
      env: { LATTICEAG_CONTROL_SOCKET: missing },
    });
    expect(result.status).toBe(11);
    const envelope = JSON.parse(result.stdout) as {
      ok: boolean;
      command: string;
      error: { code: string };
    };
    expect(envelope.ok).toBe(false);
    expect(envelope.command).toBe("gateway status");
    expect(envelope.error.code).toBe("RUNTIME_UNAVAILABLE");
  });

  it("READY over a fake control socket exits 0", async () => {
    const dir = tempDir();
    const fake = await fakeControl(dir, (method) =>
      method === "daemon.status"
        ? {
            ok: true,
            result: {
              instance: "demo",
              state: "READY",
              config_revision: "3",
              products: 2,
              peers: 0,
              ui: "http://127.0.0.1:9848",
            },
          }
        : { ok: false, code: "METHOD_UNKNOWN" },
    );
    try {
      const result = await runCli(["gateway", "status", "--json"], {
        cwd: dir,
        env: { LATTICEAG_CONTROL_SOCKET: fake.sockPath },
      });
      expect(result.status).toBe(0);
      const envelope = JSON.parse(result.stdout) as {
        ok: boolean;
        data: { state: string; instance: string };
      };
      expect(envelope.ok).toBe(true);
      expect(envelope.data.state).toBe("READY");
      expect(envelope.data.instance).toBe("demo");
      expect(fake.requests.map((r) => r.method)).toEqual(["daemon.status"]);
    } finally {
      await fake.close();
    }
  });

  it("maps wire Failure codes through the v2 exit table", async () => {
    const dir = tempDir();
    const fake = await fakeControl(dir, () => ({
      ok: false,
      code: "REVISION_CONFLICT",
    }));
    try {
      const result = await runCli(["gateway", "status", "--json"], {
        cwd: dir,
        env: { LATTICEAG_CONTROL_SOCKET: fake.sockPath },
      });
      expect(result.status).toBe(10);
      const envelope = JSON.parse(result.stdout) as {
        ok: boolean;
        error: { code: string };
      };
      expect(envelope.error.code).toBe("REVISION_CONFLICT");
    } finally {
      await fake.close();
    }
  });
});

describe("latticeag gateway service install", () => {
  it("--manager systemd --dry-run prints the unit plan and writes nothing", async () => {
    const home = tempDir();
    const result = await runCli(
      ["gateway", "service", "install", "--manager", "systemd", "--dry-run"],
      { cwd: tempDir(), env: { HOME: home } },
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("manager systemd");
    expect(result.stdout).toContain("latticeag-gateway-");
    expect(result.stdout).toContain("Restart=on-failure");
    expect(result.stdout).toContain("UMask=0077");
    expect(result.stdout).toContain("WantedBy=default.target");
    expect(result.stdout).toContain("review_digest sha256:");
    const unit = path.join(
      home,
      ".config",
      "systemd",
      "user",
    );
    expect(existsSync(unit)).toBe(false);
  });
});

describe("latticeag gateway config migrate", () => {
  it("migrates a v1 fixture to v2 with a .bak after reviewed apply", async () => {
    const dir = tempDir();
    const file = path.join(dir, "latticeag.json");
    writeFileSync(file, `${JSON.stringify(V1_CONFIG, null, 2)}\n`);

    const dry = await runCli(
      ["--config", file, "gateway", "config", "migrate", "--dry-run", "--json"],
      { cwd: dir },
    );
    expect(dry.status).toBe(0);
    const dryEnv = JSON.parse(dry.stdout) as {
      data: { review_digest: string; plan: { new_sha256: string } };
    };
    const digest = dryEnv.data.review_digest;
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    // --dry-run leaves the file alone.
    expect(JSON.parse(readFileSync(file, "utf8"))).toMatchObject({
      schema_version: 1,
    });
    expect(readdirSync(dir).filter((f) => f.endsWith(".bak"))).toHaveLength(0);

    const applied = await runCli(
      [
        "--config",
        file,
        "gateway",
        "config",
        "migrate",
        "--yes",
        "--review-digest",
        digest,
      ],
      { cwd: dir },
    );
    expect(applied.status).toBe(0);
    const migrated = JSON.parse(readFileSync(file, "utf8")) as {
      schema_version: number;
      gateway: { workspace_id: string; instance_id: string };
      sync: { enabled: boolean; legacy: { enabled: boolean } };
    };
    expect(migrated.schema_version).toBe(2);
    expect(migrated.sync.legacy).toMatchObject({ enabled: false });
    const backups = readdirSync(dir).filter((f) => f.endsWith(".bak"));
    expect(backups).toHaveLength(1);
    expect(backups[0]).toMatch(/^latticeag\.json\.v1\.[0-9a-f]{64}\.bak$/);
    // The backup preserves the exact v1 bytes.
    expect(
      JSON.parse(readFileSync(path.join(dir, backups[0] as string), "utf8")),
    ).toMatchObject({ schema_version: 1 });
  });

  it("refuses noninteractive apply without --yes --review-digest", async () => {
    const dir = tempDir();
    const file = path.join(dir, "latticeag.json");
    writeFileSync(file, JSON.stringify(V1_CONFIG));
    const result = await runCli(
      ["--config", file, "gateway", "config", "migrate"],
      { cwd: dir },
    );
    expect(result.status).toBe(4);
    expect(result.stderr).toContain("review-digest");
  });
});

describe("latticeag gateway usage gates", () => {
  it("agent pair without --key is a usage error (exit 2)", async () => {
    const result = await runCli(["gateway", "agent", "pair"], {
      cwd: tempDir(),
    });
    expect(result.status).toBe(2);
    expect(`${result.stderr}${result.stdout}`).toContain("--key");
  });

  it("catalog pin without --digest is a usage error (exit 2)", async () => {
    const result = await runCli(
      ["gateway", "catalog", "pin", "lexverdict", "--version", "0.1.0"],
      { cwd: tempDir() },
    );
    expect(result.status).toBe(2);
    expect(`${result.stderr}${result.stdout}`).toContain("--digest");
  });

  it("approvals decide requires --revision and --action-digest", async () => {
    const dir = tempDir();
    const missing = await runCli(
      ["gateway", "approvals", "decide", "ap1", "--decision", "approve"],
      { cwd: dir },
    );
    expect(missing.status).toBe(2);
    expect(`${missing.stderr}${missing.stdout}`).toContain("--revision");

    const missingDigest = await runCli(
      [
        "gateway",
        "approvals",
        "decide",
        "ap1",
        "--decision",
        "approve",
        "--revision",
        "1",
      ],
      { cwd: dir },
    );
    expect(missingDigest.status).toBe(2);
    expect(`${missingDigest.stderr}${missingDigest.stdout}`).toContain(
      "--action-digest",
    );
  });
});

describe("latticeag gateway agent pair", () => {
  it("creates an invitation over the control socket and prints the QR payload", async () => {
    const dir = tempDir();
    const keyFile = path.join(dir, "agent.pub");
    writeFileSync(keyFile, "ssh-ed25519 AAAAC3NzaC fake-test-key\n");
    const fake = await fakeControl(dir, (method) =>
      method === "agent.pair.create"
        ? {
            ok: true,
            result: { pair: "pair1", code: "0123456789", expires_ms: 300000 },
          }
        : { ok: false, code: "METHOD_UNKNOWN" },
    );
    try {
      const result = await runCli(
        [
          "gateway",
          "agent",
          "pair",
          "--key",
          keyFile,
          "--scope",
          '{"permission":"events.emit","topics":[],"runs":[],"products":[]}',
          "--qr",
        ],
        { cwd: dir, env: { LATTICEAG_CONTROL_SOCKET: fake.sockPath } },
      );
      expect(result.status).toBe(0);
      expect(result.stdout).toContain("pair pair1");
      expect(result.stdout).toContain("code 0123456789");
      // Canonical J() payload: sorted keys, no spaces.
      expect(result.stdout).toContain(
        '{"code":"0123456789","expires_ms":300000,"instance":"default","pair":"pair1","v":1}',
      );
      const req = fake.requests.find((r) => r.method === "agent.pair.create");
      expect(req).toBeDefined();
      expect((req?.params as { role: string }).role).toBe("agent");
    } finally {
      await fake.close();
    }
  });
});

describe("root aliases", () => {
  it("latticeag sync status routes identically to gateway sync status", async () => {
    const dir = tempDir();
    const missing = path.join(dir, "absent.sock");
    const env = { LATTICEAG_CONTROL_SOCKET: missing };
    const aliased = await runCli(["sync", "status", "--json"], {
      cwd: dir,
      env,
    });
    const grouped = await runCli(["gateway", "sync", "status", "--json"], {
      cwd: dir,
      env,
    });
    expect(aliased.status).toBe(grouped.status);
    expect(aliased.status).toBe(11);
    const a = JSON.parse(aliased.stdout) as { ok: boolean; error: { code: string } };
    const g = JSON.parse(grouped.stdout) as { ok: boolean; error: { code: string } };
    expect(a.error.code).toBe(g.error.code);
  });
});

describe("run --daemon", () => {
  it("--daemon off behaves exactly like the v1 run path", async () => {
    const dir = tempDir();
    await initRunProject(dir);
    const result = await runCli(
      [
        "--cwd",
        dir,
        "run",
        "--cmd",
        "node -e \"console.log('hi')\"",
        "--attach",
        "custom",
        "--daemon",
        "off",
        "--json",
      ],
      { env: DUMMY_ADAPTER_ENV },
    );
    expect(result.status).toBe(0);
    const envelope = JSON.parse(result.stdout) as {
      ok: boolean;
      data: { child_exit: number; run_id: string };
    };
    expect(envelope.ok).toBe(true);
    expect(envelope.data.child_exit).toBe(0);
  });

  it("--no-daemon aliases --daemon off", async () => {
    const dir = tempDir();
    await initRunProject(dir);
    const result = await runCli(
      [
        "--cwd",
        dir,
        "run",
        "--cmd",
        "node -e \"console.log('hi')\"",
        "--attach",
        "custom",
        "--no-daemon",
      ],
      { env: DUMMY_ADAPTER_ENV },
    );
    expect(result.status).toBe(0);
  });

  it("--daemon required refuses the fallback when no daemon is up", async () => {
    const dir = tempDir();
    await initRunProject(dir);
    const missing = path.join(dir, "absent.sock");
    const result = await runCli(
      [
        "--cwd",
        dir,
        "run",
        "--cmd",
        "node -e \"console.log('hi')\"",
        "--attach",
        "custom",
        "--daemon",
        "required",
      ],
      { env: { ...DUMMY_ADAPTER_ENV, LATTICEAG_CONTROL_SOCKET: missing } },
    );
    expect(result.status).toBe(11);
  });
});

describe("gateway help snapshots", () => {
  it("gateway --help matches snapshot", async () => {
    const result = await runCli(["gateway", "--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(snapshot("gateway.help.txt"));
  });

  it("gateway service --help matches snapshot", async () => {
    const result = await runCli(["gateway", "service", "--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(snapshot("service.help.txt"));
  });
});
