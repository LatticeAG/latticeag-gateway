import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  ConfigMigrationError,
  ConfigMigrationRequiredError,
  ConfigSchemaError,
  loadConfigV2,
  migrateConfigFile,
  readConfigFile,
} from "./index.js";
import { migrateConfig } from "./migrate.js";

const CONFIG1 = {
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
    viscompile: {
      enabled: false,
      bin: "lattice",
      baseline: "baseline.json",
    },
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

function tempDir(): string {
  return mkdtempSync(path.join(tmpdir(), "latticeag-migrate-"));
}

function writeV1(dir: string): { filePath: string; bytes: Buffer; sha: string } {
  const filePath = path.join(dir, "latticeag.json");
  const body = `${JSON.stringify(CONFIG1, null, 2)}\n`;
  writeFileSync(filePath, body, "utf8");
  const bytes = readFileSync(filePath);
  return {
    filePath,
    bytes,
    sha: createHash("sha256").update(bytes).digest("hex"),
  };
}

describe("migrateConfigFile", () => {
  it("migrates a v1 file: exact-byte backup, valid v2 target, receipt", () => {
    const dir = tempDir();
    const { filePath, bytes, sha } = writeV1(dir);

    const result = migrateConfigFile(filePath, {
      workspace: "ws1",
      instance: "gw1",
    });

    const expectedBackup = `${filePath}.v1.${sha}.bak`;
    expect(result.backup_path).toBe(expectedBackup);
    expect(result.old_sha256).toBe(sha);
    expect(existsSync(expectedBackup)).toBe(true);
    // Backup holds the exact original bytes.
    expect(readFileSync(expectedBackup)).toEqual(bytes);
    expect(statSync(expectedBackup).mode & 0o777).toBe(
      statSync(filePath).mode & 0o777,
    );

    // The migrated file parses as v2.
    const read = readConfigFile(filePath);
    expect(read.version).toBe(2);
    if (read.version === 2) {
      expect(read.config.gateway.workspace_id).toBe("ws1");
      expect(read.config.gateway.instance_id).toBe("gw1");
      expect(read.config.gateway.ui.port).toBe(9848);
    }
    expect(result.new_sha256).toBe(
      createHash("sha256").update(readFileSync(filePath)).digest("hex"),
    );

    // The on-disk document matches migrateConfig output verbatim.
    const onDisk = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
    expect(onDisk).toEqual(migrateConfig(CONFIG1, "ws1", "gw1"));

    // loadConfigV2 accepts the migrated file.
    const loaded = loadConfigV2(dir);
    expect(loaded.version).toBe(2);
    expect(loaded.config.gateway.workspace_id).toBe("ws1");

    // Receipt fields.
    expect(result.receipt).toEqual({
      workspace_id: "ws1",
      instance_id: "gw1",
      legacy_log_path: ".latticeag/events.jsonl",
      consent_reset: true,
    });
  });

  it("refuses to clobber an existing backup on a second run", () => {
    const dir = tempDir();
    const { filePath, bytes } = writeV1(dir);
    const first = migrateConfigFile(filePath, {
      workspace: "ws1",
      instance: "gw1",
    });
    expect(existsSync(first.backup_path)).toBe(true);

    // Write another v1 config (same path) and try again.
    writeFileSync(filePath, `${JSON.stringify(CONFIG1, null, 2)}\n`, "utf8");
    expect(() =>
      migrateConfigFile(filePath, { workspace: "ws1", instance: "gw1" }),
    ).toThrowError(ConfigMigrationError);
    // The original backup bytes are untouched.
    expect(readFileSync(first.backup_path)).toEqual(bytes);
    // And the live file still contains the second v1 document.
    const read = readConfigFile(filePath);
    expect(read.version).toBe(1);
  });

  it("dry-run writes nothing", () => {
    const dir = tempDir();
    const { filePath, bytes } = writeV1(dir);
    const before = readdirSync(dir).sort();

    const result = migrateConfigFile(filePath, {
      workspace: "ws1",
      instance: "gw1",
      dryRun: true,
    });

    expect(result.backup_path).toContain(".v1.");
    expect(result.backup_path.endsWith(".bak")).toBe(true);
    expect(existsSync(result.backup_path)).toBe(false);
    expect(readFileSync(filePath)).toEqual(bytes);
    expect(readdirSync(dir).sort()).toEqual(before);
  });

  it("rejects a file that fails v1 validation without writing anything", () => {
    const dir = tempDir();
    const filePath = path.join(dir, "latticeag.json");
    const bad = { ...CONFIG1, extra_key: true };
    const body = `${JSON.stringify(bad, null, 2)}\n`;
    writeFileSync(filePath, body, "utf8");
    expect(() =>
      migrateConfigFile(filePath, { workspace: "ws1", instance: "gw1" }),
    ).toThrowError(ConfigSchemaError);
    expect(readFileSync(filePath, "utf8")).toBe(body);
    expect(readdirSync(dir)).toEqual(["latticeag.json"]);
  });

  it("loadConfigV2 throws a migrate hint on unmigrated v1", () => {
    const dir = tempDir();
    writeV1(dir);
    expect(() => loadConfigV2(dir)).toThrowError(ConfigMigrationRequiredError);
    try {
      loadConfigV2(dir);
    } catch (err) {
      expect((err as Error).message).toMatch(
        /latticeag gateway config migrate/,
      );
    }
  });
});
