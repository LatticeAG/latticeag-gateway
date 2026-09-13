import { describe, expect, it } from "vitest";
import { migrateConfig } from "./migrate.js";
import { latticeagConfigSchema } from "./schema.js";
import { latticeagConfigV2Schema } from "./schema-v2.js";

// F.config1 — the complete valid v1 input from spec §8.2 (line 906), verbatim.
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
  redaction: {
    keys: ["authorization", "api_key"],
    include_raw_text: false,
  },
  sync: {
    enabled: false,
    gateway_url_env: "LEXGATEWAY_URL",
    token_env: "LEXGATEWAY_TOKEN",
    mode: "replicate",
    local_port: 8788,
    polymesh: { enabled: false },
  },
  doctor: {},
} as const;

const EXPECTED_STREAM = {
  enabled: false,
  paused: false,
  profile: "metadata",
  include_objects: false,
  cohort: "private",
  from: "now",
};

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null) {
    for (const v of Object.values(value)) {
      deepFreeze(v);
    }
    Object.freeze(value);
  }
  return value;
}

describe("migrateConfig (TV-GW-01)", () => {
  it("produces the exact F.config2 shape", () => {
    const v2 = migrateConfig(CONFIG1, "ws1", "gw1");

    expect(v2).toEqual({
      ...structuredClone(CONFIG1),
      $schema: "https://latticeag.dev/schemas/latticeag-config/v2.json",
      schema_version: 2,
      gateway: {
        workspace_id: "ws1",
        instance_id: "gw1",
        autostart: "on-demand",
        ui: {
          enabled: true,
          bind: "127.0.0.1",
          port: 9848,
          ipv6: false,
          remote: false,
        },
        mesh: { mode: "local", contract: null },
      },
      agents: {
        access_ttl_s: 900,
        refresh_ttl_s: 2592000,
        allow_operator: false,
      },
      products: { instances: {} },
      catalog: {
        channel: "stable",
        source: null,
        pins: [],
        allowlist: [],
        strict: false,
        max_age_s: 604800,
      },
      storage: {
        root: ".latticeag",
        segment_bytes: 67108864,
        disk_bytes: "10737418240",
        retention_days: 30,
      },
      sync: {
        enabled: false,
        paused: false,
        cloud: null,
        streams: {
          runs: EXPECTED_STREAM,
          receipts: EXPECTED_STREAM,
          lineage: EXPECTED_STREAM,
          approvals: EXPECTED_STREAM,
          watch: EXPECTED_STREAM,
          mesh: EXPECTED_STREAM,
        },
        legacy: CONFIG1.sync,
      },
    });
  });

  it("stamps the spec-fixed defaults for every new section", () => {
    const v2 = migrateConfig(CONFIG1, "ws1", "gw1");
    expect(v2.$schema).toBe(
      "https://latticeag.dev/schemas/latticeag-config/v2.json",
    );
    expect(v2.schema_version).toBe(2);
    expect(v2.gateway.workspace_id).toBe("ws1");
    expect(v2.gateway.instance_id).toBe("gw1");
    expect(v2.gateway.autostart).toBe("on-demand");
    expect(v2.gateway.ui).toEqual({
      enabled: true,
      bind: "127.0.0.1",
      port: 9848,
      ipv6: false,
      remote: false,
    });
    expect(v2.gateway.mesh).toEqual({ mode: "local", contract: null });
    expect(v2.agents.access_ttl_s).toBe(900);
    expect(v2.agents.refresh_ttl_s).toBe(2592000);
    expect(v2.agents.allow_operator).toBe(false);
    expect(v2.catalog.max_age_s).toBe(604800);
    expect(v2.storage.segment_bytes).toBe(67108864);
    expect(v2.storage.disk_bytes).toBe("10737418240");
    for (const name of [
      "runs",
      "receipts",
      "lineage",
      "approvals",
      "watch",
      "mesh",
    ] as const) {
      expect(v2.sync.streams[name]).toEqual(EXPECTED_STREAM);
    }
    expect(v2.sync.enabled).toBe(false);
    expect(v2.sync.paused).toBe(false);
    expect(v2.sync.cloud).toBeNull();
  });

  it("preserves all seven adapter objects byte-identical and copies no env values", () => {
    const v2 = migrateConfig(CONFIG1, "ws1", "gw1");
    expect(v2.adapters).toEqual(CONFIG1.adapters);
    for (const name of [
      "axion",
      "visreplay",
      "lexverdict",
      "vekinbox",
      "viscompile",
      "lexshield",
      "polymesh",
    ] as const) {
      expect(v2.adapters[name]).toEqual(CONFIG1.adapters[name]);
    }
    // Env *names* are preserved verbatim; no environment values are resolved.
    expect(v2.adapters.lexverdict.base_url_env).toBe("LEXVERDICT_URL");
    expect(v2.adapters.vekinbox.api_key_env).toBe("VEKINBOX_API_KEY");
    expect(v2.adapters.polymesh.gateway_url_env).toBe("POLYMESH_GATEWAY_URL");
  });

  it("keeps v1 sync under sync.legacy and mirrors paused from it", () => {
    const v2 = migrateConfig(CONFIG1, "ws1", "gw1");
    expect(v2.sync.legacy).toEqual(CONFIG1.sync);
    const enabledSync = {
      ...structuredClone(CONFIG1),
      sync: { ...structuredClone(CONFIG1.sync), enabled: true },
    };
    const v2b = migrateConfig(enabledSync, "ws1", "gw1");
    expect(v2b.sync.paused).toBe(true);
    expect(v2b.sync.enabled).toBe(false);
    expect(v2b.sync.legacy).toEqual(enabledSync.sync);
  });

  it("is deterministic and does not mutate its input", () => {
    const frozen = deepFreeze(structuredClone(CONFIG1));
    const a = migrateConfig(frozen, "ws1", "gw1");
    const b = migrateConfig(frozen, "ws1", "gw1");
    expect(a).toEqual(b);
    expect(frozen).toEqual(CONFIG1);
    // legacy must be a clone, not an alias of the input sync object.
    expect(a.sync.legacy).not.toBe(CONFIG1.sync);
  });

  it("throws SCHEMA_UNSUPPORTED for non-v1 input", () => {
    expect(() =>
      migrateConfig({ ...structuredClone(CONFIG1), schema_version: 2 }, "w", "i"),
    ).toThrowError(/^SCHEMA_UNSUPPORTED$/);
    expect(() => migrateConfig(null, "w", "i")).toThrowError(
      /^SCHEMA_UNSUPPORTED$/,
    );
    expect(() => migrateConfig({}, "w", "i")).toThrowError(
      /^SCHEMA_UNSUPPORTED$/,
    );
  });

  it("input parses as v1 and output parses as v2", () => {
    expect(latticeagConfigSchema.safeParse(CONFIG1).success).toBe(true);
    const v2 = migrateConfig(CONFIG1, "ws1", "gw1");
    const parsed = latticeagConfigV2Schema.safeParse(v2);
    expect(parsed.success).toBe(true);
  });
});
