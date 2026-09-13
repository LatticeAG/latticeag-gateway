import { describe, expect, it } from "vitest";
import { migrateConfig } from "./migrate.js";
import { latticeagConfigV2Schema } from "./schema-v2.js";
import { validateConfigV2Semantics } from "./validate-v2.js";

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

// An F.config2-shaped document (spec §8.2 output).
function validV2() {
  return migrateConfig(
    structuredClone(CONFIG1),
    "ws1",
    "gw1",
  ) as unknown as Record<string, unknown>;
}

const HASH = "a".repeat(64);
const DIGEST = `sha256:${"b".repeat(64)}`;

describe("latticeagConfigV2Schema", () => {
  it("accepts an F.config2-shaped document", () => {
    const result = latticeagConfigV2Schema.safeParse(validV2());
    expect(result.success).toBe(true);
  });

  it("applies v1 defaults to reused fragments", () => {
    const result = latticeagConfigV2Schema.parse(validV2());
    expect(result.bus.log_path).toBe(".latticeag/events.jsonl");
    expect(result.bus.ring_capacity).toBe(10000);
  });

  it.each([
    "schema_version",
    "project",
    "bus",
    "ingest",
    "adapters",
    "redaction",
    "sync",
    "doctor",
    "gateway",
    "agents",
    "products",
    "catalog",
    "storage",
  ])("rejects a document missing required section %s", (key) => {
    const doc = validV2();
    delete doc[key];
    expect(latticeagConfigV2Schema.safeParse(doc).success).toBe(false);
  });

  it.each(["0.0.0.0", "::", "127.0.0.2", "localhost"])(
    "rejects non-loopback ui.bind %s (TV-GW-39)",
    (bind) => {
      const doc = validV2();
      (doc["gateway"] as Record<string, unknown>)["ui"] = {
        enabled: true,
        bind,
        port: 9848,
        ipv6: false,
        remote: false,
      };
      expect(latticeagConfigV2Schema.safeParse(doc).success).toBe(false);
      const sem = validateConfigV2Semantics(doc);
      expect(sem.valid).toBe(false);
      expect(sem.errors.some((e) => e.code === "SCHEMA_INVALID")).toBe(true);
    },
  );

  it.each([1, 1023, 70000, -1, 9848.5])(
    "rejects invalid ui.port %s",
    (port) => {
      const doc = validV2();
      const gateway = doc["gateway"] as Record<string, unknown>;
      (gateway["ui"] as Record<string, unknown>)["port"] = port;
      expect(latticeagConfigV2Schema.safeParse(doc).success).toBe(false);
    },
  );

  it.each([0, 1024, 65535])("accepts valid ui.port %s", (port) => {
    const doc = validV2();
    const gateway = doc["gateway"] as Record<string, unknown>;
    (gateway["ui"] as Record<string, unknown>)["port"] = port;
    expect(latticeagConfigV2Schema.safeParse(doc).success).toBe(true);
  });

  it("rejects schema_version 1 and extra top-level keys", () => {
    const v1doc = validV2();
    v1doc["schema_version"] = 1;
    expect(latticeagConfigV2Schema.safeParse(v1doc).success).toBe(false);
    const extra = { ...validV2(), surprise: true };
    expect(latticeagConfigV2Schema.safeParse(extra).success).toBe(false);
  });

  it("rejects stream.profile 'raw' and a bad from-cursor", () => {
    const badProfile = validV2();
    const sync = badProfile["sync"] as Record<string, unknown>;
    const streams = sync["streams"] as Record<string, unknown>;
    (streams["runs"] as Record<string, unknown>)["profile"] = "raw";
    expect(latticeagConfigV2Schema.safeParse(badProfile).success).toBe(false);

    const badFrom = validV2();
    const sync2 = badFrom["sync"] as Record<string, unknown>;
    const streams2 = sync2["streams"] as Record<string, unknown>;
    (streams2["watch"] as Record<string, unknown>)["from"] = "cXYZ:7";
    expect(latticeagConfigV2Schema.safeParse(badFrom).success).toBe(false);
  });

  it("accepts a real cursor-shaped from value", () => {
    const doc = validV2();
    const streams = (doc["sync"] as Record<string, unknown>)[
      "streams"
    ] as Record<string, unknown>;
    (streams["runs"] as Record<string, unknown>)["from"] =
      "c0000000000000001:7";
    expect(latticeagConfigV2Schema.safeParse(doc).success).toBe(true);
  });
});

describe("validateConfigV2Semantics", () => {
  it("passes a well-formed document", () => {
    const result = validateConfigV2Semantics(validV2());
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("requires a cloud UI grant for ui.remote", () => {
    const doc = validV2();
    const gateway = doc["gateway"] as Record<string, unknown>;
    (gateway["ui"] as Record<string, unknown>)["remote"] = true;
    const denied = validateConfigV2Semantics(doc);
    expect(denied.valid).toBe(false);
    expect(
      denied.errors.some(
        (e) => e.code === "GRANT_REQUIRED" && e.path === "gateway.ui.remote",
      ),
    ).toBe(true);
    const granted = validateConfigV2Semantics(doc, { hasCloudUiGrant: true });
    expect(granted.valid).toBe(true);
  });

  it("enforces disk_bytes within [64MiB, 2^63-1]", () => {
    const tooSmall = validV2();
    (tooSmall["storage"] as Record<string, unknown>)["disk_bytes"] = "1024";
    expect(
      validateConfigV2Semantics(tooSmall).errors.some(
        (e) => e.code === "VALUE_RANGE" && e.path === "storage.disk_bytes",
      ),
    ).toBe(true);

    const tooBig = validV2();
    (tooBig["storage"] as Record<string, unknown>)["disk_bytes"] =
      "9223372036854775808"; // 2^63
    expect(
      validateConfigV2Semantics(tooBig).errors.some(
        (e) => e.code === "VALUE_RANGE",
      ),
    ).toBe(true);

    const boundary = validV2();
    (boundary["storage"] as Record<string, unknown>)["disk_bytes"] =
      "9223372036854775807";
    expect(validateConfigV2Semantics(boundary).valid).toBe(true);
  });

  it("rejects non-HTTPS catalog sources", () => {
    const doc = validV2();
    (doc["catalog"] as Record<string, unknown>)["source"] =
      "http://catalog.example.com/index.json";
    const result = validateConfigV2Semantics(doc);
    expect(result.valid).toBe(false);
    expect(
      result.errors.some(
        (e) => e.code === "ORIGIN_UNTRUSTED" && e.path === "catalog.source",
      ),
    ).toBe(true);

    const ok = validV2();
    (ok["catalog"] as Record<string, unknown>)["source"] =
      "https://catalog.example.com/index.json";
    expect(validateConfigV2Semantics(ok).valid).toBe(true);
  });

  it("rejects duplicate pin slugs and non-SemVer pin versions", () => {
    const pin = (slug: string, version: string) => ({
      slug,
      version,
      digest: DIGEST,
      index: DIGEST,
    });
    const dup = validV2();
    (dup["catalog"] as Record<string, unknown>)["pins"] = [
      pin("widget", "1.0.0"),
      pin("widget", "1.0.1"),
    ];
    const dupResult = validateConfigV2Semantics(dup);
    expect(dupResult.valid).toBe(false);
    expect(
      dupResult.errors.some((e) => e.code === "PIN_DUPLICATE"),
    ).toBe(true);

    const badVer = validV2();
    (badVer["catalog"] as Record<string, unknown>)["pins"] = [
      pin("widget", "1.0.x"),
    ];
    const verResult = validateConfigV2Semantics(badVer);
    expect(verResult.valid).toBe(false);
    expect(
      verResult.errors.some((e) => e.code === "SEMVER_INVALID"),
    ).toBe(true);

    const good = validV2();
    (good["catalog"] as Record<string, unknown>)["pins"] = [
      pin("widget", "1.0.0-rc.1+build.7"),
    ];
    expect(validateConfigV2Semantics(good).valid).toBe(true);
  });

  it("rejects non-64-hex product manifests", () => {
    const doc = validV2();
    (doc["products"] as Record<string, unknown>)["instances"] = {
      "my-product": {
        enabled: true,
        manifest: "not-hex",
        config: {},
      },
    };
    const result = validateConfigV2Semantics(doc);
    expect(result.valid).toBe(false);
    expect(
      result.errors.some(
        (e) =>
          e.code === "SCHEMA_INVALID" &&
          e.path === "products.instances.my-product.manifest",
      ),
    ).toBe(true);

    const ok = validV2();
    (ok["products"] as Record<string, unknown>)["instances"] = {
      "my-product": { enabled: true, manifest: HASH, config: { a: 1 } },
    };
    expect(validateConfigV2Semantics(ok).valid).toBe(true);
  });
});
