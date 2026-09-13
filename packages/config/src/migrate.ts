import { LATTICEAG_CONFIG_V2_SCHEMA_URL, type ConfigV2 } from "./schema-v2.js";

interface V1SyncSection {
  enabled: boolean;
  [key: string]: unknown;
}

interface V1Document {
  schema_version: number;
  sync: V1SyncSection;
  [key: string]: unknown;
}

/**
 * v1 → v2 config migration (spec §8.2), verbatim semantics.
 *
 * Throws `Error("SCHEMA_UNSUPPORTED")` when `v1.schema_version !== 1`.
 * The input document is deep-cloned and never mutated; new sections are
 * stamped with the spec-fixed defaults and the v1 `sync` object is preserved
 * verbatim under `sync.legacy` while all six new streams start disabled.
 */
export function migrateConfig(
  v1: unknown,
  workspace: string,
  instance: string,
): ConfigV2 {
  if (
    typeof v1 !== "object" ||
    v1 === null ||
    (v1 as { schema_version?: unknown }).schema_version !== 1
  ) {
    throw new Error("SCHEMA_UNSUPPORTED");
  }
  const v1doc = v1 as V1Document;
  const result = structuredClone(v1doc) as Record<string, unknown>;
  result["$schema"] = LATTICEAG_CONFIG_V2_SCHEMA_URL;
  result["schema_version"] = 2;
  result["gateway"] = {
    workspace_id: workspace,
    instance_id: instance,
    autostart: "on-demand",
    ui: { enabled: true, bind: "127.0.0.1", port: 9848, ipv6: false, remote: false },
    mesh: { mode: "local", contract: null },
  };
  result["agents"] = {
    access_ttl_s: 900,
    refresh_ttl_s: 2592000,
    allow_operator: false,
  };
  result["products"] = { instances: {} };
  result["catalog"] = {
    channel: "stable",
    source: null,
    pins: [],
    allowlist: [],
    strict: false,
    max_age_s: 604800,
  };
  result["storage"] = {
    root: ".latticeag",
    segment_bytes: 67108864,
    disk_bytes: "10737418240",
    retention_days: 30,
  };
  const stream = () => ({
    enabled: false,
    paused: false,
    profile: "metadata",
    include_objects: false,
    cohort: "private",
    from: "now",
  });
  result["sync"] = {
    enabled: false,
    paused: v1doc.sync.enabled,
    cloud: null,
    streams: {
      runs: stream(),
      receipts: stream(),
      lineage: stream(),
      approvals: stream(),
      watch: stream(),
      mesh: stream(),
    },
    legacy: structuredClone(v1doc.sync),
  };
  return result as unknown as ConfigV2;
}
