import { latticeagConfigJsonSchema } from "./json-schema.js";
import { LATTICEAG_CONFIG_SCHEMA_URL } from "./schema.js";
import { LATTICEAG_CONFIG_V2_SCHEMA_URL } from "./schema-v2.js";

/**
 * The complete Gateway v2 config JSON Schema (spec §8.1), bundled verbatim.
 * It references the v1 schema by its original $id; consumers MUST resolve
 * those references from `localSchemaRegistry` — network schema resolution is
 * disabled, including user-supplied $schema URLs.
 */
export const latticeagConfigV2JsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://latticeag.dev/schemas/latticeag-config/v2.json",
  type: "object",
  additionalProperties: false,
  required: [
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
  ],
  properties: {
    $schema: { type: "string", format: "uri" },
    schema_version: { type: "integer", const: 2 },
    project: {
      $ref: "https://latticeag.dev/schemas/latticeag-config/v1.json#/properties/project",
    },
    bus: {
      $ref: "https://latticeag.dev/schemas/latticeag-config/v1.json#/properties/bus",
    },
    ingest: {
      $ref: "https://latticeag.dev/schemas/latticeag-config/v1.json#/properties/ingest",
    },
    adapters: {
      $ref: "https://latticeag.dev/schemas/latticeag-config/v1.json#/properties/adapters",
    },
    redaction: {
      $ref: "https://latticeag.dev/schemas/latticeag-config/v1.json#/properties/redaction",
    },
    doctor: {
      $ref: "https://latticeag.dev/schemas/latticeag-config/v1.json#/properties/doctor",
    },
    gateway: {
      type: "object",
      additionalProperties: false,
      required: ["workspace_id", "instance_id", "autostart", "ui", "mesh"],
      properties: {
        workspace_id: { $ref: "#/$defs/id" },
        instance_id: { $ref: "#/$defs/id" },
        autostart: { enum: ["on-demand", "never"] },
        ui: {
          type: "object",
          additionalProperties: false,
          required: ["enabled", "bind", "port", "ipv6", "remote"],
          properties: {
            enabled: { type: "boolean" },
            bind: { const: "127.0.0.1" },
            port: {
              anyOf: [
                { const: 0 },
                { type: "integer", minimum: 1024, maximum: 65535 },
              ],
            },
            ipv6: { type: "boolean" },
            remote: { type: "boolean" },
          },
        },
        mesh: {
          type: "object",
          additionalProperties: false,
          required: ["mode", "contract"],
          properties: {
            mode: { const: "local" },
            contract: {
              anyOf: [{ type: "null" }, { $ref: "#/$defs/nativeRef" }],
            },
          },
        },
      },
    },
    agents: {
      type: "object",
      additionalProperties: false,
      required: ["access_ttl_s", "refresh_ttl_s", "allow_operator"],
      properties: {
        access_ttl_s: { type: "integer", minimum: 60, maximum: 900 },
        refresh_ttl_s: { type: "integer", minimum: 900, maximum: 2592000 },
        allow_operator: { type: "boolean" },
      },
    },
    products: {
      type: "object",
      additionalProperties: false,
      required: ["instances"],
      properties: {
        instances: {
          type: "object",
          maxProperties: 256,
          propertyNames: { $ref: "#/$defs/slug" },
          additionalProperties: {
            type: "object",
            additionalProperties: false,
            required: ["enabled", "manifest", "config"],
            properties: {
              enabled: { type: "boolean" },
              manifest: { $ref: "#/$defs/hash" },
              config: { type: "object" },
            },
          },
        },
      },
    },
    catalog: {
      type: "object",
      additionalProperties: false,
      required: [
        "channel",
        "source",
        "pins",
        "allowlist",
        "strict",
        "max_age_s",
      ],
      properties: {
        channel: { enum: ["stable", "preview"] },
        source: {
          anyOf: [{ type: "null" }, { type: "string", format: "uri" }],
        },
        pins: {
          type: "array",
          maxItems: 256,
          uniqueItems: true,
          items: { $ref: "#/$defs/pin" },
        },
        allowlist: {
          type: "array",
          maxItems: 256,
          uniqueItems: true,
          items: { $ref: "#/$defs/slug" },
        },
        strict: { type: "boolean" },
        max_age_s: { type: "integer", minimum: 3600, maximum: 2592000 },
      },
    },
    storage: {
      type: "object",
      additionalProperties: false,
      required: ["root", "segment_bytes", "disk_bytes", "retention_days"],
      properties: {
        root: { type: "string", minLength: 1 },
        segment_bytes: {
          type: "integer",
          minimum: 1048576,
          maximum: 268435456,
        },
        disk_bytes: { type: "string", pattern: "^[1-9][0-9]*$" },
        retention_days: { type: "integer", minimum: 1, maximum: 3650 },
      },
    },
    sync: {
      type: "object",
      additionalProperties: false,
      required: ["enabled", "paused", "cloud", "streams", "legacy"],
      properties: {
        enabled: { type: "boolean" },
        paused: { type: "boolean" },
        cloud: { anyOf: [{ type: "null" }, { $ref: "#/$defs/id" }] },
        streams: {
          type: "object",
          additionalProperties: false,
          required: [
            "runs",
            "receipts",
            "lineage",
            "approvals",
            "watch",
            "mesh",
          ],
          properties: {
            runs: { $ref: "#/$defs/stream" },
            receipts: { $ref: "#/$defs/stream" },
            lineage: { $ref: "#/$defs/stream" },
            approvals: { $ref: "#/$defs/stream" },
            watch: { $ref: "#/$defs/stream" },
            mesh: { $ref: "#/$defs/stream" },
          },
        },
        legacy: {
          anyOf: [
            { type: "null" },
            {
              $ref: "https://latticeag.dev/schemas/latticeag-config/v1.json#/properties/sync",
            },
          ],
        },
      },
    },
  },
  $defs: {
    id: { type: "string", pattern: "^[A-Za-z][A-Za-z0-9_-]{0,63}$" },
    slug: { type: "string", pattern: "^[a-z][a-z0-9-]{0,63}$" },
    hash: { type: "string", pattern: "^[0-9a-f]{64}$" },
    digest: { type: "string", pattern: "^sha256:[0-9a-f]{64}$" },
    pin: {
      type: "object",
      additionalProperties: false,
      required: ["slug", "version", "digest", "index"],
      properties: {
        slug: { $ref: "#/$defs/slug" },
        version: { type: "string", minLength: 5, maxLength: 128 },
        digest: { $ref: "#/$defs/digest" },
        index: { $ref: "#/$defs/digest" },
      },
    },
    stream: {
      type: "object",
      additionalProperties: false,
      required: [
        "enabled",
        "paused",
        "profile",
        "include_objects",
        "cohort",
        "from",
      ],
      properties: {
        enabled: { type: "boolean" },
        paused: { type: "boolean" },
        profile: { enum: ["metadata", "masked", "full"] },
        include_objects: { type: "boolean" },
        cohort: { type: "string", minLength: 1, maxLength: 128 },
        from: { type: "string", pattern: "^(now|c[0-9a-f]{16}:[0-9]+)$" },
      },
    },
    nativeRef: {
      type: "object",
      additionalProperties: false,
      required: [
        "profile",
        "namespace",
        "object_id",
        "commitment",
        "raw_sha256",
        "bytes",
      ],
      properties: {
        profile: { type: "string", minLength: 1, maxLength: 128 },
        namespace: { type: "string", minLength: 1, maxLength: 128 },
        object_id: { type: "string", minLength: 1, maxLength: 256 },
        commitment: { type: ["string", "null"] },
        raw_sha256: { $ref: "#/$defs/hash" },
        bytes: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
      },
    },
  },
} as const;

/**
 * Local-only schema registry: resolves both the v1 and v2 $ids to their
 * bundled documents so $ref resolution never touches the network.
 */
export const localSchemaRegistry: ReadonlyMap<string, unknown> = new Map<
  string,
  unknown
>([
  [LATTICEAG_CONFIG_SCHEMA_URL, latticeagConfigJsonSchema()],
  [LATTICEAG_CONFIG_V2_SCHEMA_URL, latticeagConfigV2JsonSchema],
]);
