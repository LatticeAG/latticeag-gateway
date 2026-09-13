import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { latticeagConfigSchema } from "./schema.js";

/**
 * Gateway v2 config schema (spec §8.1).
 *
 * The project/bus/ingest/adapters/redaction/doctor fragments and the
 * sync.legacy fragment are reused verbatim from the v1 zod schema so their
 * additionalProperties, required fields, defaults, constants, and numeric
 * bounds are preserved exactly.
 */
export const LATTICEAG_CONFIG_V2_SCHEMA_URL =
  "https://latticeag.dev/schemas/latticeag-config/v2.json";

const v1 = latticeagConfigSchema.shape;

// ---------------------------------------------------------------------------
// $defs
// ---------------------------------------------------------------------------

export const configV2IdSchema = z
  .string()
  .regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/);

export const configV2SlugSchema = z
  .string()
  .regex(/^[a-z][a-z0-9-]{0,63}$/);

export const configV2HashSchema = z.string().regex(/^[0-9a-f]{64}$/);

export const configV2DigestSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/);

export const configV2PinSchema = z
  .object({
    slug: configV2SlugSchema,
    version: z.string().min(5).max(128),
    digest: configV2DigestSchema,
    index: configV2DigestSchema,
  })
  .strict();

export const configV2StreamSchema = z
  .object({
    enabled: z.boolean(),
    paused: z.boolean(),
    profile: z.enum(["metadata", "masked", "full"]),
    include_objects: z.boolean(),
    cohort: z.string().min(1).max(128),
    from: z.string().regex(/^(now|c[0-9a-f]{16}:[0-9]+)$/),
  })
  .strict();

export const configV2NativeRefSchema = z
  .object({
    profile: z.string().min(1).max(128),
    namespace: z.string().min(1).max(128),
    object_id: z.string().min(1).max(256),
    commitment: z.union([z.string(), z.null()]),
    raw_sha256: configV2HashSchema,
    bytes: z.string().regex(/^(0|[1-9][0-9]*)$/),
  })
  .strict();

// ---------------------------------------------------------------------------
// gateway
// ---------------------------------------------------------------------------

export const configV2UiSchema = z
  .object({
    enabled: z.boolean(),
    bind: z.literal("127.0.0.1"),
    port: z.union([
      z.literal(0),
      z.number().int().min(1024).max(65535),
    ]),
    ipv6: z.boolean(),
    remote: z.boolean(),
  })
  .strict();

export const configV2MeshSchema = z
  .object({
    mode: z.literal("local"),
    contract: z.union([z.null(), configV2NativeRefSchema]),
  })
  .strict();

export const configV2GatewaySchema = z
  .object({
    workspace_id: configV2IdSchema,
    instance_id: configV2IdSchema,
    autostart: z.enum(["on-demand", "never"]),
    ui: configV2UiSchema,
    mesh: configV2MeshSchema,
  })
  .strict();

// ---------------------------------------------------------------------------
// agents
// ---------------------------------------------------------------------------

export const configV2AgentsSchema = z
  .object({
    access_ttl_s: z.number().int().min(60).max(900),
    refresh_ttl_s: z.number().int().min(900).max(2592000),
    allow_operator: z.boolean(),
  })
  .strict();

// ---------------------------------------------------------------------------
// products
// ---------------------------------------------------------------------------

export const configV2ProductInstanceSchema = z
  .object({
    enabled: z.boolean(),
    manifest: configV2HashSchema,
    config: z.record(z.unknown()),
  })
  .strict();

export const configV2ProductsSchema = z
  .object({
    instances: z
      .record(configV2SlugSchema, configV2ProductInstanceSchema)
      .superRefine((instances, ctx) => {
        if (Object.keys(instances).length > 256) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "products.instances may have at most 256 entries",
          });
        }
      }),
  })
  .strict();

// ---------------------------------------------------------------------------
// catalog
// ---------------------------------------------------------------------------

function uniqueItems(
  arr: readonly unknown[],
): boolean {
  for (let i = 0; i < arr.length; i += 1) {
    for (let j = i + 1; j < arr.length; j += 1) {
      if (isDeepStrictEqual(arr[i], arr[j])) {
        return false;
      }
    }
  }
  return true;
}

export const configV2CatalogSchema = z
  .object({
    channel: z.enum(["stable", "preview"]),
    source: z.union([z.null(), z.string()]),
    pins: z
      .array(configV2PinSchema)
      .max(256)
      .superRefine((pins, ctx) => {
        if (!uniqueItems(pins)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "catalog.pins items must be unique",
          });
        }
      }),
    allowlist: z
      .array(configV2SlugSchema)
      .max(256)
      .superRefine((items, ctx) => {
        if (new Set(items).size !== items.length) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "catalog.allowlist items must be unique",
          });
        }
      }),
    strict: z.boolean(),
    max_age_s: z.number().int().min(3600).max(2592000),
  })
  .strict();

// ---------------------------------------------------------------------------
// storage
// ---------------------------------------------------------------------------

export const configV2StorageSchema = z
  .object({
    root: z.string().min(1),
    segment_bytes: z.number().int().min(1048576).max(268435456),
    disk_bytes: z.string().regex(/^[1-9][0-9]*$/),
    retention_days: z.number().int().min(1).max(3650),
  })
  .strict();

// ---------------------------------------------------------------------------
// sync
// ---------------------------------------------------------------------------

export const configV2StreamsSchema = z
  .object({
    runs: configV2StreamSchema,
    receipts: configV2StreamSchema,
    lineage: configV2StreamSchema,
    approvals: configV2StreamSchema,
    watch: configV2StreamSchema,
    mesh: configV2StreamSchema,
  })
  .strict();

export const configV2SyncSchema = z
  .object({
    enabled: z.boolean(),
    paused: z.boolean(),
    cloud: z.union([z.null(), configV2IdSchema]),
    streams: configV2StreamsSchema,
    legacy: z.union([z.null(), v1.sync]),
  })
  .strict();

// ---------------------------------------------------------------------------
// top-level document
// ---------------------------------------------------------------------------

export const latticeagConfigV2Schema = z
  .object({
    $schema: z.string().url().optional(),
    schema_version: z.literal(2),
    project: v1.project,
    bus: v1.bus,
    ingest: v1.ingest,
    adapters: v1.adapters,
    redaction: v1.redaction,
    sync: configV2SyncSchema,
    doctor: v1.doctor,
    gateway: configV2GatewaySchema,
    agents: configV2AgentsSchema,
    products: configV2ProductsSchema,
    catalog: configV2CatalogSchema,
    storage: configV2StorageSchema,
  })
  .strict();

export type LatticeagConfigV2 = z.infer<typeof latticeagConfigV2Schema>;

/** Alias matching the spec's `ConfigV2` name. */
export type ConfigV2 = LatticeagConfigV2;
