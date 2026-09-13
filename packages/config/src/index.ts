export {
  LATTICEAG_CONFIG_SCHEMA_URL,
  DEFAULT_REDACTION_KEYS,
  adapterNameSchema,
  ADAPTER_NAMES,
  DEFAULT_ADAPTER_SLUGS,
  DEFAULT_ADAPTERS_LIST,
  latticeagConfigSchema,
  UnknownAdapterError,
  parseAdapterList,
  enabledAdapters,
  createDefaultConfig,
} from "./schema.js";
export type { AdapterName, LatticeagConfig } from "./schema.js";

export {
  CONFIG_FILENAME,
  loadConfig,
  loadConfigV2,
  discoverConfig,
  readConfigFile,
  parseJsonStrict,
  formatZodIssue,
  ConfigNotFoundError,
  ConfigParseError,
  ConfigSchemaError,
  ConfigMigrationRequiredError,
} from "./load.js";
export type {
  LoadedConfig,
  LoadedConfigV1,
  LoadedConfigV2,
  ReadConfigFileResult,
  ReadConfigFileResultV1,
  ReadConfigFileResultV2,
  DiscoveredConfig,
} from "./load.js";

export { latticeagConfigJsonSchema } from "./json-schema.js";

export {
  LATTICEAG_CONFIG_V2_SCHEMA_URL,
  latticeagConfigV2Schema,
  configV2IdSchema,
  configV2SlugSchema,
  configV2HashSchema,
  configV2DigestSchema,
  configV2PinSchema,
  configV2StreamSchema,
  configV2NativeRefSchema,
  configV2UiSchema,
  configV2MeshSchema,
  configV2GatewaySchema,
  configV2AgentsSchema,
  configV2ProductInstanceSchema,
  configV2ProductsSchema,
  configV2CatalogSchema,
  configV2StorageSchema,
  configV2StreamsSchema,
  configV2SyncSchema,
} from "./schema-v2.js";
export type { LatticeagConfigV2, ConfigV2 } from "./schema-v2.js";

export {
  latticeagConfigV2JsonSchema,
  localSchemaRegistry,
} from "./json-schema-v2.js";

export { migrateConfig } from "./migrate.js";

export {
  migrateConfigFile,
  ConfigMigrationError,
} from "./migrate-file.js";
export type {
  MigrateConfigFileOptions,
  MigrateConfigFileResult,
  ConfigMigrationReceipt,
} from "./migrate-file.js";

export { validateConfigV2Semantics } from "./validate-v2.js";
export type {
  ValidateConfigV2Options,
  ConfigV2ValidationResult,
  ConfigV2Issue,
} from "./validate-v2.js";
