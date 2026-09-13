/**
 * Gateway v2 product lifecycle — §5.1 manifest/verify/resolve,
 * §5.2 extraction, §5.3 adapter protocol, §5.4 transition engine, and the
 * ProductService facade. The daemon binds real ports (catalog, trust
 * store, registry, spawner, clock, journal, receipt sink) via
 * LifecyclePorts.
 */
export {
  manifestDigestOf,
  parseProductManifest,
} from "./manifest.js";
export { isRevoked, verifyRelease } from "./verify.js";
export type {
  ProvenanceDescriptor,
  ReleaseTrust,
  VerifiedRelease,
  VerifyContext,
} from "./verify.js";
export {
  DependencyConflictError,
  dependentsPresent,
  EDGE_DISPOSITIONS,
  edgeDisposition,
  planHashOf,
  resolveGraph,
  resolvePlan,
  selectVersion,
} from "./resolve.js";
export type {
  EdgeDisposition,
  InstalledProduct,
  PlanDependency,
  PlanSummary,
  ResolvedPlan,
  ResolveInput,
  ResolveOptions,
} from "./resolve.js";
export { extractArchive, scanArchive } from "./extract.js";
export type { ExtractedEntry, ParsedEntry } from "./extract.js";
export { AdapterClient, describeChecked } from "./adapter-client.js";
export type {
  AdapterChild,
  AdapterClientOptions,
  ConfigureResult,
  DescribeResult,
  DrainResult,
  HealthResult,
  SnapshotResult,
  StartResult,
  StopResult,
} from "./adapter-client.js";
export {
  awaitReadiness,
  startLiveProbes,
  systemClock,
} from "./health.js";
export type {
  ClockOps,
  LiveProbeHandle,
  LiveProbeOptions,
  Probe,
  ProbeOutcome,
  ReadinessGateOptions,
  ReadinessResult,
} from "./health.js";
export {
  InjectedCrash,
  isInjectedCrash,
  LifecycleEngine,
} from "./engine.js";
export type {
  EngineOptions,
  OperationRecord,
  RunContext,
} from "./engine.js";
export type {
  CatalogPort,
  FetchedRelease,
  GenerationRow,
  JournalMutation,
  LifecyclePorts,
  PathsPort,
  PolicyView,
  ProductRegistryPort,
  SourceRef,
  TransitionReceipt,
} from "./ports.js";
export {
  createMemoryPorts,
  retainedRow,
  StubAdapterChild,
} from "./testing.js";
export type {
  MemoryPorts,
  MemoryPortsOptions,
  SpawnRecord,
  StubScript,
} from "./testing.js";
export { createProductService } from "./service.js";
export type {
  ProductServiceBundle,
  ServiceOptions,
} from "./service.js";
export {
  compareSemver,
  parseSemver,
  satisfiesNode,
  satisfiesSemver,
  stripV,
  validateNodeRange,
} from "./semver.js";
export type { SemVer } from "./semver.js";
