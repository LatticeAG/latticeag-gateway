/**
 * Gateway v2 platform layer — core service implementations over the
 * structural `PlatformPorts` seam.
 *
 * Implemented here (spec §3.2/§3.3): daemon, config, run, events,
 * objects, receipt, lineage, operation, ui sessions, and the audit
 * receipt writer. Product/agent/approval/sync/cloud/catalog services are
 * deliberately not fabricated — without their native contract bindings
 * they must surface explicit unavailable states, not stubs.
 */
export * from "./ports.js";
export {
  createMemoryPlatformPorts,
  MemoryPlatformStore,
  MemorySessionStore,
  MemoryStoreError,
  pointerFor,
  type MemoryPortsOptions,
  type MemoryPlatformPorts,
} from "./testing.js";
export { createDaemonService } from "./daemon.js";
export {
  createConfigService,
  redactConfigDocument,
  REVIEW_WINDOW_MS,
} from "./config-svc.js";
export {
  createRunService,
  HEARTBEAT_MAX_MS,
} from "./run.js";
export {
  createEventService,
  PROOF_RECORD_MAX_BYTES,
  LEGACY_RECORD_MAX_BYTES,
  SUBSCRIPTION_LEASE_MS,
  QUERY_LIMIT_MAX,
} from "./events-svc.js";
export {
  createObjectService,
  OBJECT_MAX_BYTES,
  asActionAddress,
  resolveActionEntry,
  collectActionObjectRefs,
  callerOwnsAction,
  isObjectRefShape,
} from "./objects.js";
export { createReceiptService } from "./receipts.js";
export {
  createLineageService,
  LINEAGE_MAX_NODES,
  LINEAGE_MAX_DEPTH,
} from "./lineage.js";
export { createOperationService } from "./operations.js";
export {
  createUiService,
  sessionIsLive,
  BOOTSTRAP_TTL_MS,
  VIEWER_SESSION_MS,
  VIEWER_IDLE_MS,
  OPERATOR_SESSION_MS,
  OPERATOR_IDLE_MS,
} from "./sessions.js";
export {
  emitAuditReceipt,
  AUDIT_PARTITION_MAX_EVENTS,
  AUDIT_HISTORY_EVENTS,
  type AuditReceiptInput,
} from "./audit.js";

import type {
  DaemonService,
  ConfigService,
  RunService,
  EventService,
  ObjectService,
  ReceiptService,
  LineageService,
  OperationService,
  UiService,
} from "../protocol/services.js";
import type { PlatformPorts, ServiceContext } from "./ports.js";
import { LOCAL_OPERATOR_CONTEXT } from "./ports.js";
import { createDaemonService } from "./daemon.js";
import { createConfigService } from "./config-svc.js";
import { createRunService } from "./run.js";
import { createEventService } from "./events-svc.js";
import { createObjectService } from "./objects.js";
import { createReceiptService } from "./receipts.js";
import { createLineageService } from "./lineage.js";
import { createOperationService } from "./operations.js";
import { createUiService } from "./sessions.js";

/** The implemented slice of `GatewayServices`. */
export interface PlatformServices {
  daemon: DaemonService;
  config: ConfigService;
  run: RunService;
  events: EventService;
  objects: ObjectService;
  receipt: ReceiptService;
  lineage: LineageService;
  operation: OperationService;
  ui: UiService;
}

/**
 * Build the implemented service group for one per-call binding. The
 * dispatcher supplies `ctx.principal` after authentication; the default
 * is the socket-authenticated local operator.
 */
export function createPlatformServices(
  ports: PlatformPorts,
  ctx: ServiceContext = LOCAL_OPERATOR_CONTEXT,
): PlatformServices {
  return {
    daemon: createDaemonService(ports, ctx),
    config: createConfigService(ports, ctx),
    run: createRunService(ports),
    events: createEventService(ports, ctx),
    objects: createObjectService(ports, ctx),
    receipt: createReceiptService(ports, ctx),
    lineage: createLineageService(ports, ctx),
    operation: createOperationService(ports, ctx),
    ui: createUiService(ports, ctx),
  };
}
