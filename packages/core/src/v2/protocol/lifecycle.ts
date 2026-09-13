/**
 * Gateway v2 — product lifecycle states and the complete transition
 * relation (spec §5.4).
 *
 * The state is per immutable candidate/version; the active pointer,
 * operation status, and retained prior version are separate registry
 * fields. Each listed row emits the named transition as the retained
 * result object of a native Proof Gateway action. Unlisted transitions
 * are STATE_TRANSITION and have no side effect.
 */

/** Per-candidate lifecycle states (closed union). */
export const PRODUCT_STATES = [
  "ABSENT",
  "PLANNED",
  "FETCHING",
  "VERIFIED",
  "STAGED",
  "STARTING",
  "HEALTHCHECKING",
  "READY",
  "DEGRADED",
  "DRAINING",
  "STOPPED_RETAINED",
  "UNINSTALLING",
  "REMOVED",
  "REJECTED",
  "CANCELLED",
  "CRASHED",
  "QUARANTINED",
] as const;

export type ProductState = (typeof PRODUCT_STATES)[number];

/**
 * Transition event names retained as Proof action results (§5.4). These
 * names do not extend @latticeag/events 0.1.0.
 */
export const TRANSITION_EVENTS = [
  "ProductPlanCreated",
  "ProductFetchStarted",
  "ProductVerified",
  "ProductRejected",
  "ProductStaged",
  "ProductStartRequested",
  "ProductStarted",
  "ProductActivated",
  "ProductCandidateAbortRequested",
  "ProductDegraded",
  "ProductRecoveryStarted",
  "ProductCrashed",
  "ProductRestartRequested",
  "ProductQuarantined",
  "ProductDrainRequested",
  "ProductStopped",
  "ProductContainmentConfirmed",
  "ProductUninstallStarted",
  "ProductUninstalled",
  "ProductOperationCancelled",
  "ProductRollbackPlanned",
  "ProductRecoveryPlanned",
] as const;

export type TransitionEvent = (typeof TRANSITION_EVENTS)[number];

export interface LifecycleTransition {
  readonly from: ProductState;
  readonly to: ProductState;
  /** Verbatim guard/action text from the §5.4 table. */
  readonly guard: string;
  readonly event: TransitionEvent;
}

/**
 * The complete §5.4 relation. Multi-source spec rows
 * (e.g. "PLANNED/FETCHING → REJECTED") are expanded to one entry per
 * (from, to) pair, each carrying the row's guard text verbatim.
 */
export const TRANSITIONS: readonly LifecycleTransition[] = [
  {
    from: "ABSENT",
    to: "PLANNED",
    guard:
      "Verify metadata; resolve/price-label/review full graph without running code.",
    event: "ProductPlanCreated",
  },
  {
    from: "PLANNED",
    to: "FETCHING",
    guard: "Operator review matches plan/hash/revisions and current grants.",
    event: "ProductFetchStarted",
  },
  {
    from: "FETCHING",
    to: "VERIFIED",
    guard:
      "Archive, signatures, provenance, lockfile, platform, and policy all pass.",
    event: "ProductVerified",
  },
  {
    from: "PLANNED",
    to: "REJECTED",
    guard:
      "Trust, network, package, entitlement, or dependency failure; no execution.",
    event: "ProductRejected",
  },
  {
    from: "FETCHING",
    to: "REJECTED",
    guard:
      "Trust, network, package, entitlement, or dependency failure; no execution.",
    event: "ProductRejected",
  },
  {
    from: "VERIFIED",
    to: "STAGED",
    guard:
      "Safe extraction, immutable cache, validated adapter config, private data generation.",
    event: "ProductStaged",
  },
  {
    from: "VERIFIED",
    to: "REJECTED",
    guard:
      "Extraction/schema/sandbox preparation fails; active version unchanged.",
    event: "ProductRejected",
  },
  {
    from: "STAGED",
    to: "REJECTED",
    guard:
      "Extraction/schema/sandbox preparation fails; active version unchanged.",
    event: "ProductRejected",
  },
  {
    from: "STAGED",
    to: "STARTING",
    guard:
      "Journal start intent, allocate sandbox, invoke adapter with operation ID.",
    event: "ProductStartRequested",
  },
  {
    from: "STARTING",
    to: "HEALTHCHECKING",
    guard: "Describe/configure/start match manifest and generation.",
    event: "ProductStarted",
  },
  {
    from: "HEALTHCHECKING",
    to: "READY",
    guard:
      "Three successful health checks; atomic active/config/registry/outbox commit.",
    event: "ProductActivated",
  },
  {
    from: "STARTING",
    to: "DRAINING",
    guard:
      "Start/health failure or cancellation; do not activate or publish capabilities.",
    event: "ProductCandidateAbortRequested",
  },
  {
    from: "HEALTHCHECKING",
    to: "DRAINING",
    guard:
      "Start/health failure or cancellation; do not activate or publish capabilities.",
    event: "ProductCandidateAbortRequested",
  },
  {
    from: "READY",
    to: "DEGRADED",
    guard: "Three live probe failures; withdraw executable discovery entries.",
    event: "ProductDegraded",
  },
  {
    from: "DEGRADED",
    to: "HEALTHCHECKING",
    guard:
      "Explicit recovery or bounded safe restart; native uncertainty already reconciled.",
    event: "ProductRecoveryStarted",
  },
  {
    from: "READY",
    to: "CRASHED",
    guard: "Owned process exited unexpectedly; capture termination evidence.",
    event: "ProductCrashed",
  },
  {
    from: "DEGRADED",
    to: "CRASHED",
    guard: "Owned process exited unexpectedly; capture termination evidence.",
    event: "ProductCrashed",
  },
  {
    from: "HEALTHCHECKING",
    to: "CRASHED",
    guard: "Owned process exited unexpectedly; capture termination evidence.",
    event: "ProductCrashed",
  },
  {
    from: "STARTING",
    to: "CRASHED",
    guard: "Owned process exited unexpectedly; capture termination evidence.",
    event: "ProductCrashed",
  },
  {
    from: "CRASHED",
    to: "STARTING",
    guard:
      "Pure initialization certified; no unknown native operations; restart budget remains.",
    event: "ProductRestartRequested",
  },
  {
    from: "CRASHED",
    to: "QUARANTINED",
    guard: "Restart budget exhausted, containment breach, or unknown effect.",
    event: "ProductQuarantined",
  },
  {
    from: "READY",
    to: "DRAINING",
    guard: "Approved uninstall or activated replacement; stop new admissions.",
    event: "ProductDrainRequested",
  },
  {
    from: "DEGRADED",
    to: "DRAINING",
    guard: "Approved uninstall or activated replacement; stop new admissions.",
    event: "ProductDrainRequested",
  },
  {
    from: "DRAINING",
    to: "STOPPED_RETAINED",
    guard:
      "Drain/stop and OS process identity confirm exit; retain data/archive for rollback.",
    event: "ProductStopped",
  },
  {
    from: "DRAINING",
    to: "QUARANTINED",
    guard:
      "Cannot prove child containment/termination or drain reports uncertain effects.",
    event: "ProductQuarantined",
  },
  {
    from: "CRASHED",
    to: "STOPPED_RETAINED",
    guard:
      "Operator verifies owned process termination; preserve unresolved native effects as UNKNOWN, permit local removal but no retry.",
    event: "ProductContainmentConfirmed",
  },
  {
    from: "QUARANTINED",
    to: "STOPPED_RETAINED",
    guard:
      "Operator verifies owned process termination; preserve unresolved native effects as UNKNOWN, permit local removal but no retry.",
    event: "ProductContainmentConfirmed",
  },
  {
    from: "STOPPED_RETAINED",
    to: "UNINSTALLING",
    guard:
      "Reviewed uninstall, no remaining required dependents, data disposition fixed.",
    event: "ProductUninstallStarted",
  },
  {
    from: "UNINSTALLING",
    to: "REMOVED",
    guard:
      "Unwire config/registry atomically; remove package links; retain receipts and default data.",
    event: "ProductUninstalled",
  },
  {
    from: "UNINSTALLING",
    to: "QUARANTINED",
    guard:
      "Durable removal incomplete; no readiness until recovery resolves exact journal state.",
    event: "ProductQuarantined",
  },
  {
    from: "PLANNED",
    to: "CANCELLED",
    guard: "Cancel before start/activation; retain admission/rejection evidence.",
    event: "ProductOperationCancelled",
  },
  {
    from: "FETCHING",
    to: "CANCELLED",
    guard: "Cancel before start/activation; retain admission/rejection evidence.",
    event: "ProductOperationCancelled",
  },
  {
    from: "VERIFIED",
    to: "CANCELLED",
    guard: "Cancel before start/activation; retain admission/rejection evidence.",
    event: "ProductOperationCancelled",
  },
  {
    from: "STAGED",
    to: "CANCELLED",
    guard: "Cancel before start/activation; retain admission/rejection evidence.",
    event: "ProductOperationCancelled",
  },
  {
    from: "STOPPED_RETAINED",
    to: "PLANNED",
    guard:
      "New explicit rollback/reinstall operation, current trust and dependency checks.",
    event: "ProductRollbackPlanned",
  },
  {
    from: "REMOVED",
    to: "PLANNED",
    guard:
      "New explicit rollback/reinstall operation, current trust and dependency checks.",
    event: "ProductRollbackPlanned",
  },
  {
    from: "QUARANTINED",
    to: "PLANNED",
    guard:
      "Operator-reviewed clean candidate; native uncertain operation not retried implicitly.",
    event: "ProductRecoveryPlanned",
  },
];

/**
 * Resolve a (from, to) pair to its retained transition event name, or
 * "STATE_TRANSITION" when the pair is not in the §5.4 relation — unlisted
 * transitions are STATE_TRANSITION and have no side effect.
 */
export function transitionFor(
  from: ProductState,
  to: ProductState,
): TransitionEvent | "STATE_TRANSITION" {
  for (const t of TRANSITIONS) {
    if (t.from === from && t.to === to) return t.event;
  }
  return "STATE_TRANSITION";
}

/** Look up the full transition row, or undefined for an unlisted pair. */
export function transitionRow(
  from: ProductState,
  to: ProductState,
): LifecycleTransition | undefined {
  return TRANSITIONS.find((t) => t.from === from && t.to === to);
}

/**
 * Restart budget (§5.4): at most five starts per 60-second window with
 * 1/2/4/8/16-second delays; reboots do not reset an unresolved operation
 * tombstone or bypass quarantine.
 */
export const RESTART_BUDGET = {
  maxStarts: 5,
  windowMs: 60_000,
  delaysMs: [1_000, 2_000, 4_000, 8_000, 16_000],
} as const;

/**
 * Grace/deadline constants: daemon.stop grace_ms is 0–30000 (§3.2);
 * adapter stop/drain deadlines are bounded (§5.2 examples use 5000 ms);
 * CLI timeout keeps SIGKILL at n+5000 after SIGTERM (§6.1).
 */
export const GRACE = {
  daemonStopMinMs: 0,
  daemonStopMaxMs: 30_000,
  daemonStopDefaultMs: 10_000,
  adapterStopDeadlineMs: 5_000,
  sigkillAfterSigtermMs: 5_000,
} as const;
