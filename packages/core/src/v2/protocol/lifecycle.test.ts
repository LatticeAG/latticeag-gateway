import { describe, expect, it } from "vitest";
import {
  PRODUCT_STATES,
  RESTART_BUDGET,
  TRANSITIONS,
  TRANSITION_EVENTS,
  transitionFor,
  transitionRow,
  type ProductState,
} from "./lifecycle.js";

/** Every (from,to) pair implied by the §5.4 spec table rows. */
const SPEC_ROWS: Array<[ProductState, ProductState, string]> = [
  ["ABSENT", "PLANNED", "ProductPlanCreated"],
  ["PLANNED", "FETCHING", "ProductFetchStarted"],
  ["FETCHING", "VERIFIED", "ProductVerified"],
  ["PLANNED", "REJECTED", "ProductRejected"],
  ["FETCHING", "REJECTED", "ProductRejected"],
  ["VERIFIED", "STAGED", "ProductStaged"],
  ["VERIFIED", "REJECTED", "ProductRejected"],
  ["STAGED", "REJECTED", "ProductRejected"],
  ["STAGED", "STARTING", "ProductStartRequested"],
  ["STARTING", "HEALTHCHECKING", "ProductStarted"],
  ["HEALTHCHECKING", "READY", "ProductActivated"],
  ["STARTING", "DRAINING", "ProductCandidateAbortRequested"],
  ["HEALTHCHECKING", "DRAINING", "ProductCandidateAbortRequested"],
  ["READY", "DEGRADED", "ProductDegraded"],
  ["DEGRADED", "HEALTHCHECKING", "ProductRecoveryStarted"],
  ["READY", "CRASHED", "ProductCrashed"],
  ["DEGRADED", "CRASHED", "ProductCrashed"],
  ["HEALTHCHECKING", "CRASHED", "ProductCrashed"],
  ["STARTING", "CRASHED", "ProductCrashed"],
  ["CRASHED", "STARTING", "ProductRestartRequested"],
  ["CRASHED", "QUARANTINED", "ProductQuarantined"],
  ["READY", "DRAINING", "ProductDrainRequested"],
  ["DEGRADED", "DRAINING", "ProductDrainRequested"],
  ["DRAINING", "STOPPED_RETAINED", "ProductStopped"],
  ["DRAINING", "QUARANTINED", "ProductQuarantined"],
  ["CRASHED", "STOPPED_RETAINED", "ProductContainmentConfirmed"],
  ["QUARANTINED", "STOPPED_RETAINED", "ProductContainmentConfirmed"],
  ["STOPPED_RETAINED", "UNINSTALLING", "ProductUninstallStarted"],
  ["UNINSTALLING", "REMOVED", "ProductUninstalled"],
  ["UNINSTALLING", "QUARANTINED", "ProductQuarantined"],
  ["PLANNED", "CANCELLED", "ProductOperationCancelled"],
  ["FETCHING", "CANCELLED", "ProductOperationCancelled"],
  ["VERIFIED", "CANCELLED", "ProductOperationCancelled"],
  ["STAGED", "CANCELLED", "ProductOperationCancelled"],
  ["STOPPED_RETAINED", "PLANNED", "ProductRollbackPlanned"],
  ["REMOVED", "PLANNED", "ProductRollbackPlanned"],
  ["QUARANTINED", "PLANNED", "ProductRecoveryPlanned"],
];

describe("v2 product lifecycle", () => {
  it("covers every §5.4 table row exactly once", () => {
    const table = new Map<string, string>();
    for (const t of TRANSITIONS) {
      const key = `${t.from}->${t.to}`;
      expect(table.has(key), `duplicate row ${key}`).toBe(false);
      table.set(key, t.event);
    }
    expect(TRANSITIONS.length).toBe(SPEC_ROWS.length);
    for (const [from, to, event] of SPEC_ROWS) {
      expect(table.get(`${from}->${to}`), `${from}->${to}`).toBe(event);
    }
  });

  it("uses only declared states and events", () => {
    const states = new Set<string>(PRODUCT_STATES);
    const events = new Set<string>(TRANSITION_EVENTS);
    for (const t of TRANSITIONS) {
      expect(states.has(t.from)).toBe(true);
      expect(states.has(t.to)).toBe(true);
      expect(events.has(t.event)).toBe(true);
      expect(t.guard.length).toBeGreaterThan(0);
    }
  });

  it("transitionFor returns the row's event or STATE_TRANSITION", () => {
    expect(transitionFor("ABSENT", "PLANNED")).toBe("ProductPlanCreated");
    expect(transitionFor("HEALTHCHECKING", "READY")).toBe("ProductActivated");
    // Unlisted transitions are STATE_TRANSITION with no side effect.
    expect(transitionFor("ABSENT", "READY")).toBe("STATE_TRANSITION");
    expect(transitionFor("READY", "ABSENT")).toBe("STATE_TRANSITION");
    expect(transitionFor("REMOVED", "READY")).toBe("STATE_TRANSITION");
    expect(transitionRow("ABSENT", "READY")).toBeUndefined();
  });

  it("declares the restart budget", () => {
    expect(RESTART_BUDGET.maxStarts).toBe(5);
    expect(RESTART_BUDGET.windowMs).toBe(60_000);
    expect(RESTART_BUDGET.delaysMs).toEqual([1000, 2000, 4000, 8000, 16000]);
  });
});
