import { describe, expect, it } from "vitest";
import {
  OUTBOX_TRANSITIONS,
  STREAMS,
  STREAM_DESTINATIONS,
  SYNC_LIMITS,
  backoff,
  backoffCap,
  canOutboxTransition,
} from "./sync.js";

describe("v2 sync outbox", () => {
  it("declares all six streams with metadata default profiles", () => {
    expect(STREAMS).toEqual([
      "runs",
      "receipts",
      "lineage",
      "approvals",
      "watch",
      "mesh",
    ]);
    for (const s of STREAMS) {
      expect(STREAM_DESTINATIONS[s].profile).toBe("metadata");
      expect(STREAM_DESTINATIONS[s].destination.length).toBeGreaterThan(0);
    }
  });

  it("models the §9.2 state machine", () => {
    expect(canOutboxTransition("PENDING", "IN_FLIGHT")).toBe(true);
    expect(canOutboxTransition("IN_FLIGHT", "ACKED")).toBe(true);
    expect(canOutboxTransition("IN_FLIGHT", "RETRY")).toBe(true);
    expect(canOutboxTransition("RETRY", "IN_FLIGHT")).toBe(true);
    expect(canOutboxTransition("BLOCKED", "PENDING")).toBe(true);
    for (const from of ["PENDING", "RETRY", "IN_FLIGHT"] as const) {
      expect(canOutboxTransition(from, "BLOCKED")).toBe(true);
    }
    // ACKED is terminal and never reenters PENDING.
    expect(OUTBOX_TRANSITIONS.ACKED).toEqual([]);
    expect(canOutboxTransition("ACKED", "PENDING")).toBe(false);
    expect(canOutboxTransition("PENDING", "ACKED")).toBe(false);
  });

  it("keeps backoff within [0, min(300000, 1000*2^attempt)]", () => {
    expect(backoffCap(0)).toBe(1000);
    expect(backoffCap(8)).toBe(256000);
    expect(backoffCap(9)).toBe(300000);
    expect(backoffCap(40)).toBe(300000);
    for (let attempt = 0; attempt <= 12; attempt += 1) {
      for (let i = 0; i < 50; i += 1) {
        const v = backoff(attempt);
        const cap = Math.min(300000, 1000 * 2 ** attempt);
        expect(v).toBeGreaterThanOrEqual(0);
        expect(v).toBeLessThanOrEqual(cap);
        expect(Number.isInteger(v)).toBe(true);
      }
    }
  });

  it("declares §9.1 batch limits", () => {
    expect(SYNC_LIMITS.payloadBytes).toBe(1024 * 1024);
    expect(SYNC_LIMITS.batchEvents).toBe(1000);
    expect(SYNC_LIMITS.batchBlobs).toBe(64);
    expect(SYNC_LIMITS.batchBytes).toBe(8 * 1024 * 1024);
  });
});
