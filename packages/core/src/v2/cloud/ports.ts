/**
 * Gateway v2 cloud — injected ports for pairing state (spec §9.3, §3.2).
 *
 * Cloud pairing never grants operator authority: the paired principal is
 * viewer-only and the remote flag is separately scoped by the local
 * `gateway.ui.remote` config grant. All persistence, the clock, provider
 * bindings, and revocation notice delivery are injected; this package
 * never opens a listener or performs network IO.
 */

import type { Id, NativeRef } from "../protocol/refs.js";
import type { StreamName } from "../protocol/sync.js";
import { newControlId, newPairCode } from "../crypto/ids.js";

export type EnrollmentState =
  | "AWAITING_PROVIDER"
  | "CONSUMED"
  | "EXPIRED";

export interface CloudEnrollment {
  readonly id: Id;
  readonly provider: string;
  readonly streams: readonly StreamName[];
  readonly remote_ui: boolean;
  readonly user_code: string;
  state: EnrollmentState;
  readonly created_ms: number;
  readonly expires_ms: number;
}

export type CloudState = "PAIRED" | "REVOKED";

export interface CloudPairing {
  readonly id: Id;
  readonly provider: string;
  readonly binding: NativeRef;
  readonly streams: readonly StreamName[];
  readonly remote_ui: boolean;
  /** Cloud pairing is viewer-only; it can never name "operator". */
  readonly role: "viewer";
  state: CloudState;
  readonly paired_ms: number;
  /** Revocation notice delivery state, once revoked. */
  remote_notice: "SENT" | "QUEUED" | null;
}

/** A pinned provider binding the operator enrolled out of band. */
export interface ProviderBinding {
  readonly id: Id;
  readonly provider: string;
}

export interface CloudPorts {
  now(): number;
  newId(): Id;
  /** Enrollment user code (Crockford base32). */
  pairCode(): string;
  /** The local `gateway.ui.remote` config grant (separately scoped). */
  uiRemoteGranted(): boolean;
  /** Pinned provider bindings by provider name. */
  providers(): ReadonlyMap<string, ProviderBinding>;
  /** Enrollment lifetime, ms (default 300000). */
  enrollmentTtlMs(): number;
  getEnrollment(id: Id): CloudEnrollment | undefined;
  putEnrollment(enrollment: CloudEnrollment): void;
  getCloud(id: Id): CloudPairing | undefined;
  putCloud(cloud: CloudPairing): void;
  /** Current pairing, if any (single active pairing). */
  currentCloud(): CloudPairing | undefined;
  /**
   * Validate a review binding for cloud.pair.complete: the review commits
   * to exactly (method, params-without-review, prior state). Absent →
   * the review must be a well-formed NativeRef.
   */
  validateReview?(method: string, params: unknown, review: unknown): boolean;
  /**
   * Deliver the remote revocation notice over the paired relay. Returns
   * true when delivered ("SENT"); false queues it ("QUEUED") — an
   * offline revoke still closes local remote sessions immediately (§9.3).
   */
  notifyRevocation(cloud: CloudPairing): Promise<boolean>;
}

export interface MemoryCloudPorts extends CloudPorts {
  readonly clock: { value: number };
  readonly enrollments: Map<Id, CloudEnrollment>;
  readonly clouds: Map<Id, CloudPairing>;
  uiRemote: boolean;
  readonly providerBindings: Map<string, ProviderBinding>;
  /** When true, notifyRevocation reports delivery ("SENT"). */
  reachable: boolean;
  reviewer?: (method: string, params: unknown, review: unknown) => boolean;
  advance(ms: number): void;
}

export function createMemoryCloudPorts(opts?: {
  now?: number;
  uiRemote?: boolean;
  providers?: readonly string[];
}): MemoryCloudPorts {
  const clock = { value: opts?.now ?? 0 };
  const enrollments = new Map<Id, CloudEnrollment>();
  const clouds = new Map<Id, CloudPairing>();
  const providerBindings = new Map<string, ProviderBinding>();
  for (const provider of opts?.providers ?? ["hosted"]) {
    providerBindings.set(provider, { id: `binding-${provider}`, provider });
  }
  const ports: MemoryCloudPorts = {
    clock,
    enrollments,
    clouds,
    uiRemote: opts?.uiRemote ?? false,
    providerBindings,
    reachable: false,
    advance(ms: number) {
      clock.value += ms;
    },
    now: () => clock.value,
    newId: () => newControlId(),
    pairCode: () => newPairCode(),
    uiRemoteGranted: () => ports.uiRemote,
    providers: () => ports.providerBindings,
    enrollmentTtlMs: () => 300_000,
    getEnrollment: (id) => enrollments.get(id),
    putEnrollment: (enrollment) => {
      enrollments.set(enrollment.id, enrollment);
    },
    getCloud: (id) => clouds.get(id),
    putCloud: (cloud) => {
      clouds.set(cloud.id, cloud);
    },
    currentCloud: () => [...clouds.values()].find((c) => c.state === "PAIRED"),
    validateReview: (method, params, review) =>
      ports.reviewer === undefined
        ? typeof review === "object" && review !== null
        : ports.reviewer(method, params, review),
    async notifyRevocation() {
      return ports.reachable;
    },
  };
  return ports;
}
