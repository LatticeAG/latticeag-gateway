/**
 * Gateway v2 sync — injected ports for the outbox engine and sync service
 * (spec §9.1–§9.2).
 *
 * Every side effect lives behind this interface: item persistence, the
 * clock, the jitter source, destination adapter lookup, the consent store,
 * and the durable per-stream pause flag. `createMemorySyncPorts()` is the
 * deterministic in-memory implementation used by tests and the CLI
 * fallback path; no port ever performs network IO itself (fetch/adapters
 * are injected).
 */

import type { Count, Id, ObjectRef } from "../protocol/refs.js";
import type {
  OutboxItem,
  SinkAck,
  StreamName,
  StreamProfile,
} from "../protocol/sync.js";
import { STREAMS } from "../protocol/sync.js";
import { newControlId } from "../crypto/ids.js";
import type { OutboxBatch, SinkAdapter } from "./sinks.js";

/**
 * Consent record bound at enable time (§9.1): destination, workspace,
 * cohort, object inclusion, disclosure profile, and the selected native
 * capabilities. `from:"now"` is resolved once at consent commit — the
 * stored record always carries the resolved cursor.
 */
export interface StreamConsent {
  /** Disabled streams produce no outbox work. */
  readonly enabled: boolean;
  /** Config-level pause flag (mirrors the durable pause flag). */
  readonly paused: boolean;
  readonly profile: StreamProfile;
  /** include_objects stream flag — allows object bodies under "full". */
  readonly include_objects: boolean;
  readonly cohort: string;
  /** Resolved start cursor captured at consent commit. */
  readonly from: string;
  /** Pinned destination adapter/binding id. */
  readonly destination: Id;
  /** Consent revision recorded on every item. */
  readonly revision: Count;
  /** Disclosure consent flags (§9.1): even hashes/IDs/object-existence
   *  information require consent; all default false (deny). */
  readonly hashes?: boolean;
  readonly ids?: boolean;
  readonly existence?: boolean;
  /** E48: explicit personal-data export consent. */
  readonly personalData?: boolean;
  /** E48: destination deletion/retention contract is deletion-capable. */
  readonly deletionContract?: boolean;
  /** Explicitly allowed object digests for the "full" profile. */
  readonly allowedObjects?: readonly string[];
  /** Extra redaction keys merged over the default set (case-insensitive). */
  readonly redactKeys?: readonly string[];
  /** include_raw_text — false excludes raw prompt/completion/tool text. */
  readonly includeRawText?: boolean;
}

/** Durable outbox item store (registry projection behind §8 indexes). */
export interface OutboxStore {
  all(): OutboxItem[];
  get(id: Id): OutboxItem | undefined;
  put(item: OutboxItem): void;
}

export interface SyncPorts {
  /** Injectable clock (ms). */
  now(): number;
  /** Control-id mint (defaults to newControlId). */
  newId(): Id;
  /** Uniform [0,1) source for full-jitter backoff. */
  random(): number;
  /**
   * Cooperative wait used by flush/pump loops. Implementations may advance
   * a virtual clock (memory ports do) or wrap setTimeout.
   */
  sleep(ms: number): Promise<void>;
  /** Durable item persistence. */
  readonly store: OutboxStore;
  /**
   * Immutable payload object persistence (§8 objects/sha256/…): redacted
   * payload bytes are created before the item becomes sendable.
   */
  putObject?(ref: ObjectRef, bytes: string): void;
  /** Consent store: undefined or enabled:false means the stream is off. */
  consent(stream: StreamName): StreamConsent | undefined;
  /**
   * Destination adapter lookup by pinned binding id. An absent adapter is
   * a stream BLOCKED / CAP_ADAPTER_UNAVAILABLE — endpoints are never
   * invented (§9.2).
   */
  sink(destination: Id): SinkAdapter | undefined;
  /** Durable per-stream pause flag — orthogonal to item state (§9.2). */
  isPaused(stream: StreamName): boolean;
  setPaused(stream: StreamName, paused: boolean): void;
  /** Durable last-ACKed remote cut per stream (flush `through` baseline). */
  ackedThrough(stream: StreamName): string | undefined;
  setAckedThrough(stream: StreamName, through: string): void;
  /**
   * Whether the daemon's admitted sync cut is provably known (§9.2 /
   * §6.1 exit 5). "unknown" plus admitted work is nonempty, never success.
   */
  daemonStatus(): "known" | "unknown";
  /**
   * Validate retained native ACK bytes under the pinned destination
   * binding before `stored=true` is trusted (§9.1). Defaults to accept.
   */
  validateAck?(batch: OutboxBatch, ack: SinkAck): boolean;
}

/** In-memory SyncPorts with a manual clock — deterministic tests. */
export interface MemorySyncPorts extends SyncPorts {
  /** Manual clock; advance with `advance(ms)` or via `sleep`. */
  readonly clock: { value: number };
  /** All persisted items by id. */
  readonly items: Map<Id, OutboxItem>;
  /** Consent records by stream. */
  readonly consents: Map<StreamName, StreamConsent>;
  /** Destination adapters by binding id. */
  readonly sinks: Map<Id, SinkAdapter>;
  /** Durable per-stream pause flags. */
  readonly paused: Set<StreamName>;
  /** Durable last-ACKed cut per stream. */
  readonly throughMarks: Map<StreamName, string>;
  /** Immutable redacted payload bytes by digest. */
  readonly objects: Map<string, string>;
  /** Daemon-cut status flag. */
  daemon: "known" | "unknown";
  /** Advance the manual clock. */
  advance(ms: number): void;
}

export function createMemorySyncPorts(
  opts?: { now?: number; realtimeSleep?: boolean },
): MemorySyncPorts {
  const clock = { value: opts?.now ?? 0 };
  const items = new Map<Id, OutboxItem>();
  const consents = new Map<StreamName, StreamConsent>();
  const sinks = new Map<Id, SinkAdapter>();
  const paused = new Set<StreamName>();
  const throughMarks = new Map<StreamName, string>();
  const objects = new Map<string, string>();
  const ports: MemorySyncPorts = {
    clock,
    items,
    consents,
    sinks,
    paused,
    throughMarks,
    objects,
    daemon: "known",
    now: () => clock.value,
    newId: () => newControlId(),
    random: () => Math.random(),
    advance(ms: number) {
      clock.value += ms;
    },
    async sleep(ms: number) {
      if (opts?.realtimeSleep === true) {
        if (ms > 0) {
          await new Promise<void>((resolve) => setTimeout(resolve, ms));
        }
        return;
      }
      // Deterministic: a cooperative wait advances the manual clock.
      clock.value += ms;
    },
    store: {
      all: () => [...items.values()],
      get: (id) => items.get(id),
      put: (item) => {
        items.set(item.id, item);
      },
    },
    putObject: (ref, bytes) => {
      objects.set(ref.digest, bytes);
    },
    consent: (stream) => consents.get(stream),
    sink: (destination) => sinks.get(destination),
    isPaused: (stream) =>
      paused.has(stream) || consents.get(stream)?.paused === true,
    setPaused: (stream, value) => {
      if (value) paused.add(stream);
      else paused.delete(stream);
      const consent = consents.get(stream);
      if (consent !== undefined) {
        consents.set(stream, { ...consent, paused: value });
      }
    },
    ackedThrough: (stream) => throughMarks.get(stream),
    setAckedThrough: (stream, through) => {
      throughMarks.set(stream, through);
    },
    daemonStatus: () => ports.daemon,
  };
  return ports;
}

/** Consent helper: a fully-consented enabled stream for tests. */
export function streamConsent(
  overrides?: Partial<StreamConsent> & { stream?: StreamName },
): StreamConsent {
  const { stream: _stream, ...rest } = overrides ?? {};
  return {
    enabled: true,
    paused: false,
    profile: "metadata",
    include_objects: false,
    cohort: "private",
    from: "0",
    destination: "dest1",
    revision: "1",
    hashes: true,
    ids: true,
    existence: true,
    ...rest,
  };
}

/** Enable every stream in a consent map with the same overrides. */
export function consentAll(
  consents: Map<StreamName, StreamConsent>,
  overrides?: Partial<StreamConsent>,
): void {
  for (const stream of STREAMS) {
    consents.set(stream, streamConsent(overrides));
  }
}
