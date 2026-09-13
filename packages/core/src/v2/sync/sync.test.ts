/**
 * Gateway v2 sync — outbox engine, disclosure, sinks, and §3.3 service
 * shapes. Covers TV-GW-29..33, TV-GW-63, TV-GW-64, pause/in-flight
 * semantics, and bounded full-jitter backoff (spec §9.1–§9.2).
 */
import { describe, expect, it } from "vitest";
import { H, J, F } from "@latticeag/testkit";
import type { JsonObject, NativeRef } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type { OutboxItem, StreamName } from "../protocol/sync.js";
import { STREAMS, SYNC_LIMITS, backoffCap } from "../protocol/sync.js";
import { canonicalJson } from "../crypto/canonical.js";
import { OutboxEngine } from "./outbox.js";
import type { EnqueueArgs } from "./outbox.js";
import {
  createMemorySyncPorts,
  streamConsent,
} from "./ports.js";
import type { MemorySyncPorts, StreamConsent } from "./ports.js";
import {
  MemoryProofDestination,
  MemoryVekInbox,
  SinkError,
  createMemorySink,
  createProofImportSink,
  createVekInboxSink,
} from "./sinks.js";
import type { OutboxBatch, SinkAdapter } from "./sinks.js";
import {
  createSyncService,
  makeReviewValidator,
  reviewBindingHash,
} from "./service.js";
import type { SyncServicePorts } from "./service.js";

const THROUGH = F.cursor as string; // "c0000000000000001:7"

function srcRef(objectId: string, commitment: string | null = null): NativeRef {
  return {
    profile: "fixture.event/1",
    namespace: "fixture",
    object_id: objectId,
    commitment,
    raw_sha256: H(`fixture/${objectId}/${commitment ?? ""}`),
    bytes: "10",
  };
}

function args(overrides: Partial<EnqueueArgs> & { stream: StreamName }): EnqueueArgs {
  return {
    source: srcRef(overrides.source?.object_id ?? "evt1", overrides.source?.commitment ?? null),
    envelope: { kind: "fixture", n: 1 },
    through: THROUGH,
    ...overrides,
  };
}

function payloadOf(ports: MemorySyncPorts, item: OutboxItem): string {
  const bytes = ports.objects.get(item.payload.digest);
  expect(bytes).toBeTypeOf("string");
  return bytes!;
}

/** Let every queued microtask + the current send settle. */
function tick(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/** Drive the engine until the item leaves PENDING/IN_FLIGHT/RETRY. */
async function drive(
  engine: OutboxEngine,
  streams: readonly StreamName[],
  timeout = 60_000,
) {
  return engine.flush(streams, timeout);
}

describe("TV-GW-29 receipts-only consent + redaction", () => {
  it("sends only the consented stream and never exports secret values", async () => {
    const ports = createMemorySyncPorts();
    const sink = createMemorySink();
    ports.sinks.set("proof-native-import", sink);
    ports.consents.set(
      "receipts",
      streamConsent({ destination: "proof-native-import" }),
    );
    const engine = new OutboxEngine(ports);

    // Non-consented streams produce no work at all.
    for (const stream of ["runs", "approvals", "lineage", "watch", "mesh"] as const) {
      expect(engine.enqueue(args({ stream }))).toBeNull();
    }
    expect(ports.items.size).toBe(0);

    const envelope = {
      kind: "receipt",
      action: "action1",
      authorization: "Bearer secret-token-value-123",
      nested: { Api_Key: "ak-xyzzy-secret", note: "ok" },
      list: [{ password: "pw-secret-9" }],
    };
    const before = structuredClone(envelope);
    const item = engine.enqueue(
      args({ stream: "receipts", envelope }),
    )!;
    expect(item).not.toBeNull();
    expect(item.state).toBe("PENDING");
    // Immutable redacted payload bytes exist before the item is sendable.
    const bytes = payloadOf(ports, item);
    expect(bytes).not.toContain("secret-token-value-123");
    expect(bytes).not.toContain("ak-xyzzy-secret");
    expect(bytes).not.toContain("pw-secret-9");
    expect(bytes).toContain("[REDACTED]");

    const res = await drive(engine, ["receipts"]);
    expect(res.pending).toBe(0);
    expect(ports.items.get(item.id)?.state).toBe("ACKED");
    expect(sink.attempts.length).toBe(1);
    expect(sink.sent.length).toBe(1);
    // Wire bytes equal the persisted immutable payload bytes.
    const wire = sink.sent[0]!.items[0]!;
    expect(ports.objects.get(wire.payload.digest)).toBe(bytes);
    // The signed source envelope was never mutated in place.
    expect(envelope).toEqual(before);
  });
});

describe("TV-GW-30 identical retry after timeout", () => {
  it("does not resend an ACKed batch; resends identical bytes after timeout", async () => {
    const ports = createMemorySyncPorts();
    const sink = createMemorySink();
    ports.sinks.set("vekinbox-compatible", sink);
    ports.consents.set(
      "approvals",
      streamConsent({ destination: "vekinbox-compatible" }),
    );
    const engine = new OutboxEngine(ports);

    const a = engine.enqueue(
      args({ stream: "approvals", source: srcRef("cardA", H("a")) }),
    )!;
    await drive(engine, ["approvals"]);
    expect(a.state).toBe("ACKED");
    expect(sink.attempts.length).toBe(1);

    sink.failWith.push("timeout");
    const b = engine.enqueue(
      args({ stream: "approvals", source: srcRef("cardB", H("b")) }),
    )!;
    const res = await drive(engine, ["approvals"], 120_000);
    expect(res.pending).toBe(0);
    expect(b.state).toBe("ACKED");

    // Three attempts total: batch1 (acked), batch2 timeout, batch2 retry.
    expect(sink.attempts.length).toBe(3);
    expect(sink.sent.length).toBe(2); // two logical deliveries remote-side
    const [first, timedOut, retried] = sink.attempts;
    expect(first!.hash).not.toBe(timedOut!.hash);
    // Identical retry: same batch hash and same member payload bytes.
    expect(retried!.hash).toBe(timedOut!.hash);
    expect(retried!.items.map((i) => i.payload.digest)).toEqual(
      timedOut!.items.map((i) => i.payload.digest),
    );
    // The ACKed batch-1 item was never a member of a later send.
    expect(timedOut!.items.map((i) => i.id)).toEqual([b.id]);
  });
});

describe("TV-GW-31 lost commit ACK recovery", () => {
  it("resolves the committed stage through import.get — no second import", async () => {
    const ports = createMemorySyncPorts();
    const dest = new MemoryProofDestination();
    dest.dropAcks = true; // durable commit, lost ACK
    ports.sinks.set("proof-native-import", createProofImportSink(dest));
    ports.consents.set(
      "receipts",
      streamConsent({ destination: "proof-native-import" }),
    );
    const engine = new OutboxEngine(ports);

    const item = engine.enqueue(args({ stream: "receipts" }))!;
    const res = await drive(engine, ["receipts"], 120_000);
    expect(res.pending).toBe(0);
    expect(item.state).toBe("ACKED");
    // One stage, one durable commit — import.get recovered the lost ACK.
    expect(dest.stages.size).toBe(1);
    expect(dest.commits).toBe(1);
    expect(item.remote_stage).toBe("stage1");
  });
});

describe("TV-GW-32 slot conflict retention", () => {
  it("retains both signed candidates and marks the slot CONFLICTED", async () => {
    const ports = createMemorySyncPorts();
    const dest = new MemoryProofDestination();
    ports.sinks.set("proof-native-import", createProofImportSink(dest));
    ports.consents.set(
      "receipts",
      streamConsent({ destination: "proof-native-import" }),
    );
    const engine = new OutboxEngine(ports);

    // Same (namespace, object_id) slot, different signed bodies.
    const a = engine.enqueue(
      args({ stream: "receipts", source: srcRef("slotX", H("body-a")) }),
    )!;
    const b = engine.enqueue(
      args({ stream: "receipts", source: srcRef("slotX", H("body-b")) }),
    )!;
    expect(a.id).not.toBe(b.id);
    await drive(engine, ["receipts"], 120_000);

    const slot = "fixture/slotX";
    expect(dest.slots.candidates(slot).length).toBe(2);
    expect(dest.slots.isConflicted(slot)).toBe(true);
    // No wall-clock last-write-wins: neither item claims a clean cut.
    expect(a.state).toBe("BLOCKED");
    expect(b.state).toBe("BLOCKED");
    expect(engine.blockedCodeOf(a.id)).toBe("OBJECT_CONFLICT");
  });
});

describe("TV-GW-33 approvals CAS", () => {
  it("deny at rev 1 then approve at rev 1 → REVISION_CONFLICT", async () => {
    const ports = createMemorySyncPorts();
    const inbox = new MemoryVekInbox();
    ports.sinks.set("vekinbox-compatible", createVekInboxSink(inbox));
    ports.consents.set(
      "approvals",
      streamConsent({ destination: "vekinbox-compatible" }),
    );
    const engine = new OutboxEngine(ports);

    const deny = engine.enqueue(
      args({
        stream: "approvals",
        source: srcRef("card1", H("deny")),
        envelope: { card_id: "card1", action: "deny" },
      }),
    )!;
    await drive(engine, ["approvals"]);
    expect(deny.state).toBe("ACKED");
    // E07 ack shape preserved: {card_id, revision, stored}.
    expect(inbox.cards.get("card1")?.revision).toBe(1n);

    const approve = engine.enqueue(
      args({
        stream: "approvals",
        source: srcRef("card1", H("approve")),
        envelope: { card_id: "card1", action: "approve" },
      }),
    )!;
    await drive(engine, ["approvals"], 120_000);
    expect(approve.state).toBe("BLOCKED");
    expect(engine.blockedCodeOf(approve.id)).toBe("REVISION_CONFLICT");
    // The denied card was never overwritten.
    expect(inbox.cards.get("card1")?.revision).toBe(1n);
  });
});

describe("TV-GW-63 absent adapter", () => {
  it("blocks all three items CAP_ADAPTER_UNAVAILABLE and sends zero frames", async () => {
    const ports = createMemorySyncPorts();
    const sentinel = createMemorySink(); // registered nowhere — must see nothing
    ports.consents.set("runs", streamConsent({ destination: "no-such-adapter" }));
    const engine = new OutboxEngine(ports);

    const items = [
      engine.enqueue(args({ stream: "runs", source: srcRef("i1") }))!,
      engine.enqueue(args({ stream: "runs", source: srcRef("i2") }))!,
      engine.enqueue(args({ stream: "runs", source: srcRef("i3") }))!,
    ];
    const res = await drive(engine, ["runs"], 120_000);
    expect(res.blocked).toBe(3);
    for (const item of items) {
      expect(item.state).toBe("BLOCKED");
      expect(engine.blockedCodeOf(item.id)).toBe("CAP_ADAPTER_UNAVAILABLE");
    }
    expect(sentinel.attempts.length).toBe(0);
  });
});

describe("TV-GW-64 personal receipt denial", () => {
  it("denies CIS/personal export before any object or digest leaves", () => {
    const ports = createMemorySyncPorts();
    ports.consents.set(
      "receipts",
      streamConsent({ destination: "proof-native-import" }),
    );
    const engine = new OutboxEngine(ports);
    const envelope = { kind: "receipt", receipt_class: "cis", person: "p1" };
    let error: unknown;
    try {
      engine.enqueue(
        args({ stream: "receipts", envelope, personal: true }),
      );
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(RpcError);
    expect((error as RpcError).code).toBe("POLICY_DENIED");
    // Denial raised before export: no item, no payload object, no digest.
    expect(ports.items.size).toBe(0);
    expect(ports.objects.size).toBe(0);
  });

  it("allows personal export only with both E48 consent flags", async () => {
    const ports = createMemorySyncPorts();
    const sink = createMemorySink();
    ports.sinks.set("proof-native-import", sink);
    ports.consents.set(
      "receipts",
      streamConsent({
        destination: "proof-native-import",
        personalData: true,
        deletionContract: true,
      }),
    );
    const engine = new OutboxEngine(ports);
    const item = engine.enqueue(
      args({ stream: "receipts", personal: true }),
    )!;
    await drive(engine, ["receipts"]);
    expect(item.state).toBe("ACKED");
  });
});

describe("pause/resume semantics", () => {
  it("pause blocks new sends while an in-flight send completes", async () => {
    const ports = createMemorySyncPorts();
    const engine = new OutboxEngine(ports);
    const pausing: SinkAdapter = {
      async send(batch: OutboxBatch) {
        engine.pause(["approvals"]); // pause mid-flight
        return {
          stored: true,
          batch: batch.hash,
          through: batch.through,
          conflicts: [],
          native: {
            profile: "fixture.ack/1",
            namespace: "fixture",
            object_id: "ack1",
            commitment: null,
            raw_sha256: batch.hash,
            bytes: "0",
          },
        };
      },
    };
    ports.sinks.set("vekinbox-compatible", pausing);
    ports.consents.set(
      "approvals",
      streamConsent({ destination: "vekinbox-compatible" }),
    );

    const first = engine.enqueue(
      args({ stream: "approvals", source: srcRef("c1", H("1")) }),
    )!;
    const res = await drive(engine, ["approvals"]);
    // The in-flight send finished and its ACK was recorded.
    expect(first.state).toBe("ACKED");
    expect(res.pending).toBe(0);

    // New work does not send while paused.
    const second = engine.enqueue(
      args({ stream: "approvals", source: srcRef("c2", H("2")) }),
    )!;
    engine.pump();
    expect(second.state).toBe("PENDING");
    const res2 = await drive(engine, ["approvals"], 5_000);
    expect(second.state).toBe("PENDING");
    expect(res2.pending).toBe(1);

    // Resume re-checks consent and drains.
    expect(engine.resume(["approvals"])).toEqual(["approvals"]);
    await drive(engine, ["approvals"]);
    expect(second.state).toBe("ACKED");
  });

  it("resume skips a disabled stream", () => {
    const ports = createMemorySyncPorts();
    const engine = new OutboxEngine(ports);
    engine.pause(["runs"]);
    expect(engine.resume(["runs"])).toEqual([]); // no consent → not resumed
    expect(ports.isPaused("runs")).toBe(true);
  });
});

describe("bounded full-jitter backoff", () => {
  it("delays stay within [0, min(300000, 1000*2^attempt)] and honor Retry-After", async () => {
    const ports = createMemorySyncPorts();
    ports.random = () => 0; // deterministic: jitter floor 0
    const sink = createMemorySink();
    ports.sinks.set("vekinbox-compatible", sink);
    ports.consents.set(
      "approvals",
      streamConsent({ destination: "vekinbox-compatible" }),
    );
    const engine = new OutboxEngine(ports);
    const item = engine.enqueue(args({ stream: "approvals" }))!;

    // Attempt 1 fails with an authenticated Retry-After floor of 5s.
    sink.failWith.push(
      new SinkError("NETWORK_UNAVAILABLE", "slow down", {
        retryable: true,
        retryAfterMs: 5_000,
      }),
    );
    engine.pump();
    await tick();
    expect(item.state).toBe("RETRY");
    expect(item.attempts).toBe(1);
    expect(item.next_attempt_ms - ports.now()).toBe(5_000);

    // Attempt 2 fails without Retry-After: jitter 0 with random()=0.
    sink.failWith.push(
      new SinkError("NETWORK_UNAVAILABLE", "again", { retryable: true }),
    );
    ports.advance(5_000);
    engine.pump();
    await tick();
    expect(item.state).toBe("RETRY");
    expect(item.attempts).toBe(2);
    expect(item.next_attempt_ms - ports.now()).toBe(0);

    // Bounds across attempts with the default random source.
    ports.random = Math.random;
    for (let attempt = 3; attempt <= 6; attempt += 1) {
      sink.failWith.push(
        new SinkError("NETWORK_UNAVAILABLE", "flaky", { retryable: true }),
      );
      ports.advance(Number(item.next_attempt_ms - ports.now()) + 1);
      const before = ports.now();
      engine.pump();
      await tick();
      const delay = item.next_attempt_ms - before;
      expect(delay).toBeGreaterThanOrEqual(0);
      expect(delay).toBeLessThanOrEqual(backoffCap(attempt - 1));
      expect(delay).toBeLessThanOrEqual(SYNC_LIMITS.backoffCapMs);
    }
  });
});

describe("failOnSyncStatus (exit-5 gate)", () => {
  it("reports empty/unknown per §6.2", async () => {
    const ports = createMemorySyncPorts();
    ports.sinks.set("dest1", createMemorySink());
    ports.consents.set("runs", streamConsent({}));
    const engine = new OutboxEngine(ports);

    expect(engine.failOnSyncStatus("run1")).toEqual({
      empty: true,
      unknown: false,
    });
    const item = engine.enqueue(args({ stream: "runs", run: "run1" }))!;
    // Admitted but unsent → nonempty.
    expect(engine.failOnSyncStatus("run1")).toEqual({
      empty: false,
      unknown: false,
    });
    await drive(engine, ["runs"]);
    expect(item.state).toBe("ACKED");
    expect(engine.failOnSyncStatus("run1")).toEqual({
      empty: true,
      unknown: false,
    });
  });

  it("unknowable daemon cut plus admitted work is never success", () => {
    const ports = createMemorySyncPorts();
    ports.consents.set("runs", streamConsent({}));
    const engine = new OutboxEngine(ports);
    engine.enqueue(args({ stream: "runs", run: "run9" }));
    ports.daemon = "unknown";
    const status = engine.failOnSyncStatus("run9");
    expect(status.empty).toBe(false);
    expect(status.unknown).toBe(true);
  });
});

describe("sync service §3.3 shapes", () => {
  function servicePorts(): SyncServicePorts & MemorySyncPorts {
    const ports = createMemorySyncPorts() as MemorySyncPorts &
      Partial<SyncServicePorts>;
    let revision = "0";
    let paused = false;
    let doc: JsonObject | null = null;
    ports.syncPaused = () => paused || ports.paused.size > 0;
    ports.syncRevision = () => revision;
    ports.applySync = (document, next) => {
      doc = document;
      revision = next;
      paused = document.paused === true;
    };
    ports.cloud = () => null;
    ports.validateReview = makeReviewValidator("operator1", F.now + 300_000);
    void doc;
    return ports as SyncServicePorts & MemorySyncPorts;
  }

  const syncDoc = (): JsonObject => ({
    enabled: true,
    paused: false,
    cloud: null,
    streams: Object.fromEntries(
      STREAMS.map((s) => [
        s,
        {
          enabled: s === "runs",
          paused: false,
          profile: "metadata",
          include_objects: false,
          cohort: "private",
          from: "now",
        },
      ]),
    ) as JsonObject["streams"],
  });

  it("status/pause/resume/configure/flush shapes", async () => {
    const ports = servicePorts();
    const service = createSyncService(ports);

    const status = await service.status({});
    expect(status.paused).toBe(false);
    expect(status.cloud).toBeNull();
    for (const stream of STREAMS) {
      expect(Object.keys(status.streams[stream]).sort()).toEqual(
        ["acked", "blocked", "cohort", "in_flight", "pending", "profile"].sort(),
      );
    }

    expect(await service.pause({ streams: ["runs"] })).toEqual({
      paused: ["runs"],
    });
    ports.consents.set("runs", streamConsent({}));
    expect(await service.resume({ streams: ["runs"] })).toEqual({
      resumed: ["runs"],
    });

    const doc = syncDoc();
    const sansReview = { expected_revision: "0", sync: doc };
    const review = reviewBindingHash(
      "sync.configure",
      sansReview,
      "operator1",
      F.now + 300_000,
    ) as unknown as NativeRef;
    expect(
      await service.configure({
        expected_revision: "0",
        sync: doc,
        review,
      }),
    ).toEqual({ revision: "1" });
    // CAS conflict on a stale revision.
    await expect(
      service.configure({ expected_revision: "0", sync: doc, review }),
    ).rejects.toMatchObject({ code: "REVISION_CONFLICT" });

    const flushed = await service.flush({ streams: ["runs"], timeout_ms: 0 });
    expect(flushed).toEqual({ through: { runs: "0" }, pending: 0, blocked: 0 });
  });

  it("rejects malformed stream names and bad timeouts", async () => {
    const ports = servicePorts();
    const service = createSyncService(ports);
    await expect(
      service.pause({ streams: ["bogus" as StreamName] }),
    ).rejects.toMatchObject({ code: "SCHEMA_INVALID" });
    await expect(
      service.flush({ streams: ["runs"], timeout_ms: 300_001 }),
    ).rejects.toMatchObject({ code: "SCHEMA_INVALID", field: "timeout_ms" });
  });
});

describe("atomic enqueue commit", () => {
  it("a throwing source-event hook leaves no sendable item", () => {
    const ports = createMemorySyncPorts();
    ports.consents.set("runs", streamConsent({}));
    const engine = new OutboxEngine(ports);
    expect(() =>
      engine.enqueue(
        args({
          stream: "runs",
          commit: () => {
            throw new Error("source commit failed");
          },
        }),
      ),
    ).toThrow("source commit failed");
    expect(ports.items.size).toBe(0);
    // Payload bytes were prepared but the intent was never persisted.
    expect(ports.objects.size).toBe(1);
  });
});

describe("disclosure profiles", () => {
  function projected(
    profile: StreamConsent["profile"],
    consent: Partial<StreamConsent> = {},
    extra: Partial<EnqueueArgs> = {},
  ): { ports: MemorySyncPorts; item: OutboxItem } {
    const ports = createMemorySyncPorts();
    ports.consents.set(
      "receipts",
      streamConsent({ destination: "dest1", profile, ...consent }),
    );
    const engine = new OutboxEngine(ports);
    const item = engine.enqueue(args({ stream: "receipts", ...extra }))!;
    return { ports, item };
  }

  it("metadata marks referenced objects WITHHELD", () => {
    const { ports, item } = projected("metadata", {}, {
      objects: { [H("obj1")]: { data: 1 } },
    });
    const parsed = JSON.parse(payloadOf(ports, item)) as {
      objects: Record<string, unknown>;
      withheld: Array<{ digest?: string; availability: string }>;
    };
    expect(parsed.objects).toEqual({});
    expect(parsed.withheld).toEqual([
      { digest: H("obj1"), availability: "WITHHELD" },
    ]);
  });

  it("full exports only allowlisted objects and denies signed secrets", () => {
    const { ports, item } = projected(
      "full",
      { include_objects: true, allowedObjects: [H("obj1")] },
      { objects: { [H("obj1")]: { data: 1 }, [H("obj2")]: { data: 2 } } },
    );
    const parsed = JSON.parse(payloadOf(ports, item)) as {
      objects: Record<string, unknown>;
    };
    expect(Object.keys(parsed.objects)).toEqual([H("obj1")]);

    const deniedPorts = createMemorySyncPorts();
    deniedPorts.consents.set(
      "receipts",
      streamConsent({ destination: "dest1", profile: "full" }),
    );
    const engine = new OutboxEngine(deniedPorts);
    expect(() =>
      engine.enqueue(
        args({
          stream: "receipts",
          signed: true,
          envelope: { sig: "abc", token: "tok-secret-1234" },
        }),
      ),
    ).toThrow(RpcError);
    expect(deniedPorts.items.size).toBe(0);
  });

  it("canonical payload bytes are stable and bounded", () => {
    const { ports, item } = projected("metadata");
    const bytes = payloadOf(ports, item);
    expect(bytes).toBe(canonicalJson(JSON.parse(bytes)));
    expect(item.payload.bytes).toBe(String(Buffer.byteLength(bytes, "utf8")));
  });
});
