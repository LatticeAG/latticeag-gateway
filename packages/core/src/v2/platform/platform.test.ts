/**
 * Platform service tests — the §3.3 exchanges plus the listed edge cases,
 * run against the in-memory `PlatformPorts` implementation.
 *
 * Fixture values come from @latticeag/testkit (F, J, H, history, sealProof,
 * origin/auditor keys). The deterministic clock is `now = 1789257600000`;
 * the audit writer uses the fixture `auditor` key so emitted Proof events
 * are byte-identical to the spec harness's `history()` output.
 */
import { describe, expect, it } from "vitest";
import { Buffer } from "node:buffer";
import {
  F,
  H,
  J,
  auditor,
  blob,
  history,
  now,
  observation,
  origin,
  ref,
  scrub,
  token,
} from "@latticeag/testkit";
import type { NativeRef } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import {
  sealProofEvent,
  proofBody,
  verifyProofEvent,
} from "../crypto/proof.js";
import {
  createMemoryPlatformPorts,
  type MemoryPlatformPorts,
  type ServiceContext,
} from "./testing.js";
import {
  createPlatformServices,
  type PlatformServices,
} from "./index.js";
import { emitAuditReceipt } from "./audit.js";
import { sessionIsLive } from "./sessions.js";

const OPERATOR: ServiceContext = {
  principal: { id: "operator1", role: "local_operator" },
};
const AGENT_PEER1: ServiceContext = {
  principal: { id: "peer1", role: "agent" },
};

/** Enroll src1 (fixture origin key) to the socket operator principal. */
function seedSrc1(ports: MemoryPlatformPorts, owner = "operator1"): void {
  ports.store.seedSource({
    source: "src1",
    key_id: origin.material.id,
    public: origin.material.public,
    owner,
  });
}

function seededPorts(
  opts: Parameters<typeof createMemoryPlatformPorts>[0] = {},
): { ports: MemoryPlatformPorts; svc: PlatformServices } {
  const ports = createMemoryPlatformPorts({
    now,
    workspace: "ws1",
    instance: "gw1",
    auditKey: auditor.secret,
    ...opts,
  });
  seedSrc1(ports);
  ports.store.seedConfig(F.config2, "1");
  return { ports, svc: createPlatformServices(ports, OPERATOR) };
}

/** Publish F.events[i] under the caller's enrolled src1 identity. */
async function publishFixtureEvent(
  svc: PlatformServices,
  i: number,
): Promise<{ cursor: string; durable: boolean; duplicate: boolean }> {
  return svc.events.publish({
    profile: "proof-evidence/1",
    topic: "telemetry",
    producer: "src1",
    seq: String(i + 1),
    record: blob(J(F.events[i])),
  });
}

async function publishAllFixtureEvents(svc: PlatformServices): Promise<void> {
  for (let i = 0; i < F.events.length; i += 1) {
    await publishFixtureEvent(svc, i);
  }
}

function errCode(e: unknown): string {
  return e instanceof RpcError ? e.code : `non-rpc:${String(e)}`;
}

async function expectCode(fn: () => Promise<unknown>, code: string) {
  try {
    await fn();
  } catch (e) {
    expect(errCode(e)).toBe(code);
    return;
  }
  expect.unreachable(`expected ${code}`);
}

// ── daemon ───────────────────────────────────────────────────────────────

describe("daemon", () => {
  it("hello returns the exact §3.3 result", async () => {
    const { svc } = seededPorts();
    const result = await svc.daemon.hello({
      profiles: ["@latticeag/events@0.1.0", "proof-evidence/1"],
      interfaces: "interfaces/1",
    });
    expect(result).toEqual({
      protocol: "gateway-control/2",
      profiles: ["@latticeag/events@0.1.0", "proof-evidence/1"],
      interfaces: "interfaces/1",
      mesh: { available: false, code: "CAP_ADAPTER_UNAVAILABLE" },
    });
  });

  it("hello rejects when no required profile intersects", async () => {
    const { svc } = seededPorts();
    await expectCode(
      () =>
        svc.daemon.hello({
          profiles: ["unknown/9"],
          interfaces: "interfaces/1",
        }),
      "SCHEMA_UNSUPPORTED",
    );
  });

  it("status returns the exact §3.3 result", async () => {
    const { svc } = seededPorts();
    expect(await svc.daemon.status({})).toEqual({
      instance: "gw1",
      state: "READY",
      config_revision: "1",
      products: 0,
      peers: 0,
      ui: "http://127.0.0.1:9848",
    });
  });

  it("stop returns DRAINING and schedules the stop callback", async () => {
    let stopped = -1;
    const { svc, ports } = seededPorts({
      onStop: (g) => {
        stopped = g;
      },
    });
    await expect(svc.daemon.stop({ grace_ms: 10000 })).resolves.toEqual({
      state: "DRAINING",
    });
    // The durable response precedes the scheduled shutdown.
    await new Promise((r) => setTimeout(r, 20));
    expect(stopped).toBe(10000);
    expect(await ports.store.registry.kvGet("daemon:state")).toBe("DRAINING");
    await expectCode(() => svc.daemon.stop({ grace_ms: 40000 }), "SCHEMA_INVALID");
    await expectCode(() => svc.daemon.stop({ grace_ms: -1 }), "SCHEMA_INVALID");
  });
});

// ── config ───────────────────────────────────────────────────────────────

/** The §3.3/harness review rewrite over params without `review`. */
function reviewFor(method: string, params: Record<string, unknown>): string {
  return H(J({ method, params, operator: "operator1", expires_ms: now + 300000 }));
}

describe("config", () => {
  it("get returns revision 1 and the redacted document", async () => {
    const { svc } = seededPorts();
    const result = await svc.config.get({});
    expect(result).toEqual({ revision: "1", document: F.config2 });
  });

  it("get redacts inline credential material but keeps *_env names", async () => {
    const { svc, ports } = seededPorts();
    const doc = JSON.parse(JSON.stringify(F.config2)) as Record<string, unknown>;
    (doc.adapters as Record<string, unknown>).rogue = {
      enabled: true,
      api_key: "sk-live-material",
      base_url_env: "ROGUE_URL",
    };
    ports.store.seedConfig(doc, "1");
    const result = await svc.config.get({});
    const adapters = (result.document as Record<string, unknown>).adapters as Record<
      string,
      Record<string, unknown>
    >;
    expect(adapters.rogue!.api_key).toBe("[redacted]");
    expect(adapters.rogue!.base_url_env).toBe("ROGUE_URL");
  });

  it("validate accepts F.config2 and reports errors for bad docs", async () => {
    const { svc } = seededPorts();
    expect(await svc.config.validate({ document: F.config2 })).toEqual({
      valid: true,
      errors: [],
    });
    const bad = JSON.parse(JSON.stringify(F.config2)) as Record<string, unknown>;
    delete bad.gateway;
    const result = await svc.config.validate({ document: bad as never });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("apply with the recomputed review yields revision 2", async () => {
    const { svc } = seededPorts();
    const review = reviewFor("config.apply", {
      expected_revision: "1",
      document: F.config2,
    });
    await expect(
      svc.config.apply({
        expected_revision: "1",
        document: F.config2,
        review: review as unknown as NativeRef,
      }),
    ).resolves.toEqual({ revision: "2", restart_required: false });
  });

  it("apply rejects a stale expected_revision and a wrong review", async () => {
    const { svc } = seededPorts();
    const review = reviewFor("config.apply", {
      expected_revision: "1",
      document: F.config2,
    });
    await expectCode(
      () =>
        svc.config.apply({
          expected_revision: "9",
          document: F.config2,
          review: reviewFor("config.apply", {
            expected_revision: "9",
            document: F.config2,
          }) as unknown as NativeRef,
        }),
      "REVISION_CONFLICT",
    );
    await expectCode(
      () =>
        svc.config.apply({
          expected_revision: "1",
          document: F.config2,
          review: "0".repeat(64) as unknown as NativeRef,
        }),
      "POLICY_DENIED",
    );
    // A review bound to a different document also fails.
    const otherDoc = JSON.parse(JSON.stringify(F.config2));
    otherDoc.agents.access_ttl_s = 600;
    await expectCode(
      () =>
        svc.config.apply({
          expected_revision: "1",
          document: otherDoc,
          review: review as unknown as NativeRef,
        }),
      "POLICY_DENIED",
    );
  });

  it("apply denies protected changes and flags restart-required edits", async () => {
    const { svc } = seededPorts();
    // Protected: gateway.ui.port is a control endpoint.
    const protectedDoc = JSON.parse(JSON.stringify(F.config2)) as Record<
      string,
      unknown
    >;
    (protectedDoc.gateway as Record<string, unknown>).ui = {
      ...(protectedDoc.gateway as { ui: object }).ui,
      port: 9999,
    };
    await expectCode(
      () =>
        svc.config.apply({
          expected_revision: "1",
          document: protectedDoc as never,
          review: reviewFor("config.apply", {
            expected_revision: "1",
            document: protectedDoc,
          }) as unknown as NativeRef,
        }),
      "POLICY_DENIED",
    );
    // Unprotected: agents.access_ttl_s is editable, but restarts the bus.
    const editable = JSON.parse(JSON.stringify(F.config2)) as Record<
      string,
      unknown
    >;
    (editable.agents as Record<string, unknown>).access_ttl_s = 600;
    await expect(
      svc.config.apply({
        expected_revision: "1",
        document: editable as never,
        review: reviewFor("config.apply", {
          expected_revision: "1",
          document: editable,
        }) as unknown as NativeRef,
      }),
    ).resolves.toEqual({ revision: "2", restart_required: true });
  });
});

// ── run ──────────────────────────────────────────────────────────────────

describe("run", () => {
  it("register/heartbeat/finish reproduce the §3.3 exchanges", async () => {
    const { svc } = seededPorts();
    await expect(
      svc.run.register({
        run_id: F.ulid,
        kit: "openai-completions",
        owner: "cli1",
        resume: false,
      }),
    ).resolves.toEqual({ run_id: F.ulid, owner: "cli1", mode: "gateway" });
    await expect(
      svc.run.heartbeat({ run_id: F.ulid, owner: "cli1", spool_seq: "7" }),
    ).resolves.toEqual({ accepted: true });
    await expect(
      svc.run.finish({
        run_id: F.ulid,
        owner: "cli1",
        exit_code: 0,
        signal: null,
        spool_seq: "7",
      }),
    ).resolves.toEqual({ state: "FINISHED", pending_sync: 0 });
  });

  it("rejects non-ULID run ids and foreign owners", async () => {
    const { svc } = seededPorts();
    await expectCode(
      () =>
        svc.run.register({
          run_id: "not-a-ulid",
          kit: "k",
          owner: "cli1",
          resume: false,
        }),
      "SCHEMA_INVALID",
    );
    await svc.run.register({
      run_id: F.ulid,
      kit: "openai-completions",
      owner: "cli1",
      resume: false,
    });
    await expectCode(
      () =>
        svc.run.register({
          run_id: F.ulid,
          kit: "openai-completions",
          owner: "cli2",
          resume: false,
        }),
      "POLICY_DENIED",
    );
    await expectCode(
      () => svc.run.heartbeat({ run_id: F.ulid, owner: "cli2", spool_seq: "1" }),
      "POLICY_DENIED",
    );
    await expectCode(
      () => svc.run.heartbeat({ run_id: F.ulid, owner: "cli1", spool_seq: "9" })
        .then(() =>
          svc.run.heartbeat({ run_id: F.ulid, owner: "cli1", spool_seq: "5" }),
        ),
      "REVISION_CONFLICT",
    );
  });
});

// ── events ───────────────────────────────────────────────────────────────

describe("events", () => {
  it("publish returns {cursor,durable:true,duplicate:false}", async () => {
    const { svc } = seededPorts();
    const result = await publishFixtureEvent(svc, 0);
    expect(result.durable).toBe(true);
    expect(result.duplicate).toBe(false);
    expect(result.cursor).toMatch(/^c[0-9a-f]{16}:[0-9]+$/);
  });

  it("duplicate publish of identical bytes ACKs without a second record", async () => {
    const { svc, ports } = seededPorts();
    const first = await publishFixtureEvent(svc, 0);
    const second = await publishFixtureEvent(svc, 0);
    expect(second).toEqual({
      cursor: first.cursor,
      durable: true,
      duplicate: true,
    });
    const head = await ports.store.laneHead("proof/ws1");
    expect(head.nextRecordOrdinal).toBe(2); // exactly one record committed
  });

  it("conflicting bytes for one slot are both retained and marked", async () => {
    const { svc, ports } = seededPorts();
    const first = await publishFixtureEvent(svc, 0);
    // A second valid signature binds a different body to (ws1,src1,main,"1").
    const rival = sealProofEvent(
      proofBody({
        workspace: "ws1",
        source: "src1",
        stream: "main",
        seq: "1",
        lamport: "1",
        key: origin.material.id,
        data: { kind: "RunOpened", run: "rival", intent: null, policy: null, hypothetical: false },
      }),
      origin.secret,
    );
    const second = await svc.events.publish({
      profile: "proof-evidence/1",
      topic: "telemetry",
      producer: "src1",
      seq: "1",
      record: blob(J(rival)),
    });
    expect(second.duplicate).toBe(false);
    expect(second.cursor).not.toBe(first.cursor);
    const slot = ports.store.slotEntries("ws1", "src1", "main", "1");
    expect(slot).toHaveLength(2);
    expect(slot.every((e) => e.conflict)).toBe(true);
    // No overwrite: the first record's bytes are intact at its cursor.
    expect(Buffer.from(ports.store.recordAt(first.cursor)!).toString()).toBe(
      J(F.events[0]),
    );
  });

  it("rejects bad signatures, unenrolled and foreign producers", async () => {
    const { svc } = seededPorts();
    const tampered = JSON.parse(J(F.events[0]));
    tampered.signature = Buffer.alloc(64, 1).toString("base64url");
    await expectCode(
      () =>
        svc.events.publish({
          profile: "proof-evidence/1",
          topic: "telemetry",
          producer: "src1",
          seq: "1",
          record: blob(J(tampered)),
        }),
      "SIGNATURE_INVALID",
    );
    await expectCode(
      () =>
        svc.events.publish({
          profile: "proof-evidence/1",
          topic: "telemetry",
          producer: "nobody",
          seq: "1",
          record: blob(J(F.events[0])),
        }),
      "POLICY_DENIED",
    );
    // gateway.action is reserved to the core writer.
    await expectCode(
      () =>
        svc.events.publish({
          profile: "proof-evidence/1",
          topic: "gateway.action",
          producer: "src1",
          seq: "1",
          record: blob(J(F.events[0])),
        }),
      "POLICY_DENIED",
    );
  });

  it("query returns transport references, never raw bytes", async () => {
    const { svc } = seededPorts();
    const published = await publishFixtureEvent(svc, 0);
    const page = await svc.events.query({
      topics: ["telemetry"],
      after: null,
      limit: 100,
    });
    expect(page.items).toEqual([
      {
        cursor: published.cursor,
        topic: "telemetry",
        profile: "proof-evidence/1",
        record_ref: {
          digest: F.eventBlob.ref.digest,
          bytes: F.eventBlob.ref.bytes,
          media: "application/json",
        },
        availability: "WITHHELD",
      },
    ]);
    expect(page.next).toBeNull();
    // An empty topic filter on a fresh store pages nothing.
    const other = await svc.events.query({
      topics: ["verdict"],
      after: null,
      limit: 100,
    });
    expect(other).toEqual({ items: [], next: null });
  });

  it("query pages by cursor", async () => {
    const { svc } = seededPorts();
    await publishFixtureEvent(svc, 0);
    await publishFixtureEvent(svc, 1);
    const third = await publishFixtureEvent(svc, 2);
    const page1 = await svc.events.query({
      topics: ["telemetry"],
      after: null,
      limit: 2,
    });
    expect(page1.items).toHaveLength(2);
    expect(page1.next).not.toBeNull();
    const page2 = await svc.events.query({
      topics: ["telemetry"],
      after: page1.next,
      limit: 2,
    });
    expect(page2.items).toHaveLength(1);
    expect((page2.items[0] as { cursor: string }).cursor).toBe(third.cursor);
    expect(page2.next).toBeNull();
  });

  it("subscribe mints a 60 s lease at the committed frontier; ack advances it", async () => {
    const { svc } = seededPorts();
    const published = await publishFixtureEvent(svc, 0);
    const sub = await svc.events.subscribe({ topics: ["telemetry"], after: null });
    expect(sub.cursor).toBe(published.cursor);
    expect(sub.expires_ms).toBe(now + 60_000);
    expect(sub.subscription).toMatch(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/);
    await expect(
      svc.events.ack({ subscription: sub.subscription, cursor: published.cursor }),
    ).resolves.toEqual({ cursor: published.cursor });
  });

  it("ack rejects unseen and foreign-topic cursors", async () => {
    const { svc } = seededPorts();
    const sub = await svc.events.subscribe({ topics: ["telemetry"], after: null });
    const published = await publishFixtureEvent(svc, 0);
    // Committed after the lease frontier → not yet delivered.
    await expectCode(
      () =>
        svc.events.ack({
          subscription: sub.subscription,
          cursor: published.cursor,
        }),
      "POLICY_DENIED",
    );
    await expectCode(
      () =>
        svc.events.ack({
          subscription: "nosuchsub",
          cursor: published.cursor,
        }),
      "NOT_FOUND",
    );
    await expectCode(
      () =>
        svc.events.ack({
          subscription: sub.subscription,
          cursor: "cffffffffffffffff:1",
        }),
      "CURSOR_GONE",
    );
  });

  it("a pruned cursor surfaces CURSOR_GONE (TV-GW-37)", async () => {
    const { svc, ports } = seededPorts();
    const published = await publishFixtureEvent(svc, 0);
    ports.store.pruneBefore("proof/ws1", 2);
    await expectCode(
      () =>
        svc.events.subscribe({ topics: ["telemetry"], after: published.cursor }),
      "CURSOR_GONE",
    );
    await expectCode(
      () =>
        svc.events.query({
          topics: ["telemetry"],
          after: published.cursor,
          limit: 10,
        }),
      "CURSOR_GONE",
    );
  });
});

// ── objects ──────────────────────────────────────────────────────────────

describe("objects", () => {
  const ownAction = () => ({ workspace: "ws1", event: ref(F.events[0]) });

  it("put/get round-trips F.intent bound to a caller-owned action", async () => {
    const { svc } = seededPorts();
    await publishFixtureEvent(svc, 0);
    await expect(
      svc.objects.put({ action: ownAction() as never, blob: F.intent }),
    ).resolves.toEqual({ ref: F.intent.ref });
    await expect(
      svc.objects.get({ action: ownAction() as never, ref: F.intent.ref }),
    ).resolves.toEqual({ blob: F.intent });
  });

  it("rejects a declared size of 1048577 as OBJECT_LIMIT before allocation", async () => {
    const { svc } = seededPorts();
    await publishFixtureEvent(svc, 0);
    await expectCode(
      () =>
        svc.objects.put({
          action: ownAction() as never,
          blob: {
            ref: {
              digest: "0".repeat(64),
              bytes: "1048577",
              media: "application/json",
            },
            content: "",
          },
        }),
      "OBJECT_LIMIT",
    );
  });

  it("never becomes an existence oracle: every auth failure is NOT_FOUND", async () => {
    const { svc } = seededPorts();
    await publishFixtureEvent(svc, 0);
    // Unknown action → NOT_FOUND.
    await expectCode(
      () =>
        svc.objects.get({
          action: {
            workspace: "ws1",
            event: { source: "src1", stream: "main", seq: "9", hash: "0".repeat(64) },
          } as never,
          ref: F.intent.ref,
        }),
      "NOT_FOUND",
    );
    // Digest known but not referenced by the action's lane cut → NOT_FOUND.
    await expectCode(
      () =>
        svc.objects.get({
          action: ownAction() as never,
          ref: blob("mystery").ref,
        }),
      "NOT_FOUND",
    );
    // Foreign principal cannot put to the operator's action.
    const foreign = seededPorts();
    await publishFixtureEvent(foreign.svc, 0);
    const foreignSvc = createPlatformServices(foreign.ports, AGENT_PEER1);
    await expectCode(
      () =>
        foreignSvc.objects.put({
          action: ownAction() as never,
          blob: F.intent,
        }),
      "NOT_FOUND",
    );
  });
});

// ── receipt / lineage ────────────────────────────────────────────────────

describe("receipt + lineage", () => {
  it("receipt.get returns the HASHES_ONLY index summary with WITHHELD inventory", async () => {
    const { svc, ports } = seededPorts();
    await publishAllFixtureEvents(svc);
    // Seed the referenced objects so joins resolve (bytes stay withheld).
    for (const b of [F.intent]) {
      await ports.store.putObject(
        Buffer.from(b.content, "base64url"),
        1_048_576,
      );
    }
    const result = await svc.receipt.get({
      action: F.pointer as never,
      disclosure: "HASHES_ONLY",
    });
    expect(result).toEqual({
      action: F.pointer,
      inventory: F.inventory,
      outer: "SIGNED_UNANCHORED",
      inner: "NOT_EVALUATED",
      bundle: null,
    });
  });

  it("lineage.query returns the action node and the unavailable-adapter gap", async () => {
    const { svc, ports } = seededPorts();
    await publishAllFixtureEvents(svc);
    // Seed the joined observation object so the value ref resolves.
    await ports.store.putObject(
      Buffer.from(observation.content, "base64url"),
      1_048_576,
    );
    const result = await svc.lineage.query({
      action: F.pointer as never,
      max_nodes: 64,
      max_depth: 16,
    });
    expect(result).toEqual({
      nodes: [F.pointer],
      edges: [],
      gaps: ["CAP_ADAPTER_UNAVAILABLE"],
      native_assessment: "NOT_EVALUATED",
    });
  });

  it("lineage.query enforces the max_nodes/max_depth bounds", async () => {
    const { svc } = seededPorts();
    await publishAllFixtureEvents(svc);
    await expectCode(
      () =>
        svc.lineage.query({ action: F.pointer as never, max_nodes: 0, max_depth: 16 }),
      "SCHEMA_INVALID",
    );
    await expectCode(
      () =>
        svc.lineage.query({
          action: F.pointer as never,
          max_nodes: 64,
          max_depth: 129,
        }),
      "SCHEMA_INVALID",
    );
  });
});

// ── operations ───────────────────────────────────────────────────────────

describe("operation", () => {
  function seedOp(ports: MemoryPlatformPorts, state = "READY"): void {
    ports.store.seedOperation({
      id: "op1",
      principal: "operator1",
      kind: "install",
      state,
      slug: "lexverdict",
      from: null,
      to: "0.1.0",
      cursor: F.cursor,
      error: null,
    });
  }

  it("get/cancel reproduce the §3.3 exchanges", async () => {
    const { svc, ports } = seededPorts();
    seedOp(ports);
    await expect(svc.operation.get({ operation: "op1" })).resolves.toEqual({
      operation: "op1",
      kind: "install",
      state: "READY",
      slug: "lexverdict",
      from: null,
      to: "0.1.0",
      cursor: F.cursor,
      error: null,
    });
    await expect(
      svc.operation.cancel({ operation: "op1" }),
    ).resolves.toEqual({ operation: "op1", state: "CANCELLED" });
    expect(
      (await svc.operation.get({ operation: "op1" })).state,
    ).toBe("CANCELLED");
  });

  it("cancel after effect admission is CANCEL_UNSAFE; unknown is NOT_FOUND", async () => {
    const { svc, ports } = seededPorts();
    seedOp(ports, "RUNNING");
    await expectCode(
      () => svc.operation.cancel({ operation: "op1" }),
      "CANCEL_UNSAFE",
    );
    await expectCode(
      () => svc.operation.get({ operation: "missing" }),
      "NOT_FOUND",
    );
  });
});

// ── ui sessions ──────────────────────────────────────────────────────────

describe("ui session", () => {
  function sessionPorts() {
    const toks = [F.bootstrap, F.access, F.csrf, token(9), token(10)];
    let i = 0;
    return seededPorts({ newToken: () => toks[i++ % toks.length]! });
  }

  it("create/exchange/revoke reproduce the §3.3 exchanges", async () => {
    const { svc } = sessionPorts();
    const created = await svc.ui.sessionCreate({ role: "viewer" });
    expect(created).toEqual({
      bootstrap: F.bootstrap,
      expires_ms: now + 60_000,
      url: "http://127.0.0.1:9848/#bootstrap=" + F.bootstrap,
    });
    const exchanged = await svc.ui.sessionExchange({ bootstrap: F.bootstrap });
    expect(exchanged).toEqual({
      session: F.access,
      role: "viewer",
      csrf: F.csrf,
      expires_ms: now + 28_800_000,
    });
    await expect(
      svc.ui.sessionRevoke({ session: exchanged.session }),
    ).resolves.toEqual({ session: exchanged.session, state: "REVOKED" });
  });

  it("bootstrap is one-use: replay is AUTH_REQUIRED", async () => {
    const { svc } = sessionPorts();
    await svc.ui.sessionCreate({ role: "viewer" });
    await svc.ui.sessionExchange({ bootstrap: F.bootstrap });
    await expectCode(
      () => svc.ui.sessionExchange({ bootstrap: F.bootstrap }),
      "AUTH_REQUIRED",
    );
  });

  it("bootstrap expires at the 60 s equality boundary", async () => {
    const { svc, ports } = sessionPorts();
    await svc.ui.sessionCreate({ role: "viewer" });
    ports.advance(59_999);
    const ok = await svc.ui.sessionExchange({ bootstrap: F.bootstrap });
    expect(ok.expires_ms).toBe(now + 59_999 + 28_800_000);

    const { svc: svc2, ports: ports2 } = sessionPorts();
    await svc2.ui.sessionCreate({ role: "viewer" });
    ports2.advance(60_000);
    await expectCode(
      () => svc2.ui.sessionExchange({ bootstrap: F.bootstrap }),
      "AUTH_REQUIRED",
    );
  });

  it("viewer sessions live 8 h and die at the equality boundary", async () => {
    const { svc, ports } = sessionPorts();
    await svc.ui.sessionCreate({ role: "viewer" });
    const ex = await svc.ui.sessionExchange({ bootstrap: F.bootstrap });
    expect(ex.expires_ms).toBe(now + 28_800_000);
    const rec = await ports.sessionStore.sessionGet(sha256Hex(ex.session));
    expect(rec).not.toBeNull();
    expect(rec!.expires_ms).toBe(now + 28_800_000);
    expect(rec!.idle_expires_ms).toBe(now + 1_800_000);
    // Idle bound bites first: live at 30 min - 1 ms, dead at exactly 30 min.
    expect(sessionIsLive(rec!, now + 1_800_000 - 1)).toBe(true);
    expect(sessionIsLive(rec!, now + 1_800_000)).toBe(false);
    // Absolute bound: a record with a fresh idle window still dies at 8 h.
    const freshIdle = { ...rec!, idle_expires_ms: now + 28_800_000 };
    expect(sessionIsLive(freshIdle, now + 28_800_000 - 1)).toBe(true);
    expect(sessionIsLive(freshIdle, now + 28_800_000)).toBe(false);
  });

  it("operator sessions live 10 min", async () => {
    const { svc } = sessionPorts();
    await svc.ui.sessionCreate({ role: "operator" });
    const ex = await svc.ui.sessionExchange({ bootstrap: F.bootstrap });
    expect(ex.role).toBe("operator");
    expect(ex.expires_ms).toBe(now + 600_000);
  });

  it("revoke closes the owner's open subscriptions", async () => {
    const { svc, ports } = sessionPorts();
    const created = await svc.ui.sessionCreate({ role: "viewer" });
    void created;
    const ex = await svc.ui.sessionExchange({ bootstrap: F.bootstrap });
    const sub = await svc.events.subscribe({ topics: ["telemetry"], after: null });
    await svc.ui.sessionRevoke({ session: ex.session });
    expect(
      (await ports.store.registry.subscriptionGet(sub.subscription))!.state,
    ).toBe("CLOSED");
  });
});

// ── audit receipts ───────────────────────────────────────────────────────

describe("audit receipt", () => {
  it("commits the five-event history and returns the StepClosed pointer", async () => {
    const { ports } = seededPorts();
    const params = { document: F.config2 };
    const result = { revision: "1" };
    const pointer = await emitAuditReceipt(ports, { ...OPERATOR, requestId: "q1" }, {
      method: "config.get",
      request: "q1",
      operation: null,
      params: scrub(params),
      result: scrub(result),
      outcome: "SUCCEEDED",
      code: "OK",
      previous_action: null,
    });
    expect(pointer.workspace).toBe("audit1");
    expect(pointer.event.source).toBe("gateway1");
    expect(pointer.event.stream).toBe("q1");
    expect(pointer.event.seq).toBe("4");
    expect(pointer.event.hash).toMatch(/^[0-9a-f]{64}$/);

    // Exactly the history the spec harness builds.
    const action = blob(
      J({
        v: 1,
        method: "config.get",
        principal: "operator1",
        request: "q1",
        operation: null,
        redacted_params_sha256: H(J(scrub(params))),
        result_sha256: H(J(scrub(result))),
        outcome: "SUCCEEDED",
        code: "OK",
        previous_action: null,
      }),
    );
    const expected = history(
      "op_q1",
      blob(J({ method: "config.get", params: scrub(params) })),
      action,
      "audit1",
      "gateway1",
      auditor,
      "q1",
    );
    expect(pointer.event.hash).toBe(expected[3].hash);
    expect(pointer.event).toEqual(ref(expected[3]));

    // All five events committed to the proof/audit1 lane, verified under
    // the fixture auditor key.
    const records: { cursor: string; data: Uint8Array }[] = [];
    for await (const rec of ports.store.laneScan("proof/audit1")) {
      records.push(rec);
    }
    expect(records).toHaveLength(5);
    const kinds = records.map(
      (r) => (JSON.parse(Buffer.from(r.data).toString()) as { body: { data: { kind: string } } }).body.data.kind,
    );
    expect(kinds).toEqual([
      "RunOpened",
      "StepOpened",
      "ObservationRecorded",
      "StepClosed",
      "RunClosed",
    ]);
    const parsed = records.map(
      (r) =>
        JSON.parse(Buffer.from(r.data).toString()) as {
          hash: string;
          body: { prev: string; seq: string; data: { kind: string } };
        },
    );
    expect(parsed[0]!.body.prev).toBe("0".repeat(64));
    for (let i = 1; i < 5; i += 1) {
      expect(parsed[i]!.body.prev).toBe(parsed[i - 1]!.hash);
    }
    // Every record verifies as a sealed Proof event under the auditor key.
    for (const p of parsed) {
      expect(verifyProofEvent(p, auditor.public)).toBe(true);
    }
    // The committed events are byte-identical to the harness history.
    for (let i = 0; i < 5; i += 1) {
      expect(parsed[i]!.hash).toBe(expected[i].hash);
    }
    // The action is indexed for objects/lineage joins.
    const idx = await ports.store.registry.actionGet(
      sha256Hex(canonicalJson(pointer)),
    );
    expect(idx).not.toBeNull();
    expect(idx!.method).toBe("config.get");
    expect(idx!.principal).toBe("operator1");
  });

  it("each additional audited action opens a fresh stream", async () => {
    const { ports } = seededPorts();
    const p1 = await emitAuditReceipt(ports, { ...OPERATOR, requestId: "q1" }, {
      method: "daemon.status",
      request: "q1",
      operation: null,
      params: {},
      result: {},
      outcome: "SUCCEEDED",
      code: "OK",
    });
    const p2 = await emitAuditReceipt(ports, { ...OPERATOR, requestId: "q2" }, {
      method: "daemon.status",
      request: "q2",
      operation: null,
      params: {},
      result: {},
      outcome: "SUCCEEDED",
      code: "OK",
    });
    expect(p1.event.stream).toBe("q1");
    expect(p2.event.stream).toBe("q2");
    expect(p2.event.seq).toBe("4"); // fresh genesis chain per action
    const count = (await ports.store.laneHead("proof/audit1")).nextRecordOrdinal;
    expect(count).toBe(11); // 10 records committed
  });
});
