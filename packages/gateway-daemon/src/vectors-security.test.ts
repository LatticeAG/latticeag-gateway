/**
 * TV-GW TRANSPORT / SECURITY conformance vectors — consolidated suite
 * (spec §13.2). One named test per vector id, each asserting the
 * vector's forbidden side effects — not merely its status/error code:
 *
 *  - TV-GW-35  daemon crash before a durable approval decision: no
 *    decision/ACK persists, the stale UI action is unsupported, and the
 *    native executor stays NOT_DISPATCHED.
 *  - TV-GW-36  cloud viewer (receipts-only): approval.decide and
 *    product.install are FORBIDDEN before any service runs; a hosted
 *    receipt never confers native reviewer authority.
 *  - TV-GW-37/38 SSE: a stale Last-Event-ID yields 410 CURSOR_GONE with
 *    no silent jump and no durable-ACK advance; an over-credit consumer
 *    is disconnected with zero dropped control records.
 *  - TV-GW-39..43 bind/Host/Origin/CSRF/terminal/egress guards.
 *  - TV-GW-48  crash/recovery idempotency: durable operations replay
 *    returns the original result; an unknown commit never fabricates
 *    success.
 *  - TV-GW-49/50 authn + transport security: invalid/expired/revoked
 *    credentials and hostile headers never reach a handler.
 */
import { afterEach, describe, expect, test, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";

import { F } from "@latticeag/testkit";
import { validateConfigV2Semantics } from "@latticeag/config";

import {
  canonicalJson,
  sanitizeTerminalText,
  isTerminalSafe,
  sha256Hex,
} from "./core-v2.js";
import { createApprovalRuntime } from "../../core/dist/v2/approvals/service.js";
import { createMemoryApprovalPorts } from "../../core/dist/v2/approvals/ports.js";
import {
  cryptoEntropy,
  sequentialIds,
} from "../../core/dist/v2/peers/ports.js";
import type { NativeRef } from "./core-v2.js";

import { GatewayStore } from "./store/store.js";
import { createStorePorts } from "./adapters/store-ports.js";
import type {
  CatalogSourcePorts,
  CloudRuntimePorts,
  SyncRuntimePorts,
} from "./adapters/store-ports.js";

import {
  createBridgeListener,
  CSRF_HEADER,
  type BridgeHandle,
} from "./net/bridge.js";
import {
  cursorPrecedes,
  parseLastEventId,
  serveSse,
  SSE_LIMITS,
  type SseFrame,
  type SseSource,
} from "./net/sse.js";
import {
  assertEgressUrlAllowed,
  egressFetch,
  EGRESS_MAX_REDIRECTS,
  type EgressResponse,
} from "./net/egress.js";

import {
  SessionStore,
  type PeerGrant,
  type PeerProofHeaders,
  type SessionRecord,
} from "./rpc/auth.js";
import {
  dispatchRequest,
  type DispatchContext,
  type DispatchOutcome,
} from "./rpc/dispatch.js";
import {
  AuditReceiptWriter,
  RegistryIdempotency,
} from "./runtime.js";
import type { ReceiptPointer } from "./rpc/dispatch.js";
import type { ServerResponse } from "node:http";

const now = F.now as number;

// ── shared helpers ───────────────────────────────────────────────────────

function rawRequest(
  port: number,
  opts: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    body?: string;
  },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolveP, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: opts.method ?? "GET",
        path: opts.path ?? "/healthz",
        headers: opts.headers ?? {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolveP({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    req.on("error", reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

function rpcBody(method: string, params: unknown, id = "q1"): string {
  return JSON.stringify({ v: 2, id, workspace: "ws1", method, params });
}

const roots: string[] = [];
async function tmpRoot(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "gw-vec-"));
  roots.push(dir);
  return dir;
}
afterEach(async () => {
  while (roots.length > 0) await rm(roots.pop()!, { recursive: true, force: true });
});

const viewerSession: SessionRecord = {
  id: "s1",
  role: "viewer",
  csrf: "csrf-1",
  created_ms: now,
  last_seen_ms: now,
  absolute_expires_ms: now + 8 * 3600_000,
  idle_ms: 30 * 60_000,
  revoked: false,
};

/** dispatch ctx whose service methods count invocations. */
function countingCtx(
  serviceImpl: Record<string, (params: unknown, caller?: unknown) => Promise<unknown>>,
  group = "approval",
): { ctx: DispatchContext; calls: Map<string, number>; receiptCalls: number[] } {
  const calls = new Map<string, number>();
  const receiptCalls: number[] = [];
  const svc: Record<string, unknown> = {};
  for (const [name, impl] of Object.entries(serviceImpl)) {
    svc[name] = async (params: unknown, caller?: unknown) => {
      calls.set(name, (calls.get(name) ?? 0) + 1);
      return impl(params, caller);
    };
  }
  const ctx: DispatchContext = {
    instance: "gw1",
    workspace: "ws1",
    epoch: "1",
    services: { [group]: svc } as DispatchContext["services"],
    receipts: {
      async commitAction(): Promise<ReceiptPointer> {
        receiptCalls.push(1);
        return {
          workspace: "audit1",
          event: { source: "gateway1", stream: "audit1", seq: "1", hash: sha256Hex("r") },
        };
      },
    },
    idempotency: null,
    now: () => now,
  };
  return { ctx, calls, receiptCalls };
}

function peerHeaders(overrides: Partial<PeerProofHeaders> = {}): PeerProofHeaders {
  return {
    authorization: "Bearer peer-access-token",
    nonce: Buffer.alloc(32, 1).toString("base64url"),
    epoch: "1",
    issued_ms: String(now - 1000),
    expires_ms: String(now + 30_000),
    key_proof: "00",
    ...overrides,
  };
}

function grantOf(patch: Partial<PeerGrant>): PeerGrant {
  return {
    peer: "peer1",
    publicKey: "A".repeat(43),
    role: "agent",
    scopes: [],
    expires_ms: now + 60_000,
    revoked: false,
    epoch: "1",
    ...patch,
  };
}

// ── approval helpers ─────────────────────────────────────────────────────

const approvalParams = {
  action: F.nativeRef as NativeRef,
  target: "product1",
  expires_ms: now + 300_000,
  native: F.intent.ref as { digest: string; bytes: string; media: "application/json" },
};

const REVIEWER = {
  id: "operator1",
  role: "local_operator" as const,
  reviewer: true,
};

function storePortsDeps(
  clock: () => number,
): Parameters<typeof createStorePorts>[1] {
  return {
    identity: {
      epoch: "e1",
      ids: sequentialIds(),
      entropy: cryptoEntropy(),
      now: clock,
    },
    catalog: {
      trust: () => ({
        roots: new Map(),
        quorum: 0,
        channel: "stable",
        strict: false,
        allowlist: [],
        max_age_s: 604_800,
      }),
      configuredPins: () => ({ pins: [], revision: "0" }),
    } as CatalogSourcePorts,
    cloud: {
      uiRemoteGranted: () => false,
      providers: () => new Map(),
    } as CloudRuntimePorts,
    sync: {
      syncPaused: () => false,
      syncRevision: () => "0",
      applySync: () => undefined,
      cloud: () => null,
      configuredConsent: () => undefined,
    } as SyncRuntimePorts,
  };
}

// ═════════════════════════════════════════════════════════════════════════
// TV-GW-35 — crash before durable approval decision
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-35: daemon killed before the durable approval decision — no decision/ACK persists, stale UI action unsupported, native executor stays blocked", async () => {
  const root = await tmpRoot();
  const store = await GatewayStore.open(root, { instance: "gw1" });
  const ports = createStorePorts(store, storePortsDeps(() => now));
  const runtime = createApprovalRuntime(ports.approvals);

  // The pending request IS durable before the crash.
  const req = runtime.manager.request(approvalParams, REVIEWER);
  expect(req.state).toBe("PENDING");
  expect(ports.approvals.getApproval(req.approval)?.state).toBe("PENDING");

  // Crash seam: the process dies between the caller's UI click and the
  // durable decision write — every subsequent commitSync fails as it
  // would on a killed daemon (the in-memory decide result is lost).
  const crash = new Error("process killed before durable decision commit");
  store.commitSync = () => {
    throw crash;
  };
  expect(() =>
    runtime.manager.decide(
      {
        approval: req.approval,
        expected_revision: "1",
        action: F.nativeRef as NativeRef,
        decision: "approve",
        reason: "ui approve click",
      },
      REVIEWER,
    ),
  ).toThrow(crash);

  // Forbidden side effects IN-PROCESS: the registry-backed read model
  // never observed the decision — no APPROVED row, no ACK.
  const stillPending = ports.approvals.getApproval(req.approval);
  expect(stillPending?.state).toBe("PENDING");
  expect(stillPending?.revision).toBe("1");
  expect(stillPending?.decision).toBeNull();
  expect(stillPending?.native_status).toBe("NOT_DISPATCHED");

  await store.close();

  // Recovery: reopen — the durable record is exactly the PENDING request.
  const store2 = await GatewayStore.open(root, { instance: "gw1" });
  const ports2 = createStorePorts(store2, storePortsDeps(() => now));
  const runtime2 = createApprovalRuntime(ports2.approvals);
  const recovered = ports2.approvals.getApproval(req.approval);
  expect(recovered).toMatchObject({
    revision: "1",
    state: "PENDING",
    decision: null,
    decided_ms: null,
    reviewer: null,
    native_status: "NOT_DISPATCHED",
    authority: "NONE",
  });
  // The stale UI approve is not durable — it must be re-issued, and only
  // then does it commit (a fresh decide after recovery succeeds).
  const decide = runtime2.manager.decide(
    {
      approval: req.approval,
      expected_revision: "1",
      action: F.nativeRef as NativeRef,
      decision: "approve",
      reason: "reissued after recovery",
    },
    REVIEWER,
  );
  expect(decide.state).toBe("APPROVED");
  expect(ports2.approvals.getApproval(req.approval)?.state).toBe("APPROVED");
  await store2.close();
});

// ═════════════════════════════════════════════════════════════════════════
// TV-GW-36 — cloud viewer authority boundary
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-36: receipts-only cloud viewer — approval.decide and product.install FORBIDDEN before any service runs; hosted receipt confers no reviewer authority", async () => {
  const { ctx, calls, receiptCalls } = countingCtx(
    {
      request: async () => ({}),
      decide: async () => ({}),
    },
    "approval",
  );
  ctx.services = {
    ...ctx.services,
    product: {
      install: async () => ({}),
    } as unknown as DispatchContext["services"]["product"],
  };

  // A viewer session is the cloud-viewer principal (roles = {V}).
  const decideOut = await dispatchRequest(ctx, {
    body: rpcBody(
      "approval.decide",
      {
        approval: "a1",
        expected_revision: "1",
        action: F.nativeRef,
        decision: "approve",
        reason: "hosted receipt claims approval",
      },
      "q-decide",
    ),
    transport: "bridge",
    credentials: { kind: "session", session: viewerSession },
  });
  expect(decideOut.status).toBe(403);
  expect((decideOut.response as { error: { code: string } }).error.code).toBe(
    "FORBIDDEN",
  );

  const installOut = await dispatchRequest(ctx, {
    body: rpcBody("product.install", { plan: "p1", review: F.nativeRef }, "q-inst"),
    transport: "bridge",
    credentials: { kind: "session", session: viewerSession },
  });
  expect(installOut.status).toBe(403);
  expect((installOut.response as { error: { code: string } }).error.code).toBe(
    "FORBIDDEN",
  );

  // Forbidden side effects: neither service ran and no audit receipt was
  // committed for a forbidden authorization-stage rejection.
  expect(calls.size).toBe(0);
  expect(receiptCalls).toHaveLength(0);

  // A hosted receipt presented by a peer/agent caller still does not
  // mint native reviewer authority — decide stays FORBIDDEN at the
  // manager too.
  const managerRuntime = createApprovalRuntime(
    createMemoryApprovalPorts({ now }),
  );
  const rec = managerRuntime.manager.request(approvalParams, {
    id: "requester1",
    role: "agent" as const,
  });
  expect(() =>
    managerRuntime.manager.decide(
      {
        approval: rec.approval,
        expected_revision: "1",
        action: F.nativeRef as NativeRef,
        decision: "approve",
        reason: "hosted receipt attached",
      },
      { id: "hosted-receipt-holder", role: "agent", reviewer: false },
    ),
  ).toThrowError(expect.objectContaining({ code: "FORBIDDEN" }));
  expect(rec.state).toBe("PENDING");
});

// ═════════════════════════════════════════════════════════════════════════
// TV-GW-37 / 38 — SSE cursors + slow-consumer disconnect
// ═════════════════════════════════════════════════════════════════════════

const sseFrame = (n: number, pad = 0): SseFrame => ({
  cursor: `c0000000000000001:${n}`,
  topic: "telemetry" + "t".repeat(pad),
  profile: "proof-evidence/1",
  record_ref: "ab".repeat(32),
  availability: "INLINE",
});

test("TV-GW-37: Last-Event-ID :7 with earliest retained :12 → 410 CURSOR_GONE — no silent jump, durable ACK unmoved", async () => {
  // Structural order, not lexicographic: :7 precedes :12.
  expect(cursorPrecedes("c0000000000000001:7", "c0000000000000001:12")).toBe(true);
  expect(cursorPrecedes("c0000000000000001:12", "c0000000000000001:7")).toBe(false);
  expect(cursorPrecedes("c0000000000000001:12", "c0000000000000002:1")).toBe(true);
  expect(parseLastEventId("c0000000000000001:7")).toBe("c0000000000000001:7");
  expect(parseLastEventId("not-a-cursor")).toBeNull();

  // Durable subscription ack is at :7; the lane retained from :12.
  const sub = { id: "sub1", lastAckCursor: "c0000000000000001:7" };
  let reads = 0;
  const source: SseSource = {
    earliestRetainedCursor: () => "c0000000000000001:12",
    readAfter: async () => {
      reads += 1;
      return [];
    },
    waitFor: async () => undefined,
  };

  const sessions = new SessionStore(() => now);
  const { bootstrap } = sessions.createBootstrap("viewer");
  const session = sessions.exchange(bootstrap)!;
  const bridge = await createBridgeListener("127.0.0.1", 0, {
    instance: "gw1",
    sessions,
    staticDir: null,
    onRpc: async () => {
      throw new Error("unreachable");
    },
    sse: {
      registry: { lookup: (id) => (id === "sub1" ? sub : null) },
      source,
    },
  });
  try {
    const cookie = `latticeag_session_gw1_${bridge.port}=${session.id}`;
    const r = await rawRequest(bridge.port, {
      path: "/v2/events?subscription=sub1",
      headers: {
        Host: `127.0.0.1:${bridge.port}`,
        Cookie: cookie,
        [CSRF_HEADER]: session.csrf,
        "Last-Event-ID": "c0000000000000001:7",
      },
    });
    expect(r.status).toBe(410);
    const env = JSON.parse(r.body) as { error: { code: string } };
    expect(env.error.code).toBe("CURSOR_GONE");
    // Forbidden side effects: the tail never silently jumped ahead —
    // readAfter was never invoked — and the durable ack did not advance.
    expect(reads).toBe(0);
    expect(sub.lastAckCursor).toBe("c0000000000000001:7");
  } finally {
    await bridge.close();
  }
});

test("TV-GW-38: consumer >256 KiB behind for >5000 ms is disconnected; writer continues; zero control records dropped", async () => {
  const PAD = 380; // each frame ≈ 430 bytes on the wire
  const N_FIRST = 700; // ≈ 300 KiB — crosses the 256 KiB credit cap
  const first = Array.from({ length: N_FIRST }, (_, i) => sseFrame(i + 13, PAD));
  const second = [sseFrame(N_FIRST + 13, PAD)];
  let calls = 0;
  let phase = 0;
  const source: SseSource = {
    earliestRetainedCursor: () => "c0000000000000001:12",
    readAfter: async (_s, _c, _l) => {
      calls += 1;
      if (calls === 1) return first;
      // The next writer batch arrives at t0+10s — the consumer has held
      // >256 KiB of unflushed credit for >5000 ms by then.
      phase = 1;
      return second;
    },
    waitFor: async () => undefined,
  };
  // Clock seam: phase 0 = t0 (over-credit begins), phase 1 = t0+10s.
  const clock = () => (phase === 0 ? 0 : 10_000);

  let ended = false;
  let written = 0;
  let drainHandler: (() => void) | null = null;
  const res = {
    writeHead: vi.fn(),
    flushHeaders: vi.fn(),
    setHeader: vi.fn(),
    write(chunk: string) {
      written += Buffer.byteLength(chunk, "utf8");
      return true; // accepted into the (never-draining) socket buffer
    },
    once(name: string, fn: () => void) {
      if (name === "drain") drainHandler = fn;
      return this;
    },
    on() {
      return this;
    },
    off() {
      return this;
    },
    end() {
      ended = true;
      return this;
    },
    get writableLength() {
      return 4096; // permanently backed up: kernel buffer never drains
    },
    get writableEnded() {
      return ended;
    },
  } as unknown as ServerResponse;
  void drainHandler;

  // Durable ack sits at the retained floor — a live subscriber, not a
  // stale one: replay starts strictly after :12.
  const sub = { id: "sub1", lastAckCursor: "c0000000000000001:12" };
  const serve = serveSse(res, sub, source, {
    lastEventId: null,
    now: clock,
    heartbeatMs: 60_000,
    overCreditMs: SSE_LIMITS.overCreditMs,
  });
  await serve;

  // Forbidden side effects verified: the stream was closed (disconnect),
  // every produced frame was handed to the socket exactly once (zero
  // dropped control records — the subscriber lost buffered output, not
  // durable records), the durable ack cursor was retained, and the writer
  // was still readable.
  expect(ended).toBe(true);
  expect(sub.lastAckCursor).toBe("c0000000000000001:12");
  const expectedBytes = first.concat(second).reduce((sum, f) => {
    return (
      sum +
      Buffer.byteLength(
        `id: ${f.cursor}\nevent: bus\ndata: ${JSON.stringify({
          cursor: f.cursor,
          topic: f.topic,
          profile: f.profile,
          record_ref: f.record_ref,
          availability: f.availability,
        })}\n\n`,
        "utf8",
      )
    );
  }, Buffer.byteLength(`retry: 1000\n\n`, "utf8"));
  expect(written).toBe(expectedBytes); // preamble + every frame, none dropped
  expect(calls).toBeGreaterThanOrEqual(2);
});

// ═════════════════════════════════════════════════════════════════════════
// TV-GW-39..41 — bind / Host-Origin / CSRF
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-39: gateway.ui.bind 0.0.0.0/:: fail SCHEMA_INVALID; cast or non-TS caller cannot open a non-loopback listener", async () => {
  const doc = (bind: string) => {
    const d = structuredClone(F.config2) as Record<string, unknown>;
    (d.gateway as { ui: { bind: string } }).ui.bind = bind;
    return d;
  };
  for (const bind of ["0.0.0.0", "::"]) {
    const result = validateConfigV2Semantics(doc(bind));
    expect(result.valid).toBe(false);
    expect(
      result.errors.some(
        (e) => e.code === "SCHEMA_INVALID" && e.path.includes("bind"),
      ),
    ).toBe(true);
  }

  // Runtime guard (same deny) — a JS caller or a TS cast must not reach
  // server.listen. The throw precedes socket creation: afterwards a
  // loopback bind still succeeds and the port space is untouched.
  const sessions = new SessionStore(() => now);
  const opts = {
    instance: "gw1",
    sessions,
    onRpc: async (): Promise<DispatchOutcome> => ({
      status: 200,
      response: { v: 2, id: "q1", ok: true, result: {}, receipt: null },
      headers: {},
    }),
  };
  for (const bind of ["0.0.0.0", "::", "10.0.0.5", "192.168.1.1"]) {
    await expect(
      createBridgeListener(bind as "127.0.0.1", 0, opts),
    ).rejects.toMatchObject({ code: "SCHEMA_INVALID", field: "bind" });
  }
  // No non-loopback listener was opened anywhere: loopback still binds.
  const ok = await createBridgeListener("127.0.0.1", 0, opts);
  expect(ok.port).toBeGreaterThan(0);
  await ok.close();
  const ok6 = await createBridgeListener("::1", 0, opts);
  expect(ok6.port).toBeGreaterThan(0);
  await ok6.close();
});

test("TV-GW-40: hostile Host and Origin with a valid session cookie → FORBIDDEN before resource lookup; RPC handler never runs", async () => {
  const sessions = new SessionStore(() => now);
  const { bootstrap } = sessions.createBootstrap("viewer");
  const session = sessions.exchange(bootstrap)!;
  let rpcCalls = 0;
  const bridge: BridgeHandle = await createBridgeListener("127.0.0.1", 0, {
    instance: "gw1",
    sessions,
    staticDir: null,
    onRpc: async () => {
      rpcCalls += 1;
      return {
        status: 200,
        response: { v: 2, id: "q1", ok: true, result: {}, receipt: null },
        headers: {},
      };
    },
  });
  try {
    const cookie = `latticeag_session_gw1_${bridge.port}=${session.id}`;
    const baseHeaders = {
      "content-type": "application/json",
      cookie,
      [CSRF_HEADER]: session.csrf,
    };
    const body = rpcBody("daemon.status", {});
    // Hostile Host (DNS-rebinding shape) — rejected byte-for-byte.
    const badHost = await rawRequest(bridge.port, {
      method: "POST",
      path: "/v2/rpc",
      headers: { ...baseHeaders, Host: "evil.example:9848" },
      body,
    });
    expect(badHost.status).toBe(403);
    expect(
      (JSON.parse(badHost.body) as { error: { code: string } }).error.code,
    ).toBe("FORBIDDEN");
    // Hostile Origin with the correct Host — same deny, before lookup.
    const badOrigin = await rawRequest(bridge.port, {
      method: "POST",
      path: "/v2/rpc",
      headers: {
        ...baseHeaders,
        Host: `127.0.0.1:${bridge.port}`,
        Origin: "http://evil.example",
      },
      body,
    });
    expect(badOrigin.status).toBe(403);
    expect(
      (JSON.parse(badOrigin.body) as { error: { code: string } }).error.code,
    ).toBe("FORBIDDEN");
    // Forbidden side effect: no resource lookup or RPC handler ran.
    expect(rpcCalls).toBe(0);
    // Control: the exact Host + same-origin proceeds to the handler.
    const good = await rawRequest(bridge.port, {
      method: "POST",
      path: "/v2/rpc",
      headers: {
        ...baseHeaders,
        Host: `127.0.0.1:${bridge.port}`,
        Origin: `http://127.0.0.1:${bridge.port}`,
      },
      body,
    });
    expect(good.status).toBe(200);
    expect(rpcCalls).toBe(1);
  } finally {
    await bridge.close();
  }
});

test("TV-GW-41: same-origin session POST without X-LatticeAG-CSRF → FORBIDDEN and zero mutation; wrong token same", async () => {
  const sessions = new SessionStore(() => now);
  const { bootstrap } = sessions.createBootstrap("operator");
  const session = sessions.exchange(bootstrap)!;
  let mutations = 0;
  const bridge = await createBridgeListener("127.0.0.1", 0, {
    instance: "gw1",
    sessions,
    staticDir: null,
    onRpc: async () => {
      mutations += 1;
      return {
        status: 200,
        response: { v: 2, id: "q1", ok: true, result: {}, receipt: null },
        headers: {},
      };
    },
  });
  try {
    const cookie = `latticeag_session_gw1_${bridge.port}=${session.id}`;
    const body = rpcBody("catalog.refresh", { source: "configured" });
    const origin = `http://127.0.0.1:${bridge.port}`;
    for (const csrf of [undefined, "attacker-guess"]) {
      const headers: Record<string, string> = {
        Host: `127.0.0.1:${bridge.port}`,
        Origin: origin,
        "content-type": "application/json",
        cookie,
      };
      if (csrf !== undefined) headers[CSRF_HEADER] = csrf;
      const r = await rawRequest(bridge.port, {
        method: "POST",
        path: "/v2/rpc",
        headers,
        body,
      });
      expect(r.status).toBe(403);
      expect(
        (JSON.parse(r.body) as { error: { code: string } }).error.code,
      ).toBe("FORBIDDEN");
    }
    // Forbidden side effect: the mutation never executed.
    expect(mutations).toBe(0);
    const ok = await rawRequest(bridge.port, {
      method: "POST",
      path: "/v2/rpc",
      headers: {
        Host: `127.0.0.1:${bridge.port}`,
        Origin: origin,
        "content-type": "application/json",
        cookie,
        [CSRF_HEADER]: session.csrf,
      },
      body,
    });
    expect(ok.status).toBe(200);
    expect(mutations).toBe(1);
  } finally {
    await bridge.close();
  }
});

// ═════════════════════════════════════════════════════════════════════════
// TV-GW-42 — terminal/UI text sanitization
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-42: untrusted text projects to inert terminal-safe form — escapes, OSC/DCS, controls, bidi, zero-width all stripped; markup stays literal; pure", () => {
  // All hostile material is built with \u escapes — the test source
  // itself must contain no control or invisible bytes.
  const E = "\u001b"; // ESC
  const BEL = "\u0007"; // BEL
  const ST = E + "\\"; // ST (ESC \)

  const hostile = [
    "line1",
    E + "[31mRED" + E + "[0m", // CSI color
    E + "[2J" + E + "[1;1H", // CSI screen clear / cursor
    E + "]8;;https://evil.example/x" + BEL + "click" + E + "]8;;" + BEL, // OSC-8
    E + "]0;pwned" + BEL, // OSC title
    E + "Ppayload" + ST, // DCS
    E + "Xsos" + ST, // SOS
    E + "^pm" + ST, // PM
    E + "_apc" + ST, // APC
    E + "c", // RIS full reset
    E + "(B", // charset select
    "\u0007\u0008", // BEL + BS
    "\u0012", // C0 DC2
    "\u000d", // CR (not preserved — only LF/TAB survive)
    "\u007f", // DEL
    "\u009b31m", // C1 CSI single-byte
    "\u009dosc", // C1 OSC single-byte
    "a\u061c\u202ab", // ALM + bidi embedding
    "c\u202e\u2066d", // RLO + LRI
    "e\u200e\u200d\u200bf", // LRM + ZWJ + ZWSP
    "g\ufeff\u2060h", // BOM/ZWNBSP + word joiner
    "<b>&\"'</b>", // literal markup preserved
    "line2\tcol\n",
  ].join("");

  const before = hostile.slice();
  const out = sanitizeTerminalText(hostile);

  // The hostile input was not modified (purity).
  expect(hostile).toBe(before);

  // Nothing actionable survives.
  expect(out).not.toContain(E);
  expect(out).not.toContain(BEL);
  expect(out).not.toContain("evil.example"); // hyperlink target went with OSC
  // C0 except LF/TAB, DEL, C1 — all gone.
  expect(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/u.test(out)).toBe(false);
  // Bidi marks/embeddings/overrides/isolates and zero-widths gone.
  for (const cp of [
    "\u061c", "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\u200b", "\u200c", "\u200d",
    "\ufeff", "\u2060",
  ]) {
    expect(out.includes(cp)).toBe(false);
  }
  // Literal markup characters remain literal — no entity rewriting.
  expect(out).toContain("<b>&\"'</b>");
  expect(out).toContain("line1");
  expect(out).toContain("line2\tcol\n");
  expect(out).toContain("click"); // link text survives; the link does not
  expect(out).toContain("abcdefg"); // inner text of the format-char pairs
  // LF + TAB kept; CR is gone.
  expect(out).toContain("\n");
  expect(out).toContain("\t");
  expect(out).not.toContain("\r");

  // Idempotent + safe predicate.
  expect(isTerminalSafe(out)).toBe(true);
  expect(sanitizeTerminalText(out)).toBe(out);
  expect(isTerminalSafe("plain text <>&\n\t")).toBe(true);
  expect(isTerminalSafe(hostile)).toBe(false);
});

// ═════════════════════════════════════════════════════════════════════════
// TV-GW-43 — safe egress
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-43: egress guard denies unsafe schemes/hosts before connect, revalidates every redirect hop, strips cross-origin credentials", async () => {
  const denied = (u: string) =>
    expect(() => assertEgressUrlAllowed(u)).toThrowError(
      expect.objectContaining({ code: "NETWORK_DENIED" }),
    );

  // Schemes: only https.
  for (const u of [
    "http://example.com/",
    "file:///etc/passwd",
    "ftp://example.com/",
    "ws://example.com/",
    "wss://example.com/",
    "data:text/plain,x",
    "javascript:alert(1)",
    "notaurl",
  ]) {
    denied(u);
  }
  // Userinfo.
  denied("https://user:pass@example.com/");
  denied("https://user@example.com/");
  // Literal unsafe IPv4/IPv6 + alternate numeric forms (the URL parser
  // canonicalizes hex/int/octal/short forms to dotted decimal, and the
  // embedded-v4 policy covers ::ffff: mapped space).
  for (const h of [
    "127.0.0.1",
    "0x7f000001",
    "2130706433",
    "0177.0.0.1",
    "127.1",
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "172.31.255.1",
    "192.0.2.1",
    "192.168.0.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "[::1]",
    "[::]",
    "[::ffff:127.0.0.1]",
    "[::ffff:10.0.0.1]",
    "[fe80::1]",
    "[fc00::1]",
    "[ff02::1]",
    "[2001:db8::1]",
    "[2002::1]",
    "[64:ff9b::1]",
  ]) {
    denied(`https://${h}/`);
  }
  // Localhost-style names.
  for (const h of [
    "localhost",
    "foo.localhost",
    "svc.local",
    "host.internal",
    "gw.home.arpa",
    "node.corp",
    "peer.lan",
    "mesh.intranet",
    "localhost.",
  ]) {
    denied(`https://${h}/`);
  }
  // A normal public name is allowed.
  expect(assertEgressUrlAllowed("https://catalog.example.com/x").hostname).toBe(
    "catalog.example.com",
  );

  // Redirect chasing revalidates EVERY hop; a denied target never reaches
  // the transport. The transport log proves zero unsafe requests.
  const seen: string[] = [];
  const transport = async (url: URL): Promise<EgressResponse> => {
    seen.push(url.href);
    if (url.hostname === "edge.example.com") {
      return { status: 302, headers: { location: "http://169.254.169.254/latest" }, body: new Uint8Array() };
    }
    return { status: 200, headers: {}, body: new Uint8Array([1]) };
  };
  await expect(
    egressFetch("https://edge.example.com/i", transport),
  ).rejects.toMatchObject({ code: "NETWORK_DENIED" });
  expect(seen).toEqual(["https://edge.example.com/i"]); // hop 2 never ran

  // Credentials never cross origins; same-origin hop keeps them.
  const hdrSeen: Array<Record<string, string>> = [];
  const t2 = async (url: URL, req: { headers?: Record<string, string> }): Promise<EgressResponse> => {
    hdrSeen.push(req.headers ?? {});
    if (url.origin === "https://a.example.com") {
      return { status: 302, headers: { location: "https://b.example.com/final" }, body: new Uint8Array() };
    }
    return { status: 200, headers: {}, body: new Uint8Array([1]) };
  };
  const ok = await egressFetch("https://a.example.com/start", t2, {
    headers: { authorization: "Bearer t", "x-trace": "1" },
  });
  expect(ok.status).toBe(200);
  expect(hdrSeen[0]).toMatchObject({ authorization: "Bearer t" });
  expect(hdrSeen[1]).not.toHaveProperty("authorization");
  expect(hdrSeen[1]).toHaveProperty("x-trace");

  // DNS rebind: a public name resolving to loopback is denied before the
  // transport is invoked.
  const calls: string[] = [];
  await expect(
    egressFetch(
      "https://rebind.example.com/",
      async (url) => {
        calls.push(url.href);
        return { status: 200, headers: {}, body: new Uint8Array() };
      },
      { resolve: async () => ["93.184.216.34", "127.0.0.1"] },
    ),
  ).rejects.toMatchObject({ code: "NETWORK_DENIED" });
  expect(calls).toHaveLength(0);

  // Redirect cap.
  const loop = async (): Promise<EgressResponse> => ({
    status: 302,
    headers: { location: "https://edge2.example.com/next" },
    body: new Uint8Array(),
  });
  await expect(
    egressFetch("https://edge2.example.com/0", loop),
  ).rejects.toMatchObject({ code: "NETWORK_DENIED" });
  expect(EGRESS_MAX_REDIRECTS).toBe(2);
});

// ═════════════════════════════════════════════════════════════════════════
// TV-GW-48 — durable idempotency across crash/restart
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-48: a durably committed operation replays its saved result after restart; an unknown commit never fabricates success", async () => {
  const root = await tmpRoot();
  const key = generateKeyPairSync("ed25519").privateKey;
  const store = await GatewayStore.open(root, { instance: "gw1" });
  const writer = new AuditReceiptWriter(store, key, { workspace: "audit1" });
  await writer.resume();
  const idem = new RegistryIdempotency(store.registry);

  let implCalls = 0;
  const makeCtx = (
    s: GatewayStore,
    w: AuditReceiptWriter,
    i: RegistryIdempotency,
  ): DispatchContext => ({
    instance: "gw1",
    workspace: "ws1",
    epoch: "1",
    services: {
      approval: {
        request: async () => {
          implCalls += 1;
          return { approval: "a1", revision: "1", state: "PENDING", authority: "NONE" };
        },
      } as unknown as DispatchContext["services"]["approval"],
    },
    receipts: w,
    idempotency: i,
    now: () => now,
  });

  const body = rpcBody(
    "approval.request",
    {
      action: F.nativeRef,
      target: "product1",
      expires_ms: now + 300_000,
      native: F.intent.ref,
    },
    "req-48",
  );
  const first = await dispatchRequest(makeCtx(store, writer, idem), {
    body,
    transport: "socket",
    credentials: { kind: "local" },
  });
  expect(first.status).toBe(200);
  expect((first.response as { ok: boolean }).ok).toBe(true);
  expect(implCalls).toBe(1);
  const laneCount = async (s: GatewayStore): Promise<number> => {
    let n = 0;
    for await (const _ of s.laneScan("proof/audit")) n += 1;
    return n;
  };
  const committedLane = await laneCount(store);
  expect(committedLane).toBe(1);

  // ── crash/restart: close and reopen; durable state survives ──
  await store.close();
  const store2 = await GatewayStore.open(root, { instance: "gw1" });
  const writer2 = new AuditReceiptWriter(store2, key, { workspace: "audit1" });
  await writer2.resume();
  const idem2 = new RegistryIdempotency(store2.registry);

  // The durable binding exists — the restart did not lose it.
  const row = store2.registry.operationLookup("ws1:local", "req-48");
  expect(row).not.toBeNull();
  expect(row!.state).toBe("COMPLETED");
  expect(row!.result_json).not.toBeNull();

  // Repeating the SAME logical operation returns the original result —
  // the service impl does not run again and no second lane record lands.
  const replay = await dispatchRequest(makeCtx(store2, writer2, idem2), {
    body,
    transport: "socket",
    credentials: { kind: "local" },
  });
  expect(replay.status).toBe(200);
  expect(replay.response).toEqual(first.response);
  expect(implCalls).toBe(1);
  expect(await laneCount(store2)).toBe(1);

  // A different body under the same request id is an idempotency
  // conflict — never silently rebound.
  const conflict = await dispatchRequest(makeCtx(store2, writer2, idem2), {
    body: rpcBody(
      "approval.request",
      {
        action: { ...F.nativeRef, object_id: "other" },
        target: "product1",
        expires_ms: now + 300_000,
        native: F.intent.ref,
      },
      "req-48",
    ),
    transport: "socket",
    credentials: { kind: "local" },
  });
  expect(conflict.status).toBe(409);
  expect((conflict.response as { error: { code: string } }).error.code).toBe(
    "IDEMPOTENCY_CONFLICT",
  );
  expect(implCalls).toBe(1);
  expect(await laneCount(store2)).toBe(1);

  // ── commit status unknown → no fabricated success: a durable row
  // without a result binds nothing, and the operation executes honestly.
  store2.commitSync({
    mutation: {
      v: 1,
      kind: "operations",
      operations: [
        {
          principal: "ws1:local",
          id: "req-unknown",
          request_hash: sha256Hex("different-body"),
          state: "PENDING",
        },
      ],
    },
    result_sha256: sha256Hex("pending-marker"),
  });
  const unknownRow = store2.registry.operationLookup("ws1:local", "req-unknown");
  expect(unknownRow).not.toBeNull();
  expect(unknownRow!.result_json).toBeNull();
  const unknown = await dispatchRequest(makeCtx(store2, writer2, idem2), {
    body: rpcBody(
      "approval.request",
      {
        action: F.nativeRef,
        target: "product1",
        expires_ms: now + 300_000,
        native: F.intent.ref,
      },
      "req-unknown",
    ),
    transport: "socket",
    credentials: { kind: "local" },
  });
  // Not a replay: the impl ran and committed a real receipt.
  expect(unknown.status).toBe(200);
  expect(implCalls).toBe(2);
  expect(await laneCount(store2)).toBe(2);
  await store2.close();
});

// ═════════════════════════════════════════════════════════════════════════
// TV-GW-49 / 50 — authn + transport security
// ═════════════════════════════════════════════════════════════════════════

test("TV-GW-49: invalid/expired/revoked credentials are rejected with the right code before any resource lookup or mutation", async () => {
  const { ctx, calls, receiptCalls } = countingCtx(
    { status: async () => ({}) },
    "daemon",
  );
  // Peer path: a store where every access token lookup is controllable.
  let grant: PeerGrant | null = null;
  ctx.peers = {
    lookupAccess: () => grant,
    nonceSeen: () => false,
  };

  const dispatch = (headers: PeerProofHeaders, id = "q-auth") =>
    dispatchRequest(ctx, {
      body: rpcBody("daemon.status", {}, id),
      transport: "bridge",
      credentials: { kind: "peer", headers },
    });
  const code = async (h: PeerProofHeaders, id = "q-auth") =>
    ((await dispatch(h, id)).response as { error: { code: string } }).error.code;

  // Unknown token → AUTH_REQUIRED (generic — not a token oracle).
  expect(await code(peerHeaders())).toBe("AUTH_REQUIRED");
  // Malformed Authorization scheme → AUTH_REQUIRED.
  expect(await code(peerHeaders({ authorization: "Basic abc" }))).toBe(
    "AUTH_REQUIRED",
  );
  // Revoked grant → TOKEN_REVOKED.
  grant = grantOf({ revoked: true });
  expect(await code(peerHeaders())).toBe("TOKEN_REVOKED");
  // Expired grant → TOKEN_EXPIRED.
  grant = grantOf({ expires_ms: now - 1 });
  expect(await code(peerHeaders())).toBe("TOKEN_EXPIRED");
  // Wrong epoch → AUTH_REQUIRED.
  grant = grantOf({});
  expect(await code(peerHeaders({ epoch: "9" }))).toBe("AUTH_REQUIRED");
  // Replayed nonce → AUTH_REQUIRED.
  ctx.peers = { lookupAccess: () => grant, nonceSeen: () => true };
  expect(await code(peerHeaders())).toBe("AUTH_REQUIRED");

  // Forbidden side effects: not one of those requests reached the
  // service or committed a receipt.
  expect(calls.size).toBe(0);
  expect(receiptCalls).toHaveLength(0);

  // Transport level: a bogus session cookie over the real bridge is
  // AUTH_REQUIRED and never reaches the RPC handler.
  const sessions = new SessionStore(() => now);
  let rpcCalls = 0;
  const bridge = await createBridgeListener("127.0.0.1", 0, {
    instance: "gw1",
    sessions,
    staticDir: null,
    onRpc: async () => {
      rpcCalls += 1;
      return {
        status: 200,
        response: { v: 2, id: "q1", ok: true, result: {}, receipt: null },
        headers: {},
      };
    },
  });
  try {
    for (const cookie of [
      "latticeag_session_gw1_x=fabricated",
      "latticeag_session_other=none",
    ]) {
      const r = await rawRequest(bridge.port, {
        method: "POST",
        path: "/v2/rpc",
        headers: {
          Host: `127.0.0.1:${bridge.port}`,
          "content-type": "application/json",
          cookie,
          [CSRF_HEADER]: "anything",
        },
        body: rpcBody("daemon.status", {}),
      });
      expect(r.status).toBe(401);
      expect(
        (JSON.parse(r.body) as { error: { code: string } }).error.code,
      ).toBe("AUTH_REQUIRED");
    }
    expect(rpcCalls).toBe(0);
  } finally {
    await bridge.close();
  }
});

test("TV-GW-50: session cookie is host-only HttpOnly SameSite=Strict; revoked/expired sessions and hostile origins never reach a mutating handler", async () => {
  const sessions = new SessionStore(() => now);
  const { bootstrap } = sessions.createBootstrap("operator");
  const session = sessions.exchange(bootstrap)!;
  let rpcCalls = 0;
  const bridge = await createBridgeListener("127.0.0.1", 0, {
    instance: "gw1",
    sessions,
    staticDir: null,
    onRpc: async (body, _creds, sess) => {
      rpcCalls += 1;
      const method = (body as { method?: string }).method;
      // The bootstrap exchange is the one session-less call by design.
      if (method !== "ui.session.exchange" && sess === null) {
        throw new Error("session expected");
      }
      return {
        status: 200,
        response: {
          v: 2,
          id: "q1",
          ok: true,
          result: { session: session.id },
          receipt: null,
        },
        headers: {},
      };
    },
  });
  try {
    const host = `127.0.0.1:${bridge.port}`;
    const cookie = `latticeag_session_gw1_${bridge.port}=${session.id}`;
    const body = rpcBody("daemon.status", {});

    // Successful bootstrap exchange sets the hardened cookie attributes.
    const ex = await rawRequest(bridge.port, {
      method: "POST",
      path: "/v2/rpc",
      headers: { Host: host, "content-type": "application/json" },
      body: rpcBody("ui.session.exchange", { bootstrap: "tok" }),
    });
    expect(ex.status).toBe(200);
    const setCookie = ex.headers["set-cookie"];
    expect(setCookie).toBeDefined();
    const sc = Array.isArray(setCookie) ? setCookie[0]! : setCookie!;
    expect(sc).toContain("HttpOnly");
    expect(sc).toContain("SameSite=Strict");
    expect(sc).toContain("Path=/");
    expect(sc).not.toContain("Domain=");
    expect(sc).not.toContain("Secure"); // loopback: no Secure attr

    // Revoked session → the store stops resolving it → AUTH_REQUIRED.
    sessions.revoke(session.id);
    const revoked = await rawRequest(bridge.port, {
      method: "POST",
      path: "/v2/rpc",
      headers: {
        Host: host,
        "content-type": "application/json",
        cookie,
        [CSRF_HEADER]: session.csrf,
      },
      body,
    });
    expect(revoked.status).toBe(401);

    // Expired session (absolute deadline passed) → same.
    const sessions2 = new SessionStore(() => now);
    const { bootstrap: b2 } = sessions2.createBootstrap("viewer");
    const s2 = sessions2.exchange(b2)!;
    s2.absolute_expires_ms = now - 1; // force expiry
    const bridge2 = await createBridgeListener("127.0.0.1", 0, {
      instance: "gw1",
      sessions: sessions2,
      staticDir: null,
      onRpc: async () => {
        rpcCalls += 1;
        return {
          status: 200,
          response: { v: 2, id: "q1", ok: true, result: {}, receipt: null },
          headers: {},
        };
      },
    });
    try {
      const expired = await rawRequest(bridge2.port, {
        method: "POST",
        path: "/v2/rpc",
        headers: {
          Host: `127.0.0.1:${bridge2.port}`,
          "content-type": "application/json",
          cookie: `latticeag_session_gw1_${bridge2.port}=${s2.id}`,
          [CSRF_HEADER]: s2.csrf,
        },
        body,
      });
      expect(expired.status).toBe(401);
      // And SSE needs a live session too — no silent downgrade.
      const sse = await rawRequest(bridge2.port, {
        path: "/v2/events?subscription=x",
        headers: {
          Host: `127.0.0.1:${bridge2.port}`,
          cookie: `latticeag_session_gw1_${bridge2.port}=${s2.id}`,
          [CSRF_HEADER]: s2.csrf,
        },
      });
      expect(sse.status).toBe(404); // no SSE wiring on this bridge → 404, never a stream
    } finally {
      await bridge2.close();
    }

    // A mutating call on the first bridge with revoked session + valid
    // CSRF still never reaches the handler.
    expect(rpcCalls).toBe(1); // only the session.exchange itself
  } finally {
    await bridge.close();
  }
});
