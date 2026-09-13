/**
 * Dispatch-pipeline tests (spec §3.1/§3.2/§3.3): envelope shape, role
 * authorization, idempotent replay/conflict, exempt methods, unavailable
 * fallbacks, peer request proofs.
 */
import { describe, expect, test } from "vitest";
import { randomBytes } from "node:crypto";
import { F, H, origin } from "@latticeag/testkit";
import {
  canonicalJson,
  requestProofBody,
  sha256Hex,
  signRequest,
} from "../core-v2.js";
import { InMemoryPeerTokenStore, type SessionRecord } from "./auth.js";
import {
  dispatchRequest,
  type DispatchContext,
  type IdempotencyLookup,
  type ReceiptPointer,
  type ReceiptWriter,
  type SavedBinding,
  type AuditAction,
} from "./dispatch.js";

// ── in-memory receipt + idempotency store ────────────────────────────────

class TestReceipts implements ReceiptWriter, IdempotencyLookup {
  readonly binds = new Map<string, SavedBinding>();
  seq = 0;

  async commitAction(
    _action: AuditAction,
    bind: {
      principalKey: string;
      id: string;
      requestHash: string;
      makeResultJson: (r: ReceiptPointer) => string;
    } | null,
  ): Promise<ReceiptPointer> {
    this.seq += 1;
    const ptr: ReceiptPointer = {
      workspace: "audit1",
      event: {
        source: "gateway1",
        stream: "audit1",
        seq: String(this.seq),
        hash: sha256Hex(`audit-${this.seq}`),
      },
    };
    if (bind !== null) {
      this.binds.set(`${bind.principalKey}|${bind.id}`, {
        principalKey: bind.principalKey,
        id: bind.id,
        requestHash: bind.requestHash,
        saved: bind.makeResultJson(ptr),
      });
    }
    return ptr;
  }

  async commitBind(bind: {
    principalKey: string;
    id: string;
    requestHash: string;
    resultJson: string;
  }): Promise<void> {
    this.binds.set(`${bind.principalKey}|${bind.id}`, {
      principalKey: bind.principalKey,
      id: bind.id,
      requestHash: bind.requestHash,
      saved: bind.resultJson,
    });
  }

  lookup(principalKey: string, id: string): SavedBinding | null {
    return this.binds.get(`${principalKey}|${id}`) ?? null;
  }
}

const viewerSession: SessionRecord = {
  id: "s1",
  role: "viewer",
  csrf: "csrf",
  created_ms: Date.now(),
  last_seen_ms: Date.now(),
  absolute_expires_ms: Date.now() + 8 * 3600_000,
  idle_ms: 30 * 60_000,
  revoked: false,
};

function req(method: string, params: unknown, id = "q1"): Record<string, unknown> {
  return { v: 2, id, workspace: "ws1", method, params };
}

function makeCtx(overrides: Partial<DispatchContext> = {}): {
  ctx: DispatchContext;
  receipts: TestReceipts;
} {
  const receipts = new TestReceipts();
  const ctx: DispatchContext = {
    instance: "gw1",
    workspace: "ws1",
    epoch: "1",
    services: {
      config: {
        get: async () => ({ document: { ok: true }, revision: "1" }),
        validate: async () => ({ valid: true, errors: [] }),
        apply: async () => ({ revision: "2", restart_required: false }),
      } as DispatchContext["services"]["config"],
      daemon: {
        hello: async () => ({
          protocol: "latticeag-gateway/2",
          profiles: [],
          interfaces: "interfaces/1",
          mesh: { available: false },
        }),
        status: async () => ({
          instance: "gw1",
          state: "READY",
          config_revision: "1",
          products: 0,
          peers: 0,
          ui: null,
        }),
        stop: async () => ({ state: "DRAINING" }),
      },
      agent: {
        renew: async () => ({
          access: F.access2,
          refresh: F.refresh2,
          expires_ms: 999,
        }),
      } as unknown as DispatchContext["services"]["agent"],
    },
    receipts,
    idempotency: receipts,
    ...overrides,
  };
  return { ctx, receipts };
}

// ── golden envelope semantics (§3.3) ─────────────────────────────────────

describe("dispatchRequest", () => {
  test("success envelope shape: {v:2,id,ok:true,result,receipt}", async () => {
    const { ctx } = makeCtx();
    const out = await dispatchRequest(ctx, {
      body: req("config.get", {}),
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(out.status).toBe(200);
    const r = out.response as {
      v: number;
      id: string;
      ok: boolean;
      result: unknown;
      receipt: { workspace: string; event: { seq: string } } | null;
    };
    expect(r.v).toBe(2);
    expect(r.id).toBe("q1");
    expect(r.ok).toBe(true);
    expect(r.result).toEqual({ document: { ok: true }, revision: "1" });
    expect(r.receipt).not.toBeNull();
    expect(r.receipt?.workspace).toBe("audit1");
    expect(r.receipt?.event.seq).toBe("1");
  });

  test("exempt (connection-accounted) methods carry receipt:null", async () => {
    const { ctx } = makeCtx();
    const out = await dispatchRequest(ctx, {
      body: req("daemon.hello", { profiles: [], interfaces: "interfaces/1" }),
      transport: "socket",
      credentials: { kind: "local" },
    });
    const r = out.response as { ok: boolean; receipt: unknown };
    expect(r.ok).toBe(true);
    expect(r.receipt).toBeNull();
  });

  test("viewer cannot call config.apply → 403 FORBIDDEN", async () => {
    const { ctx } = makeCtx();
    const out = await dispatchRequest(ctx, {
      body: req("config.apply", { document: {}, expected_revision: "1" }),
      transport: "bridge",
      credentials: { kind: "session", session: viewerSession },
    });
    expect(out.status).toBe(403);
    const r = out.response as { ok: boolean; error: { code: string } };
    expect(r.ok).toBe(false);
    expect(r.error.code).toBe("FORBIDDEN");
  });

  test("idempotent replay returns the saved result+receipt", async () => {
    const { ctx } = makeCtx();
    const body = req("config.apply", { document: { a: 1 }, expected_revision: "1" }, "op1");
    const first = await dispatchRequest(ctx, {
      body,
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(first.status).toBe(200);
    const again = await dispatchRequest(ctx, {
      body: structuredClone(body),
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(again.status).toBe(200);
    expect(again.response).toEqual(first.response);
  });

  test("same id with changed params → IDEMPOTENCY_CONFLICT", async () => {
    const { ctx } = makeCtx();
    await dispatchRequest(ctx, {
      body: req("config.apply", { document: { a: 1 } }, "op1"),
      transport: "socket",
      credentials: { kind: "local" },
    });
    const conflict = await dispatchRequest(ctx, {
      body: req("config.apply", { document: { a: 2 } }, "op1"),
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(conflict.status).toBe(409);
    const r = conflict.response as { error: { code: string } };
    expect(r.error.code).toBe("IDEMPOTENCY_CONFLICT");
  });

  test("same id under a different principal does not collide", async () => {
    const { ctx } = makeCtx();
    const opSession: SessionRecord = { ...viewerSession, id: "s9", role: "operator" };
    await dispatchRequest(ctx, {
      body: req("config.apply", { document: { a: 1 } }, "op1"),
      transport: "socket",
      credentials: { kind: "local" },
    });
    const other = await dispatchRequest(ctx, {
      body: req("config.apply", { document: { a: 2 } }, "op1"),
      transport: "bridge",
      credentials: { kind: "session", session: opSession },
    });
    expect(other.status).toBe(200);
  });

  test("malformed JSON → JSON_INVALID 400", async () => {
    const { ctx } = makeCtx();
    const out = await dispatchRequest(ctx, {
      body: Buffer.from("{not json"),
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(out.status).toBe(400);
    expect((out.response as { error: { code: string } }).error.code).toBe(
      "JSON_INVALID",
    );
    expect((out.response as { receipt: unknown }).receipt).toBeNull();
  });

  test("unknown method → METHOD_UNKNOWN; absent service → domain unavailable code", async () => {
    const { ctx } = makeCtx();
    const bad = await dispatchRequest(ctx, {
      body: req("bogus.method", {}),
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(bad.status).toBe(400);
    expect((bad.response as { error: { code: string } }).error.code).toBe(
      "METHOD_UNKNOWN",
    );
    // No events service injected → STORAGE_UNAVAILABLE, not METHOD_UNKNOWN.
    const missing = await dispatchRequest(ctx, {
      body: req("events.query", { topics: ["telemetry"] }),
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect((missing.response as { error: { code: string } }).error.code).toBe(
      "STORAGE_UNAVAILABLE",
    );
  });

  test("workspace binding mismatch → FORBIDDEN", async () => {
    const { ctx } = makeCtx();
    const out = await dispatchRequest(ctx, {
      body: { v: 2, id: "q1", workspace: "other", method: "daemon.status", params: {} },
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(out.status).toBe(403);
  });

  test("DRAINING rejects new mutations but allows reads", async () => {
    const { ctx } = makeCtx({ draining: () => true });
    const mut = await dispatchRequest(ctx, {
      body: req("config.apply", { document: { a: 1 } }),
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(mut.status).toBe(409);
    expect((mut.response as { error: { code: string } }).error.code).toBe(
      "STATE_TRANSITION",
    );
    const read = await dispatchRequest(ctx, {
      body: req("config.get", {}),
      transport: "socket",
      credentials: { kind: "local" },
    });
    expect(read.status).toBe(200);
  });

  // ── peer request proof (spec §4.3) ──────────────────────────────────────

  function peerCreds(
    method: string,
    params: unknown,
    id: string,
    peers: InMemoryPeerTokenStore,
    overrides: { nonce?: string; issued?: number; expires?: number } = {},
  ): {
    kind: "peer";
    headers: {
      authorization: string;
      nonce: string;
      epoch: string;
      issued_ms: string;
      expires_ms: string;
      key_proof: string;
    };
  } {
    const issued = overrides.issued ?? Date.now();
    const expires = overrides.expires ?? issued + 60_000;
    const nonce =
      overrides.nonce ?? randomBytes(32).toString("base64url");
    const body = requestProofBody({
      gateway: "gw1",
      workspace: "ws1",
      epoch: "1",
      token_hash: H(F.access),
      id,
      method,
      params_sha256: sha256Hex(canonicalJson(params)),
      nonce,
      issued_ms: issued,
      expires_ms: expires,
    });
    void peers;
    return {
      kind: "peer",
      headers: {
        authorization: `Bearer ${F.access}`,
        nonce,
        epoch: "1",
        issued_ms: String(issued),
        expires_ms: String(expires),
        key_proof: signRequest(body, origin.secret),
      },
    };
  }

  function mkPeerStore(expiresMs = Date.now() + 900_000): InMemoryPeerTokenStore {
    const peers = new InMemoryPeerTokenStore();
    peers.bindAccessToken(F.access, {
      peer: "peer1",
      publicKey: F.key.public,
      role: "agent",
      scopes: [
        { permission: "events.emit", topics: ["telemetry"], runs: ["self"], products: [] },
        { permission: "events.consume", topics: ["telemetry"], runs: ["self"], products: [] },
      ],
      expires_ms: expiresMs,
      revoked: false,
      epoch: "1",
    });
    return peers;
  }

  test("peer bearer + signed proof authenticates (agent.list)", async () => {
    const peers = mkPeerStore();
    const { ctx } = makeCtx({ peers });
    (ctx.services.agent as unknown as Record<string, unknown>).list = async () => ({ peers: [] });
    const creds = peerCreds("agent.list", {}, "q9", peers);
    const out = await dispatchRequest(ctx, {
      body: req("agent.list", {}, "q9"),
      transport: "bridge",
      credentials: creds,
    });
    expect(out.status).toBe(200);
    expect((out.response as { ok: boolean }).ok).toBe(true);
  });

  test("replayed proof nonce → AUTH_REQUIRED", async () => {
    const peers = mkPeerStore();
    const { ctx } = makeCtx({ peers });
    (ctx.services.agent as unknown as Record<string, unknown>).list = async () => ({ peers: [] });
    const creds = peerCreds("agent.list", {}, "q9", peers, {
      nonce: randomBytes(32).toString("base64url"),
    });
    const first = await dispatchRequest(ctx, {
      body: req("agent.list", {}, "q9"),
      transport: "bridge",
      credentials: creds,
    });
    expect(first.status).toBe(200);
    // Same nonce, different request id → signature still valid over a new
    // body but the nonce replay check fires first... build a fresh proof
    // reusing the nonce.
    const creds2 = peerCreds("agent.list", {}, "q10", peers, {
      nonce: creds.headers.nonce,
    });
    const second = await dispatchRequest(ctx, {
      body: req("agent.list", {}, "q10"),
      transport: "bridge",
      credentials: creds2,
    });
    expect(second.status).toBe(401);
    expect((second.response as { error: { code: string } }).error.code).toBe(
      "AUTH_REQUIRED",
    );
  });

  test("expired access token → TOKEN_EXPIRED", async () => {
    const peers = mkPeerStore(Date.now() - 1);
    const { ctx } = makeCtx({ peers });
    const creds = peerCreds("agent.list", {}, "q1", peers, {
      issued: Date.now() - 61_000,
      expires: Date.now() - 1000,
    });
    const out = await dispatchRequest(ctx, {
      body: req("agent.list", {}, "q1"),
      transport: "bridge",
      credentials: creds,
    });
    expect(out.status).toBe(401);
    expect((out.response as { error: { code: string } }).error.code).toBe(
      "TOKEN_EXPIRED",
    );
  });

  test("tampered signature → AUTH_REQUIRED", async () => {
    const peers = mkPeerStore();
    const { ctx } = makeCtx({ peers });
    const creds = peerCreds("agent.list", {}, "q1", peers);
    creds.headers.key_proof = Buffer.from(randomBytes(64)).toString("base64url");
    const out = await dispatchRequest(ctx, {
      body: req("agent.list", {}, "q1"),
      transport: "bridge",
      credentials: creds,
    });
    expect(out.status).toBe(401);
  });

  test("agent calling outside its scopes → FORBIDDEN", async () => {
    const peers = mkPeerStore();
    const { ctx } = makeCtx({ peers });
    (ctx.services as Record<string, unknown>).events = {
      publish: async () => ({ cursor: "c0000000000000001:1", durable: true, duplicate: false }),
      query: async () => ({ events: [] }),
      subscribe: async () => ({ subscription: "s", cursor: "", expires_ms: 0 }),
      ack: async () => ({}),
    };
    // peer scopes only allow topic "telemetry"; publish to "admin" → 403.
    const creds = peerCreds(
      "events.publish",
      { profile: "proof-evidence/1", topic: "admin", producer: "src1", seq: "1", record: {} },
      "q5",
      peers,
    );
    const out = await dispatchRequest(ctx, {
      body: req("events.publish", { profile: "proof-evidence/1", topic: "admin", producer: "src1", seq: "1", record: {} }, "q5"),
      transport: "bridge",
      credentials: creds,
    });
    expect(out.status).toBe(403);
  });

  test("exempt-binding method binds only its param subset (agent.renew)", async () => {
    const peers = mkPeerStore();
    const { ctx, receipts } = makeCtx({ peers });
    const params1 = { peer: "peer1", refresh: F.refresh };
    const creds = peerCreds("agent.renew", params1, "q20", peers);
    const first = await dispatchRequest(ctx, {
      body: req("agent.renew", params1, "q20"),
      transport: "bridge",
      credentials: creds,
    });
    expect(first.status).toBe(200);
    expect((first.response as { receipt: unknown }).receipt).toBeNull();
    // Same id, same bound subset (peer + refresh_hash) → replay.
    const creds2 = peerCreds("agent.renew", params1, "q20", peers);
    const replay = await dispatchRequest(ctx, {
      body: req("agent.renew", params1, "q20"),
      transport: "bridge",
      credentials: creds2,
    });
    expect(replay.status).toBe(200);
    expect(replay.response).toEqual(first.response);
    // Same id, different refresh → different refresh_hash → conflict.
    const creds3 = peerCreds("agent.renew", { peer: "peer1", refresh: F.refresh2 }, "q20", peers);
    const conflict = await dispatchRequest(ctx, {
      body: req("agent.renew", { peer: "peer1", refresh: F.refresh2 }, "q20"),
      transport: "bridge",
      credentials: creds3,
    });
    expect(conflict.status).toBe(409);
    expect(receipts.binds.size).toBeGreaterThan(0);
  });
});
