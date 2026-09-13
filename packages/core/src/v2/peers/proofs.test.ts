/**
 * TV-GW-25/26/27 — request-proof, revocation, and replay vectors (§4.3).
 */
import { describe, expect, it } from "vitest";
import { F, auditor, now, origin, token } from "@latticeag/testkit";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import {
  requestProofBody,
  signRequest,
  verifyRequest,
  type RequestProofBody,
} from "../crypto/pairing.js";
import {
  createMemoryPeerPorts,
  queuedEntropy,
  sequentialIds,
  type MemoryPeerPorts,
} from "./ports.js";
import { createAgentRuntime, type AgentRuntime } from "./service.js";
import {
  REQUEST_PROOF_HEADERS,
  readProofHeaders,
  verifyRequestProof,
  type RequestProofContext,
  type RequestProofFields,
} from "./proofs.js";
import { PeerRegistry } from "./registry.js";

interface Ctx {
  ports: MemoryPeerPorts;
  rt: AgentRuntime;
  ctx: RequestProofContext;
}

function setup(): Ctx {
  const ports = createMemoryPeerPorts({
    now,
    ids: sequentialIds(),
    entropy: queuedEntropy({
      tokens: [F.access, F.refresh, F.access2, F.refresh2],
      nonces: [F.serverNonce],
      pairCodes: [F.code],
    }),
  });
  const rt = createAgentRuntime(ports, {
    gateway: "gw1",
    workspace: "ws1",
    epoch: "1",
  });
  return {
    ports,
    rt,
    ctx: {
      ports,
      tokens: rt.tokens,
      gateway: "gw1",
      workspace: "ws1",
      epoch: "1",
    },
  };
}

async function enroll(ctx: Ctx) {
  const svc = ctx.rt.service;
  await svc.pairCreate({ role: "agent", scopes: F.scopes, key: F.key.id });
  await svc.challenge({ key: F.key.public, nonce: F.clientNonce });
  await svc.pairPropose(F.registration);
  await svc.pairApprove({
    pair: "pair1",
    proposal: F.proposal,
    key: F.key.id,
    scopes: F.scopes,
  });
  return svc.register(F.registration);
}

function expectThrowCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (e) {
    expect(e).toMatchObject({ name: "RpcError", code });
    return;
  }
  expect.unreachable(`expected RpcError ${code}`);
}

interface BuiltProof {
  fields: RequestProofFields;
  body: RequestProofBody;
  params_sha256: string;
}

/** Build the exact §4.3 proof fields + REQUEST/1 signature. */
function makeProof(opts: {
  nonce?: string;
  id?: string;
  method?: string;
  params?: unknown;
  issued_ms?: number;
  expires_ms?: number;
  access?: string;
  key?: typeof origin;
}): BuiltProof {
  const nonce = opts.nonce ?? token(20);
  const issued_ms = opts.issued_ms ?? now;
  const expires_ms = opts.expires_ms ?? now + 60000;
  const access = opts.access ?? F.access;
  const params_sha256 = sha256Hex(canonicalJson(opts.params ?? { q: 1 }));
  const body = requestProofBody({
    gateway: "gw1",
    workspace: "ws1",
    epoch: "1",
    token_hash: sha256Hex(access),
    id: opts.id ?? "q10",
    method: opts.method ?? "events.publish",
    params_sha256,
    nonce,
    issued_ms,
    expires_ms,
  });
  return {
    fields: {
      nonce,
      epoch: "1",
      issued_ms,
      expires_ms,
      proof: signRequest(body, (opts.key ?? origin).secret),
    },
    body,
    params_sha256,
  };
}

function callWith(ctx: Ctx, p: BuiltProof, id = "q10") {
  return verifyRequestProof(ctx.ctx, {
    access: F.access,
    id,
    method: "events.publish",
    params_sha256: p.params_sha256,
    proof: p.fields,
  });
}

describe("request proof verification (§4.3)", () => {
  it("accepts a fresh well-formed proof and records the nonce", async () => {
    const ctx = setup();
    await enroll(ctx);
    const p = makeProof({});
    const out = callWith(ctx, p);
    expect(out.peer.id).toBe("peer1");
    expect(out.grant.scopes).toEqual(F.scopes);
    expect(ctx.ports.hasNonce(sha256Hex(F.access), p.fields.nonce)).toBe(true);
  });

  it("TV-GW-26: replaying an accepted nonce is AUTH_REQUIRED", async () => {
    const ctx = setup();
    await enroll(ctx);
    const p = makeProof({});
    callWith(ctx, p);
    // The same nonce+proof on a second request never re-executes — even
    // for a different envelope id (the nonce is bound to the token).
    expectThrowCode(() => callWith(ctx, p), "AUTH_REQUIRED");
    expectThrowCode(() => callWith(ctx, p, "q11"), "AUTH_REQUIRED");
  });

  it("TV-GW-27: a stolen token + auditor-signed proof is AUTH_REQUIRED", async () => {
    const ctx = setup();
    await enroll(ctx);
    const p = makeProof({ key: auditor });
    // The signature itself is a valid REQUEST/1 proof — under auditor.
    expect(verifyRequest(p.body, p.fields.proof, auditor.material.public)).toBe(
      true,
    );
    expect(verifyRequest(p.body, p.fields.proof, F.key.public)).toBe(false);
    // …but peer1 is enrolled under origin, so the request is rejected.
    expectThrowCode(() => callWith(ctx, p), "AUTH_REQUIRED");
  });

  it("rejects TTL>60000, future issued_ms, and expiry at equality", async () => {
    const ctx = setup();
    await enroll(ctx);
    expectThrowCode(
      () =>
        callWith(
          ctx,
          makeProof({
            nonce: token(21),
            issued_ms: now,
            expires_ms: now + 60001,
          }),
        ),
      "AUTH_REQUIRED",
    );
    expectThrowCode(
      () =>
        callWith(
          ctx,
          makeProof({
            nonce: token(22),
            issued_ms: now + 5001,
            expires_ms: now + 61000,
          }),
        ),
      "AUTH_REQUIRED",
    );
    ctx.ports.advance(60000);
    // now === expires_ms is already expired (equality semantics).
    expectThrowCode(() => callWith(ctx, makeProof({ nonce: token(23) })), "AUTH_REQUIRED");
  });

  it("rejects proof expiry beyond the access-token expiry", async () => {
    const ctx = setup();
    await enroll(ctx);
    // Access expires at now+900000; a proof claiming longer is rejected.
    const p = makeProof({
      nonce: token(24),
      issued_ms: now + 890000,
      expires_ms: now + 950000,
    });
    ctx.ports.advance(890000);
    expectThrowCode(() => callWith(ctx, p), "AUTH_REQUIRED");
  });

  it("readProofHeaders parses the six §4.3 headers case-insensitively", () => {
    const headers = {
      authorization: "Bearer x",
      "x-latticeag-nonce": token(30),
      "X-LATTICEAG-EPOCH": "1",
      "X-LatticeAG-Issued-Ms": String(now),
      "X-LatticeAG-Expires-Ms": String(now + 60000),
      "X-LatticeAG-Key-Proof": "sig",
    };
    const fields = readProofHeaders(headers);
    expect(fields.epoch).toBe("1");
    expect(fields.issued_ms).toBe(now);
    expect(Object.keys(REQUEST_PROOF_HEADERS)).toHaveLength(6);
    expectThrowCode(() => readProofHeaders({}), "AUTH_REQUIRED");
  });
});

describe("TV-GW-25 — revocation closes sessions, drops deliveries, kills tokens", () => {
  it("revoked peer: old access TOKEN_REVOKED, SSE resume TOKEN_REVOKED", async () => {
    const ctx = setup();
    await enroll(ctx);
    const registry: PeerRegistry = ctx.rt.registry;

    // A live SSE session and a queued undispatched delivery.
    const session = registry.openSession("peer1", "sse", F.cursor);
    expect(session.session).toBe("sess1");
    ctx.ports.putDelivery({
      delivery: "del1",
      peer: "peer1",
      topic: "approval.decision",
      payload: { approval: "approval1" },
      queued_ms: now,
      state: "QUEUED",
    });

    // A valid proof works before revocation.
    callWith(ctx, makeProof({ nonce: token(31) }));

    const out = await ctx.rt.service.revoke({
      peer: "peer1",
      reason: "operator_requested",
    });
    expect(out).toEqual({
      peer: "peer1",
      state: "REVOKED",
      grant_revision: "2",
    });

    // Old access token → TOKEN_REVOKED; session closed; delivery dropped.
    expectThrowCode(() => ctx.rt.tokens.verifyAccess(F.access), "TOKEN_REVOKED");
    expectThrowCode(
      () => callWith(ctx, makeProof({ nonce: token(32) })),
      "TOKEN_REVOKED",
    );
    expectThrowCode(() => registry.resumeSession(session.session), "TOKEN_REVOKED");
    expect(ctx.ports.getSession(session.session)?.state).toBe("CLOSED");
    expect(ctx.ports.deliveriesByPeer("peer1")[0]?.state).toBe("DROPPED");

    // The grant row is durably revoked and the revision bumped.
    const grant = ctx.ports.grantByAccessHash(sha256Hex(F.access));
    expect(grant?.state).toBe("REVOKED");
    expect(ctx.rt.registry.getPeer("peer1").grant_revision).toBe("2");
  });

  it("revocation is idempotent and revoke-on-missing is NOT_FOUND", async () => {
    const ctx = setup();
    await enroll(ctx);
    const first = await ctx.rt.service.revoke({
      peer: "peer1",
      reason: "operator_requested",
    });
    const again = await ctx.rt.service.revoke({
      peer: "peer1",
      reason: "operator_requested",
    });
    expect(again).toEqual(first);
    await expect(
      ctx.rt.service.revoke({ peer: "peerX", reason: "operator_requested" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

describe("native boundary — no CONNECTED without a native ACK", () => {
  it("registered peers stay REGISTERED until markNativeConnected", async () => {
    const ctx = setup();
    await enroll(ctx);
    const peer = ctx.rt.registry.getPeer("peer1");
    expect(peer.state).toBe("REGISTERED");
    // Only the native-ACK edge connects a peer.
    const connected = ctx.rt.registry.markNativeConnected("peer1");
    expect(connected.state).toBe("CONNECTED");
    expect(ctx.rt.registry.disconnect("peer1").state).toBe("DISCONNECTED");
  });
});
