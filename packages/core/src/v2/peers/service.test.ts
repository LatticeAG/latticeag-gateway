/**
 * TV-GW-19..23 + renew — agent.* pairing ceremony vectors (spec §4.2, §3.3).
 */
import { describe, expect, it } from "vitest";
import {
  F,
  H,
  auditor,
  capability,
  now,
  origin,
  signed,
  type FixtureKey,
} from "@latticeag/testkit";
import type { Registration } from "../protocol/peers.js";
import {
  createMemoryPeerPorts,
  queuedEntropy,
  sequentialIds,
  type MemoryPeerPorts,
} from "./ports.js";
import { createAgentRuntime, type AgentRuntime } from "./service.js";

const PAIR_DOMAIN = "LATTICEAG-GATEWAY-PAIR/1";

interface Ctx {
  ports: MemoryPeerPorts;
  rt: AgentRuntime;
}

function setup(): Ctx {
  const ports = createMemoryPeerPorts({
    now,
    ids: sequentialIds(),
    entropy: queuedEntropy({
      tokens: [F.access, F.refresh, F.access2, F.refresh2],
      nonces: [F.serverNonce, F.serverNonce, F.serverNonce],
      pairCodes: [F.code],
    }),
  });
  const rt = createAgentRuntime(ports, {
    gateway: "gw1",
    workspace: "ws1",
    epoch: "1",
  });
  return { ports, rt };
}

/** Run the ceremony up to a registered peer (TV-GW-19 happy path). */
async function enroll({ rt }: Ctx) {
  await rt.service.pairCreate({ role: "agent", scopes: F.scopes, key: F.key.id });
  await rt.service.challenge({ key: F.key.public, nonce: F.clientNonce });
  await rt.service.pairPropose(F.registration);
  await rt.service.pairApprove({
    pair: "pair1",
    proposal: F.proposal,
    key: F.key.id,
    scopes: F.scopes,
  });
  return rt.service.register(F.registration);
}

async function expectRpc(p: Promise<unknown>, code: string): Promise<void> {
  await expect(p).rejects.toMatchObject({ name: "RpcError", code });
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

/** Re-sign a registration variant under a fixture key. */
function signedRegistration(
  overrides: Partial<Registration>,
  k: FixtureKey = origin,
): Registration {
  const reg = { ...F.registration, ...overrides } as Registration;
  const body = {
    v: 1,
    kind: "register",
    gateway: "gw1",
    workspace: "ws1",
    epoch: reg.epoch,
    pair: reg.pair,
    challenge: reg.challenge,
    client_nonce: reg.client_nonce,
    server_nonce: reg.server_nonce,
    key: reg.key.id,
    profiles: reg.profiles,
    interfaces: reg.interfaces,
    capabilities: reg.capabilities,
  };
  return { ...reg, proof: signed(PAIR_DOMAIN, body, k) };
}

describe("TV-GW-19 — full pairing ceremony", () => {
  it("produces the exact §3.3 exchange shapes ending REGISTERED/ADAPTER_REQUIRED", async () => {
    const ctx = setup();
    const svc = ctx.rt.service;

    const created = await svc.pairCreate({
      role: "agent",
      scopes: F.scopes,
      key: F.key.id,
    });
    expect(created).toEqual({
      pair: "pair1",
      code: F.code,
      expires_ms: now + 300000,
    });

    const ch = await svc.challenge({ key: F.key.public, nonce: F.clientNonce });
    expect(ch).toEqual({
      challenge: "challenge1",
      nonce: F.serverNonce,
      audience: "gw1",
      epoch: "1",
      expires_ms: now + 60000,
    });

    const proposed = await svc.pairPropose(F.registration);
    expect(proposed).toEqual({
      pair: "pair1",
      state: "AWAITING_OPERATOR",
      proposal: F.proposal,
      key: F.key.id,
      scopes: F.scopes,
    });

    const view = await svc.pairGet({ pair: "pair1", code: F.code });
    expect(view).toEqual(proposed);

    const approved = await svc.pairApprove({
      pair: "pair1",
      proposal: F.proposal,
      key: F.key.id,
      scopes: F.scopes,
    });
    expect(approved).toEqual({ pair: "pair1", state: "APPROVED" });

    const reg = await svc.register(F.registration);
    expect(reg).toEqual({
      peer: "peer1",
      source: "src1",
      role: "agent",
      scopes: F.scopes,
      access: F.access,
      refresh: F.refresh,
      expires_ms: now + 900000,
      mesh: "ADAPTER_REQUIRED",
    });

    const peer = ctx.rt.registry.getPeer("peer1");
    expect(peer.state).toBe("REGISTERED");
    expect(peer.capabilities).toEqual([capability]);
    expect(peer.grant_revision).toBe("1");
    // The invitation and challenge are consumed by the final commit.
    expect(ctx.ports.getPair("pair1")?.state).toBe("CONSUMED");
    expect(ctx.ports.getChallenge("challenge1")?.consumed).toBe(true);
    // Only token hashes are stored — never the plaintext tokens.
    expect(ctx.ports.grantByAccessHash(H(F.access))?.peer).toBe("peer1");
    expect(ctx.ports.grantByRefreshHash(H(F.refresh))?.peer).toBe("peer1");

    const listed = await svc.list({ after: null, limit: 100 });
    expect(listed.next).toBeNull();
    expect(listed.items).toHaveLength(1);
    expect(listed.items[0]).toMatchObject({
      id: "peer1",
      source: "src1",
      role: "agent",
      state: "REGISTERED",
    });
  });

  it("keeps a changed proposal in AWAITING_OPERATOR and re-approves", async () => {
    const ctx = setup();
    const svc = ctx.rt.service;
    await svc.pairCreate({ role: "agent", scopes: F.scopes, key: null });
    await svc.challenge({ key: F.key.public, nonce: F.clientNonce });
    await svc.pairPropose(F.registration);
    await svc.pairApprove({
      pair: "pair1",
      proposal: F.proposal,
      key: F.key.id,
      scopes: F.scopes,
    });
    // A changed proposal (extra profile) invalidates the approval.
    const changed = signedRegistration({
      profiles: [...capability.profiles, "proof-bundle/1"],
      capabilities: [
        { ...capability, profiles: [...capability.profiles, "proof-bundle/1"] },
      ],
    });
    const view = await svc.pairPropose(changed);
    expect(view.state).toBe("AWAITING_OPERATOR");
    expect(view.proposal).not.toBe(F.proposal);
    // Registering against the stale approval fails — approval invalidated.
    await expectRpc(svc.register(changed), "STATE_TRANSITION");
  });
});

describe("TV-GW-20 — fingerprint mismatch on register", () => {
  it("rejects a validly signed registration under the wrong key (FORBIDDEN)", async () => {
    const ctx = setup();
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

    // The auditor obtains its own challenge and signs a registration.
    const ch2 = await svc.challenge({
      key: auditor.material.public,
      nonce: F.clientNonce,
    });
    const bad = signedRegistration(
      { key: auditor.material, challenge: ch2.challenge },
      auditor,
    );
    await expectRpc(svc.register(bad), "FORBIDDEN");
    // No grant/token/route was created for the auditor key.
    expect(ctx.ports.listPeers()).toHaveLength(0);
    expect(ctx.ports.grants.size).toBe(0);
  });
});

describe("TV-GW-21 — invitation expiry at equality", () => {
  it("register at exactly now+300000 is PAIRING_EXPIRED", async () => {
    const ctx = setup();
    const svc = ctx.rt.service;
    await svc.pairCreate({ role: "agent", scopes: F.scopes, key: F.key.id });
    ctx.ports.advance(300000);
    // A fresh challenge issued at the deadline is itself valid; the
    // invitation is what has expired.
    await svc.challenge({ key: F.key.public, nonce: F.clientNonce });
    await expectRpc(svc.register(F.registration), "PAIRING_EXPIRED");
    expect(ctx.ports.getPair("pair1")?.state).toBe("EXPIRED");
    expect(ctx.ports.listPeers()).toHaveLength(0);
  });
});

describe("TV-GW-22 — five failed attempts lock the invitation", () => {
  it("locks on the fifth wrong-code attempt and stays locked", async () => {
    const ctx = setup();
    const svc = ctx.rt.service;
    await svc.pairCreate({ role: "agent", scopes: F.scopes, key: F.key.id });
    await svc.challenge({ key: F.key.public, nonce: F.clientNonce });

    const wrong = { ...F.registration, code: "0000000000" };
    for (let i = 0; i < 4; i += 1) {
      await expectRpc(svc.pairPropose(wrong), "FORBIDDEN");
    }
    // The fifth failed attempt locks the invitation.
    await expectRpc(svc.pairPropose(wrong), "PAIRING_LOCKED");
    // …and the correct code cannot rescue it (subsequent attempts stay locked).
    await expectRpc(svc.pairPropose(F.registration), "PAIRING_LOCKED");
    // Exactly one lock record — the single LOCKED transition.
    const rec = ctx.ports.getPair("pair1");
    expect(rec?.state).toBe("LOCKED");
    expect(rec?.attempts).toBe(5);
    expect(ctx.ports.listPeers()).toHaveLength(0);
  });
});

describe("TV-GW-23 — unsupported required profile", () => {
  it("register requiring only proof-evidence/9 is SCHEMA_UNSUPPORTED", async () => {
    const ctx = setup();
    const svc = ctx.rt.service;
    await svc.pairCreate({ role: "agent", scopes: F.scopes, key: F.key.id });
    await svc.challenge({ key: F.key.public, nonce: F.clientNonce });
    const reg = signedRegistration({
      profiles: ["proof-evidence/9"],
      capabilities: [{ ...capability, profiles: ["proof-evidence/9"] }],
    });
    // At propose the unknown profile is already rejected before enrollment.
    await expectRpc(svc.pairPropose(reg), "SCHEMA_UNSUPPORTED");
    // And the daemon cannot be enrolled through register either.
    await svc.pairPropose(F.registration);
    await svc.pairApprove({
      pair: "pair1",
      proposal: F.proposal,
      key: F.key.id,
      scopes: F.scopes,
    });
    await expectRpc(svc.register(reg), "SCHEMA_UNSUPPORTED");
    expect(ctx.ports.listPeers()).toHaveLength(0);
  });
});

describe("agent.renew — refresh rotation", () => {
  function seedRenewChallenge(ports: MemoryPeerPorts): void {
    // The renew exchange is an independent fixture step: seed a fresh,
    // unconsumed challenge1 bound to the origin key and the fixture nonces.
    ports.putChallenge({
      challenge: "challenge1",
      key_id: F.key.id,
      key_public: F.key.public,
      client_nonce: F.clientNonce,
      server_nonce: F.serverNonce,
      audience: "gw1",
      epoch: "1",
      created_ms: now,
      expires_ms: now + 60000,
      consumed: false,
    });
  }

  const renewParams = (request_id?: string) => ({
    peer: "peer1",
    refresh: F.refresh,
    challenge: "challenge1",
    server_nonce: F.serverNonce,
    epoch: "1",
    proof: F.renewProof,
    request_id,
  });

  it("rotates both tokens after verifying F.renewProof (RENEW/1)", async () => {
    const ctx = setup();
    await enroll(ctx);
    seedRenewChallenge(ctx.ports);

    const out = await ctx.rt.service.renew(renewParams());
    expect(out).toEqual({
      access: F.access2,
      refresh: F.refresh2,
      expires_ms: now + 900000,
    });

    // The old grant is consumed; the rotated access token verifies.
    expectThrowCode(() => ctx.rt.tokens.verifyAccess(F.access), "TOKEN_REVOKED");
    const verified = ctx.rt.tokens.verifyAccess(F.access2);
    expect(verified.peer.id).toBe("peer1");
    expect(verified.grant.grant_revision).toBe("1");
  });

  it("unrelated reuse of a consumed refresh token revokes the family", async () => {
    const ctx = setup();
    await enroll(ctx);
    seedRenewChallenge(ctx.ports);
    await ctx.rt.service.renew(renewParams());
    // A different request id reusing the consumed refresh revokes all
    // family grants — including the just-issued rotation.
    await expectRpc(
      ctx.rt.service.renew(renewParams("q-other")),
      "TOKEN_REVOKED",
    );
    expectThrowCode(() => ctx.rt.tokens.verifyAccess(F.access2), "TOKEN_REVOKED");
  });

  it("the exact request id replays the saved result", async () => {
    const ctx = setup();
    await enroll(ctx);
    seedRenewChallenge(ctx.ports);
    const first = await ctx.rt.service.renew(renewParams("q42"));
    const replay = await ctx.rt.service.renew(renewParams("q42"));
    expect(replay).toEqual(first);
  });

  it("a tampered renew proof is AUTH_REQUIRED", async () => {
    const ctx = setup();
    await enroll(ctx);
    seedRenewChallenge(ctx.ports);
    const forged = signed(PAIR_DOMAIN, { any: "thing" }, auditor);
    await expectRpc(
      ctx.rt.service.renew({ ...renewParams(), proof: forged }),
      "AUTH_REQUIRED",
    );
  });
});

describe("pair lifecycle extras", () => {
  it("a review outlasting 60 s re-challenges without changing the approval (§4.2 step 5)", async () => {
    const ctx = setup();
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
    // Review outlasted the 60 s challenge window: the stale challenge is
    // rejected but the committed approval survives unchanged.
    ctx.ports.advance(60000);
    await expectRpc(svc.register(F.registration), "AUTH_REQUIRED");
    const ch2 = await svc.challenge({ key: F.key.public, nonce: F.clientNonce });
    expect(ch2.challenge).toBe("challenge2");
    const reg2 = signedRegistration({
      challenge: ch2.challenge,
      server_nonce: ch2.nonce,
    });
    const out = await svc.register(reg2);
    expect(out.peer).toBe("peer1");
    expect(out.mesh).toBe("ADAPTER_REQUIRED");
  });

  it("pair.cancel transitions to CANCELLED and blocks later use", async () => {
    const ctx = setup();
    const svc = ctx.rt.service;
    await svc.pairCreate({ role: "agent", scopes: F.scopes, key: F.key.id });
    const out = await svc.pairCancel({ pair: "pair1" });
    expect(out).toEqual({ pair: "pair1", state: "CANCELLED" });
    await svc.challenge({ key: F.key.public, nonce: F.clientNonce });
    await expectRpc(svc.pairPropose(F.registration), "STATE_TRANSITION");
  });

  it("unapproved register is STATE_TRANSITION; wrong proposal REVISION_CONFLICT", async () => {
    const ctx = setup();
    const svc = ctx.rt.service;
    await svc.pairCreate({ role: "agent", scopes: F.scopes, key: F.key.id });
    await svc.challenge({ key: F.key.public, nonce: F.clientNonce });
    await svc.pairPropose(F.registration);
    await expectRpc(svc.register(F.registration), "STATE_TRANSITION");
    await expectRpc(
      svc.pairApprove({
        pair: "pair1",
        proposal: H("bogus"),
        key: F.key.id,
        scopes: F.scopes,
      }),
      "REVISION_CONFLICT",
    );
  });

  it("disconnect keeps enrollment; agent.list pages", async () => {
    const ctx = setup();
    await enroll(ctx);
    const out = await ctx.rt.service.disconnect({ peer: "peer1" });
    expect(out).toEqual({ peer: "peer1", state: "DISCONNECTED" });
    const listed = await ctx.rt.service.list({ after: null, limit: 1 });
    expect(listed.items).toHaveLength(1);
    expect(listed.items[0]).toMatchObject({ state: "DISCONNECTED" });
  });

  it("issued tokens are 32-byte base64url with a 900 s expiry", async () => {
    const ctx = setup();
    const reg = await enroll(ctx);
    for (const t of [reg.access, reg.refresh]) {
      expect(Buffer.from(t, "base64url")).toHaveLength(32);
    }
    expect(reg.expires_ms - now).toBe(900000);
  });
});
