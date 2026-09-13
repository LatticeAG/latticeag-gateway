/**
 * TV-GW-24/28 + §4.1 effective-grant and §4.4 connector-family vectors
 * (TV-GW-57..63).
 */
import { describe, expect, it } from "vitest";
import {
  F,
  capability,
  now,
  origin,
  signed,
  token,
} from "@latticeag/testkit";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import { requestProofBody, signRequest } from "../crypto/pairing.js";
import type { Peer, Scope } from "../protocol/peers.js";
import type { Json } from "../protocol/refs.js";
import {
  assertRole,
  assertScope,
  bindCapabilities,
  effectiveGrant,
  intersectScopes,
  principalRoles,
  scopeCoversProduct,
  scopeCoversRun,
} from "./scopes.js";
import {
  CONNECTOR_FAMILIES,
  CONNECTOR_FAMILY_NAMES,
  familyAssertions,
  isConnectorFamily,
  peerTranscriptValidation,
  type ConnectorFamilyName,
} from "./families.js";
import {
  createMemoryPeerPorts,
  queuedEntropy,
  sequentialIds,
} from "./ports.js";
import { createAgentRuntime } from "./service.js";

function expectThrowCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (e) {
    expect(e).toMatchObject({ name: "RpcError", code });
    return;
  }
  expect.unreachable(`expected RpcError ${code}`);
}

function makePeer(overrides: Partial<Peer> = {}): Peer {
  return {
    id: "peer1",
    source: "src1",
    key: F.key.id,
    role: "agent",
    scopes: [...F.scopes],
    capabilities: [capability],
    state: "REGISTERED",
    grant_revision: "1",
    ...overrides,
  };
}

const manageScope: Scope = {
  permission: "products.manage",
  topics: [],
  runs: [],
  products: ["release1"],
};

describe("§4.1 effective grant — intersection and native binding", () => {
  it("grant = requested ∩ approved ∩ policy, then clipped by capabilities", () => {
    const requested: Scope[] = [
      { permission: "events.emit", topics: ["telemetry", "x"], runs: ["self"], products: [] },
    ];
    const approved: Scope[] = [
      { permission: "events.emit", topics: ["telemetry"], runs: ["self"], products: [] },
    ];
    const policy: Scope[] = [
      { permission: "events.emit", topics: ["telemetry"], runs: ["self"], products: [] },
    ];
    expect(effectiveGrant(requested, approved, policy)).toEqual([
      { permission: "events.emit", topics: ["telemetry"], runs: ["self"], products: [] },
    ]);
    // Native capability binding clips emit topics to ∪cap.emit.
    const bound = bindCapabilities(approved, [
      { emit: [], consume: [], request_approvals: false, lineage: "none" },
    ]);
    expect(bound).toEqual([
      { permission: "events.emit", topics: [], runs: ["self"], products: [] },
    ]);
    // No advertised capability → no approvals.request / lineage.read grant.
    expect(
      bindCapabilities(
        [
          { permission: "approvals.request", topics: [], runs: ["self"], products: [] },
          { permission: "lineage.read", topics: [], runs: ["self"], products: [] },
        ],
        [{ emit: [], consume: [], request_approvals: false, lineage: "none" }],
      ),
    ).toEqual([]);
  });

  it("intersectScopes drops non-matching permissions and keeps dim ∩", () => {
    const a: Scope[] = [
      { permission: "events.consume", topics: ["a", "b"], runs: ["self"], products: [] },
      { permission: "lineage.read", topics: [], runs: ["self"], products: [] },
    ];
    const b: Scope[] = [
      { permission: "events.consume", topics: ["b", "c"], runs: ["self"], products: [] },
    ];
    expect(intersectScopes(a, b)).toEqual([
      { permission: "events.consume", topics: ["b"], runs: ["self"], products: [] },
    ]);
  });
});

describe("TV-GW-24 — scoped agent calling product.install is FORBIDDEN", () => {
  it("agent role fails the O-only role gate regardless of claims", () => {
    const peer = makePeer();
    expectThrowCode(
      () => assertScope(peer, "product.install", { plan_hash: "x" }),
      "FORBIDDEN",
    );
    // Claimed operator status inside params never elevates the peer.
    expectThrowCode(
      () =>
        assertScope(peer, "product.install", {
          plan_hash: "x",
          role_claim: "operator",
        }),
      "FORBIDDEN",
    );
  });

  it("operator tier still needs manage scope + config + confirmation + slug", () => {
    const op = makePeer({ role: "operator", scopes: [manageScope] });
    const params = { slug: "release1" };
    // All four conditions satisfied → admitted.
    assertScope(op, "product.install", params, {
      allowOperator: true,
      localOperatorConfirmation: true,
    });
    // Missing allow_operator.
    expectThrowCode(
      () => assertScope(op, "product.install", params, { localOperatorConfirmation: true }),
      "FORBIDDEN",
    );
    // Missing local confirmation.
    expectThrowCode(
      () => assertScope(op, "product.install", params, { allowOperator: true }),
      "FORBIDDEN",
    );
    // Exact-product check: a different slug is not covered.
    expectThrowCode(
      () =>
        assertScope(op, "product.install", { slug: "other" }, {
          allowOperator: true,
          localOperatorConfirmation: true,
        }),
      "FORBIDDEN",
    );
    // No products.manage scope at all.
    expectThrowCode(
      () =>
        assertScope(makePeer({ role: "operator", scopes: [] }), "product.install", params, {
          allowOperator: true,
          localOperatorConfirmation: true,
        }),
      "FORBIDDEN",
    );
  });
});

describe("TV-GW-28 — viewer role never mutates config", () => {
  it("config.apply with a valid document hash is still FORBIDDEN", () => {
    const viewer = { id: "ui1", role: "viewer" as const };
    expectThrowCode(() => assertRole(viewer, "config.apply"), "FORBIDDEN");
    expectThrowCode(() => assertRole(viewer, "config.validate"), "FORBIDDEN");
    // …but read surfaces stay open to the viewer.
    assertRole(viewer, "daemon.status");
    assertRole(viewer, "events.query");
    // Operator/local operator pass the gate.
    assertRole({ id: "op1", role: "operator" }, "config.apply");
    assertRole({ id: "lo1", role: "local_operator" }, "daemon.stop");
  });

  it("principalRoles maps §3.2 letters and adds reviewer R", () => {
    expect(principalRoles({ role: "viewer" })).toEqual(["V"]);
    expect(principalRoles({ role: "agent", reviewer: true })).toEqual(["A", "R"]);
    expect(principalRoles({ role: "local_operator" })).toEqual(["L"]);
    // A viewer+reviewer claim still fails approval.decide's [R,O] gate? —
    // reviewer is a server-side enrollment flag; a viewer holding R passes
    // the letter check but decide() itself enforces role semantics.
    expect(principalRoles({ role: "viewer", reviewer: true })).toEqual(["V", "R"]);
  });
});

describe("scope admission for events/run methods", () => {
  const peer = makePeer();

  it("events.publish requires the exact emit topic", () => {
    assertScope(peer, "events.publish", { topic: "telemetry" });
    expectThrowCode(
      () => assertScope(peer, "events.publish", { topic: "approval.decision" }),
      "FORBIDDEN",
    );
    expectThrowCode(
      () => assertScope(peer, "events.publish", { topic: "not-a-topic" }),
      "SCHEMA_INVALID",
    );
  });

  it("events.subscribe requires consume coverage for every topic", () => {
    assertScope(peer, "events.subscribe", { topics: ["approval.decision"] });
    expectThrowCode(
      () => assertScope(peer, "events.subscribe", { topics: ["telemetry"] }),
      "FORBIDDEN",
    );
  });

  it("run.* requires self-or-exact run coverage; scopeCovers* agree", () => {
    assertScope(peer, "run.heartbeat", { run_id: "run9" }); // runs:["self"]
    expect(scopeCoversRun(peer, "run9")).toBe(true);
    expect(scopeCoversRun(makePeer({ scopes: [] }), "run9")).toBe(false);
    expect(scopeCoversProduct(peer, "release1")).toBe(false);
    expect(scopeCoversProduct(makePeer({ scopes: [manageScope] }), "release1")).toBe(true);
  });

  it("an agent may disconnect only itself", () => {
    assertScope(peer, "agent.disconnect", { peer: "peer1" });
    expectThrowCode(
      () => assertScope(peer, "agent.disconnect", { peer: "peer2" }),
      "FORBIDDEN",
    );
    assertScope(makePeer({ role: "operator" }), "agent.disconnect", { peer: "peer1" });
  });

  it("unknown method → METHOD_UNKNOWN", () => {
    expectThrowCode(() => assertScope(peer, "nope.method", {}), "METHOD_UNKNOWN");
    expectThrowCode(() => assertRole({ id: "x", role: "agent" }, "nope.method"), "METHOD_UNKNOWN");
  });
});

// ── §4.4 connector families + peerTranscript validation (TV-GW-57..63) ──

const TRANSCRIPT_METHODS = [
  "agent.challenge",
  "agent.pair.propose",
  "agent.pair.approve",
  "agent.register",
  "events.publish",
  "objects.put",
  "events.subscribe",
  "approval.request",
  "lineage.query",
  "agent.disconnect",
] as const;

/** Params recorded on each transcript request line (peer calls covered by F.scopes). */
const EXCHANGE_PARAMS: Record<string, Json> = {
  "agent.challenge": { key: F.key.public, nonce: F.clientNonce },
  "agent.pair.propose": F.registration as unknown as Json,
  "agent.pair.approve": {
    pair: "pair1",
    proposal: F.proposal,
    key: F.key.id,
    scopes: F.scopes,
  } as unknown as Json,
  "agent.register": F.registration as unknown as Json,
  "events.publish": { topic: "telemetry", event: { kind: "heartbeat" } },
  "objects.put": { media: "application/json", bytes: "64" },
  "events.subscribe": { topics: ["approval.decision"], after: null },
  "approval.request": { target: "tool-call", expires_ms: now + 60000 },
  "lineage.query": { run_id: "run1", max_depth: 8 },
  "agent.disconnect": { peer: "peer1" },
};

/**
 * Build the §4.4 `peerTranscript(family,transport,session)` output: one
 * header line plus ten exchange lines. The first four exchanges execute
 * against a real in-memory agent service; the six peer-authenticated
 * exchanges carry real §4.3 headers and REQUEST/1 signatures under the
 * enrolled key. The header labels the native boundary explicitly — no
 * PolyMesh packet is fabricated.
 */
async function generatePeerTranscript(
  family: ConnectorFamilyName,
  transport: string,
  session: string,
): Promise<string[]> {
  const ports = createMemoryPeerPorts({
    now,
    ids: sequentialIds(),
    entropy: queuedEntropy({
      tokens: [F.access, F.refresh],
      nonces: [F.serverNonce],
      pairCodes: [F.code],
    }),
  });
  const rt = createAgentRuntime(ports, {
    gateway: "gw1",
    workspace: "ws1",
    epoch: "1",
  });
  const svc = rt.service;

  const header = {
    connector: { family, transport, session },
    native_boundary: {
      pinned_artifact_required: true,
      fixture_routes: 0,
      interoperability_claim: false,
    },
  };

  // Real pairing-ceremony exchanges.
  const pairCreate = await svc.pairCreate({
    role: "agent",
    scopes: F.scopes,
    key: F.key.id,
  });
  const challenge = await svc.challenge({
    key: F.key.public,
    nonce: F.clientNonce,
  });
  const propose = await svc.pairPropose(F.registration);
  const approve = await svc.pairApprove({
    pair: pairCreate.pair,
    proposal: F.proposal,
    key: F.key.id,
    scopes: F.scopes,
  });
  const register = await svc.register(F.registration);
  const disconnect = await svc.disconnect({ peer: "peer1" });

  const results: Record<string, unknown> = {
    "agent.challenge": challenge,
    "agent.pair.propose": propose,
    "agent.pair.approve": approve,
    "agent.register": register,
    "events.publish": { seq: "5", hash: sha256Hex("event1") },
    "objects.put": { ref: { digest: sha256Hex("o1"), bytes: "64", media: "application/json" } },
    "events.subscribe": { session: "sess1", cursor: F.cursor },
    "approval.request": {
      approval: "approval1",
      revision: "1",
      state: "PENDING",
      authority: "NONE",
    },
    "lineage.query": { edges: [], gaps: [] },
    "agent.disconnect": disconnect,
  };

  const peer = rt.registry.getPeer("peer1");
  let nonceCounter = 40;
  const lines: string[] = [JSON.stringify(header)];
  TRANSCRIPT_METHODS.forEach((method, i) => {
    const id = `q${i + 1}`;
    const params: Json = EXCHANGE_PARAMS[method] ?? ({} as Json);
    const request = { id, method, params, workspace: "ws1" };
    const line: Record<string, unknown> = {
      request,
      response: { result: results[method] },
    };
    if (i >= 4) {
      // Peer-authenticated exchange: §4.3 headers + REQUEST/1 signature.
      // Scope admission is enforced before the exchange is admitted.
      assertScope(peer, method, params);
      const nonce = token(nonceCounter++);
      const body = requestProofBody({
        gateway: "gw1",
        workspace: "ws1",
        epoch: "1",
        token_hash: sha256Hex(F.access),
        id,
        method,
        params_sha256: sha256Hex(canonicalJson(params)),
        nonce,
        issued_ms: now,
        expires_ms: now + 60000,
      });
      line.headers = {
        Authorization: `Bearer ${F.access}`,
        "X-LatticeAG-Nonce": nonce,
        "X-LatticeAG-Epoch": "1",
        "X-LatticeAG-Issued-Ms": String(now),
        "X-LatticeAG-Expires-Ms": String(now + 60000),
        "X-LatticeAG-Key-Proof": signRequest(body, origin.secret),
      };
    }
    lines.push(JSON.stringify(line));
  });
  return lines;
}

describe("§4.4 connector-family table (TV-GW-57..62)", () => {
  it("carries exactly the six spec families in table order", () => {
    expect(CONNECTOR_FAMILY_NAMES).toEqual([
      "openai-completions",
      "openai-agents",
      "hermes",
      "langgraph",
      "custom-http",
      "custom-wss",
    ]);
    for (const name of CONNECTOR_FAMILY_NAMES) {
      expect(isConnectorFamily(name)).toBe(true);
      const f = CONNECTOR_FAMILIES[name];
      // Every family binds the peer key — never a provider API key — and
      // marks fixture approvals hypothetical/local-fixture.
      expect(f.identity.providerKeyIsIdentity).toBe(false);
      expect(f.approval.fixtureApprovalIsHypothetical).toBe(true);
      expect(f.identity.retainedIds.length).toBeGreaterThan(0);
      expect(f.resume.never.length).toBeGreaterThan(0);
    }
    expect(isConnectorFamily("custom HTTP")).toBe(false);
    expect(isConnectorFamily("unknown")).toBe(false);
  });

  it("familyAssertions returns common transcript checks + family rules", () => {
    for (const name of CONNECTOR_FAMILY_NAMES) {
      const assertions = familyAssertions(name);
      expect(assertions.length).toBeGreaterThanOrEqual(6);
      expect(assertions.every((a) => a.vector === CONNECTOR_FAMILIES[name].vectors[0])).toBe(
        true,
      );
      const ids = assertions.map((a) => a.id);
      expect(ids).toContain("ten-exchanges");
      expect(ids).toContain("native-boundary");
      expect(ids).toContain("adapter-required");
      expect(ids).toContain("peer-proofs");
    }
    expect(familyAssertions("langgraph").map((a) => a.id)).toContain(
      "checkpoint-conflict",
    );
    expect(familyAssertions("custom-http").map((a) => a.id)).toContain(
      "control-without-mesh",
    );
    expect(familyAssertions("custom-wss").map((a) => a.id)).toContain(
      "revoked-reconnect",
    );
  });
});

describe("peerTranscript validation — TV-GW-57..62", () => {
  const cases: Array<[ConnectorFamilyName, string, string]> = [
    ["openai-completions", "loopback-http-sse", "completion1"],
    ["openai-agents", "loopback-http-sse", "agent-run1"],
    ["hermes", "loopback-http-sse", "hermes-session1"],
    ["langgraph", "loopback-http-sse", "thread1"],
    ["custom-http", "paired-native-http", "custom-session1"],
    ["custom-wss", "paired-native-wss", "custom-session2"],
  ];

  for (const [family, transport, session] of cases) {
    it(`${family}: ten exchanges validate, ADAPTER_REQUIRED, real proofs`, async () => {
      const lines = await generatePeerTranscript(family, transport, session);
      const out = peerTranscriptValidation(family, lines, {
        verifyKey: origin.material.public,
        gateway: "gw1",
      });
      expect(out.exchanges).toBe(10);
      for (const c of out.checks) {
        expect(c.ok, `${family} check ${c.name}: ${c.detail ?? ""}`).toBe(true);
      }
      expect(out.ok).toBe(true);
    });
  }

  it("a tampered proof header fails peer-proofs-verify", async () => {
    const lines = await generatePeerTranscript(
      "openai-completions",
      "loopback-http-sse",
      "completion1",
    );
    // Line 5 is the first peer-authenticated exchange (events.publish).
    const bad = JSON.parse(lines[5]!);
    bad.headers["X-LatticeAG-Nonce"] = token(90); // signature no longer matches
    lines[5] = JSON.stringify(bad);
    const out = peerTranscriptValidation("openai-completions", lines, {
      verifyKey: origin.material.public,
    });
    expect(out.ok).toBe(false);
    expect(out.checks.find((c) => c.name === "peer-proofs-verify")?.ok).toBe(false);
  });

  it("a transcript claiming mesh routes fails the native boundary check", async () => {
    const lines = await generatePeerTranscript(
      "custom-http",
      "paired-native-http",
      "custom-session1",
    );
    const bad = JSON.parse(lines[0]!);
    bad.native_boundary.fixture_routes = 1;
    lines[0] = JSON.stringify(bad);
    const out = peerTranscriptValidation("custom-http", lines);
    expect(out.ok).toBe(false);
    expect(out.checks.find((c) => c.name === "native-boundary")?.ok).toBe(false);
  });
});

/** Sign a fresh registration bound to `gateway` for the current challenge. */
function registrationFor(
  gateway: string,
  challenge: string,
  serverNonce: string,
) {
  const reg = {
    pair: "pair1",
    code: F.code,
    key: F.key,
    challenge,
    client_nonce: F.clientNonce,
    server_nonce: serverNonce,
    epoch: "1",
    profiles: capability.profiles,
    interfaces: "interfaces/1",
    capabilities: [capability],
  };
  const body = {
    v: 1,
    kind: "register",
    gateway,
    workspace: "ws1",
    epoch: "1",
    pair: reg.pair,
    challenge: reg.challenge,
    client_nonce: reg.client_nonce,
    server_nonce: reg.server_nonce,
    key: reg.key.id,
    profiles: reg.profiles,
    interfaces: reg.interfaces,
    capabilities: reg.capabilities,
  };
  return {
    ...reg,
    proof: signed("LATTICEAG-GATEWAY-PAIR/1", body, origin),
  };
}

describe("TV-GW-63 — no native artifact: every instance reports ADAPTER_REQUIRED", () => {
  it("gw1/gw2/gw3 enroll but never route; no CONNECTED without native ACK", async () => {
    for (const gateway of ["gw1", "gw2", "gw3"] as const) {
      const ports = createMemoryPeerPorts({
        now,
        ids: sequentialIds(),
        entropy: queuedEntropy({
          tokens: [F.access, F.refresh],
          nonces: [F.serverNonce],
          pairCodes: [F.code],
        }),
      });
      // No pinned native mesh artifact on any instance.
      const rt = createAgentRuntime(ports, {
        gateway,
        workspace: "ws1",
        epoch: "1",
      });
      const svc = rt.service;
      await svc.pairCreate({ role: "agent", scopes: F.scopes, key: F.key.id });
      const ch = await svc.challenge({
        key: F.key.public,
        nonce: F.clientNonce,
      });
      const reg = registrationFor(gateway, ch.challenge, ch.nonce);
      await svc.pairPropose(reg);
      await svc.pairApprove({
        pair: "pair1",
        // The proposal hash depends only on key/profiles/interfaces/
        // capabilities — identical across gateways.
        proposal: F.proposal,
        key: F.key.id,
        scopes: F.scopes,
      });
      const out = await svc.register(reg);
      // Federation requested, artifact absent → control-plane enrollment
      // succeeds, mesh reports ADAPTER_REQUIRED, zero frames routed, and
      // the peer is never CONNECTED without a native ACK.
      expect(out.mesh).toBe("ADAPTER_REQUIRED");
      expect(rt.registry.getPeer(out.peer).state).toBe("REGISTERED");
    }
  });
});
