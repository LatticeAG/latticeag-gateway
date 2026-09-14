/**
 * §3.3 golden exchanges — every one of the 58 registry RPCs driven through
 * the real dispatch pipeline (strict-json bytes → envelope → auth → role →
 * idempotency → service → receipt) against seeded memory ports, asserting
 * the spec's expected `result` verbatim.
 *
 * Fixture determinism is honest: ids come from sequentialIds, tokens from
 * queuedEntropy, state from explicit port seeds or real commits — the same
 * seams the daemon wiring uses. Receipts are asserted by shape (pointer to
 * a committed gateway.action audit event).
 *
 * Two known spec-internal divergences (§3.1 normative fields the §3.3
 * fixture shorthand omits) are asserted field-wise and recorded in
 * STATUS.md: sync.status per-stream cohort/profile metadata and
 * catalog.show's freshness field.
 */
import { describe, expect, test } from "vitest";
import {
  EXCHANGE_SPECS,
  F,
  observation,
  H,
  J,
  now,
  planFor,
  origin,
  auditor,
} from "@latticeag/testkit";
import {
  createGoldenGateway,
  GOLDEN_NOW,
  type GoldenGateway,
} from "./golden-harness.js";
import { NO_RECEIPT_METHODS } from "../core-v2.js";
import {
  canonicalJson,
  requestProofBody,
  sha256Hex,
  signRequest,
} from "../core-v2.js";
import type { TransportCredentials } from "./auth.js";
import type { StoredPeer } from "../../../core/dist/v2/peers/ports.js";
import type { ApprovalRecord } from "../../../core/dist/v2/approvals/ports.js";
import type { PlatformRunEntry } from "../../../core/dist/v2/platform/index.js";

const RECEIPT_SHAPE = {
  workspace: "audit1",
  event: {
    source: "gateway1",
    stream: "gateway.action",
    seq: expect.any(String),
    hash: expect.any(String),
  },
};

/**
 * The spec exchange() param transform (plan injection + review rewrite).
 * The binding names the dispatch principal — "local" for the socket
 * operator (the spec harness calls it "operator1").
 */
function goldenParams(method: string, params: unknown): unknown {
  const p = structuredClone(params) as Record<string, unknown>;
  if (
    ["product.install", "product.uninstall", "product.update", "product.rollback"].includes(method)
  ) {
    p.plan = H(J(planFor(method.split(".")[1]!)));
  }
  if (Object.hasOwn(p, "review")) {
    delete p.review;
    p.review = H(J({ method, params: p, operator: "local", expires_ms: now + 300000 }));
  }
  return p;
}

// ── seeds ────────────────────────────────────────────────────────────────

/** Commit `n` dummy records into the proof lane so the next lands at :n+1. */
async function seedProofLane(gw: GoldenGateway, n: number): Promise<void> {
  for (let i = 0; i < n; i++) {
    await gw.ports.platform.store.commit({
      records: [{ lane: "proof", partition: "ws1", data: new Uint8Array([i + 1]) }],
      result_sha256: sha256Hex(new Uint8Array([i + 1])),
      mutation: { v: 1, kind: "noop" },
    });
  }
}

/**
 * Commit the fixture proof lane: `F.events` is the sealed 5-event
 * src1/main history whose seq-4 `StepClosed` is the action anchor
 * `F.pointer` resolves to. Storing the real lane gives objects.put/get
 * their lane-cut refs (intent+observation), receipt.get its inventory,
 * and lineage.query its gap-free prev/parent walk.
 */
async function seedCommittedAction(gw: GoldenGateway): Promise<void> {
  const records = (F.events as { hash: string }[]).map((e) =>
    Buffer.from(J(e), "utf8"),
  );
  await gw.ports.platform.store.commit({
    records: records.map((data) => ({ lane: "legacy", data })),
    result_sha256: "0".repeat(64),
    mutation: {
      v: 1,
      kind: "events",
      events: (F.events as { body: { seq: string }; hash: string }[]).map(
        (e, i) => {
          const record = records[i]!;
          return {
            workspace: "ws1",
            source: "src1",
            stream: "main",
            seq: e.body.seq,
            hash: e.hash,
            raw_sha256: sha256Hex(
              Buffer.concat([record, Buffer.from([0x0a])]),
            ),
            topic: "main",
            profile: "proof-evidence/1",
            media: "application/json",
            record_bytes: String(record.length),
            record: i,
          };
        },
      ),
    },
  });
  // The committed-action index (native-id form + lineage isAction checks).
  gw.ports.platform.store.seedAction({
    pointer: F.pointer,
    nativeRef: F.nativeRef,
    previous: null,
    principal: "local",
    method: "fixture.call",
  });
  // The lane-cut objects themselves, so objects.get and the lineage
  // observation join resolve real bytes instead of recording a gap.
  for (const b of [F.intent, observation]) {
    const blob = b as { content: string };
    await gw.ports.platform.store.putObject(
      Buffer.from(blob.content, "base64url"),
      1_048_576,
    );
  }
}

function seedSource(gw: GoldenGateway, owner = "local"): void {
  gw.ports.platform.store.seedSource({
    source: "src1",
    key_id: F.key.id,
    public: F.key.public,
    owner,
  });
}

function seedRun(gw: GoldenGateway, patch: Partial<PlatformRunEntry> = {}): void {
  gw.ports.platform.store.seedRun({
    run_id: F.ulid,
    owner: "cli1",
    kit: "openai-completions",
    state: "RUNNING",
    spool_seq: "6",
    exit_code: null,
    signal: null,
    pending_sync: 0,
    ...patch,
  });
}

function seedOp(gw: GoldenGateway, state: string): void {
  gw.ports.platform.store.seedOperation({
    id: "op1",
    principal: "local",
    kind: "install",
    state,
    slug: "lexverdict",
    from: null,
    to: "0.1.0",
    cursor: F.cursor,
    error: null,
  });
}

function seedGeneration(
  gw: GoldenGateway,
  version: string,
  generation: string,
  state: string,
  active: boolean,
): void {
  const rel = version === "0.1.0" ? F.release1 : F.release2;
  gw.ports.lifecycle.putGeneration({
    slug: "lexverdict",
    version,
    generation,
    state,
    active,
    manifest_digest: rel.wire.manifest.ref.digest,
    archive_digest: rel.manifest.package.archive.digest,
    staged_dir: null,
    data_dir: null,
    pid: null,
    dependencies: [],
    activation_indexed: true,
    projected: true,
    snapshot_verified: true,
    irreversible_data: false,
    capabilities_withdrawn: false,
    starts: [],
  } as never);
}

function seedPair(
  gw: GoldenGateway,
  state: string,
  extra: Record<string, unknown> = {},
): void {
  gw.ports.peers.pairs.set("pair1", {
    pair: "pair1",
    code_hash: H(F.code),
    role: "agent",
    scopes: F.scopes,
    pinned_key: F.key.id,
    state,
    epoch: "1",
    attempts: 0,
    proposal: null,
    proposal_key: null,
    proposal_key_material: null,
    proposal_profiles: null,
    proposal_interfaces: null,
    proposal_capabilities: null,
    approved: null,
    created_ms: GOLDEN_NOW,
    expires_ms: GOLDEN_NOW + 300000,
    ...extra,
  } as never);
}

function seedChallenge(gw: GoldenGateway, consumed = false): void {
  gw.ports.peers.challenges.set("challenge1", {
    challenge: "challenge1",
    key_id: F.key.id,
    key_public: F.key.public,
    client_nonce: F.clientNonce,
    server_nonce: F.serverNonce,
    audience: "gw1",
    epoch: "1",
    created_ms: GOLDEN_NOW,
    expires_ms: GOLDEN_NOW + 60000,
    consumed,
  } as never);
}

function seedPeer(gw: GoldenGateway, state = "CONNECTED"): void {
  const peer: StoredPeer = {
    id: "peer1",
    source: "src1",
    key: F.key.id,
    key_material: F.key,
    role: "agent",
    scopes: F.scopes,
    state: state as StoredPeer["state"],
    grant_revision: "1",
    capabilities: [],
    profiles: [],
    interfaces: "interfaces/1",
    session: null,
    connected_ms: null,
    disconnected_ms: null,
    epoch: "1",
    registered_ms: GOLDEN_NOW,
  } as unknown as StoredPeer;
  gw.ports.peers.peers.set("peer1", peer);
  gw.ports.peers.sources.set(F.key.id, "src1");
}

function seedGrant(gw: GoldenGateway): void {
  gw.ports.peers.putGrant({
    grant: "grant1",
    family: "fam1",
    peer: "peer1",
    instance: "gw1",
    workspace: "ws1",
    key_hash: F.key.id,
    role: "agent",
    scopes: F.scopes,
    grant_revision: "1",
    epoch: "1",
    access_hash: H(F.access),
    refresh_hash: H(F.refresh),
    access_expires_ms: GOLDEN_NOW + 900000,
    refresh_expires_ms: GOLDEN_NOW + 2592000000,
    state: "ACTIVE",
    created_ms: GOLDEN_NOW,
  } as never);
}

function seedApproval(gw: GoldenGateway, patch: Partial<ApprovalRecord> = {}): void {
  gw.ports.approvals.putApproval({
    approval: "approval1",
    revision: "1",
    state: "PENDING",
    action: F.nativeRef,
    action_hash: H(J(F.nativeRef)),
    target: "product1",
    expires_ms: GOLDEN_NOW + 60000,
    native: F.intent.ref,
    native_status: "NOT_DISPATCHED",
    authority: "NONE",
    requester: "local",
    created_ms: GOLDEN_NOW,
    decided_ms: null,
    decision: null,
    reason: null,
    reviewer: null,
    ...patch,
  } as ApprovalRecord);
}

/** Drive a real install through the dispatch pipeline (plan → commit → READY). */
async function realInstall(gw: GoldenGateway): Promise<void> {
  const plan = await gw.call(
    "product.plan",
    {
      kind: "install",
      source: "lexverdict",
      version: "0.1.0",
      cascade: false,
      keep_data: true,
    },
    "q-seed-plan",
  );
  expect(plan.status).toBe(200);
  const planHash = (
    plan.response as { result: { plan: string } }
  ).result.plan;
  const acc = await gw.call(
    "product.install",
    { plan: planHash, review: "0".repeat(64) },
    "q-seed-install",
  );
  expect(acc.status).toBe(200);
  const op = (
    acc.response as { result: { operation: string } }
  ).result.operation;
  const done = await gw.product.waitOperation(op);
  expect(done.state).toBe("READY");
}

/** Real peer credentials: Bearer F.access + REQUEST/1 signed headers. */
function peerCreds(method: string, params: unknown, id: string): TransportCredentials {
  const nonce = "peernonce".padEnd(43, "0");
  const issued = GOLDEN_NOW;
  const expires = issued + 60000;
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

// ── per-method configuration ─────────────────────────────────────────────

type Caller = "operator" | "anonymous" | "peer";

interface MethodSetup {
  opts?: Parameters<typeof createGoldenGateway>[0];
  seed?: (gw: GoldenGateway) => void | Promise<void>;
  /** For product.* commits: drive product.plan of this kind first. */
  planFirst?: { kind: string; source?: string; version?: string; cascade?: boolean; keep_data?: boolean };
  /** Transport caller: the §3.3 corpus runs as the socket operator except
   *  the pairing/session-bootstrap (P) and agent.renew (A) methods. */
  as?: Caller;
}

const SETUP: Record<string, MethodSetup> = {
  "daemon.status": { opts: { configDocument: F.config2 } },
  "config.get": { opts: { configDocument: F.config2 } },
  "config.apply": { opts: { configDocument: F.config2 } },
  "run.heartbeat": { seed: (gw) => seedRun(gw) },
  "run.finish": { seed: (gw) => seedRun(gw) },
  "events.publish": {
    seed: async (gw) => {
      seedSource(gw);
      await seedProofLane(gw, 6);
    },
  },
  "events.subscribe": {
    opts: { platformIds: ["sub1"] },
    seed: async (gw) => {
      seedSource(gw);
      await seedProofLane(gw, 7);
    },
  },
  "events.ack": {
    opts: { platformIds: ["sub1"] },
    seed: async (gw) => {
      seedSource(gw);
      await seedProofLane(gw, 6);
      // F.cursor names the 7th committed position; it must be a retained
      // *event* on the subscription's topic with order ≤ the lease's
      // delivered frontier (7, set when subscribe runs below).
      const record = new Uint8Array([7]);
      await gw.ports.platform.store.commit({
        records: [{ lane: "proof", partition: "ws1", data: record }],
        result_sha256: sha256Hex(record),
        mutation: {
          v: 1,
          kind: "events",
          events: [
            {
              workspace: "ws1",
              source: "src1",
              stream: "telemetry",
              seq: "1",
              hash: sha256Hex(record),
              raw_sha256: sha256Hex(
                Buffer.concat([Buffer.from(record), Buffer.from([0x0a])]),
              ),
              topic: "telemetry",
              profile: "proof-evidence/1",
              media: "application/json",
              record_bytes: "1",
            },
          ],
        },
      });
      await gw.call("events.subscribe", { topics: ["telemetry"], after: null }, "q-seed");
    },
  },
  "objects.put": {
    seed: async (gw) => {
      await seedCommittedAction(gw);
    },
  },
  "objects.get": {
    seed: async (gw) => {
      await seedCommittedAction(gw);
      await gw.ports.platform.store.putObject(
        Buffer.from(F.intent.content, "base64url"),
        1 << 20,
      );
    },
  },
  "receipt.get": {
    seed: async (gw) => {
      await seedCommittedAction(gw);
    },
  },
  "lineage.query": {
    seed: async (gw) => {
      await seedCommittedAction(gw);
    },
  },
  "operation.get": { seed: (gw) => seedOp(gw, "READY") },
  "operation.cancel": { seed: (gw) => seedOp(gw, "QUEUED") },
  "product.plan": {},
  "product.install": {
    planFirst: { kind: "install", source: "lexverdict", version: "0.1.0", cascade: false, keep_data: true },
  },
  "product.uninstall": {
    planFirst: { kind: "uninstall", source: "lexverdict" },
    seed: (gw) => seedGeneration(gw, "0.1.0", "1", "READY", true),
  },
  "product.update": {
    planFirst: { kind: "update", source: "lexverdict", version: "0.1.1" },
    seed: (gw) => seedGeneration(gw, "0.1.0", "1", "READY", true),
  },
  "product.rollback": {
    planFirst: { kind: "rollback", source: "lexverdict", version: "0.1.0" },
    seed: (gw) => {
      seedGeneration(gw, "0.1.0", "1", "STOPPED_RETAINED", false);
      seedGeneration(gw, "0.1.1", "2", "READY", true);
    },
  },
  "product.health": {
    seed: async (gw) => {
      await realInstall(gw);
    },
  },
  "agent.pair.create": { opts: { peerPairCodes: [F.code] } },
  "agent.pair.propose": {
    as: "anonymous",
    seed: (gw) => {
      seedPair(gw, "CREATED");
      seedChallenge(gw);
    },
  },
  "agent.pair.get": {
    seed: (gw) =>
      seedPair(gw, "AWAITING_OPERATOR", {
        proposal: F.proposal,
        proposal_key: F.key.id,
        proposal_key_material: F.key,
        proposal_profiles: ["@latticeag/events@0.1.0", "proof-evidence/1"],
        proposal_interfaces: "interfaces/1",
        proposal_capabilities: F.registration.capabilities,
      }),
  },
  "agent.pair.approve": {
    seed: (gw) =>
      seedPair(gw, "AWAITING_OPERATOR", {
        proposal: F.proposal,
        proposal_key: F.key.id,
        proposal_key_material: F.key,
        proposal_profiles: ["@latticeag/events@0.1.0", "proof-evidence/1"],
        proposal_interfaces: "interfaces/1",
        proposal_capabilities: F.registration.capabilities,
      }),
  },
  "agent.pair.cancel": { seed: (gw) => seedPair(gw, "AWAITING_OPERATOR") },
  "agent.challenge": { as: "anonymous", opts: { peerNonces: [F.serverNonce] } },
  "agent.register": {
    as: "anonymous",
    opts: { peerTokens: [F.access, F.refresh] },
    seed: (gw) => {
      seedPair(gw, "APPROVED", {
        proposal: F.proposal,
        proposal_key: F.key.id,
        proposal_key_material: F.key,
        proposal_profiles: ["@latticeag/events@0.1.0", "proof-evidence/1"],
        proposal_interfaces: "interfaces/1",
        proposal_capabilities: F.registration.capabilities,
        approved: { proposal: F.proposal, key: F.key.id, scopes: F.scopes },
      });
      seedChallenge(gw);
    },
  },
  "agent.renew": {
    as: "peer",
    opts: { peerTokens: [F.access2, F.refresh2] },
    seed: (gw) => {
      seedPeer(gw);
      seedGrant(gw);
      seedChallenge(gw);
    },
  },
  "agent.revoke": { seed: (gw) => seedPeer(gw) },
  "agent.disconnect": { seed: (gw) => seedPeer(gw, "CONNECTED") },
  "approval.get": { seed: (gw) => seedApproval(gw) },
  "approval.decide": { seed: (gw) => seedApproval(gw) },
  "approval.cancel": { seed: (gw) => seedApproval(gw) },
  "ui.session.create": { opts: { platformTokens: [F.bootstrap] } },
  "ui.session.exchange": {
    as: "anonymous",
    opts: { platformTokens: ["session1", F.csrf] },
    seed: (gw) => {
      void gw.ports.platform.sessionStore.bootstrapPut({
        hash: H(F.bootstrap),
        role: "viewer",
        expires_ms: GOLDEN_NOW + 60000,
      });
    },
  },
  "ui.session.revoke": {
    seed: (gw) => {
      void gw.ports.platform.sessionStore.sessionPut({
        hash: H("session1"),
        role: "viewer",
        csrf_sha256: H(F.csrf),
        owner: "local",
        expires_ms: GOLDEN_NOW + 28800000,
        idle_expires_ms: GOLDEN_NOW + 1800000,
        created_ms: GOLDEN_NOW,
        state: "ACTIVE",
      });
    },
  },
  "sync.resume": { opts: { consented: ["receipts"] } },
  "cloud.pair.begin": { opts: { cloudIds: ["enroll1"], cloudPairCodes: [F.code] } },
  "cloud.pair.complete": {
    opts: { cloudIds: ["cloud1"] },
    seed: (gw) => {
      gw.ports.cloud.putEnrollment({
        id: "enroll1",
        provider: "hosted",
        streams: ["receipts"],
        remote_ui: false,
        user_code: F.code,
        state: "AWAITING_PROVIDER",
        created_ms: GOLDEN_NOW,
        expires_ms: GOLDEN_NOW + 300000,
      });
    },
  },
  "cloud.pair.revoke": {
    seed: (gw) => {
      gw.ports.cloud.putCloud({
        id: "cloud1",
        provider: "hosted",
        binding: F.nativeRef,
        streams: ["receipts"],
        remote_ui: false,
        role: "viewer",
        state: "PAIRED",
        paired_ms: GOLDEN_NOW,
        remote_notice: null,
      });
    },
  },
  "catalog.refresh": { opts: { catalogIndex: F.index } },
  "catalog.search": { opts: { catalogCache: true } },
  "catalog.show": { opts: { catalogCache: true } },
  "catalog.pin": { opts: { catalogCache: true } },
  "catalog.unpin": {
    opts: { catalogCache: true },
    seed: (gw) => {
      (gw.ports.catalog.pinList as unknown[]).push(F.pin);
      gw.ports.catalog.pinRev = 2n;
    },
  },
};

// ── the suite ────────────────────────────────────────────────────────────

describe("§3.3 golden exchanges", () => {
  test("registry covers exactly the 58 spec exchanges", () => {
    expect(EXCHANGE_SPECS.length).toBe(58);
  });

  let n = 0;
  for (const spec of EXCHANGE_SPECS) {
    const id = `q${++n}`;
    test(`§3.3 ${spec.method}`, async () => {
      const setup = SETUP[spec.method] ?? {};
      const gw = createGoldenGateway(setup.opts ?? {});
      await setup.seed?.(gw);

      if (setup.planFirst !== undefined) {
        const plan = await gw.call(
          "product.plan",
          {
            kind: setup.planFirst.kind,
            source: setup.planFirst.source ?? "lexverdict",
            ...(setup.planFirst.version !== undefined
              ? { version: setup.planFirst.version }
              : {}),
            cascade: setup.planFirst.cascade ?? false,
            keep_data: setup.planFirst.keep_data ?? true,
          },
          "q-plan",
        );
        expect(plan.status, `plan for ${spec.method}`).toBe(200);
      }

      const params = goldenParams(spec.method, spec.params);
      const caller = setup.as ?? "operator";
      const creds: TransportCredentials =
        caller === "peer"
          ? peerCreds(spec.method, params, id)
          : caller === "anonymous"
            ? { kind: "anonymous" }
            : { kind: "local" };
      const out = await gw.callAs(creds, spec.method, params, id);
      expect(
        out.status,
        `${spec.method} → ${JSON.stringify(out.response)}`,
      ).toBe(200);
      const res = out.response as {
        v: number;
        id: string;
        ok: boolean;
        result: Record<string, unknown>;
        receipt: unknown;
      };
      expect(res.v).toBe(2);
      expect(res.id).toBe(id);
      expect(res.ok).toBe(true);

      if (spec.method === "sync.status") {
        // §3.1 adds per-stream redaction/cohort metadata the §3.3 fixture
        // shorthand omits — assert the normative count fields verbatim.
        const result = res.result as {
          paused: boolean;
          streams: Record<string, Record<string, unknown>>;
          cloud: unknown;
        };
        expect(result.paused).toBe(false);
        expect(result.cloud).toBeNull();
        for (const [s, counts] of Object.entries(
          (spec.result as { streams: Record<string, Record<string, unknown>> })
            .streams,
        )) {
          expect(result.streams[s]).toMatchObject(counts);
        }
      } else if (spec.method === "catalog.show") {
        // §3.2 catalog.show carries trust freshness beside the entry; the
        // §3.3 literal predates it — assert the fixture fields verbatim.
        const entry = (res.result as { entry: Record<string, unknown> }).entry;
        expect(entry).toMatchObject(
          (spec.result as { entry: Record<string, unknown> }).entry,
        );
        expect(entry.freshness).toBe("CURRENT");
      } else {
        expect(res.result).toEqual(spec.result);
      }

      if (NO_RECEIPT_METHODS.has(spec.method)) {
        expect(res.receipt).toBeNull();
      } else {
        expect(res.receipt).toEqual(RECEIPT_SHAPE);
      }
      await gw.product.engine.close();
    });
  }
});
