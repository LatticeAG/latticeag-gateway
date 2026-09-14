/**
 * TV-X-01 … TV-X-32 — the cross-product interface reference vectors from
 * INTERFACES.md §4, ported faithfully to TypeScript/Vitest.
 *
 * What this file is (and is not), per spec §4.1:
 *  - The vectors are *interface* tests over fully defined inputs. They are
 *    not proof that the 25 named product implementations ran — none of
 *    those native runtimes exist in this repository, so the reference
 *    checks below are the executable form of the vectors exactly as
 *    published (same fixtures, same expected literals/predicates).
 *  - Reference primitives (J, H, D, B64, UN64, I, signed_ok) are
 *    re-implemented verbatim from §4.2 so the vectors stay self-contained.
 *  - Where this repository owns the same primitive, the test additionally
 *    cross-checks it: the testkit prelude's `J`/`H` must agree with the
 *    §4.2 reference functions on every fixture input, and the prelude's
 *    `origin`/`auditor` keys ARE the vector's SK/SK2 (same RFC 8032 test
 *    seeds — public fixture material, never production identity).
 *  - Real-repo counterparts of the boundaries these vectors model are
 *    covered where the implementation actually lives: strict-JSON input
 *    rejection is exercised on the real control socket in
 *    `packages/cli/src/e2e/daemon.test.ts` and `packages/gateway-daemon/
 *    src/net/strict-json.test.ts`; the OBJECT_LIMIT pre-allocation bound
 *    is exercised by the real `objects.put` service in
 *    `packages/core/src/v2/platform/platform.test.ts` and on the wire in
 *    the e2e suite.
 *  - `test.todo` entries at the bottom mark the native-verifier
 *    counterparts the spec requires of a full conformance runner
 *    (§4.1: "a production conformance runner MUST replace those ports
 *    with real pinned native verifiers"). They are exclusions, not
 *    passes: the products they name are not present in this repository.
 */

import { describe, expect, test } from "vitest";
import { Buffer } from "node:buffer";
import { createHash, sign, verify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { H, J, auditor, origin } from "./prelude.mts";

// ── §4.2 reference primitives (ported verbatim) ─────────────────────────

/** §4.2 J: fixture-profile canonical JSON, UTF-16BE key ordering. */
function jRef(x: unknown): Buffer {
  if (x === null || typeof x === "boolean" || typeof x === "string") {
    return Buffer.from(JSON.stringify(x), "utf8");
  }
  if (
    typeof x === "number" &&
    Number.isInteger(x) &&
    Math.abs(x) <= 9007199254740991
  ) {
    return Buffer.from(String(x), "ascii");
  }
  if (Array.isArray(x)) {
    return Buffer.concat([
      Buffer.from("["),
      ...x.flatMap((v, i) => (i === 0 ? [jRef(v)] : [Buffer.from(","), jRef(v)])),
      Buffer.from("]"),
    ]);
  }
  if (x !== null && typeof x === "object") {
    const obj = x as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (!keys.every((k) => typeof k === "string")) {
      throw new Error("outside fixture JSON profile");
    }
    const sorted = keys.sort((a, b) => {
      const ab = utf16be(a);
      const bb = utf16be(b);
      return Buffer.compare(ab, bb);
    });
    const parts: Buffer[] = [Buffer.from("{")];
    sorted.forEach((k, i) => {
      if (i > 0) parts.push(Buffer.from(","));
      parts.push(jRef(k), Buffer.from(":"), jRef(obj[k]));
    });
    parts.push(Buffer.from("}"));
    return Buffer.concat(parts);
  }
  throw new Error("outside fixture JSON profile");
}

function utf16be(s: string): Buffer {
  const b = Buffer.alloc(s.length * 2);
  for (let i = 0; i < s.length; i += 1) b.writeUInt16BE(s.charCodeAt(i), i * 2);
  return b;
}

/** §4.2 H: sha256 hex digest of bytes. */
function hRef(b: Buffer | string): string {
  return createHash("sha256").update(b).digest("hex");
}

/** §4.2 D: domain-separated digest D(tag, x) = H(tag‖0x00‖J(x)). */
function dRef(tag: string, x: unknown): string {
  return hRef(Buffer.concat([Buffer.from(`${tag}\0`, "ascii"), jRef(x)]));
}

const b64 = (b: Buffer): string => b.toString("base64url");
const un64 = (s: string): Buffer => Buffer.from(s, "base64url");
const iRef = (prefix: string, n: number): string =>
  `${prefix}_${String(n).padStart(21, "0")}`;

function signedOk(publicKey: KeyObject, signature: Buffer, message: Buffer): boolean {
  try {
    return verify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}

/** §4.2 raw_ref / admission helpers used by the join vectors. */
function rawRef(
  profile: string,
  namespace: string,
  objectId: string,
  commitment: string,
  value: unknown,
): Record<string, unknown> {
  const raw = jRef(value);
  return {
    profile,
    namespace,
    object_id: objectId,
    commitment,
    raw_sha256: hRef(raw),
    bytes: String(raw.length),
  };
}
const admission = (supported: boolean, allowed = true): string =>
  supported && allowed ? "ELIGIBLE" : "UNSUPPORTED_COMPOSITION";

// ── §4.2 fixtures ────────────────────────────────────────────────────────

const ZERO = "0".repeat(64);
const SK = origin.secret; // 9d61b19d… — the vector's SK
const PK = origin.public;
const SK2 = auditor.secret; // 4ccd089b… — the vector's SK2
const PK2 = auditor.public;
const PK_HEX = Buffer.from(origin.material.public, "base64url").toString("hex");
const PK2_HEX = Buffer.from(auditor.material.public, "base64url").toString(
  "hex",
);

const E1_BODY = {
  v: 1, world: "w1", claim: "cA", branch: "main", seq: "1",
  prev: ZERO, kind: "ClaimCreated", schema: 1, actor: "pAdmin",
  command: "q1", causes: [] as unknown[], lamport: "1", tick_ms: "1000",
  writer_epoch: "1", policy: "policy1",
  payload: { owner: "pAdmin", auth_rev: "1", state_rev: "0" },
};
const E1_HASH = "8bc4334746ebf1500f4862e2357f82e5401a03bc0d9e4c9ac6c80f56a13efca9";
const E1_SIG =
  "-IUor-21OqWX57iXPhKlLBCoXyPNMR7GINmFQcSqna-FNCQlWpomvyGPLMuxdab-UHwOMRVlxl8VdXV1rnn2Bg";
const E1 = { body: E1_BODY, hash: E1_HASH, key_id: "writer-test-1", signature: E1_SIG };

const M1 = {
  data: { asset: "SIMUSD", market_id: "m1", policy: "mint-policy-1" },
  prev: ZERO, seq: 1, time: "2026-09-12T00:00:00.000Z", type: "MarketOpened",
};
const M1_HASH = "fe5d2302525732816f2b6940e9b931ae5c3583c179cfcf2284dbfec664a9819f";
const M2 = {
  data: { actor: "poster-1", amount: "12700", external_ref: "sim-deposit-1" },
  prev: M1_HASH, seq: 2, time: "2026-09-12T00:00:01.000Z", type: "AccountCredited",
};
const M2_HASH = "dd7b3f2b81bb5c1a7494d69aed4be2540cb0f04b4666398cd8b04c176efcc3d8";

const T = 1_000_000;
const OBS = {
  v: 1,
  challenge: `lnn_${"B".repeat(32)}`,
  card_hash: hRef(Buffer.from("card-fixture")),
  sub: iRef("lsu", 1),
  caller_jkt: b64(Buffer.from(hRef(Buffer.from("caller-jwk-fixture")), "hex")),
  status: "active",
  checked_at: T,
  valid_until: T + 5,
  evidence_hash: hRef(Buffer.from("retained-herald-evidence-fixture")),
};

function observationOk(
  o: typeof OBS,
  nowMs: number,
  challenge: string,
): boolean {
  return (
    o.status === "active" &&
    o.challenge === challenge &&
    o.checked_at <= nowMs &&
    nowMs < o.valid_until &&
    o.valid_until - o.checked_at > 0 &&
    o.valid_until - o.checked_at <= 5
  );
}

/** Every vector must record exactly once — mirrors §4.2 `check`. */
const checked: string[] = [];
function check(vector: string, actual: unknown, expected: unknown): void {
  expect(checked).not.toContain(vector);
  checked.push(vector);
  expect(actual, vector).toEqual(expected);
}

// ── the vectors ──────────────────────────────────────────────────────────

describe("TV-X cross-product interface vectors (INTERFACES.md §4)", () => {
  test("reference primitives agree with the repo's own canonicalizer", () => {
    // The §4.2 J/H are the vector's reference functions; the testkit
    // prelude's J/H are this repo's production fixture implementations.
    // They must agree byte-for-byte on the shared fixture domain.
    for (const value of [E1_BODY, M1, M2, OBS, { nested: [1, "é", null, true] }]) {
      expect(J(value)).toBe(jRef(value).toString("utf8"));
    }
    expect(H(jRef(E1_BODY))).toBe(hRef(jRef(E1_BODY)));
    // The vector keys are exactly the prelude's origin/auditor seeds.
    expect(origin.material.id).toMatch(/^[0-9a-f]{64}$/);
    expect(PK_HEX).toHaveLength(64);
    expect(PK2_HEX).toHaveLength(64);
  });

  test("TV-X-01: World bytes survive a Proof object round trip", () => {
    const raw = jRef(E1);
    const blobObj = {
      ref: { digest: hRef(raw), bytes: String(raw.length), media: "application/json" },
      content: b64(raw),
    };
    const msg = Buffer.concat([
      Buffer.from("LAGI-WORLD-SIGN/v1\0"),
      Buffer.from(E1_HASH, "hex"),
    ]);
    check(
      "TV-X-01",
      [
        dRef("LAGI-WORLD-EVENT/v1", E1_BODY),
        un64(blobObj.content).equals(raw),
        signedOk(PK, un64(E1_SIG), msg),
        E1.hash,
        E1.signature,
      ],
      [E1_HASH, true, true, E1_HASH, E1_SIG],
    );
  });

  test("TV-X-02: World receipt is opaque, not Proof FULL_REPLAY", () => {
    const worldClaim = {
      world: "w1", claim: "cA", branch: "main", crossing: "x1",
      intent: null, simulation: null, authority: [], preparation: [],
      dispatch: null,
      result: { outcome: "UNKNOWN" },
      dependencies: [], checkpoints: [], artifacts: [],
      disclosure: "HASHES_ONLY",
    };
    const installed = new Set(["proof-evidence/1"]);
    check(
      "TV-X-02",
      {
        bridge: admission(installed.has("world-lineage/1")),
        assessment: "NOT_EVALUATED",
        dispatches: 0,
        raw_preserved: un64(b64(jRef(worldClaim))).equals(jRef(worldClaim)),
      },
      {
        bridge: "UNSUPPORTED_COMPOSITION",
        assessment: "NOT_EVALUATED",
        dispatches: 0,
        raw_preserved: true,
      },
    );
  });

  test("TV-X-03: Mint log hashes remain Mint hashes in World/Treaty evidence", () => {
    const leaf1 = createHash("sha256")
      .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(M1_HASH, "hex")]))
      .digest();
    const leaf2 = createHash("sha256")
      .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(M2_HASH, "hex")]))
      .digest();
    check(
      "TV-X-03",
      [
        dRef("mint.log.v1", M1),
        dRef("mint.log.v1", M2),
        hRef(Buffer.concat([Buffer.from([0x01]), leaf1, leaf2])),
        false, // unsigned fixture: no checkpoint authentication may be claimed
      ],
      [
        M1_HASH,
        M2_HASH,
        "2d1c91f6c3128ca2e623cc74e700abf7427c8bdb1cffe9e696ec354b888ca329",
        false,
      ],
    );
  });

  test("TV-X-04: Mint slash evidence references a Treaty decision without laundering authority", () => {
    const slash = {
      seq: 64, prev: M2_HASH, time: "2026-09-12T01:00:00.000Z",
      type: "SlashApplied",
      data: {
        task_id: "t1", reservation_id: "res-e1", amount: "1250",
        order_id: "order-appeal-1",
      },
    };
    const treatyHash = (x: unknown): string =>
      `sha256:${dRef("LATTICEAGI-TREATY-OBJECT/1", x)}`;
    const decision = {
      schema: "treaty-decision/1",
      operation: `sha256:${hRef(Buffer.from("operation-fixture"))}`,
      decision: "commit",
      votes: [
        `sha256:${hRef(Buffer.from("amber-ready"))}`,
        `sha256:${hRef(Buffer.from("harbor-ready"))}`,
      ].sort(),
    };
    const join = {
      schema: "interfaces.evidence-join/1",
      subject: rawRef("mint.log.v1", "m1", "64", dRef("mint.log.v1", slash), slash),
      related: [
        rawRef("treaty-decision/1", "treaty-fixture", "decision1", treatyHash(decision), decision),
      ],
      relation: "supports",
      assessment: "OPAQUE",
    };
    check(
      "TV-X-04",
      [
        (join.related[0] as { commitment: string }).commitment === treatyHash(decision),
        (join.related[0] as { raw_sha256: string }).raw_sha256 === hRef(jRef(decision)),
        join.assessment,
        0,
      ],
      [true, true, "OPAQUE", 0],
    );
  });

  test("TV-X-05: Treaty READY is not an expiring World preparation", () => {
    const x05 = { state: "READY", timer_elapsed: true, abort_certificate: false };
    check(
      "TV-X-05",
      {
        state:
          x05.state === "READY" && !x05.abort_certificate
            ? "IN_DOUBT"
            : "RESOLVED",
        reservation_retained: !x05.abort_certificate,
        releases: 0,
      },
      { state: "IN_DOUBT", reservation_retained: true, releases: 0 },
    );
  });

  test("TV-X-06: Treaty cannot dispatch a Covenant refund as prepared apply", () => {
    check(
      "TV-X-06",
      {
        code: admission(new Set(["fenced-kv/1"]).has("covenant-stripe-refund")),
        stages: 0,
        sends: 0,
      },
      { code: "UNSUPPORTED_COMPOSITION", stages: 0, sends: 0 },
    );
  });

  test("TV-X-07: Herald observation accepted by LexScope before expiry", () => {
    check(
      "TV-X-07",
      [
        observationOk(OBS, T + 4, OBS.challenge),
        observationOk(OBS, T + 5, OBS.challenge),
        observationOk(OBS, T + 4, "lrq_changed"),
      ],
      [true, false, false],
    );
  });

  test("TV-X-08: Herald key rotation does not multiply Mint/VQ principals", () => {
    const keysToGroup: Record<string, string> = {
      "key-old": "group1",
      "key-new": "group1",
    };
    const distinct = new Set(Object.values(keysToGroup)).size;
    check(
      "TV-X-08",
      { distinct_principals: distinct, threshold_met: distinct >= 2 },
      { distinct_principals: 1, threshold_met: false },
    );
  });

  const VQH = (kind: string, x: unknown): string =>
    `vq1:${hRef(Buffer.concat([Buffer.from(`VekQuorum/${kind}/1\n`), jRef(x)]))}`;
  const VQS = (kind: string, x: unknown): Buffer =>
    Buffer.concat([
      Buffer.from(`VekQuorum/sign/${kind}/1\n`),
      Buffer.from(VQH(kind, x).slice(4), "hex"),
    ]);

  const policy = {
    v: 1, tenant: iRef("vqt", 1), policy_id: iRef("vqp", 1), version: 1,
    executor_id: iRef("vqx", 1), environment: "test", tool: "run.pause",
    threshold: 2,
    roster: [
      { key_id: iRef("vqk", 1), principal_id: iRef("vqu", 1), kind: "human", public_key: PK_HEX },
      { key_id: iRef("vqk", 2), principal_id: iRef("vqu", 2), kind: "human", public_key: PK2_HEX },
    ],
    require_human: true, max_ttl_ms: 60000, enrichment_required: false,
  };
  const action = {
    v: 1, tenant: iRef("vqt", 1), proposal_id: iRef("vqa", 1),
    operation_id: iRef("vqo", 1), executor_id: iRef("vqx", 1),
    proposer_id: iRef("vqu", 1), environment: "test", tool: "run.pause",
    args: {
      alert_digest: hRef(Buffer.from("watch-alert-fixture")),
      identity_evidence_digest: OBS.evidence_hash,
      run: "run1",
    },
    policy_hash: VQH("policy", policy),
    authority_epoch: 1, created_ms: T * 1000, expires_ms: T * 1000 + 60000,
    nonce: iRef("vqn", 1), preconditions: [] as unknown[], enrichment_hash: null,
    oversight: {
      goal: "Review local pause",
      human_initiator: iRef("vqu", 1),
      trace_id: iRef("vqc", 1),
      parent_receipt_hash: null,
    },
    external_refs: [] as unknown[],
  };
  const votes = [
    { n: 1, key: SK, pub: PK },
    { n: 2, key: SK2, pub: PK2 },
  ].map(({ n, key }) => {
    const body = {
      v: 1, action_hash: VQH("action", action), policy_hash: VQH("policy", policy),
      key_id: iRef("vqk", n), decision: "approve",
    };
    return { body, signature: sign(null, VQS("vote", body), key).toString("hex") };
  });

  test("TV-X-09: Watch alert + Herald identity passes a separately authorized VQ gate", () => {
    const principalMap = new Map<string, string>([
      [`${OBS.card_hash}|${OBS.sub}|${OBS.caller_jkt}`, iRef("vqu", 1)],
    ]);
    const identityKey = `${OBS.card_hash}|${OBS.sub}|${OBS.caller_jkt}`;
    const pubs = [PK, PK2];
    const validPrincipals = new Set(
      policy.roster
        .map((member, idx) => ({ member, public: pubs[idx]!, vote: votes[idx]! }))
        .filter(
          ({ member, public: pub, vote }) =>
            vote.body.key_id === member.key_id &&
            vote.body.action_hash === VQH("action", action) &&
            vote.body.policy_hash === VQH("policy", policy) &&
            vote.body.decision === "approve" &&
            signedOk(pub, Buffer.from(vote.signature, "hex"), VQS("vote", vote.body)),
        )
        .map(({ member }) => member.principal_id),
    );
    const validVotes = validPrincipals.size;
    const identityValid =
      observationOk(OBS, T + 4, OBS.challenge) &&
      principalMap.get(identityKey) === action.proposer_id;
    check(
      "TV-X-09",
      {
        identity: identityValid,
        approvals: validVotes,
        eligible: identityValid && validVotes >= 2,
        eligible_without_votes: identityValid && 0 >= 2,
        mapped_without_enrollment:
          new Map<string, string>().get(identityKey) === action.proposer_id,
        dispatches: 0,
      },
      {
        identity: true,
        approvals: 2,
        eligible: true,
        eligible_without_votes: false,
        mapped_without_enrollment: false,
        dispatches: 0,
      },
    );
  });

  test("TV-X-10: VQ signature cannot become a Charter/Bedrock policy signature", () => {
    const probe = votes[0]!.body;
    const policyMessage = (owner: string, kind: string, x: unknown): Buffer => {
      const digest = hRef(Buffer.concat([Buffer.from(`LAGI-${owner}/${kind}/1\n`), jRef(x)]));
      return Buffer.from(`LAGI-${owner}/sign/${kind}/1\n${digest}`);
    };
    const sig = Buffer.from(votes[0]!.signature, "hex");
    check(
      "TV-X-10",
      [
        signedOk(PK, sig, VQS("vote", probe)),
        signedOk(PK, sig, policyMessage("CHARTER", "policy", probe)),
        signedOk(PK, sig, policyMessage("BEDROCK", "charter", probe)),
      ],
      [true, false, false],
    );
  });

  test("TV-X-11: LexTier BlastCard survives VQ enrichment without hash collapse", () => {
    const blastEvidence: Record<string, unknown> = {
      status: "known",
      target: { resource: "file:/workspace/drafts/a.txt", version: "7", digest: hRef(Buffer.from("old")) },
      files: 1, rows: null, money: null,
      undo: { kind: "none", instruction: "No verified undo path." },
      observed_ms: T,
    };
    const card: Record<string, unknown> = {
      ...blastEvidence,
      evidence_hash: hRef(jRef(blastEvidence)),
    };
    const enrichment = {
      v: 1,
      source: "lextier-stop-card/1",
      source_action_hash: hRef(Buffer.from("lextier-action-fixture")),
      card,
    };
    check(
      "TV-X-11",
      [
        enrichment.card === card,
        card["evidence_hash"] !== hRef(jRef(card)),
        VQH("enrichment", enrichment).startsWith("vq1:"),
        enrichment.card["observed_ms"],
      ],
      [true, true, true, T],
    );
  });

  test("TV-X-12: No name-only LexScope→LexTier tool alias", () => {
    const tierTools = new Set([
      "db.delete_rows", "db.select_rows", "fs.read_text",
      "fs.remove_file", "fs.write_text", "payments.send",
    ]);
    check(
      "TV-X-12",
      [admission(tierTools.has("records.delete")), 0],
      ["UNSUPPORTED_COMPOSITION", 0],
    );
  });

  test("TV-X-13: Human approval does not extend LexScope token expiry", () => {
    check(
      "TV-X-13",
      {
        token_valid: Math.floor(1_300_000 / 1000) < 1300,
        review_approved: true,
        dispatches: 0,
      },
      { token_valid: false, review_approved: true, dispatches: 0 },
    );
  });

  test("TV-X-14: LexSieve hold defeats a downstream attempt to release tool text", () => {
    const screen = { verdict: "hold", data: [] as unknown[], tier_release: true, scope_allow: true };
    check(
      "TV-X-14",
      {
        model_bytes: jRef(screen.data).length - 2,
        verdict: screen.verdict,
        raw_released: false,
      },
      { model_bytes: 0, verdict: "hold", raw_released: false },
    );
  });

  test("TV-X-15: GhostSession unknown action remains unknown in Proof evidence", () => {
    const sessionEvent = {
      event: "action.unknown",
      operation_id: iRef("go", 1),
      action_binding: hRef(Buffer.from("opaque-hmac-fixture")),
    };
    const outcomeMap: Record<string, string> = { "action.unknown": "UNKNOWN" };
    check(
      "TV-X-15",
      {
        outcome: outcomeMap[sessionEvent.event],
        observation: null,
        retries: 0,
      },
      { outcome: "UNKNOWN", observation: null, retries: 0 },
    );
  });

  test("TV-X-16: LexWatt wide counter cannot be narrowed into Trellis/Proof", () => {
    const wide = "9223372036854775808";
    check(
      "TV-X-16",
      [
        BigInt(wide) <= 2n ** 127n - 1n,
        BigInt(wide) <= 2n ** 63n - 1n,
        BigInt(wide).toString(10),
      ],
      [true, false, "9223372036854775808"],
    );
  });

  test("TV-X-17: Trellis LexWatt mode fails before allocation", () => {
    const missing = [
      "lifetime-owner-binding",
      "heartbeat-fd-binding",
      "containment-profile-certification",
    ];
    check(
      "TV-X-17",
      {
        available: missing.length === 0,
        code: "CAP_ADAPTER_UNAVAILABLE",
        missing,
        allocated_runs: 0,
      },
      {
        available: false,
        code: "CAP_ADAPTER_UNAVAILABLE",
        missing: [
          "lifetime-owner-binding",
          "heartbeat-fd-binding",
          "containment-profile-certification",
        ],
        allocated_runs: 0,
      },
    );
  });

  test("TV-X-18: Weather domains are counted separately from VQ principals", () => {
    const oneDomain: Array<[string, string]> = [["w1", "d1"], ["w2", "d1"]];
    const twoDomains: Array<[string, string]> = [["w1", "d1"], ["w2", "d2"]];
    check(
      "TV-X-18",
      [
        new Set(oneDomain.map(([, d]) => d)).size >= 2,
        new Set(twoDomains.map(([, d]) => d)).size >= 2,
        0,
      ],
      [false, true, 0],
    );
  });

  test("TV-X-19: Weather page cannot become a Watch clearance", () => {
    check(
      "TV-X-19",
      { code: admission(false), clearances: 0, policy_changes: 0 },
      { code: "UNSUPPORTED_COMPOSITION", clearances: 0, policy_changes: 0 },
    );
  });

  test("TV-X-20: Watch USD minor-unit delta to Weather micro-USD", () => {
    const usage = { usage_id: "u1", delta_minor: "123", currency: "USD" };
    const seen = new Set<string>();
    const consumeUsage = (u: typeof usage): number => {
      if (seen.has(u.usage_id)) return 0;
      seen.add(u.usage_id);
      return Number(u.delta_minor) * 10000;
    };
    check(
      "TV-X-20",
      [String(consumeUsage(usage)), String(consumeUsage(usage)), "usd_micro"],
      ["1230000", "0", "usd_micro"],
    );
  });

  test("TV-X-21: VisLineage body commitment is not Sunlight raw artifact identity", () => {
    const vlBodyProbe = { v: 1, disclosure: "NORMALIZED_ONLY" };
    const vlNative = dRef("VL-BUNDLE/1", vlBodyProbe);
    const vlProbe = {
      body: vlBodyProbe, hash: vlNative, steps: [], origins: [],
      audit: [], attachments: [],
    };
    const vlRaw = hRef(jRef(vlProbe));
    check(
      "TV-X-21",
      {
        distinct: vlNative !== vlRaw,
        source_commitment: vlNative,
        handoff_matches: vlProbe.hash === vlNative,
      },
      { distinct: true, source_commitment: vlNative, handoff_matches: true },
    );
  });

  test("TV-X-22: ForgeVerity acknowledgement requires canonical export bytes", () => {
    const fvProbe = { v: "fv.sunlight-export/1" };
    const canonicalExport = jRef(fvProbe);
    const spacedExport = Buffer.from('{ "v": "fv.sunlight-export/1" }');
    check(
      "TV-X-22",
      [
        hRef(canonicalExport) === hRef(jRef(fvProbe)),
        hRef(spacedExport) === hRef(jRef(fvProbe)),
        un64(b64(spacedExport)).equals(spacedExport),
      ],
      [true, false, true],
    );
  });

  test("TV-X-23: EvalSeal body_hash is not its Proof object digest", () => {
    const esBody = { schema: "evalseal-status/1", probe: 1 };
    const esBh = `sha256:${hRef(Buffer.concat([Buffer.from("evalseal/1/status\n"), jRef(esBody)]))}`;
    const esMsg = Buffer.from(
      `evalseal/1/signature\nstatus\n${iRef("es_key", 1)}\n${esBh}`,
    );
    const esProbe = {
      schema: "evalseal-signed/1", kind: "status", key_id: iRef("es_key", 1),
      body_hash: esBh, body: esBody,
      signature: b64(sign(null, esMsg, SK)),
    };
    check(
      "TV-X-23",
      [
        esBh !== `sha256:${hRef(jRef(esProbe))}`,
        signedOk(PK, un64(esProbe.signature), esMsg),
      ],
      [true, true],
    );
  });

  test("TV-X-24: Proof rejects a sibling object one byte over its cap", () => {
    // Reference-side check; the real boundary is objects.put rejecting a
    // declared bytes="1048577" with OBJECT_LIMIT before any allocation —
    // covered by the real service in packages/core/src/v2/platform/
    // platform.test.ts and by the socket-level e2e in
    // packages/cli/src/e2e/daemon.test.ts.
    const objectBytes = "1048577";
    check(
      "TV-X-24",
      {
        code: Number(objectBytes) > 1048576 ? "OBJECT_LIMIT" : "OK",
        imports: 0,
        truncated: false,
      },
      { code: "OBJECT_LIMIT", imports: 0, truncated: false },
    );
  });

  test("TV-X-25: Mint task funding does not satisfy Bond liability hold", () => {
    const mintCapabilities = new Set(["task.fund", "settlement.execute"]);
    check(
      "TV-X-25",
      {
        code: mintCapabilities.has("mint.reserve")
          ? "OK"
          : "MINT_EXCLUSIVE_HOLD_UNAVAILABLE",
        creates: 0,
        reused_reservations: 0,
      },
      { code: "MINT_EXCLUSIVE_HOLD_UNAVAILABLE", creates: 0, reused_reservations: 0 },
    );
  });

  test("TV-X-26: CIS receipt cannot be published as a native public Proof object by default", () => {
    const cisRequest = {
      consent: false, public: true, contains_personal_data: true,
      native_profile_installed: false,
    };
    check(
      "TV-X-26",
      {
        export: cisRequest.consent && !cisRequest.public,
        native_verified: cisRequest.native_profile_installed,
        refund_authorized: false,
      },
      { export: false, native_verified: false, refund_authorized: false },
    );
  });

  test("TV-X-27: PolyCite genesis stays zero/null in World/Proof attachments", () => {
    const pcGenesis = { sequence: 0, previous_hash: null as string | null };
    check(
      "TV-X-27",
      [
        JSON.parse(jRef(pcGenesis).toString("utf8")) as unknown,
        pcGenesis.sequence === 1 && pcGenesis.previous_hash === ZERO,
      ],
      [pcGenesis, false],
    );
  });

  test("TV-X-28: World NFD evidence must not be normalized into Charter policy", () => {
    const composed = "é";
    const decomposed = "é";
    check(
      "TV-X-28",
      [
        hRef(jRef(composed)) === hRef(jRef(decomposed)),
        decomposed.normalize("NFC") === decomposed,
        JSON.parse(jRef(decomposed).toString("utf8")) === decomposed,
      ],
      [false, false, true],
    );
  });

  test("TV-X-29: Watch and Weather display rounding must remain labeled", () => {
    // Decimal("0.0000005") quantized to 6 places: half-up → 0.000001,
    // half-even → 0.000000. JS has no decimal; reproduce with exact
    // integer micro-units at the 7th digit boundary.
    const micro = 5; // 0.0000005 expressed in units of 1e-7
    const halfUp = Math.floor((micro + 5) / 10); // 1 → "0.000001"
    const halfEven = (() => {
      const q = Math.floor(micro / 10);
      const r = micro % 10;
      return r > 5 || (r === 5 && q % 2 === 1) ? q + 1 : q; // 0 → "0.000000"
    })();
    check(
      "TV-X-29",
      [
        `0.${String(halfUp).padStart(6, "0")}`,
        `0.${String(halfEven).padStart(6, "0")}`,
      ],
      ["0.000001", "0.000000"],
    );
  });

  test("TV-X-30: Prefix collision and source slot conflict are different cases", () => {
    const nativeId = iRef("ltk", 1);
    const entityA = `lextier/1|tenant1|key|${nativeId}`;
    const entityB = `lexscope/1|tenant1|token|${nativeId}`;
    const slot = "workspace1|source1|stream1|1";
    const candidates: Array<[string, string]> = [
      [slot, hRef(Buffer.from("a"))],
      [slot, hRef(Buffer.from("b"))],
    ];
    check(
      "TV-X-30",
      [
        entityA !== entityB,
        new Set(candidates.map(([s]) => s)).size,
        new Set(candidates.map(([, h]) => h)).size > 1,
      ],
      [true, 1, true],
    );
  });

  test("TV-X-31: Seatbelt maximum charge survives a World UNKNOWN observation", () => {
    const budget = { limit: 1000, held: 100, charged: 0 };
    budget.charged += budget.held;
    budget.held = 0;
    check(
      "TV-X-31",
      {
        held: String(budget.held),
        charged: String(budget.charged),
        available: String(budget.limit - budget.held - budget.charged),
        restored_by_stop: "0",
      },
      { held: "0", charged: "100", available: "900", restored_by_stop: "0" },
    );
  });

  test("TV-X-32: Shared amount representation does not make currencies interchangeable", () => {
    const amounts = [
      { asset: "GBP", scale: 2, amount: "10000" },
      { asset: "SIMUSD", scale: 2, amount: "10000" },
      { asset: "USD", scale: 2, amount: "10000" },
    ];
    check(
      "TV-X-32",
      [
        new Set(amounts.map((x) => `${x.asset}|${x.scale}`)).size,
        amounts.map((x) => x.amount),
        0,
      ],
      [3, ["10000", "10000", "10000"], 0],
    );
  });

  test("all 32 vectors ran exactly once, in order", () => {
    const expected = Array.from(
      { length: 32 },
      (_, i) => `TV-X-${String(i + 1).padStart(2, "0")}`,
    );
    expect(checked.slice().sort()).toEqual(expected);
  });
});

// ── Native-verifier counterparts the spec requires but this repo lacks ──
// INTERFACES.md §4.1: "a production conformance runner MUST replace those
// ports with real pinned native verifiers and additionally run the source
// specs' full suites." None of the named products (World, Mint, Treaty,
// Herald, VQ, LexScope/LexTier/LexSieve/LexWatt, Weather, Watch, Trellis,
// Seatbelt, CIS, PolyCite, GhostSession, VisLineage, ForgeVerity, EvalSeal,
// Bond, Charter, Bedrock) ship a native implementation in this repository.
// These todos record that scope explicitly — they are not passes.
describe("TV-X native-verifier counterparts (out of scope here)", () => {
  test.todo("native: real Mint court/ledger verifies log + slash evidence (TV-X-03/04/25)");
  test.todo("native: real World stream authority and NFD policy enforcement (TV-X-01/02/05/27/28/31)");
  test.todo("native: real Treaty 2PC runtime and Covenant adapter set (TV-X-05/06)");
  test.todo("native: real Herald registry observation binding (TV-X-07/08/09)");
  test.todo("native: real VekQuorum gate, roster enrollment, domain-separated signing (TV-X-09/10)");
  test.todo("native: real LexScope/LexTier/LexSieve/LexWatt tool and hold enforcement (TV-X-12/13/14/16/17)");
  test.todo("native: real Weather corroboration ledger and Watch clearance/currency adapters (TV-X-18/19/20/29/32)");
  test.todo("native: real Proof object store admission and native receipt profiles (TV-X-02/15/23/24/26/30)");
});
