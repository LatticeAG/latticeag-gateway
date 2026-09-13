import { Buffer } from "node:buffer";
import { describe, expect, test } from "vitest";
import type { EventRef } from "../protocol/refs.js";
import { canonicalJson } from "./canonical.js";
import {
  keyFromSeed32,
  keyIdOfPublic,
  publicKeyB64u,
  publicKeyOf,
} from "./ed25519.js";
import { CryptoError } from "./errors.js";
import { sha256Hex } from "./hash.js";
import {
  GENESIS_PREV,
  MAX_PROOF_EVENT_BYTES,
  assertProofBody,
  eventRefOf,
  isCount,
  proofBody,
  proofEventHash,
  sealProofEvent,
  sortParents,
  verifyProofEvent,
} from "./proof.js";
import type { ProofEvent } from "./proof.js";

// §13.1 fixture seeds.
const ORIGIN_SEED =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const AUDITOR_SEED =
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const ORIGIN_PUBLIC_B64U = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const ORIGIN_KEY_ID =
  "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";

function blobRef(content: string, media = "application/json") {
  const bytes = Buffer.from(content, "utf8");
  return { digest: sha256Hex(bytes), bytes: String(bytes.length), media };
}

/** §13.1 `history("run1", intent, observation)` rebuilt via our primitives. */
function fixtureHistory(): ProofEvent[] {
  const secret = keyFromSeed32(ORIGIN_SEED);
  const key = keyIdOfPublic(publicKeyOf(secret));
  const intent = blobRef("{}");
  const observation = blobRef("ok", "text/plain");
  const events: ProofEvent[] = [];
  const add = (data: unknown, parents: EventRef[] = []): void => {
    const n = events.length;
    const body = proofBody({
      workspace: "ws1",
      source: "src1",
      stream: "main",
      seq: String(n + 1),
      prev: n === 0 ? GENESIS_PREV : events[n - 1]!.hash,
      lamport: String(n + 1),
      key,
      parents,
      data,
    });
    events.push(sealProofEvent(body, secret));
  };
  add({
    kind: "RunOpened",
    run: "run1",
    intent,
    policy: null,
    hypothetical: false,
  });
  add({
    kind: "StepOpened",
    run: "run1",
    step: "step1",
    operation: "compute",
    input: null,
  });
  add({
    kind: "ObservationRecorded",
    run: "run1",
    step: "step1",
    value: observation,
  });
  add(
    {
      kind: "StepClosed",
      run: "run1",
      step: "step1",
      outcome: "SUCCEEDED",
      observation: eventRefOf(events[2]!),
    },
    [eventRefOf(events[2]!)],
  );
  add({ kind: "RunClosed", run: "run1", outcome: "SUCCEEDED" });
  return events;
}

describe("proof event lane", () => {
  test("KAT: events[0] hash and signature match the fixture", () => {
    const events = fixtureHistory();
    // GATEWAY_SPEC_EXTREME §13.1 asserts:
    expect(events[0]!.hash).toBe(
      "8126edf35ef72f9a94909cde60f0c3955cedf774be3a0357f01078b1b1c1c2d9",
    );
    expect(events[0]!.signature).toBe(
      "ameqsvtAKofB1m1uZrPYDrdI4GCHEppx57f0QP2P-m1OqE-Jkbz4WvIrLTp0iIfck0EdvRQprvzyQHmodDPGBA",
    );
    expect(events[0]!.body.key).toBe(ORIGIN_KEY_ID);
  });

  test("full 5-event history verifies under the public key", () => {
    const events = fixtureHistory();
    for (const event of events) {
      expect(verifyProofEvent(event, ORIGIN_PUBLIC_B64U)).toBe(true);
    }
  });

  test("verifyProofEvent rejects tampered body, hash, signature, wrong key", () => {
    const events = fixtureHistory();
    const event = events[0]!;
    const pub = publicKeyOf(keyFromSeed32(ORIGIN_SEED));

    expect(
      verifyProofEvent(
        { ...event, body: { ...event.body, workspace: "ws2" } },
        pub,
      ),
    ).toBe(false);
    expect(verifyProofEvent({ ...event, hash: "0".repeat(64) }, pub)).toBe(
      false,
    );
    expect(
      verifyProofEvent(
        { ...event, signature: Buffer.alloc(64).toString("base64url") },
        pub,
      ),
    ).toBe(false);
    const auditor = publicKeyOf(keyFromSeed32(AUDITOR_SEED));
    expect(verifyProofEvent(event, auditor)).toBe(false);
    expect(verifyProofEvent(event, "not-a-key")).toBe(false);
    expect(verifyProofEvent({ body: event.body, hash: event.hash }, pub)).toBe(
      false,
    );
    expect(verifyProofEvent({ ...event, extra: 1 }, pub)).toBe(false);
  });

  test("eventRefOf returns {source,stream,seq,hash}", () => {
    const events = fixtureHistory();
    expect(eventRefOf(events[3]!)).toEqual({
      source: "src1",
      stream: "main",
      seq: "4",
      hash: events[3]!.hash,
    });
  });

  test("proofBody genesis defaults prev to 64 zeroes", () => {
    const body = proofBody({
      workspace: "ws1",
      source: "src1",
      stream: "main",
      seq: "1",
      lamport: "1",
      key: ORIGIN_KEY_ID,
      data: { kind: "RunOpened" },
    });
    expect(body.prev).toBe(GENESIS_PREV);
    expect(body.parents).toEqual([]);
  });

  test("proofBody sorts parents by source/stream/numeric-seq/hash", () => {
    const ref = (
      source: string,
      stream: string,
      seq: string,
      h: string,
    ): EventRef => ({ source, stream, seq, hash: h });
    const parents = [
      ref("b", "s1", "2", "f".repeat(64)),
      ref("a", "s1", "10", "a".repeat(64)),
      ref("a", "s1", "2", "b".repeat(64)),
      ref("a", "s1", "2", "a".repeat(64)),
    ];
    const sorted = sortParents(parents);
    expect(sorted.map((r) => `${r.source}${r.seq}${r.hash[0]}`)).toEqual([
      "a2a",
      "a2b",
      "a10a",
      "b2f",
    ]);
    const body = proofBody({
      workspace: "ws1",
      source: "z",
      stream: "main",
      seq: "2",
      prev: "c".repeat(64),
      lamport: "7",
      key: ORIGIN_KEY_ID,
      parents,
      data: {},
    });
    expect(body.parents).toEqual(sorted);
  });

  test("assertProofBody rejects malformed fields", () => {
    const base = {
      workspace: "ws1",
      source: "src1",
      stream: "main",
      seq: "2",
      prev: "a".repeat(64),
      lamport: "2",
      key: ORIGIN_KEY_ID,
      parents: [] as EventRef[],
      data: {},
    };
    const good = { v: 1, ...base };
    expect(() => assertProofBody(good)).not.toThrow();
    const cases: Record<string, unknown>[] = [
      { ...good, v: 2 },
      { ...good, workspace: "1bad" }, // must start with a letter
      { ...good, seq: "0" },
      { ...good, seq: "01" },
      { ...good, seq: "9223372036854775808" }, // 2^63
      { ...good, seq: "1" }, // genesis requires zero prev
      { ...good, seq: "1", prev: GENESIS_PREV, lamport: "0" },
      { ...good, seq: "3", prev: GENESIS_PREV }, // non-genesis zero prev
      { ...good, prev: "A".repeat(64) },
      { ...good, key: "short" },
      { ...good, lamport: "1.5" },
      { ...good, data: 0.5 }, // outside canonical domain
      { ...good, extra: 1 },
    ];
    for (const bad of cases) {
      expect(() => assertProofBody(bad)).toThrow(CryptoError);
    }
    // Object.keys check: missing field rejected.
    const missing = { ...base };
    expect(() => assertProofBody(missing)).toThrow(CryptoError);
  });

  test("assertProofBody rejects unsorted, duplicate, self, and later parents", () => {
    const ref = (seq: string, h: string): EventRef => ({
      source: "a",
      stream: "s1",
      seq,
      hash: h,
    });
    const mk = (parents: EventRef[]) => ({
      v: 1,
      workspace: "ws1",
      source: "a",
      stream: "s1",
      seq: "5",
      prev: "c".repeat(64),
      lamport: "5",
      key: ORIGIN_KEY_ID,
      parents,
      data: {},
    });
    expect(() =>
      assertProofBody(
        mk([ref("2", "b".repeat(64)), ref("1", "a".repeat(64))]),
      ),
    ).toThrow(/sorted/);
    expect(() =>
      assertProofBody(
        mk([ref("2", "a".repeat(64)), ref("2", "a".repeat(64))]),
      ),
    ).toThrow(/sorted/);
    expect(() =>
      assertProofBody(mk([ref("5", "d".repeat(64))])),
    ).toThrow(/itself or a later slot/);
    expect(() =>
      assertProofBody(mk([ref("9", "d".repeat(64))])),
    ).toThrow(/itself or a later slot/);
    const tooMany = Array.from({ length: 65 }, (_, i) =>
      ref("1", i.toString(16).padStart(64, "0")),
    );
    expect(() => assertProofBody(mk(tooMany))).toThrow(/at most 64/);
  });

  test("sealProofEvent enforces the 64 KiB serialized cap", () => {
    const secret = keyFromSeed32(ORIGIN_SEED);
    const body = proofBody({
      workspace: "ws1",
      source: "src1",
      stream: "main",
      seq: "1",
      lamport: "1",
      key: ORIGIN_KEY_ID,
      data: { blob: "x".repeat(MAX_PROOF_EVENT_BYTES) },
    });
    expect(() => sealProofEvent(body, secret)).toThrow(/exceeds 65536/);
    try {
      sealProofEvent(body, secret);
      expect.unreachable("sealProofEvent should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoError);
      expect((err as CryptoError).code).toBe("EVENT_LIMIT");
    }
  });

  test("proofEventHash matches H(domain || NUL || J(body))", () => {
    const events = fixtureHistory();
    expect(proofEventHash(events[0]!.body)).toBe(events[0]!.hash);
  });

  test("isCount accepts canonical decimals within 2^63-1", () => {
    for (const ok of ["0", "1", "9223372036854775807"]) {
      expect(isCount(ok)).toBe(true);
    }
    for (const bad of [
      "00",
      "01",
      "-1",
      "1.0",
      "9223372036854775808",
      " 1",
      "",
      7,
    ]) {
      expect(isCount(bad)).toBe(false);
    }
  });

  test("sealed event serializes deterministically", () => {
    const events = fixtureHistory();
    const a = canonicalJson(events[0]!);
    const b = canonicalJson(events[0]!);
    expect(a).toBe(b);
    expect(a.startsWith('{"body":{')).toBe(true);
  });
});
