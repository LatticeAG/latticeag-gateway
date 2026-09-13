import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { canonicalJson } from "./canonical.js";
import {
  keyFromSeed32,
  publicKeyB64u,
  publicKeyOf,
} from "./ed25519.js";
import { sha256Hex } from "./hash.js";
import {
  PAIR_DOMAIN,
  RENEW_DOMAIN,
  REQUEST_DOMAIN,
  inviteCodeValid,
  proposalHash,
  registerBody,
  renewBody,
  requestProofBody,
  signRegister,
  signRenew,
  signRequest,
  verifyRegister,
  verifyRenew,
  verifyRequest,
} from "./pairing.js";

const ORIGIN_SEED =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const AUDITOR_SEED =
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const NOW = 1789257600000;

const originSecret = keyFromSeed32(ORIGIN_SEED);
const auditorSecret = keyFromSeed32(AUDITOR_SEED);
const originPubB64u = publicKeyB64u(publicKeyOf(originSecret));
const auditorPubB64u = publicKeyB64u(publicKeyOf(auditorSecret));

const capability = {
  name: "latticeag.events.relay",
  revision: 1,
  profiles: ["@latticeag/events@0.1.0", "proof-evidence/1"],
  emit: ["telemetry"],
  consume: ["approval.decision"],
  request_approvals: true,
  lineage: "own",
};

const KEY_ID = "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";

function fixtureRegisterBody() {
  return registerBody({
    gateway: "gw1",
    workspace: "ws1",
    epoch: "1",
    pair: "pair1",
    challenge: "challenge1",
    client_nonce: Buffer.alloc(32, 1).toString("base64url"),
    server_nonce: Buffer.alloc(32, 2).toString("base64url"),
    key: KEY_ID,
    profiles: capability.profiles,
    interfaces: "interfaces/1",
    capabilities: [capability],
  });
}

describe("pairing / request proof domains", () => {
  test("domain constants match the spec strings", () => {
    expect(PAIR_DOMAIN).toBe("LATTICEAG-GATEWAY-PAIR/1");
    expect(RENEW_DOMAIN).toBe("LATTICEAG-GATEWAY-RENEW/1");
    expect(REQUEST_DOMAIN).toBe("LATTICEAG-GATEWAY-REQUEST/1");
  });

  test("register body has the exact §4.2 field set", () => {
    const body = fixtureRegisterBody();
    expect(Object.keys(body).sort()).toEqual([
      "capabilities",
      "challenge",
      "client_nonce",
      "epoch",
      "gateway",
      "interfaces",
      "key",
      "kind",
      "pair",
      "profiles",
      "server_nonce",
      "v",
      "workspace",
    ]);
    expect(body.v).toBe(1);
    expect(body.kind).toBe("register");
  });

  test("signRegister / verifyRegister round-trip; tamper and wrong key fail", () => {
    const body = fixtureRegisterBody();
    const sig = signRegister(body, originSecret);
    expect(verifyRegister(body, sig, originPubB64u)).toBe(true);
    // Tampered body fails.
    expect(
      verifyRegister({ ...body, workspace: "ws2" }, sig, originPubB64u),
    ).toBe(false);
    // Wrong key fails.
    expect(verifyRegister(body, sig, auditorPubB64u)).toBe(false);
    // Malformed signature fails without throwing.
    expect(verifyRegister(body, `${sig}=`, originPubB64u)).toBe(false);
  });

  test("renew body + proof round-trip", () => {
    const refresh = Buffer.alloc(32, 4).toString("base64url");
    const body = renewBody({
      gateway: "gw1",
      workspace: "ws1",
      epoch: "1",
      peer: "peer1",
      refresh_hash: sha256Hex(refresh),
      challenge: "challenge1",
      server_nonce: Buffer.alloc(32, 2).toString("base64url"),
    });
    expect(body).toMatchObject({ v: 1, kind: "renew", peer: "peer1" });
    const sig = signRenew(body, originSecret);
    expect(verifyRenew(body, sig, originPubB64u)).toBe(true);
    expect(verifyRenew({ ...body, peer: "peer2" }, sig, originPubB64u)).toBe(
      false,
    );
    // Renew proofs are not valid under other domains.
    expect(verifyRequest(body, sig, originPubB64u)).toBe(false);
  });

  test("request proof body + round-trip", () => {
    const access = Buffer.alloc(32, 3).toString("base64url");
    const params = { method: "events.publish" };
    const body = requestProofBody({
      gateway: "gw1",
      workspace: "ws1",
      epoch: "1",
      token_hash: sha256Hex(access),
      id: "q1",
      method: "events.publish",
      params_sha256: sha256Hex(canonicalJson(params)),
      nonce: Buffer.alloc(32, 20).toString("base64url"),
      issued_ms: NOW,
      expires_ms: NOW + 60000,
    });
    expect(body).toMatchObject({ v: 1, kind: "request", method: "events.publish" });
    const sig = signRequest(body, originSecret);
    expect(verifyRequest(body, sig, originPubB64u)).toBe(true);
  });

  test("TV-GW-27 shape: proof signed by the wrong key does not verify", () => {
    const access = Buffer.alloc(32, 3).toString("base64url");
    const body = requestProofBody({
      gateway: "gw1",
      workspace: "ws1",
      epoch: "1",
      token_hash: sha256Hex(access),
      id: "q1",
      method: "events.publish",
      params_sha256: sha256Hex(canonicalJson({})),
      nonce: Buffer.alloc(32, 21).toString("base64url"),
      issued_ms: NOW,
      expires_ms: NOW + 60000,
    });
    // Stolen token presented with auditor's key proof instead of origin's.
    const forged = signRequest(body, auditorSecret);
    expect(verifyRequest(body, forged, originPubB64u)).toBe(false);
    // The proof itself is cryptographically valid under the auditor key —
    // binding the token to the enrolled key id is the caller's job.
    expect(verifyRequest(body, forged, auditorPubB64u)).toBe(true);
  });

  test("requestProofBody rejects malformed lexical fields", () => {
    const base = {
      gateway: "gw1",
      workspace: "ws1",
      epoch: "1",
      token_hash: sha256Hex("t"),
      id: "q1",
      method: "m",
      params_sha256: sha256Hex("p"),
      nonce: "n",
      issued_ms: NOW,
      expires_ms: NOW + 60000,
    };
    expect(() =>
      requestProofBody({ ...base, token_hash: "zz" }),
    ).toThrow(/token_hash/);
    expect(() =>
      requestProofBody({ ...base, params_sha256: "GG".repeat(32) }),
    ).toThrow(/params_sha256/);
    expect(() => requestProofBody({ ...base, issued_ms: 0.5 })).toThrow(
      /safe integer/,
    );
  });

  test("proposalHash equals H(J({key,profiles,interfaces,capabilities}))", () => {
    const params = {
      key: KEY_ID,
      profiles: capability.profiles,
      interfaces: "interfaces/1",
      capabilities: [capability],
    };
    expect(proposalHash(params)).toBe(sha256Hex(canonicalJson(params)));
    // Independent fixture-style recomputation: H() over fixture J().
    const J = (x: unknown): string =>
      Array.isArray(x)
        ? `[${x.map(J).join(",")}]`
        : x !== null && typeof x === "object"
          ? `{${Object.keys(x)
              .sort()
              .map(
                (k) =>
                  `${JSON.stringify(k)}:${J((x as Record<string, unknown>)[k])}`,
              )
              .join(",")}}`
          : (JSON.stringify(x) as string);
    const manual = createHash("sha256").update(J(params)).digest("hex");
    expect(proposalHash(params)).toBe(manual);
    // A changed proposal produces a different hash.
    expect(
      proposalHash({ ...params, interfaces: "interfaces/2" }),
    ).not.toBe(proposalHash(params));
  });

  test("inviteCodeValid checks the 10-char Crockford shape", () => {
    expect(inviteCodeValid("6J7K8M9N2P")).toBe(true); // fixture code
    expect(inviteCodeValid("0000000000")).toBe(true);
    for (const bad of [
      "6J7K8M9N2I",
      "6J7K8M9N2L",
      "6J7K8M9N2O",
      "6J7K8M9N2U",
      "6J7K8M9N2",
      "6J7K8M9N2PP",
      "6j7k8m9n2p",
      "",
    ]) {
      expect(inviteCodeValid(bad)).toBe(false);
    }
  });
});
