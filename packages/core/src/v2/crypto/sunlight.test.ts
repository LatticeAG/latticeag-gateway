import { Buffer } from "node:buffer";
import { describe, expect, test } from "vitest";
import type { SunlightStatement } from "../protocol/refs.js";
import { canonicalJson } from "./canonical.js";
import {
  keyFromSeed32,
  keyIdOfPublic,
  publicKeyB64u,
  publicKeyOf,
} from "./ed25519.js";
import { sha256Hex } from "./hash.js";
import {
  SUNLIGHT_DIGEST_RE,
  issueSunlightStatement,
  nativeRefOf,
  sunlightArtifact,
  sunlightHash,
  sunlightSign,
  sunlightStatement,
  verifyReleaseThreshold,
  verifySunlightStatement,
} from "./sunlight.js";
import type { SunlightTrustRoot } from "./sunlight.js";

// §13.1 fixture seeds and Sunlight-style identifier conventions.
const ORIGIN_SEED =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const AUDITOR_SEED =
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const THIRD_SEED = "11".repeat(32);
const NOW = 1789257600000;

const sls = (n: number) => `sls_${String(n).padStart(21, "0")}`;
const slk = (n: number) => `slk_${String(n).padStart(21, "0")}`;
const LEDGER = `sll_${"1".padStart(21, "0")}`;

const originSecret = keyFromSeed32(ORIGIN_SEED);
const auditorSecret = keyFromSeed32(AUDITOR_SEED);
const thirdSecret = keyFromSeed32(THIRD_SEED);

/** Three-key pinned root set, keyed by signer label like the fixture. */
function rootSet(): Map<string, string> {
  return new Map([
    [slk(1), publicKeyB64u(publicKeyOf(originSecret))],
    [slk(2), publicKeyB64u(publicKeyOf(auditorSecret))],
    [slk(3), publicKeyB64u(publicKeyOf(thirdSecret))],
  ]);
}

function statementFor(
  n: number,
  secretKey = originSecret,
  signer = slk(1),
): SunlightStatement {
  return issueSunlightStatement(
    {
      id: sls(n),
      ledger: LEDGER,
      signer,
      claimed_at_ms: NOW - 604800000,
      capture: "posthoc",
      artifact: sunlightArtifact(`manifest-bytes-${n}`),
    },
    secretKey,
  );
}

describe("sunlight statements", () => {
  test("statement body matches the §5.1/fixture shape", () => {
    const body = sunlightStatement({
      id: sls(1),
      ledger: LEDGER,
      signer: slk(1),
      claimed_at_ms: NOW - 604800000,
      capture: "posthoc",
      artifact: sunlightArtifact("raw manifest"),
    });
    expect(body).toEqual({
      v: "sunlight.statement/1",
      id: sls(1),
      ledger: LEDGER,
      signer: slk(1),
      claimed_at_ms: NOW - 604800000,
      capture: "posthoc",
      subject: {
        kind: "evidence",
        artifact: sunlightArtifact("raw manifest"),
      },
      parents: [],
      details: { type: "creation" },
      evidence: [],
    });
  });

  test("sunlightHash is sha256: + H(profile\\n + J(body))", () => {
    const stmt = statementFor(1);
    expect(stmt.hash).toMatch(SUNLIGHT_DIGEST_RE);
    expect(sunlightHash(stmt.body)).toBe(stmt.hash);
    // Independently recompute the preimage shape.
    const manual = `sha256:${sha256Hex(
      Buffer.concat([
        Buffer.from("sunlight.statement/1\n"),
        Buffer.from(canonicalJson(stmt.body)),
      ]),
    )}`;
    expect(stmt.hash).toBe(manual);
  });

  test("signed statement verifies under an authorized signer", () => {
    const stmt = statementFor(1);
    expect(stmt.signature_hex).toMatch(/^[0-9a-f]{128}$/);
    expect(verifySunlightStatement(stmt, rootSet())).toBe(true);
  });

  test("rejects unknown signer, tampered body, tampered signature", () => {
    const roots = rootSet();
    const stmt = statementFor(1);
    // Signer label not in the root set.
    const stranger = issueSunlightStatement(
      {
        id: sls(9),
        ledger: LEDGER,
        signer: "slk_999999999999999999999",
        claimed_at_ms: NOW,
        capture: "posthoc",
        artifact: sunlightArtifact("x"),
      },
      originSecret,
    );
    expect(verifySunlightStatement(stranger, roots)).toBe(false);
    // Tampered body after signing → hash mismatch.
    const tampered: SunlightStatement = {
      ...stmt,
      body: { ...stmt.body, claimed_at_ms: stmt.body.claimed_at_ms + 1 },
    };
    expect(verifySunlightStatement(tampered, roots)).toBe(false);
    // Tampered signature.
    expect(
      verifySunlightStatement(
        { ...stmt, signature_hex: "00".repeat(64) },
        roots,
      ),
    ).toBe(false);
    // Hash/signature lexical checks.
    expect(
      verifySunlightStatement({ ...stmt, hash: stmt.hash.toUpperCase() }, roots),
    ).toBe(false);
    expect(
      verifySunlightStatement(
        { ...stmt, signature_hex: stmt.signature_hex.toUpperCase() },
        roots,
      ),
    ).toBe(false);
  });

  test("signature is bound to the signing key, not the signer label", () => {
    const roots = rootSet();
    // Signed by origin but claims auditor's signer id → invalid.
    const forged = statementFor(5, originSecret, slk(2));
    expect(verifySunlightStatement(forged, roots)).toBe(false);
  });

  test("Set-form roots accept signer = raw pubkey b64u or its key id", () => {
    const originPubB64u = publicKeyB64u(publicKeyOf(originSecret));
    const originKeyId = keyIdOfPublic(originPubB64u);
    const roots: SunlightTrustRoot = new Set([
      originPubB64u,
      publicKeyB64u(publicKeyOf(auditorSecret)),
    ]);
    const byKey = statementFor(1, originSecret, originPubB64u);
    expect(verifySunlightStatement(byKey, roots)).toBe(true);
    const byId = statementFor(2, originSecret, originKeyId);
    expect(verifySunlightStatement(byId, roots)).toBe(true);
    // A label like slk_… cannot resolve against a Set of raw keys.
    const byLabel = statementFor(3, originSecret, slk(1));
    expect(verifySunlightStatement(byLabel, roots)).toBe(false);
  });

  test("2-of-3 release threshold accepts origin + auditor", () => {
    const roots = rootSet();
    const s1 = statementFor(3, originSecret, slk(1));
    const s2 = statementFor(4, auditorSecret, slk(2));
    expect(verifyReleaseThreshold([s1, s2], roots)).toBe(true);
    expect(verifyReleaseThreshold([s1, s2], roots, 3)).toBe(false);
  });

  test("threshold requires distinct keys, not just distinct labels", () => {
    const roots = rootSet();
    const s1 = statementFor(3, originSecret, slk(1));
    expect(verifyReleaseThreshold([s1], roots)).toBe(false);
    // Two statements signed by the same key under different labels.
    const aliased = new Map([
      [slk(1), publicKeyB64u(publicKeyOf(originSecret))],
      [slk(9), publicKeyB64u(publicKeyOf(originSecret))],
    ]);
    const s9 = statementFor(9, originSecret, slk(9));
    expect(verifyReleaseThreshold([s1, s9], aliased)).toBe(false);
  });

  test("TV-GW-47: one malformed extra signature fails the whole set", () => {
    const roots = rootSet();
    const s1 = statementFor(3, originSecret, slk(1));
    const s2 = statementFor(4, auditorSecret, slk(2));
    const malformed = {
      ...statementFor(5, thirdSecret, slk(3)),
      signature_hex: "ab".repeat(64), // well-formed hex, wrong signature
    };
    expect(verifySunlightStatement(malformed, roots)).toBe(false);
    expect(verifyReleaseThreshold([s1, s2, malformed], roots)).toBe(false);
    // And a structurally malformed extra also fails.
    const structurallyBad = { body: s1.body, hash: "sha256:00", signature_hex: "00" };
    expect(verifyReleaseThreshold([s1, s2, structurallyBad], roots)).toBe(false);
  });

  test("nativeRefOf matches fixture native() fields", () => {
    const stmt = statementFor(1);
    const ref = nativeRefOf(stmt);
    expect(ref.profile).toBe("sunlight.statement/1");
    expect(ref.namespace).toBe(LEDGER);
    expect(ref.object_id).toBe(sls(1));
    expect(ref.commitment).toBe(stmt.hash);
    expect(ref.raw_sha256).toBe(sha256Hex(canonicalJson(stmt)));
    expect(ref.bytes).toBe(
      String(Buffer.byteLength(canonicalJson(stmt), "utf8")),
    );
  });

  test("sunlightSign returns {body,hash,signature_hex}", () => {
    const body = sunlightStatement({
      id: sls(7),
      ledger: LEDGER,
      signer: slk(1),
      claimed_at_ms: NOW,
      capture: "creation_hook",
      artifact: sunlightArtifact("m"),
    });
    const stmt = sunlightSign(body, originSecret);
    expect(Object.keys(stmt).sort()).toEqual([
      "body",
      "hash",
      "signature_hex",
    ]);
    expect(stmt.body).toBe(body);
  });
});
