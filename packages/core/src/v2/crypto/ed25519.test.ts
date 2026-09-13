import { Buffer } from "node:buffer";
import { describe, expect, test } from "vitest";
import {
  isB64uCanonical,
  keyFromSeed32,
  keyIdOfPublic,
  publicKeyB64u,
  publicKeyFromB64u,
  publicKeyOf,
  requirePublicKeyArg,
  signB64u,
  verifyB64u,
} from "./ed25519.js";
import { CryptoError } from "./errors.js";

// §13.1 fixture seeds (origin = signer 1, auditor = signer 2).
const ORIGIN_SEED =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const AUDITOR_SEED =
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

// Derived with the fixture makeKey(): SPKI DER low-order 32 bytes.
const ORIGIN_PUBLIC_B64U = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const ORIGIN_KEY_ID = "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";

describe("ed25519 keys", () => {
  test("keyFromSeed32 derives the fixture key material", () => {
    const secret = keyFromSeed32(ORIGIN_SEED);
    expect(secret.asymmetricKeyType).toBe("ed25519");
    expect(secret.type).toBe("private");
    const pub = publicKeyOf(secret);
    expect(publicKeyB64u(pub)).toBe(ORIGIN_PUBLIC_B64U);
    expect(keyIdOfPublic(pub)).toBe(ORIGIN_KEY_ID);
    // material.id = H(raw public) per fixture makeKey().
    expect(keyIdOfPublic(ORIGIN_PUBLIC_B64U)).toBe(ORIGIN_KEY_ID);
  });

  test("publicKeyFromB64u round-trips and validates strictly", () => {
    const pub = publicKeyFromB64u(ORIGIN_PUBLIC_B64U);
    expect(publicKeyB64u(pub)).toBe(ORIGIN_PUBLIC_B64U);
    for (const bad of [
      `${ORIGIN_PUBLIC_B64U}=`, // padded — not canonical
      ORIGIN_PUBLIC_B64U.slice(0, -1),
      `${ORIGIN_PUBLIC_B64U}A`, // 44 chars → 33 bytes? invalid length
      "!!!!",
      "",
    ]) {
      expect(() => publicKeyFromB64u(bad)).toThrow(CryptoError);
    }
  });

  test("isB64uCanonical rejects padding and non-alphabet chars", () => {
    expect(isB64uCanonical(ORIGIN_PUBLIC_B64U)).toBe(true);
    expect(isB64uCanonical(`${ORIGIN_PUBLIC_B64U}=`)).toBe(false);
    expect(isB64uCanonical("a+b/c")).toBe(false);
    expect(isB64uCanonical("")).toBe(false);
    expect(isB64uCanonical(42)).toBe(false);
  });

  test("requirePublicKeyArg accepts b64u, public, and private KeyObjects", () => {
    const secret = keyFromSeed32(AUDITOR_SEED);
    const pub = publicKeyOf(secret);
    expect(requirePublicKeyArg(pub).type).toBe("public");
    expect(requirePublicKeyArg(secret).type).toBe("public");
    const fromB64u = requirePublicKeyArg(publicKeyB64u(pub));
    expect(publicKeyB64u(fromB64u)).toBe(publicKeyB64u(pub));
  });
});

describe("signB64u / verifyB64u", () => {
  const body = { a: 1, b: [true, null, "x"], nested: { k: "v" } };

  test("round-trip verifies under the public key", () => {
    const secret = keyFromSeed32(ORIGIN_SEED);
    const sig = signB64u("TEST/1", body, secret);
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/); // 64 bytes unpadded
    expect(verifyB64u("TEST/1", body, sig, publicKeyOf(secret))).toBe(true);
    expect(verifyB64u("TEST/1", body, sig, ORIGIN_PUBLIC_B64U)).toBe(true);
  });

  test("rejects wrong domain, tampered body, wrong key", () => {
    const secret = keyFromSeed32(ORIGIN_SEED);
    const sig = signB64u("TEST/1", body, secret);
    expect(verifyB64u("OTHER/1", body, sig, ORIGIN_PUBLIC_B64U)).toBe(false);
    expect(
      verifyB64u("TEST/1", { ...body, a: 2 }, sig, ORIGIN_PUBLIC_B64U),
    ).toBe(false);
    const other = keyFromSeed32(AUDITOR_SEED);
    expect(
      verifyB64u("TEST/1", body, sig, publicKeyOf(other)),
    ).toBe(false);
  });

  test("rejects malformed signatures without throwing", () => {
    for (const sig of [
      "not-base64url!!!",
      `${"A".repeat(86)}=`,
      Buffer.alloc(63).toString("base64url"), // wrong length
      "",
    ]) {
      expect(verifyB64u("TEST/1", body, sig, ORIGIN_PUBLIC_B64U)).toBe(false);
    }
  });

  test("signB64u throws on out-of-domain body", () => {
    const secret = keyFromSeed32(ORIGIN_SEED);
    expect(() => signB64u("TEST/1", { bad: 0.5 }, secret)).toThrow(CryptoError);
    expect(() => signB64u("TEST/1", { bad: undefined }, secret)).toThrow(
      CryptoError,
    );
  });
});
