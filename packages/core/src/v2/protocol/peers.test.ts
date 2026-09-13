import { describe, expect, it } from "vitest";
import {
  PAIR_TRANSITIONS,
  PEER_LIMITS,
  canPairTransition,
  checkScopeAdmission,
  validateScope,
  validateScopes,
  type Scope,
} from "./peers.js";

function scope(partial: Partial<Scope> & { permission: Scope["permission"] }): Scope {
  return { topics: [], runs: [], products: [], ...partial };
}

const AGENT_CTX = {
  role: "agent" as const,
  allowOperator: false,
  localOperatorConfirmation: false,
};

const OPERATOR_CTX = {
  role: "operator" as const,
  allowOperator: true,
  localOperatorConfirmation: true,
};

describe("validateScope", () => {
  it("accepts a well-formed events scope", () => {
    const r = validateScope(
      scope({ permission: "events.emit", topics: ["telemetry"], runs: ["self"] }),
    );
    expect(r.ok).toBe(true);
  });

  it("rejects wildcard topics", () => {
    const r = validateScope(scope({ permission: "events.emit", topics: ["*"] }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.field).toBe("topics");
    const prefix = validateScope(
      scope({ permission: "events.consume", topics: ["tele*"] }),
    );
    expect(prefix.ok).toBe(false);
  });

  it("rejects topics outside the §3.4 registry", () => {
    const r = validateScope(
      scope({ permission: "events.consume", topics: ["bogus.topic"] }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("SCHEMA_INVALID");
  });

  it("rejects irrelevant non-empty dimensions", () => {
    // approvals.request uses runs only; topics must be empty.
    const r = validateScope(
      scope({ permission: "approvals.request", topics: ["verdict"], runs: ["self"] }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.field).toBe("topics");
    // products.manage uses products only.
    const r2 = validateScope(
      scope({ permission: "products.manage", products: ["lexverdict"], runs: ["self"] }),
    );
    expect(r2.ok).toBe(false);
  });

  it("rejects unknown permissions and extra fields", () => {
    expect(
      validateScope(scope({ permission: "events.admin" as Scope["permission"] })).ok,
    ).toBe(false);
    expect(
      validateScope({ ...scope({ permission: "lineage.read" }), extra: 1 }).ok,
    ).toBe(false);
  });

  it("validateScopes enforces the 64-scope cap and duplicates", () => {
    expect(validateScopes([]).ok).toBe(true);
    const tooMany = Array.from({ length: PEER_LIMITS.maxScopes + 1 }, () =>
      scope({ permission: "lineage.read" }),
    );
    expect(validateScopes(tooMany).ok).toBe(false);
    const dup = validateScopes([
      scope({ permission: "lineage.read", runs: ["self"] }),
      scope({ permission: "lineage.read", runs: ["self"] }),
    ]);
    expect(dup.ok).toBe(false);
  });
});

describe("checkScopeAdmission", () => {
  const manage = scope({ permission: "products.manage", products: ["lexverdict"] });

  it("denies products.manage to a normal agent (FORBIDDEN)", () => {
    const r = checkScopeAdmission(manage, AGENT_CTX);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("FORBIDDEN");
  });

  it("denies operator peers without allow_operator or local confirmation", () => {
    expect(
      checkScopeAdmission(manage, { ...OPERATOR_CTX, allowOperator: false }).ok,
    ).toBe(false);
    expect(
      checkScopeAdmission(manage, {
        ...OPERATOR_CTX,
        localOperatorConfirmation: false,
      }).ok,
    ).toBe(false);
    expect(
      checkScopeAdmission(manage, { ...OPERATOR_CTX, role: "agent" }).ok,
    ).toBe(false);
  });

  it("admits operator peers meeting all three conditions", () => {
    expect(checkScopeAdmission(manage, OPERATOR_CTX).ok).toBe(true);
  });

  it("admits non-manage permissions regardless of tier", () => {
    expect(
      checkScopeAdmission(
        scope({ permission: "events.emit", topics: ["telemetry"] }),
        AGENT_CTX,
      ).ok,
    ).toBe(true);
  });
});

describe("pairing state machine", () => {
  it("follows CREATED→AWAITING_OPERATOR→APPROVED→CONSUMED", () => {
    expect(canPairTransition("CREATED", "AWAITING_OPERATOR")).toBe(true);
    expect(canPairTransition("AWAITING_OPERATOR", "APPROVED")).toBe(true);
    expect(canPairTransition("APPROVED", "CONSUMED")).toBe(true);
    // A changed proposal returns to AWAITING_OPERATOR.
    expect(canPairTransition("APPROVED", "AWAITING_OPERATOR")).toBe(true);
  });

  it("lets unconsumed live states become CANCELLED/EXPIRED/LOCKED", () => {
    for (const from of ["CREATED", "AWAITING_OPERATOR", "APPROVED"] as const) {
      for (const to of ["CANCELLED", "EXPIRED", "LOCKED"] as const) {
        expect(canPairTransition(from, to), `${from}->${to}`).toBe(true);
      }
    }
  });

  it("treats CONSUMED/CANCELLED/EXPIRED/LOCKED as terminal", () => {
    for (const s of ["CONSUMED", "CANCELLED", "EXPIRED", "LOCKED"] as const) {
      expect(PAIR_TRANSITIONS[s]).toEqual([]);
    }
    expect(canPairTransition("CONSUMED", "CANCELLED")).toBe(false);
  });

  it("declares §4 limits", () => {
    expect(PEER_LIMITS.maxCapabilities).toBe(32);
    expect(PEER_LIMITS.maxScopes).toBe(64);
    expect(PEER_LIMITS.maxSetEntries).toBe(64);
    expect(PEER_LIMITS.maxNameBytes).toBe(64);
    expect(PEER_LIMITS.maxPendingInvitations).toBe(128);
    expect(PEER_LIMITS.invitationTtlMs).toBe(300_000);
    expect(PEER_LIMITS.maxCodeAttempts).toBe(5);
  });
});
