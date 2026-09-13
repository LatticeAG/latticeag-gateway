import { describe, expect, it } from "vitest";
import {
  ENVELOPE_LIMITS,
  IDEMPOTENCY_EXEMPT_BINDING,
  NO_RECEIPT_METHODS,
  jsonDepth,
  validateEnvelopeRequest,
} from "./envelope.js";

const VALID = {
  v: 2,
  id: "req1",
  workspace: "ws1",
  method: "daemon.status",
  params: {},
};

function nest(depth: number): unknown {
  let v: unknown = 1;
  for (let i = 0; i < depth; i += 1) v = { a: v };
  return v;
}

describe("jsonDepth", () => {
  it("counts object nesting with scalars at depth 0", () => {
    expect(jsonDepth(1)).toBe(0);
    expect(jsonDepth("x")).toBe(0);
    expect(jsonDepth(null)).toBe(0);
    expect(jsonDepth({})).toBe(1);
    expect(jsonDepth({ a: { b: [1] } })).toBe(3);
    expect(jsonDepth(nest(32))).toBe(32);
  });
});

describe("validateEnvelopeRequest", () => {
  it("accepts a complete closed request", () => {
    const r = validateEnvelopeRequest(VALID);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.request.v).toBe(2);
      expect(r.request.method).toBe("daemon.status");
    }
  });

  it("rejects depth >32 anywhere in the envelope", () => {
    // Envelope is already depth 1, so params nested 32 deep makes 33.
    const r = validateEnvelopeRequest({ ...VALID, params: nest(32) });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("JSON_INVALID");
    expect(jsonDepth({ ...VALID, params: nest(32) })).toBeGreaterThan(
      ENVELOPE_LIMITS.maxJsonDepth,
    );
  });

  it("rejects v:1 as SCHEMA_UNSUPPORTED", () => {
    const r = validateEnvelopeRequest({ ...VALID, v: 1 });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("SCHEMA_UNSUPPORTED");
      expect(r.field).toBe("v");
    }
  });

  it("rejects a missing id", () => {
    const { id: _id, ...rest } = VALID;
    const r = validateEnvelopeRequest(rest);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("SCHEMA_INVALID");
      expect(r.field).toBe("id");
    }
  });

  it("rejects unknown fields (closed object)", () => {
    const r = validateEnvelopeRequest({ ...VALID, extra: true });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("SCHEMA_INVALID");
      expect(r.field).toBe("extra");
    }
  });

  it("rejects non-objects, arrays, and malformed ids", () => {
    expect(validateEnvelopeRequest(null).ok).toBe(false);
    expect(validateEnvelopeRequest([VALID]).ok).toBe(false);
    expect(validateEnvelopeRequest({ ...VALID, id: "bad id!" }).ok).toBe(false);
    expect(validateEnvelopeRequest({ ...VALID, id: "" }).ok).toBe(false);
  });

  it("rejects non-JSON params leaves via depth check", () => {
    const r = validateEnvelopeRequest({ ...VALID, params: { f: undefined } });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("JSON_INVALID");
  });
});

describe("receipt and idempotency registries", () => {
  it("NO_RECEIPT_METHODS lists the six connection-accounted methods", () => {
    expect([...NO_RECEIPT_METHODS].sort()).toEqual(
      [
        "agent.challenge",
        "agent.renew",
        "daemon.hello",
        "events.ack",
        "run.heartbeat",
        "ui.session.exchange",
      ].sort(),
    );
  });

  it("IDEMPOTENCY_EXEMPT_BINDING binds the spec's param subsets", () => {
    expect(IDEMPOTENCY_EXEMPT_BINDING["agent.register"]).toEqual([
      "pair",
      "key",
      "profiles",
      "interfaces",
      "capabilities",
    ]);
    expect(IDEMPOTENCY_EXEMPT_BINDING["agent.pair.propose"]).toEqual([
      "pair",
      "key",
      "profiles",
      "interfaces",
      "capabilities",
    ]);
    expect(IDEMPOTENCY_EXEMPT_BINDING["agent.renew"]).toEqual(["peer", "refresh_hash"]);
  });
});
