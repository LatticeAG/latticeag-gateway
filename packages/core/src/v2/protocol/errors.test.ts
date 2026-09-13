import { describe, expect, it } from "vitest";
import {
  ERROR_CODES,
  ERROR_PRECEDENCE,
  HTTP_STATUS,
  READ_ONLY,
  RETRYABLE,
  RpcError,
  type RegistryErrorCode,
} from "./errors.js";
import { EXIT, exitForError } from "./exit-codes.js";

describe("v2 protocol error registry", () => {
  it("contains exactly 45 closed codes, all unique", () => {
    expect(ERROR_CODES.length).toBe(45);
    expect(new Set(ERROR_CODES).size).toBe(45);
  });

  it("maps every registry code to an HTTP status", () => {
    for (const code of ERROR_CODES) {
      const status = HTTP_STATUS[code];
      expect(typeof status, code).toBe("number");
      expect(status).toBeGreaterThanOrEqual(400);
      expect(status).toBeLessThanOrEqual(503);
    }
    // No extra keys beyond the registry.
    expect(Object.keys(HTTP_STATUS).sort()).toEqual([...ERROR_CODES].sort());
  });

  it("groups HTTP statuses per the spec table", () => {
    const byStatus = new Map<number, RegistryErrorCode[]>();
    for (const code of ERROR_CODES) {
      const list = byStatus.get(HTTP_STATUS[code]) ?? [];
      list.push(code);
      byStatus.set(HTTP_STATUS[code], list);
    }
    expect(byStatus.get(400)?.sort()).toEqual(
      ["JSON_INVALID", "SCHEMA_INVALID", "SCHEMA_UNSUPPORTED", "METHOD_UNKNOWN"].sort(),
    );
    expect(byStatus.get(401)?.sort()).toEqual(
      ["AUTH_REQUIRED", "TOKEN_EXPIRED", "TOKEN_REVOKED"].sort(),
    );
    expect(byStatus.get(404)).toEqual(["NOT_FOUND"]);
    expect(byStatus.get(410)?.sort()).toEqual(
      ["CURSOR_GONE", "PAIRING_EXPIRED", "APPROVAL_EXPIRED", "TRUST_EXPIRED"].sort(),
    );
    expect(byStatus.get(413)?.sort()).toEqual(["OBJECT_LIMIT", "BODY_LIMIT"].sort());
    expect(byStatus.get(422)?.sort()).toEqual(
      ["SIGNATURE_INVALID", "PROVENANCE_INVALID", "ARTIFACT_MISMATCH"].sort(),
    );
    expect(byStatus.get(429)?.sort()).toEqual(["BUSY", "BACKPRESSURE"].sort());
    expect(byStatus.get(503)?.sort()).toEqual(
      ["STORAGE_UNAVAILABLE", "NETWORK_UNAVAILABLE", "HEALTH_FAILED", "SYNC_BLOCKED"].sort(),
    );
  });

  it("marks only the transient set retryable", () => {
    expect([...RETRYABLE].sort()).toEqual(
      ["BACKPRESSURE", "BUSY", "NETWORK_UNAVAILABLE", "STORAGE_UNAVAILABLE", "SYNC_BLOCKED"].sort(),
    );
  });

  it("keeps READ_ONLY outside the wire registry", () => {
    expect(READ_ONLY).toBe("READ_ONLY");
    expect((ERROR_CODES as readonly string[]).includes(READ_ONLY)).toBe(false);
  });

  it("lists precedence earliest stage first", () => {
    expect(ERROR_PRECEDENCE[0]).toBe("TRANSPORT_CAP");
    expect(ERROR_PRECEDENCE[ERROR_PRECEDENCE.length - 1]).toBe("EXECUTION");
    expect(ERROR_PRECEDENCE.indexOf("JSON")).toBeLessThan(
      ERROR_PRECEDENCE.indexOf("ENVELOPE_SCHEMA"),
    );
    expect(ERROR_PRECEDENCE.indexOf("AUTHENTICATION")).toBeLessThan(
      ERROR_PRECEDENCE.indexOf("IDEMPOTENCY"),
    );
  });

  it("RpcError carries code, retryable, and field", () => {
    const err = new RpcError("BUSY", "admission saturated");
    expect(err.code).toBe("BUSY");
    expect(err.retryable).toBe(true);
    expect(err.field).toBeNull();
    const named = new RpcError("FORBIDDEN", "denied", { field: "scopes" });
    expect(named.retryable).toBe(false);
    expect(named.field).toBe("scopes");
  });
});

describe("v2 exit codes", () => {
  it("matches the §6.1 table constants", () => {
    expect(EXIT.OK).toBe(0);
    expect(EXIT.USAGE).toBe(2);
    expect(EXIT.CONFIG).toBe(3);
    expect(EXIT.POLICY).toBe(4);
    expect(EXIT.SYNC).toBe(5);
    expect(EXIT.NETWORK).toBe(6);
    expect(EXIT.AUTH).toBe(7);
    expect(EXIT.SIGNATURE).toBe(8);
    expect(EXIT.STORAGE).toBe(9);
    expect(EXIT.REVISION).toBe(10);
    expect(EXIT.BUSY).toBe(11);
    expect(EXIT.UNSUPPORTED).toBe(12);
    expect(EXIT.TIMEOUT).toBe(124);
  });

  it("maps error codes to exits (spot checks)", () => {
    expect(exitForError("AUTH_REQUIRED")).toBe(7);
    expect(exitForError("TOKEN_REVOKED")).toBe(7);
    expect(exitForError("SIGNATURE_INVALID")).toBe(8);
    expect(exitForError("SYNC_BLOCKED")).toBe(5);
    expect(exitForError("PORT_IN_USE")).toBe(11);
    expect(exitForError("CAP_ADAPTER_UNAVAILABLE")).toBe(12);
    expect(exitForError("SCHEMA_INVALID")).toBe(2);
    expect(exitForError("STORAGE_UNAVAILABLE")).toBe(9);
    expect(exitForError("REVISION_CONFLICT")).toBe(10);
    expect(exitForError("NETWORK_DENIED")).toBe(6);
    expect(exitForError("FORBIDDEN")).toBe(4);
    expect(exitForError("READ_ONLY")).toBe(4);
  });

  it("provides an exit for every registry code", () => {
    for (const code of ERROR_CODES) {
      expect(exitForError(code), code).toBeGreaterThanOrEqual(0);
    }
  });
});
