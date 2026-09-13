import { describe, expect, it } from "vitest";
import {
  RPC_METHODS,
  ROLES,
  isRpcMethod,
  type Role,
  type RpcMethodName,
} from "./rpc-registry.js";
import { NO_RECEIPT_METHODS } from "./envelope.js";

const NAMES = Object.keys(RPC_METHODS) as RpcMethodName[];
const ROLE_SET = new Set<string>(ROLES);

describe("v2 RPC registry", () => {
  it("contains exactly 58 unique methods", () => {
    expect(NAMES.length).toBe(58);
    expect(new Set(NAMES).size).toBe(58);
  });

  it("assigns every method a valid non-empty role set", () => {
    for (const name of NAMES) {
      const spec = RPC_METHODS[name];
      expect(spec.roles.length, name).toBeGreaterThan(0);
      for (const role of spec.roles) {
        expect(ROLE_SET.has(role), `${name}:${role}`).toBe(true);
      }
      expect(new Set(spec.roles).size, name).toBe(spec.roles.length);
    }
  });

  it("marks receipt=false exactly for the connection-accounted methods", () => {
    for (const name of NAMES) {
      expect(RPC_METHODS[name].receipt, name).toBe(!NO_RECEIPT_METHODS.has(name));
    }
  });

  it("carries the spec's role sets for notable methods", () => {
    expect(RPC_METHODS["daemon.stop"].roles).toEqual(["L"]);
    expect(RPC_METHODS["agent.pair.create"].roles).toEqual(["L"]);
    expect(RPC_METHODS["agent.pair.propose"].roles).toEqual(["P"]);
    expect(RPC_METHODS["agent.register"].roles).toEqual(["P"]);
    expect(RPC_METHODS["ui.session.exchange"].roles).toEqual(["P"]);
    expect(RPC_METHODS["ui.session.create"].roles).toEqual(["L"]);
    expect(RPC_METHODS["cloud.pair.begin"].roles).toEqual(["L"]);
    expect(RPC_METHODS["cloud.pair.complete"].roles).toEqual(["L"]);
    expect(RPC_METHODS["cloud.pair.revoke"].roles).toEqual(["L"]);
    expect(RPC_METHODS["approval.decide"].roles).toEqual(["R", "O"]);
    expect(RPC_METHODS["daemon.hello"].roles).toEqual(["V", "A", "O"]);
    expect(RPC_METHODS["agent.pair.get"].roles).toEqual(["P", "L"]);
    expect(RPC_METHODS["agent.challenge"].roles).toEqual(["P", "A"]);
  });

  it("recognizes registry membership", () => {
    expect(isRpcMethod("catalog.unpin")).toBe(true);
    expect(isRpcMethod("catalog.bogus")).toBe(false);
    expect(isRpcMethod("")).toBe(false);
  });

  it("covers every service prefix", () => {
    const prefixes = new Set(NAMES.map((n) => n.split(".")[0]));
    expect(prefixes).toEqual(
      new Set([
        "daemon",
        "config",
        "run",
        "events",
        "objects",
        "receipt",
        "lineage",
        "operation",
        "product",
        "agent",
        "approval",
        "ui",
        "sync",
        "cloud",
        "catalog",
      ]),
    );
  });

  it("types roles as the Role union", () => {
    const r: Role = RPC_METHODS["approval.decide"].roles[0] as Role;
    expect(r).toBe("R");
  });
});
