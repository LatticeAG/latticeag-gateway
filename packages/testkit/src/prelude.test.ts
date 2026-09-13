import {verify} from "node:crypto";
import {describe,expect,it} from "vitest";
import {F,H,J,auditor,config1,migrateConfig,now,origin,planFor} from "./prelude.mts";
import {collectPeerTranscript,createExchangeCollector} from "./harness.ts";

describe("fixture prelude known-answer tests", () => {
  it("seals F.events[0] to the spec hash and signature", () => {
    expect(F.events[0].hash).toBe("8126edf35ef72f9a94909cde60f0c3955cedf774be3a0357f01078b1b1c1c2d9");
    expect(F.events[0].signature).toBe("ameqsvtAKofB1m1uZrPYDrdI4GCHEppx57f0QP2P-m1OqE-Jkbz4WvIrLTp0iIfck0EdvRQprvzyQHmodDPGBA");
  });

  it("verifies both release1 wire signatures under the origin/auditor public keys", () => {
    const keys = [origin, auditor];
    for (const [i, s] of F.release1.wire.signatures.entries()) {
      const ok = verify(
        null,
        Buffer.concat([Buffer.from("sunlight.statement.signature/1\n"), Buffer.from(s.hash.slice(7), "hex")]),
        keys[i]!.public,
        Buffer.from(s.signature_hex, "hex"),
      );
      expect(ok).toBe(true);
    }
  });

  it("produces distinct release1/release2 archive digests", () => {
    expect(F.release1.manifest.package.archive.digest).not.toBe(F.release2.manifest.package.archive.digest);
    expect(F.archiveDigest).toBe(F.release1.manifest.package.archive.digest);
  });

  it("migrates config1 deterministically", () => {
    const a = migrateConfig(config1, "ws1", "gw1");
    const b = migrateConfig(config1, "ws1", "gw1");
    expect(J(a)).toBe(J(b));
    expect(() => migrateConfig({ schema_version: 9 }, "ws1", "gw1")).toThrowError("SCHEMA_UNSUPPORTED");
  });

  it("emits schema_version 2 carrying the seven v1 adapter keys unchanged", () => {
    expect(F.config2.schema_version).toBe(2);
    expect(Object.keys(F.config2.adapters).sort()).toEqual([
      "axion", "lexshield", "lexverdict", "polymesh", "vekinbox", "viscompile", "visreplay",
    ]);
    expect(J(F.config2.adapters)).toBe(J(config1.adapters));
  });

  it("collectPeerTranscript yields the header plus 10 exchange lines", () => {
    const lines = collectPeerTranscript("openai-completions", "loopback-http-sse", "completion1");
    expect(lines).toHaveLength(11);
    expect(JSON.parse(lines[0]!)).toEqual({
      connector: { family: "openai-completions", transport: "loopback-http-sse", provider_session: "completion1" },
      native_boundary: { required: "pinned PolyMesh owner artifact", fixture_routes: 0, interoperability_claim: false },
    });
    for (const line of lines) expect(J(JSON.parse(line))).toBe(line);
  });

  it("exchange() injects the plan hash and rewrites review for product.install", () => {
    const { exchange, entries } = createExchangeCollector();
    exchange("product.install", { plan: F.plan, review: F.review }, { operation: "op1", state: "QUEUED" });
    expect(entries).toHaveLength(1);
    const entry = entries[0]!;
    const expectedPlan = H(J(planFor("install")));
    expect(entry.request.id).toBe("q1");
    expect(entry.request.params.plan).toBe(expectedPlan);
    // The review rewrite deletes the supplied review, then binds
    // {method, params-with-injected-plan, operator, expires_ms}.
    expect(entry.request.params.review).toBe(
      H(J({ method: "product.install", params: { plan: expectedPlan }, operator: "operator1", expires_ms: now + 300000 })),
    );
    expect(entry.response.ok).toBe(true);
    expect(entry.response.receipt.workspace).toBe("audit1");
    expect(entry.response.receipt.event.seq).toBe("4");
    expect(entry.response.receipt.event.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("suppresses receipts for exempt methods and adds peer headers when peer=true", () => {
    const { exchange, entries } = createExchangeCollector();
    exchange("daemon.hello", { profiles: [] }, { protocol: "gateway-control/2" });
    expect(entries[0]!.response.receipt).toBeNull();
    exchange("agent.disconnect", { peer: "peer1" }, { peer: "peer1", state: "DISCONNECTED" }, true);
    const headers = entries[1]!.headers!;
    expect(headers.Authorization).toBe("Bearer " + F.access);
    expect(headers["X-LatticeAG-Epoch"]).toBe("1");
    expect(headers["X-LatticeAG-Nonce"]).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(headers["X-LatticeAG-Key-Proof"]).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});
