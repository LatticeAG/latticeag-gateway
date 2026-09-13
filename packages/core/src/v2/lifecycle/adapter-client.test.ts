import { describe, expect, test } from "vitest";

import { F, schema } from "@latticeag/testkit";

import { AdapterClient } from "./adapter-client.js";
import { StubAdapterChild } from "./testing.js";
import type { StubScript } from "./testing.js";
import { manifestOf } from "./testbed.js";

const manifest = manifestOf(F.release1);

const okScript: StubScript = {
  methods: {
    describe: () => ({
      contract: "gateway-adapter/1",
      product: "lexverdict",
      config_schema_digest: schema.ref.digest,
      profiles: ["@latticeag/events@0.1.0"],
    }),
    configure: (p) => ({ generation: p.generation ?? "1", accepted: true }),
    start: (p) => ({ state: "RUNNING", generation: p.generation ?? "1" }),
    health: () => ({ liveness: true, readiness: true, dependencies: [], native: { status: "ok" } }),
    drain: () => ({ in_flight: 0, uncertain: [] }),
    snapshot: () => ({ supported: false, objects: [] }),
    stop: () => ({ state: "STOPPED", uncertain: [] }),
  },
};

describe("AdapterClient (§5.2 gateway-adapter/1)", () => {
  test("all seven methods round-trip over the pipe", async () => {
    const child = new StubAdapterChild(okScript);
    const client = new AdapterClient(child);
    expect((await client.describe()).product).toBe("lexverdict");
    expect((await client.configure({ instance: "i1", config: {}, generation: "1" })).accepted).toBe(true);
    expect((await client.start({ operation: "op1", generation: "1" })).state).toBe("RUNNING");
    expect((await client.health({ generation: "1" })).readiness).toBe(true);
    expect((await client.drain({ deadline_ms: 5000 })).in_flight).toBe(0);
    expect((await client.snapshot({ generation: "1" })).supported).toBe(false);
    expect((await client.stop({ reason: "test", deadline_ms: 5000 })).state).toBe("STOPPED");
    client.close();
  });

  test("oversized reply line is a protocol breach (BODY_LIMIT)", async () => {
    const child = new StubAdapterChild({
      methods: {},
      rawReply: (_line, write) => {
        write("x".repeat(64 * 1024 + 16));
      },
    });
    const client = new AdapterClient(child);
    await expect(client.describe()).rejects.toMatchObject({ code: "BODY_LIMIT" });
  });

  test("unknown method is rejected locally with METHOD_UNKNOWN (no write)", async () => {
    let writes = 0;
    const child = new StubAdapterChild({
      methods: {},
      rawReply: () => {
        writes += 1;
      },
    });
    const client = new AdapterClient(child);
    await expect(client.request("exec", {})).rejects.toMatchObject({
      code: "METHOD_UNKNOWN",
      field: "method",
    });
    expect(writes).toBe(0); // nothing reached the child
    client.close();
  });

  test("adapter-side METHOD_UNKNOWN error shape maps through", async () => {
    // A stub that knows nothing: every request gets the fixture's error reply.
    const child = new StubAdapterChild({ methods: {} });
    const client = new AdapterClient(child);
    await expect(client.describe()).rejects.toMatchObject({ code: "METHOD_UNKNOWN" });
    client.close();
  });

  test("one outstanding request at a time → BUSY", async () => {
    const child = new StubAdapterChild({
      methods: {
        // never replies
        describe: () => {
          throw new Error("unreachable");
        },
      },
      rawReply: () => undefined,
    });
    const client = new AdapterClient(child, { timeoutMs: 50 });
    const slow = client.describe();
    await expect(client.health({ generation: "1" })).rejects.toMatchObject({ code: "BUSY" });
    await expect(slow).rejects.toMatchObject({ code: "OUTCOME_UNKNOWN" });
    client.close();
  });

  test("reply with mismatched id is a schema violation", async () => {
    const child = new StubAdapterChild({
      methods: {},
      rawReply: (_line, write) => {
        write(JSON.stringify({ v: 1, id: "other", ok: true, result: {} }) + "\n");
      },
    });
    const client = new AdapterClient(child);
    await expect(client.describe()).rejects.toMatchObject({ code: "SCHEMA_INVALID" });
    client.close();
  });

  test("stderr is captured bounded + redacted", async () => {
    const child = new StubAdapterChild(okScript);
    const client = new AdapterClient(child);
    child.stderr.write("token=supersecretvalue\n");
    await client.describe();
    expect(client.stderrTail()).toContain("[redacted]");
    expect(client.stderrTail()).not.toContain("supersecretvalue");
    client.close();
  });
});
