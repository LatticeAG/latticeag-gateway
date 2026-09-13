import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { backoffMs, OutboxStore, type OutboxItem } from "./outbox.js";
import { Registry } from "./registry.js";
import { sha256hex } from "./util.js";

const roots: string[] = [];

async function tmpRoot(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "gw-outbox-"));
  roots.push(dir);
  return dir;
}

afterEach(async () => {
  while (roots.length > 0) {
    await rm(roots.pop()!, { recursive: true, force: true });
  }
});

function item(id: string): OutboxItem {
  return {
    v: 1,
    id,
    destination: "cloud-1",
    cohort: "private",
    stream: "runs",
    source: { profile: "proof", namespace: "ns", object_id: "e1" },
    payload: { digest: sha256hex("p"), bytes: "12" },
    consent_revision: "1",
    redaction_sha256: sha256hex("red"),
    from: "now",
    through: "c0000000000000001:1",
    state: "PENDING",
    attempts: 0,
    next_attempt_ms: 0,
    remote_stage: null,
  };
}

describe("outbox", () => {
  it("walks PENDING→IN_FLIGHT→RETRY→IN_FLIGHT→ACKED and persists", async () => {
    const path = join(await tmpRoot(), "registry.sqlite");
    let reg = Registry.open(path, { instance: "i" });
    let ob = new OutboxStore(reg);

    const en = ob.enqueue(item("ob-1"));
    expect(en.enqueued).toBe(true);
    // Dedup on id.
    expect(ob.enqueue(item("ob-1")).enqueued).toBe(false);

    expect(ob.listPending().map((i) => i.id)).toEqual(["ob-1"]);
    ob.transition("ob-1", "IN_FLIGHT", { batch_hash: sha256hex("b1"), remote_stage: "st-1" });
    expect(ob.listPending()).toHaveLength(0);
    ob.transition("ob-1", "RETRY", { next_attempt_ms: 5000 });
    expect(ob.listPending({ due_ms: 4999 })).toHaveLength(0);
    expect(ob.listPending({ due_ms: 5000 })).toHaveLength(1);
    ob.transition("ob-1", "IN_FLIGHT");
    ob.markAcked("ob-1", { through: "c0000000000000001:9", batch_hash: sha256hex("b1") });
    expect(ob.get("ob-1")!.state).toBe("ACKED");
    reg.close();

    // State survives a reopen.
    reg = Registry.open(path, { instance: "i" });
    ob = new OutboxStore(reg);
    const reloaded = ob.get("ob-1");
    expect(reloaded!.state).toBe("ACKED");
    expect(reloaded!.through).toBe("c0000000000000001:9");
    reg.close();
  });

  it("keeps ACKED terminal and rejects illegal edges", async () => {
    const reg = Registry.open(join(await tmpRoot(), "registry.sqlite"), { instance: "i" });
    const ob = new OutboxStore(reg);
    ob.enqueue(item("a"));
    ob.enqueue(item("b"));
    ob.transition("a", "IN_FLIGHT");
    ob.markAcked("a");
    // ACKED never reenters PENDING (or anything else).
    expect(() => ob.transition("a", "PENDING")).toThrowError(
      expect.objectContaining({ code: "INVALID_TRANSITION" }),
    );
    expect(() => ob.transition("a", "RETRY")).toThrowError(
      expect.objectContaining({ code: "INVALID_TRANSITION" }),
    );
    // PENDING → ACKED skips the durable-send edge; rejected.
    expect(() => ob.markAcked("b")).toThrowError(
      expect.objectContaining({ code: "INVALID_TRANSITION" }),
    );
    // BLOCKED → PENDING is the explicit repair path.
    ob.transition("b", "BLOCKED");
    ob.transition("b", "PENDING");
    expect(ob.get("b")!.state).toBe("PENDING");
    reg.close();
  });

  it("backoff is full-jitter within [0, min(300000, 1000*2^attempt))", () => {
    expect(backoffMs(0, () => 0)).toBe(0);
    expect(backoffMs(0, () => 0.9999)).toBeLessThan(1000);
    expect(backoffMs(3, () => 0.9999)).toBeLessThan(8000);
    expect(backoffMs(20, () => 0.9999)).toBeLessThan(300000);
  });
});
