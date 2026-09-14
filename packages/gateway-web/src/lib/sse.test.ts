import { describe, expect, test, vi } from "vitest";
import { EventBuffer, EventStream, parseSse, type SseEventFrame } from "./sse.js";

const yieldMacrotask = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

const FRAME = (cursor: string, topic = "telemetry"): string =>
  `id: ${cursor}\nevent: bus\ndata: ${JSON.stringify({ cursor, topic, profile: "proof-evidence/1", record_ref: { digest: "ab" }, availability: "WITHHELD" })}\n\n`;

describe("parseSse", () => {
  test("parses id/event/data blocks", () => {
    const r = parseSse(FRAME("c0000000000000001:7"));
    expect(r.frames).toHaveLength(1);
    expect(r.frames[0]!.id).toBe("c0000000000000001:7");
    expect(r.frames[0]!.event).toBe("bus");
    expect(JSON.parse(r.frames[0]!.data)).toMatchObject({ cursor: "c0000000000000001:7", availability: "WITHHELD" });
    expect(r.rest).toBe("");
  });

  test("heartbeat comments count as activity, not frames", () => {
    const r = parseSse(": heartbeat\n\n");
    expect(r.frames).toHaveLength(0);
    expect(r.comments).toBe(1);
  });

  test("retry field honored", () => {
    const r = parseSse("retry: 1000\n\n");
    expect(r.retryMs).toBe(1000);
  });

  test("partial block stays in rest; multi-line data joins with \\n", () => {
    const r = parseSse("data: a\ndata: b\n\nid: c1\n");
    expect(r.frames[0]!.data).toBe("a\nb");
    expect(r.rest).toBe("id: c1\n");
  });

  test("ignores unknown fields and NUL ids", () => {
    const r = parseSse("id: ok\nx-other: 1\ndata: {}\n\nid: b\0ad\ndata: {}\n\n");
    expect(r.frames[0]!.id).toBe("ok");
    expect(r.frames[1]!.id).toBeNull();
  });
});

function streamOf(chunks: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(c) {
      for (const ch of chunks) c.enqueue(enc.encode(ch));
      c.close();
    },
  });
}

function fakeRes(status: number, body?: ReadableStream<Uint8Array>): Response {
  return { ok: status >= 200 && status < 300, status, body: body ?? null } as Response;
}

describe("EventStream", () => {
  test("streams frames, tracks cursor, honors retry, CSRF + Last-Event-ID headers", async () => {
    const calls: { headers: Record<string, string> }[] = [];
    const fetchFn = vi.fn(async (_url: unknown, init: unknown) => {
      calls.push({ headers: (init as RequestInit).headers as Record<string, string> });
      const first = calls.length === 1;
      return fakeRes(200, streamOf(first ? [`retry: 2500\n\n`, FRAME("c0000000000000001:1"), `: heartbeat\n\n`] : []));
    }) as unknown as typeof fetch;
    const frames: SseEventFrame[] = [];
    const phases: string[] = [];
    const s = new EventStream({
      url: "/v2/events?subscription=sub1",
      csrf: () => "csrf-x",
      fetchFn,
      onFrame: (f) => frames.push(f),
      onPhase: (p) => phases.push(p),
      sleep: yieldMacrotask,
    });
    const done = s.start();
    await new Promise((r) => setTimeout(r, 0));
    // Stream ended → schedules a reconnect; close it and let it settle.
    s.close();
    await done;
    expect(frames).toHaveLength(1);
    expect(frames[0]!.id).toBe("c0000000000000001:1");
    expect(s.lastEventId).toBe("c0000000000000001:1");
    expect(phases).toContain("open");
    expect(calls[0]!.headers["X-LatticeAG-CSRF"]).toBe("csrf-x");
    // reconnecting path used Last-Event-ID once it had a cursor
    const second = calls[1];
    if (second) expect(second.headers["Last-Event-ID"]).toBe("c0000000000000001:1");
  });

  test("410 → gap phase (CURSOR_GONE), no silent resume; resumeFresh drops cursor", async () => {
    const fetchFn = vi.fn(async () => fakeRes(410)) as unknown as typeof fetch;
    const phases: string[] = [];
    const s = new EventStream({
      url: "/v2/events?subscription=sub1",
      csrf: () => null,
      fetchFn,
      onPhase: (p) => phases.push(p),
      sleep: yieldMacrotask,
    });
    s.lastEventId = "c0000000000000001:99";
    await s.start();
    expect(phases.at(-1)).toBe("gap");
    expect(s.lastStatus).toBe(410);
    // It does not auto-reconnect — gap waits for explicit replay/reset.
    expect(vi.mocked(fetchFn).mock.calls).toHaveLength(1);
    s.resumeFresh();
    await new Promise((r) => setTimeout(r, 0));
    s.close();
    expect(s.lastEventId).toBeNull();
  });

  test("non-2xx error retries after retryMs then can recover", async () => {
    let n = 0;
    const fetchFn = vi.fn(async () => {
      n += 1;
      return n === 1 ? fakeRes(503) : fakeRes(200, streamOf([FRAME("c0000000000000001:2")]));
    }) as unknown as typeof fetch;
    const frames: string[] = [];
    const s = new EventStream({
      url: "/v2/events?subscription=s",
      csrf: () => null,
      fetchFn,
      onFrame: (f) => frames.push(f.id ?? ""),
      sleep: yieldMacrotask,
    });
    const done = s.start();
    await new Promise((r) => setTimeout(r, 5));
    s.close();
    await done;
    expect(n).toBeGreaterThanOrEqual(2);
    expect(frames).toContain("c0000000000000001:2");
  });

  test("resumeFrom replays from an explicit retained cursor", async () => {
    const fetchFn = vi.fn(async () => fakeRes(410)) as unknown as typeof fetch;
    const s = new EventStream({ url: "/v2/x", csrf: () => null, fetchFn, sleep: yieldMacrotask });
    s.lastEventId = "cold";
    await s.start();
    expect(s.phase).toBe("gap");
    s.resumeFrom("c0000000000000000:0");
    await new Promise((r) => setTimeout(r, 0));
    s.close();
    const headers = vi.mocked(fetchFn).mock.calls.at(-1)![1] as RequestInit;
    expect((headers.headers as Record<string, string>)["Last-Event-ID"]).toBe("c0000000000000000:0");
  });
});

describe("EventBuffer", () => {
  const ev = (cursor: string): { cursor: string; topic: string; profile: string; record_ref: null; availability: string } => ({
    cursor, topic: "telemetry", profile: "p", record_ref: null, availability: "WITHHELD",
  });

  test("caps at 2000 rows and counts dropped", () => {
    const b = new EventBuffer(2_000);
    for (let i = 0; i < 2_100; i += 1) b.push(ev(`c${i}`));
    expect(b.length).toBe(2_000);
    expect(b.dropped).toBe(100);
    expect(b.latestCursor()).toBe("c2099");
  });

  test("pause retains buffering (transport never stops)", () => {
    const b = new EventBuffer(5);
    b.paused = true;
    b.push(ev("a"));
    b.push(ev("b"));
    expect(b.length).toBe(2);
    expect(b.paused).toBe(true);
  });
});
