/**
 * SSE channel tests (spec §6): frame contract, heartbeat, resume, stale
 * cursor → CURSOR_GONE. Uses a real HTTP server + in-memory source.
 */
import { describe, expect, test } from "vitest";
import http from "node:http";
import { serveSse, SSE_LIMITS, type SseFrame, type SseSource } from "./sse.js";

/** In-memory event source: frames are appended under one subscription. */
function memSource(frames: SseFrame[], opts: { earliest?: string | null } = {}): SseSource & {
  push(f: SseFrame): void;
  close(): void;
} {
  const waiters: Array<() => void> = [];
  const closed = { v: false };
  return {
    earliestRetainedCursor: () =>
      opts.earliest !== undefined ? opts.earliest : (frames[0]?.cursor ?? null),
    async readAfter(_sub, cursor, limit) {
      const start = frames.findIndex((f) => f.cursor > cursor);
      if (start === -1) return [];
      return frames.slice(start, start + limit);
    },
    async waitFor(_s, _c, signal) {
      await new Promise<void>((res) => {
        if (closed.v) return res();
        waiters.push(res);
        signal.addEventListener("abort", () => res(), { once: true });
      });
    },
    push(f) {
      frames.push(f);
      for (const w of waiters.splice(0)) w();
    },
    close() {
      closed.v = true;
      for (const w of waiters.splice(0)) w();
    },
  };
}

const frame = (n: number): SseFrame => ({
  cursor: `c0000000000000001:${n}`,
  topic: "telemetry",
  profile: "proof-evidence/1",
  record_ref: "ab".repeat(32),
  availability: "INLINE",
});

async function withServer(
  source: SseSource,
  lastEventId: string | null,
  fn: (res: http.IncomingMessage) => Promise<void>,
): Promise<void> {
  const server = http.createServer((req, res) => {
    void serveSse(res, { id: "sub1", lastAckCursor: null }, source, {
      lastEventId,
      heartbeatMs: 50,
    }).catch((e) => {
      if ((e as { code?: string }).code === "CURSOR_GONE" && !res.headersSent) {
        res.writeHead(410, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            v: 2,
            id: null,
            ok: false,
            error: { code: "CURSOR_GONE", retryable: false, field: null },
            receipt: null,
          }),
        );
      } else if (!res.writableEnded) {
        res.end();
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  try {
    await new Promise<void>((resolveR, reject) => {
      const req = http.get(
        {
          host: "127.0.0.1",
          port,
          path: "/v2/events?subscription=sub1",
          headers: { Accept: "text/event-stream" },
        },
        (res) => fn(res).then(resolveR, reject),
      );
      req.on("error", reject);
    });
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

describe("serveSse", () => {
  test("streams committed frames in the spec's wire shape", async () => {
    const frames = [frame(1), frame(2)];
    const source = memSource(frames);
    await withServer(source, null, async (res) => {
      expect(res.statusCode).toBe(200);
      expect(res.headers["content-type"]).toContain("text/event-stream");
      expect(res.headers["cache-control"]).toBe("no-store");
      expect(res.headers["x-accel-buffering"]).toBe("no");
      let text = "";
      await new Promise<void>((done) => {
        res.on("data", (c: Buffer) => {
          text += c.toString("utf8");
          if (text.includes("c0000000000000001:2")) done();
        });
      });
      expect(text).toContain("retry: 1000");
      expect(text).toContain("id: c0000000000000001:1");
      expect(text).toContain("event: bus");
      expect(text).toContain('"topic":"telemetry"');
      expect(text).toContain('"record_ref":"' + "ab".repeat(32) + '"');
      expect(text).toContain('"availability":"INLINE"');
      res.destroy();
    });
  });

  test("new frames arrive after subscription (live tail)", async () => {
    const frames: SseFrame[] = [];
    const source = memSource(frames);
    await withServer(source, null, async (res) => {
      let text = "";
      const got = new Promise<void>((done) => {
        res.on("data", (c: Buffer) => {
          text += c.toString("utf8");
          if (text.includes("c0000000000000001:9")) done();
        });
      });
      // Give the stream a beat to open, then push.
      setTimeout(() => (source as ReturnType<typeof memSource>).push(frame(9)), 30);
      await got;
      expect(text).toContain("id: c0000000000000001:9");
      res.destroy();
    });
  });

  test("Last-Event-ID before retained history → 410 CURSOR_GONE", async () => {
    const source = memSource([frame(10)], { earliest: "c0000000000000001:5" });
    await withServer(source, "c0000000000000001:2", async (res) => {
      expect(res.statusCode).toBe(410);
      let text = "";
      await new Promise<void>((done) => {
        res.on("data", (c: Buffer) => (text += c.toString("utf8")));
        res.on("end", done);
      });
      const env = JSON.parse(text) as { error: { code: string } };
      expect(env.error.code).toBe("CURSOR_GONE");
    });
  });

  test("resume from Last-Event-ID replays only newer frames", async () => {
    const frames = [frame(1), frame(2), frame(3)];
    const source = memSource(frames);
    await withServer(source, "c0000000000000001:1", async (res) => {
      let text = "";
      await new Promise<void>((done) => {
        res.on("data", (c: Buffer) => {
          text += c.toString("utf8");
          if (text.includes("c0000000000000001:3")) done();
        });
      });
      expect(text).not.toContain("id: c0000000000000001:1\n");
      expect(text).toContain("id: c0000000000000001:2");
      expect(text).toContain("id: c0000000000000001:3");
      res.destroy();
    });
  });

  test("limits are the spec values", () => {
    expect(SSE_LIMITS.frameBytes).toBe(128 * 1024);
    expect(SSE_LIMITS.creditBytes).toBe(256 * 1024);
    expect(SSE_LIMITS.overCreditMs).toBe(5000);
    expect(SSE_LIMITS.heartbeatMs).toBe(15000);
    expect(SSE_LIMITS.retryMs).toBe(1000);
  });
});
