/**
 * §6 SSE event channel served by the loopback bridge.
 *
 * `GET /v2/events?subscription=<id>` — a durable subscription created via
 * `events.subscribe` — streams committed events ordered by cursor:
 *
 *     id: <cursor>
 *     event: bus
 *     data: {"cursor":…,"topic":…,"profile":…,"record_ref":…,"availability":…}
 *
 * Contract: 128-bit unpredictable subscription id, `Cache-Control: no-store`
 * + `X-Accel-Buffering: no` + identity encoding (no proxy buffering or
 * compression), `: heartbeat` comments every 15 s, `retry: 1000` on open,
 * frames ≤128 KiB, `Last-Event-ID` resume that replays from `cursor+1`, a
 * stale cursor (before the earliest retained) answers HTTP 410
 * `CURSOR_GONE`, and slow consumers that hold >256 KiB of unflushed credit
 * for >5000 ms are disconnected. Cursor/secret state survives disconnects.
 */
import type { ServerResponse } from "node:http";
import { parseCursor } from "../store/lanes.js";

export const SSE_LIMITS = {
  frameBytes: 128 * 1024,
  creditBytes: 256 * 1024,
  overCreditMs: 5_000,
  heartbeatMs: 15_000,
  retryMs: 1_000,
} as const;

/** One subscription's view of a committed event. */
export interface SseFrame {
  cursor: string;
  topic: string;
  profile: string;
  /** Content hash of the lane record (spec: record hash, not object hash). */
  record_ref: string;
  availability: "INLINE" | "OBJECT";
}

/**
 * Event source the SSE channel tails. `readAfter(cursor, limit)` must
 * return events strictly after `cursor` in cursor order (cursor = initial
 * read position allowed when it precedes every event), or throw
 * `STALE_CURSOR` when `cursor` precedes the earliest retained entry.
 */
export interface SseSource {
  earliestRetainedCursor(subscription: string): string | null;
  readAfter(
    subscription: string,
    cursor: string,
    limit: number,
  ): Promise<SseFrame[]>;
  /** Wait for new events or subscription liveness; resolves to wake poll. */
  waitFor(subscription: string, cursor: string, signal: AbortSignal): Promise<void>;
}

export interface SseSubscription {
  id: string;
  /** Cursor from which replay starts; frames strictly after it stream. */
  lastAckCursor: string | null;
}

export interface SseRegistry {
  lookup(id: string): SseSubscription | null;
}

export function writeSseFrame(res: ServerResponse, frame: SseFrame): boolean {
  const data = JSON.stringify({
    cursor: frame.cursor,
    topic: frame.topic,
    profile: frame.profile,
    record_ref: frame.record_ref,
    availability: frame.availability,
  });
  const text =
    `id: ${frame.cursor}\n` +
    `event: bus\n` +
    `data: ${data}\n\n`;
  if (Buffer.byteLength(text, "utf8") > SSE_LIMITS.frameBytes) {
    // A frame above the per-frame cap is skipped rather than truncated.
    return false;
  }
  return res.write(text);
}

/** The `retry: 1000` preamble emitted on connect. */
export function writeSsePreamble(res: ServerResponse): void {
  res.write(`retry: ${SSE_LIMITS.retryMs}\n\n`);
}

/**
 * Serve one SSE stream on an already-routed response. Enforces the frame
 * contract, heartbeats, resume, and the slow-consumer disconnect. Resolves
 * when the stream ends (client disconnect or over-credit close).
 */
export async function serveSse(
  res: ServerResponse,
  sub: SseSubscription,
  source: SseSource,
  opts: {
    lastEventId?: string | null;
    now?: () => number;
    heartbeatMs?: number;
    overCreditMs?: number;
  } = {},
): Promise<void> {
  const now = opts.now ?? Date.now;
  const heartbeatMs = opts.heartbeatMs ?? SSE_LIMITS.heartbeatMs;
  const overCreditMs = opts.overCreditMs ?? SSE_LIMITS.overCreditMs;
  // Resume point: Last-Event-ID wins over the subscription's stored ack.
  let cursor =
    opts.lastEventId !== undefined && opts.lastEventId !== null && opts.lastEventId !== ""
      ? opts.lastEventId
      : (sub.lastAckCursor ?? "");
  if (cursor !== "") {
    const earliest = source.earliestRetainedCursor(sub.id);
    if (earliest !== null && cursorPrecedes(cursor, earliest)) {
      // Cursor is before retained history — the tail cannot be replayed.
      const err = new Error("stale cursor");
      (err as { code?: string }).code = "CURSOR_GONE";
      throw err;
    }
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-store",
    "X-Accel-Buffering": "no",
    "Content-Encoding": "identity",
    Connection: "keep-alive",
  });
  res.flushHeaders();
  writeSsePreamble(res);

  const abort = new AbortController();
  let closed = false;
  let buffered = 0;
  let overSince: number | null = null;

  const onClose = (): void => {
    closed = true;
    abort.abort();
  };
  res.on("close", onClose);

  const heartbeat = setInterval(() => {
    if (closed) return;
    try {
      res.write(`: heartbeat\n\n`);
    } catch {
      /* socket already gone */
    }
  }, heartbeatMs);
  heartbeat.unref?.();

  try {
    while (!closed) {
      let frames: SseFrame[];
      try {
        frames = await source.readAfter(sub.id, cursor, 64);
      } catch (e) {
        if ((e as { code?: string }).code === "STALE_CURSOR") throw e;
        throw e;
      }
      for (const f of frames) {
        if (closed) break;
        const bytes = Buffer.byteLength(
          `id: ${f.cursor}\nevent: bus\ndata: ${JSON.stringify({
            cursor: f.cursor,
            topic: f.topic,
            profile: f.profile,
            record_ref: f.record_ref,
            availability: f.availability,
          })}\n\n`,
          "utf8",
        );
        const flushed = writeSseFrame(res, f);
        cursor = f.cursor;
        if (!flushed) continue; // oversize frame skipped
        buffered += bytes;
        // Track drain: when the socket drains, buffered credit resets.
        res.once("drain", () => {
          buffered = 0;
          overSince = null;
        });
        if (res.writableLength === 0) {
          buffered = 0;
          overSince = null;
        } else if (buffered > SSE_LIMITS.creditBytes) {
          if (overSince === null) overSince = now();
          if (now() - overSince > overCreditMs) {
            closed = true;
            res.end();
            break;
          }
        } else {
          overSince = null;
        }
      }
      if (closed) break;
      await source.waitFor(sub.id, cursor, abort.signal).catch(() => undefined);
    }
  } finally {
    clearInterval(heartbeat);
    res.off("close", onClose);
    if (!res.writableEnded) res.end();
  }
}

/**
 * True when `a` orders strictly before `b` in cursor order. Cursors are
 * compared structurally (lane ordinal, then record ordinal as integers) —
 * a lexicographic compare would misorder e.g. `…:7` against `…:12`.
 * Cursors outside the `c<16hex>:<ordinal>` grammar fall back to an opaque
 * byte order so the check stays total.
 */
export function cursorPrecedes(a: string, b: string): boolean {
  const pa = parseCursor(a);
  const pb = parseCursor(b);
  if (pa === null || pb === null) return a < b;
  if (pa.laneOrdinal !== pb.laneOrdinal) return pa.laneOrdinal < pb.laneOrdinal;
  return pa.recordOrdinal < pb.recordOrdinal;
}

/** `Last-Event-ID` header → cursor (format `c<16hex>:<ordinal>`). */
export function parseLastEventId(value: string | undefined): string | null {
  if (value === undefined || value === "") return null;
  return /^c[0-9a-f]{16}:[0-9]+$/.test(value) ? value : null;
}

/** Serialize a committed bus record into its SSE frame (spec §6). */
export function frameForEvent(
  cursor: string,
  event: { topic: string; profile: string; hash: string; object: unknown },
): SseFrame {
  return {
    cursor,
    topic: event.topic,
    profile: event.profile,
    record_ref: event.hash,
    availability: event.object !== null && event.object !== undefined ? "OBJECT" : "INLINE",
  };
}
