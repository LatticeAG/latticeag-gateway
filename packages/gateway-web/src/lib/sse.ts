/**
 * SSE client for `GET /v2/events?subscription=<id>` (spec §7.2).
 *
 * The daemon requires the memory-only `X-LatticeAG-CSRF` header on the
 * stream request; native `EventSource` cannot set headers, so this class
 * implements the EventSource contract over `fetch` + ReadableStream:
 * `retry:` honored (default 1000 ms), `Last-Event-ID` resume after the
 * last fully parsed event, `: heartbeat` comment liveness tracking, and
 * HTTP 410 (CURSOR_GONE) surfaced as an explicit "gap" state that offers
 * replay/reset — never a silent jump across missing events.
 */

export const SSE_DEFAULT_RETRY_MS = 1_000;
/** Two missed 15 s heartbeats → the stream is flagged stale. */
export const SSE_STALE_MS = 45_000;
/** Hard cap on buffered rows (spec §7.2: retain at most 2000 events). */
export const SSE_BUFFER_CAP = 2_000;

/** One decoded SSE block. */
export interface SseEventFrame {
  id: string | null;
  event: string;
  data: string;
}

/** The §7.2 `bus` event payload carried in a frame's data field. */
export interface BusEventData {
  cursor: string;
  topic: string;
  profile: string;
  record_ref: unknown;
  availability: string;
}

export interface SseParseResult {
  frames: SseEventFrame[];
  /** Count of comment-only blocks (heartbeats). */
  comments: number;
  /** Server-requested retry delay, when a `retry:` field was seen. */
  retryMs: number | null;
  /** Last `id:` field seen, even on a data-less block (SSE resume rule). */
  lastId: string | null;
  /** Unparsed tail to prepend to the next chunk. */
  rest: string;
}

const BLOCK_SEP = /\r\n\r\n|\n\n|\r\r/;

/** Incremental SSE block parser; feed raw text, keep `rest` for next call. */
export function parseSse(input: string): SseParseResult {
  const frames: SseEventFrame[] = [];
  let comments = 0;
  let retryMs: number | null = null;
  let lastId: string | null = null;
  let rest = input;
  for (;;) {
    const m = BLOCK_SEP.exec(rest);
    if (m === null) break;
    const block = rest.slice(0, m.index);
    rest = rest.slice(m.index + m[0].length);
    let id: string | null = null;
    let event = "message";
    const dataLines: string[] = [];
    let sawField = false;
    for (const line of block.split(/\r\n|\n|\r/)) {
      if (line === "") continue;
      if (line.startsWith(":")) continue; // comment / heartbeat
      sawField = true;
      const colon = line.indexOf(":");
      const fieldName = colon < 0 ? line : line.slice(0, colon);
      let value = colon < 0 ? "" : line.slice(colon + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      switch (fieldName) {
        case "id":
          // Per SSE spec an id containing NUL is ignored.
          if (!value.includes("\u0000")) id = value;
          break;
        case "event":
          event = value;
          break;
        case "data":
          dataLines.push(value);
          break;
        case "retry": {
          const n = Number(value);
          if (Number.isFinite(n) && n >= 0) retryMs = n;
          break;
        }
        default:
          break; // unknown fields are ignored per SSE spec
      }
    }
    if (id !== null) lastId = id;
    if (!sawField) {
      comments += 1;
      continue;
    }
    // Per the SSE dispatch rule a block only fires an event when it
    // buffered data — `retry:`/`id:`-only blocks update state silently.
    if (dataLines.length === 0) continue;
    frames.push({ id, event, data: dataLines.join("\n") });
  }
  return { frames, comments, retryMs, lastId, rest };
}

export type StreamPhase =
  | "idle"
  | "connecting"
  | "open"
  | "reconnecting"
  | "gap"      // 410 CURSOR_GONE — user chooses replay or reset
  | "error"    // transport/auth failure, will retry after retryMs
  | "closed";

export interface EventStreamOptions {
  /** e.g. `/v2/events?subscription=sub1` */
  url: string;
  /** Called per request for the CSRF header value. */
  csrf: () => string | null;
  fetchFn?: typeof fetch;
  onFrame?: (frame: SseEventFrame, bus: BusEventData | null) => void;
  onPhase?: (phase: StreamPhase, detail?: string) => void;
  /** Fires on any activity, including heartbeat comments. */
  onActivity?: (atMs: number) => void;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Reconnecting SSE reader. `start()` resolves when the stream is first
 * opened (or fails fatally); reconnects continue in the background until
 * `close()`. A 410 response parks the stream in "gap" — recovery is an
 * explicit caller choice (`resumeFresh`/`resumeFrom`), matching §7.2's
 * "never silently jump across a missing interval".
 */
export class EventStream {
  phase: StreamPhase = "idle";
  lastEventId: string | null = null;
  lastActivity = 0;
  /** Last non-2xx status seen (for the gap UI). */
  lastStatus = 0;
  private retryMs = SSE_DEFAULT_RETRY_MS;
  private abort: AbortController | null = null;
  private closed = false;
  private readonly opts: EventStreamOptions;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(opts: EventStreamOptions) {
    this.opts = opts;
    this.fetchFn = opts.fetchFn ?? fetch.bind(globalThis);
    this.now = opts.now ?? Date.now;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  private setPhase(p: StreamPhase, detail?: string): void {
    this.phase = p;
    this.opts.onPhase?.(p, detail);
  }

  /** Begin streaming. Resolves once the connect attempt completes. */
  async start(lastEventId?: string): Promise<void> {
    if (lastEventId !== undefined) this.lastEventId = lastEventId;
    this.closed = false;
    await this.loop();
  }

  close(): void {
    this.closed = true;
    this.abort?.abort();
    this.setPhase("closed");
  }

  /** §7.2 gap recovery: fresh snapshot (drop the stale cursor). */
  resumeFresh(): void {
    if (this.phase !== "gap") return;
    this.lastEventId = null;
    void this.loop();
  }

  /** §7.2 gap recovery: replay from a retained cursor supplied by the UI. */
  resumeFrom(cursor: string): void {
    if (this.phase !== "gap") return;
    this.lastEventId = cursor;
    void this.loop();
  }

  /** True when no activity (frame or heartbeat) for SSE_STALE_MS. */
  isStale(atMs = this.now()): boolean {
    return this.phase === "open" && this.lastActivity > 0 && atMs - this.lastActivity > SSE_STALE_MS;
  }

  private async loop(): Promise<void> {
    while (!this.closed) {
      this.setPhase(this.lastEventId === null ? "connecting" : "reconnecting");
      this.abort = new AbortController();
      const headers: Record<string, string> = { Accept: "text/event-stream" };
      const csrf = this.opts.csrf();
      if (csrf !== null) headers["X-LatticeAG-CSRF"] = csrf;
      if (this.lastEventId !== null) headers["Last-Event-ID"] = this.lastEventId;
      let res: Response;
      try {
        res = await this.fetchFn(this.opts.url, {
          method: "GET",
          headers,
          signal: this.abort.signal,
          credentials: "same-origin",
          referrerPolicy: "no-referrer",
          cache: "no-store",
        });
      } catch (e) {
        if (this.closed) return;
        this.setPhase("error", (e as Error).message);
        await this.sleep(this.retryMs);
        continue;
      }
      this.lastStatus = res.status;
      if (res.status === 410) {
        // CURSOR_GONE — the tail before the earliest retained cursor is
        // gone; the UI must offer replay/reset, never a silent jump.
        this.setPhase("gap", "CURSOR_GONE");
        return;
      }
      if (!res.ok || res.body === null) {
        if (this.closed) return;
        this.setPhase("error", `HTTP ${res.status}`);
        await this.sleep(this.retryMs);
        continue;
      }
      this.setPhase("open");
      try {
        await this.readBody(res.body);
      } catch {
        /* aborted or socket failure → reconnect */
      }
      if (this.closed) return;
      await this.sleep(this.retryMs);
    }
  }

  private async readBody(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        this.lastActivity = this.now();
        this.opts.onActivity?.(this.lastActivity);
        buf += decoder.decode(value, { stream: true });
        const parsed = parseSse(buf);
        buf = parsed.rest;
        if (parsed.retryMs !== null) this.retryMs = parsed.retryMs;
        if (parsed.lastId !== null) this.lastEventId = parsed.lastId;
        for (const frame of parsed.frames) {
          // Only count a fully parsed event for resume (§7.2).
          if (frame.id !== null) this.lastEventId = frame.id;
          let bus: BusEventData | null = null;
          try {
            bus = JSON.parse(frame.data) as BusEventData;
          } catch {
            bus = null; // malformed data still surfaces as a raw frame
          }
          this.opts.onFrame?.(frame, bus);
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
}

export interface BufferedEvent {
  frame: BusEventData;
  /** Monotonic receive ordinal for stable rendering. */
  ordinal: number;
}

/**
 * Bounded stream buffer with Space-pause semantics. Rows are always
 * appended (the stream itself is never paused at the transport level —
 * pause suspends rendering/autoscroll); overflow drops the OLDEST rows
 * and counts them so the UI can render an explicit gap row instead of a
 * silent jump.
 */
export class EventBuffer {
  readonly cap: number;
  paused = false;
  private rows: BufferedEvent[] = [];
  private ordinal = 0;
  /** Rows dropped from the head while at cap — rendered as a gap row. */
  dropped = 0;
  constructor(cap = SSE_BUFFER_CAP) {
    this.cap = cap;
  }
  get length(): number {
    return this.rows.length;
  }
  list(): readonly BufferedEvent[] {
    return this.rows;
  }
  latestCursor(): string | null {
    const last = this.rows[this.rows.length - 1];
    return last ? last.frame.cursor : null;
  }
  push(frame: BusEventData): void {
    this.ordinal += 1;
    this.rows.push({ frame, ordinal: this.ordinal });
    while (this.rows.length > this.cap) {
      this.rows.shift();
      this.dropped += 1;
    }
  }
  clear(): void {
    this.rows = [];
    this.dropped = 0;
  }
}
