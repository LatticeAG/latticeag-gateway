/**
 * `/events` — live event table (spec §7.1/§7.2): events.subscribe →
 * SSE lease → bounded table; Space pauses autoscroll (frames keep
 * buffering), 410 shows the explicit gap choice (replay earliest / fresh
 * snapshot — never a silent jump), expired cursor, reconnect, and the
 * raw-data access denial in the inspector.
 */
import { h, append, clear, emptyState, errorBox, pill } from "../lib/dom.js";
import { EventTable, streamBar } from "../components/event-table.js";
import { EventDetail } from "../components/event-detail.js";
import { EventStream, EventBuffer, type BusEventData } from "../lib/sse.js";
import { show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

const TOPICS = ["telemetry", "verdict", "approval.request", "approval.decision", "receipt", "lineage", "watch.alert", "gateway.action"];

export const eventsRoute: RouteModule = (ctx) => {
  const d = new Disposer();
  const buffer = new EventBuffer(2_000);
  const table = new EventTable({
    onSelect: (ev) => showDetail(ev.frame),
  });
  const barSlot = h("div");
  const tableSlot = h("div", {}, table.el);
  const gapSlot = h("div");
  const filter = h("select", { aria: { label: "Topic filter" } },
    h("option", { value: "", text: "all topics" }),
    ...TOPICS.map((t) => h("option", { value: t, text: t }))) as HTMLSelectElement;
  const root = h("section", { aria: { label: "Events" } },
    h("h1", { text: "Events" }),
    h("div", { class: "toolbar" }, filter),
    barSlot, gapSlot, tableSlot);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  let stream: EventStream | null = null;
  let subscription: string | null = null;
  let leaseTimer: ReturnType<typeof setInterval> | null = null;

  const renderBar = (phase: string): void => {
    clear(barSlot);
    append(barSlot, streamBar({
      phase,
      paused: buffer.paused,
      buffered: buffer.length,
      dropped: buffer.dropped,
      onPauseToggle: () => togglePause(),
    }));
    ctx.store.set({
      stream: {
        phase: phase as never,
        paused: buffer.paused,
        buffered: buffer.length,
        dropped: buffer.dropped,
        lastActivityMs: stream?.lastActivity ?? 0,
      },
    });
  };

  const togglePause = (): void => {
    buffer.paused = !buffer.paused;
    renderBar(stream?.phase ?? "idle");
  };

  const showGap = (detail: string): void => {
    clear(gapSlot);
    append(gapSlot, h("div", { class: "notice-box", role: "alert" },
      h("h3", { text: `Cursor gap — ${detail}` }),
      h("p", { text: "The resume cursor is older than the retained tail. Choose how to continue — the interval is never skipped silently." }),
      h("div", { class: "btn-row" },
        h("button", {
          class: "primary",
          text: "Replay earliest retained",
          on: { click: () => { clear(gapSlot); void subscribe("earliest"); } },
        }),
        h("button", {
          text: "Fresh snapshot",
          on: { click: () => { clear(gapSlot); void subscribe(null); } },
        }))));
  };

  const render = (): void => {
    const topic = filter.value;
    const rows = topic === "" ? buffer.list() : buffer.list().filter((e) => e.frame.topic === topic);
    table.setRows(rows, buffer.dropped);
    renderBar(stream?.phase ?? "idle");
  };
  filter.addEventListener("change", render);

  const showDetail = async (frame: BusEventData): Promise<void> => {
    ctx.shell.setInspector(EventDetail({ frame, objectState: "loading" }));
    // Raw bytes need an authorized objects.get; the reference alone is
    // not disclosure authority. Surface the denial verbatim.
    try {
      const obj = await ctx.client.call<unknown>("objects.get", {
        action: { workspace: ctx.store.get().session?.workspace, event: frame.record_ref },
        ref: frame.record_ref,
      });
      ctx.shell.setInspector(EventDetail({ frame, object: obj, objectState: "loaded" }));
    } catch (e) {
      ctx.shell.setInspector(EventDetail({ frame, objectState: "denied", objectError: describeError(e) }));
    }
  };

  const subscribe = async (after: string | null | "earliest"): Promise<void> => {
    stream?.close();
    stream = null;
    buffer.clear();
    table.setRows([], 0);
    renderBar("connecting");
    let sub: { subscription?: string; cursor?: string; expires_ms?: number };
    try {
      sub = await ctx.client.call("events.subscribe", {
        topics: TOPICS,
        after: after === "earliest" ? "earliest" : after,
      });
    } catch (e) {
      clear(tableSlot);
      append(tableSlot, errorBox(describeError(e), "events.subscribe failed — cannot open a stream without a lease."));
      renderBar("error");
      return;
    }
    subscription = sub.subscription ?? null;
    if (subscription === null) {
      append(tableSlot, emptyState("Daemon returned no subscription id."));
      return;
    }
    const startCursor = sub.cursor ?? null;
    stream = new EventStream({
      url: `/v2/events?subscription=${encodeURIComponent(subscription)}`,
      csrf: () => ctx.store.get().session?.csrf ?? null,
      onFrame: (_raw, bus) => {
        if (bus === null) return;
        buffer.push(bus);
        // ACK the delivered cursor for our own subscription (§3.2).
        if (buffer.length % 32 === 0 && subscription !== null) {
          ctx.client.call("events.ack", { subscription, cursor: bus.cursor }).catch(() => undefined);
        }
        if (!buffer.paused) render();
        else renderBar(stream?.phase ?? "open");
      },
      onPhase: (phase, detail) => {
        if (phase === "gap") showGap(detail ?? "CURSOR_GONE");
        renderBar(phase);
      },
    });
    // Keep the 60 s lease warm by advancing the delivered cursor (§3.2
    // events.ack) while the view lives.
    leaseTimer = setInterval(() => {
      const cursor = buffer.latestCursor() ?? startCursor;
      if (subscription === null || cursor === null || cursor === "") return;
      ctx.client.call("events.ack", { subscription, cursor }).catch(() => undefined);
    }, 30_000);
    d.add(() => { if (leaseTimer !== null) clearInterval(leaseTimer); });
    await stream.start(startCursor === null || startCursor === "" ? undefined : startCursor);
  };

  void subscribe(null);
  d.add(() => { stream?.close(); });
  d.add(() => ctx.shell.setInspector());
  return d;
};

export function eventsTopics(): readonly string[] {
  return TOPICS;
}
