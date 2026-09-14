/**
 * `/sync` — per-stream egress preview/consent/outbox (spec §7.1 + §9):
 * sync.status drives StreamConsentTable + OutboxTable; pause/resume/
 * flush are the only mutations (enable/consent changes are CAS review
 * via sync.configure). States: paused, blocked auth/schema, retry delay,
 * conflicts, offline, partial remote ACK.
 */
import { h, append, clear, errorBox, pill } from "../lib/dom.js";
import { StreamConsentTable, streamsFrom, type SyncStream } from "../components/stream-consent-table.js";
import { OutboxTable, outboxFrom } from "../components/outbox-table.js";
import { show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

export const syncRoute: RouteModule = (ctx) => {
  const d = new Disposer();
  const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
  const root = h("section", { aria: { label: "Sync" } },
    h("h1", { text: "Sync" }),
    body);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  const mutationsEnabled = () => ctx.store.get().mutationsEnabled;

  const load = async (): Promise<void> => {
    let res: Record<string, unknown>;
    try {
      res = await ctx.client.call<Record<string, unknown>>("sync.status");
    } catch (e) {
      clear(body);
      append(body, errorBox(describeError(e), "sync.status failed — egress state unknown (offline or viewer session)."));
      return;
    }
    clear(body);
    const paused = res.paused === true;
    append(body,
      h("div", { class: "panel" },
        h("h3", { text: "Egress" }),
        h("p", {},
          pill(paused ? "paused" : "running", paused ? "warn" : "ok"),
          " ",
          h("span", { class: "small muted", text: "Pause stops new sends; in-flight requests still record their outcome. Consent changes need a reviewed CAS update via `gateway sync config`." })),
        h("div", { class: "btn-row" },
          paused
            ? h("button", { class: "flat", disabled: !mutationsEnabled(), text: "Resume all", on: { click: () => void mutate("sync.resume", { streams: allStreams(res) }) } })
            : h("button", { class: "flat", disabled: !mutationsEnabled(), text: "Pause all", on: { click: () => void mutate("sync.pause", { streams: allStreams(res) }) } }),
          h("button", { class: "flat", disabled: !mutationsEnabled(), text: "Flush (30 s)", on: { click: () => void mutate("sync.flush", { streams: allStreams(res), timeout_ms: 30_000 }) } }))));
    append(body, StreamConsentTable({
      streams: streamsFrom(res),
      cloud: res.cloud ?? null,
      mutationsEnabled: mutationsEnabled(),
      onPause: (s: SyncStream) => void mutate("sync.pause", { streams: [s] }),
      onResume: (s: SyncStream) => void mutate("sync.resume", { streams: [s] }),
      onFlush: (s: SyncStream) => void mutate("sync.flush", { streams: [s], timeout_ms: 30_000 }),
    }));
    const items = outboxFrom(res.outbox ?? res.items);
    append(body, h("h3", { text: "Outbox" }), OutboxTable({ items }));
    if (typeof res.conflicts === "number" && res.conflicts > 0) {
      append(body, h("p", { class: "warn", role: "alert", text: `${res.conflicts} source-slot conflict(s) retained — CONFLICTED candidates are kept locally and remotely; nothing merges silently.` }));
    }
    if (res.partial_ack === true) {
      append(body, h("p", { class: "warn small", text: "Partial remote ACK — some batches stored, conflicts retained." }));
    }
  };

  const allStreams = (res: Record<string, unknown>): string[] =>
    Object.keys((res.streams ?? {}) as Record<string, unknown>);

  const mutate = async (method: string, params: unknown): Promise<void> => {
    try {
      const r = await ctx.client.call<Record<string, unknown>>(method, params);
      ctx.toasts.info(`${method}: ${show(r)}`);
      await load();
    } catch (e) {
      ctx.toasts.error(`${method} failed: ${describeError(e)}`);
    }
  };

  void load();
  d.every(7_500, () => void load());
  return d;
};
