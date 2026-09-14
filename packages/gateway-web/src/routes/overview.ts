/**
 * `/` — instance overview (spec §7.1): daemon.status + product.list +
 * sync.status. States: first run, offline, READY, DEGRADED, disconnected.
 * Per-area status only — no misleading all-green aggregate.
 */
import { h, append, kv, pill, emptyState } from "../lib/dom.js";
import { fmtCount, fmtDateTime, show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError, isAuthFailure } from "./ctx.js";

export const overviewRoute: RouteModule = (ctx) => {
  const d = new Disposer();
  const root = h("section", { aria: { label: "Instance overview" } }, h("h1", { text: "Overview" }));
  const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
  append(root, body);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  const render = (status: Record<string, unknown> | null, products: unknown, sync: Record<string, unknown> | null, err: string | null): void => {
    body.replaceChildren();
    if (err !== null && status === null) {
      append(body, h("div", { class: "error-box", role: "alert" },
        h("div", { class: "code", text: err }),
        h("div", { text: "The daemon is unreachable from this browser session. Retrying in the background — mutations stay disabled." })));
      return;
    }
    const state = show(status?.state ?? "UNKNOWN");
    const productsCount = typeof status?.products === "number" ? status.products : (Array.isArray((products as { items?: unknown[] })?.items) ? (products as { items: unknown[] }).items.length : 0);
    const peers = typeof status?.peers === "number" ? status.peers : null;
    const firstRun = productsCount === 0 && peers === 0;

    if (firstRun) {
      append(body, h("div", { class: "notice-box", role: "note" },
        h("h3", { text: "First run" }),
        h("p", { text: "No products installed and no agents enrolled yet." }),
        h("p", { class: "small muted", text: "Browse the catalog (g p), or pair an agent via `latticeag gateway agent pair` on the CLI — pairing approval always needs the local operator socket." })));
    }
    append(body,
      h("div", { class: "panel" },
        h("h2", { text: "Instance" }),
        kv([
          ["Instance", show(status?.instance)],
          ["State", ""],
          ["Config revision", show(status?.config_revision)],
          ["UI", show(status?.ui)],
        ])),
      h("div", { class: "panel" },
        h("h2", { text: "Areas" }),
        kv([
          ["Daemon", ""],
          ["Products", `${fmtCount(productsCount)} installed`],
          ["Peers", fmtCount(peers)],
          ["Sync", sync === null ? "unavailable" : show(sync.paused === true ? "paused" : "running")],
        ])));
    // Per-area pills — independent labels, no aggregate green.
    const areaRow = h("div", { class: "btn-row" },
      pill(`daemon ${state}`, state === "READY" ? "ok" : state === "DEGRADED" ? "warn" : "err"),
      pill(`products ${fmtCount(productsCount)}`, "muted"),
      pill(`peers ${fmtCount(peers)}`, "muted"),
      pill(`sync ${sync === null ? "unavailable" : sync.paused === true ? "paused" : "enabled"}`, sync === null ? "muted" : sync.paused === true ? "warn" : "ok"));
    append(body, areaRow);
    if (sync !== null) {
      const streams = (sync.streams ?? {}) as Record<string, unknown>;
      const blocked = Object.values(streams).filter((s) => s !== null && typeof s === "object" && typeof (s as Record<string, unknown>).blocked === "number" && (s as { blocked: number }).blocked > 0).length;
      if (blocked > 0) {
        append(body, h("p", { class: "warn small", text: `${blocked} sync stream(s) blocked — see /sync.` }));
      }
    }
    if (status?.started_ms !== undefined || status?.now_ms !== undefined) {
      append(body, h("p", { class: "small muted", text: `as of ${fmtDateTime(Number(status.now_ms ?? Date.now()))}` }));
    }
  };

  const poll = async (): Promise<void> => {
    try {
      const [status, products, sync] = await Promise.all([
        ctx.client.call<Record<string, unknown>>("daemon.status"),
        ctx.client.call<unknown>("product.list", { after: null, limit: 100 }).catch(() => null),
        ctx.client.call<Record<string, unknown>>("sync.status").catch(() => null),
      ]);
      ctx.store.set({
        connection: { ...ctx.store.get().connection, phase: show(status.state) === "READY" ? "online" : "degraded", daemonState: show(status.state), detail: "", lastOkMs: Date.now(), consecutiveFailures: 0 },
        mutationsEnabled: ctx.store.get().session?.role === "operator" && show(status.state) !== "STOPPED",
      });
      render(status, products, sync, null);
    } catch (e) {
      const conn = ctx.store.get().connection;
      const failures = conn.consecutiveFailures + 1;
      ctx.store.set({
        connection: { ...conn, phase: "offline", detail: describeError(e), consecutiveFailures: failures },
        mutationsEnabled: false,
      });
      render(null, null, null, describeError(e));
      if (isAuthFailure(e)) {
        ctx.store.set({ session: null });
      }
    }
  };
  void poll();
  d.every(5_000, () => void poll());
  return d;
};
