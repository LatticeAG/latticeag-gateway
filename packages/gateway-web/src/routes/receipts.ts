/**
 * `/receipts` — search through receipt-bearing actions (spec §7.1):
 * events.query over the audit/action topics; each row links to
 * /receipts/:workspace/:action for receipt.get + lineage.query.
 */
import { h, append, clear, emptyState, errorBox, pill } from "../lib/dom.js";
import { fmtTime, shortId, show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

interface ReceiptRow {
  workspace: string;
  action: string;   // EventRef/NativeRef text
  topic: string;
  cursor: string;
}

export const receiptsRoute: RouteModule = (ctx) => {
  const d = new Disposer();
  const search = h("input", {
    type: "search", placeholder: "Filter actions… (/)", dataset: { search: "receipts" },
    aria: { label: "Filter receipts" },
  }) as HTMLInputElement;
  const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
  const root = h("section", { aria: { label: "Receipts" } },
    h("h1", { text: "Receipts" }),
    h("div", { class: "toolbar" }, h("div", { style: "flex:1" }, search)),
    body);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  let rows: ReceiptRow[] = [];

  const render = (): void => {
    clear(body);
    const q = search.value.trim().toLowerCase();
    const list = q === "" ? rows : rows.filter((r) =>
      r.action.toLowerCase().includes(q) || r.workspace.toLowerCase().includes(q) || r.topic.toLowerCase().includes(q));
    if (list.length === 0) {
      append(body, emptyState("No receipt-bearing actions in the queried window."));
      return;
    }
    const tbody = h("tbody");
    for (const r of list) {
      const tr = h("tr", { class: "row-link", tabindex: 0 },
        h("td", { class: "mono", text: r.cursor }),
        h("td", { class: "mono", text: r.workspace }),
        h("td", { class: "mono", text: shortId(r.action, 18, 8), title: r.action }),
        h("td", { text: r.topic }));
      const open = (): void =>
        ctx.navigate(`/receipts/${encodeURIComponent(r.workspace)}/${encodeURIComponent(r.action)}`);
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (e) => {
        if ((e as KeyboardEvent).key === "Enter") open();
      });
      append(tbody, tr);
    }
    append(body, h("div", { class: "table-wrap" },
      h("table", { class: "tbl" },
        h("thead", {}, h("tr", {},
          h("th", { text: "Cursor" }), h("th", { text: "Workspace" }),
          h("th", { text: "Action ref" }), h("th", { text: "Topic" }))),
        tbody)),
      h("p", { class: "small muted" },
        pill("receipt pointers are not disclosure authority", "muted"),
        " — object bytes require their own authorized objects.get."));
  };
  search.addEventListener("input", render);

  const load = async (): Promise<void> => {
    try {
      const page = await ctx.client.call<{ items?: Record<string, unknown>[] }>(
        "events.query", { topics: ["receipt", "gateway.action"], after: null, limit: 200 });
      rows = (page.items ?? []).map((i) => ({
        workspace: ctx.store.get().session?.workspace ?? "default",
        action: show(i.record_ref ?? i.action ?? i.ref ?? i.cursor),
        topic: show(i.topic),
        cursor: show(i.cursor),
      }));
      render();
    } catch (e) {
      clear(body);
      append(body, errorBox(describeError(e), "events.query failed — receipts search needs an authorized event read."));
    }
  };

  void load();
  return d;
};

export function receiptRowTime(row: ReceiptRow): string {
  return fmtTime(Number(row.cursor.replace(/\D/g, "").slice(-10)) || 0);
}
