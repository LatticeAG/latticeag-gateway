/**
 * `/receipts/:workspace/:action` — receipt.get + lineage.query +
 * optional objects.get (spec §7.1): independent integrity/native
 * assessment/disclosure/freshness/outcome labels; withheld bytes are a
 * labelled state, not empty success.
 */
import { h, append, clear, errorBox } from "../lib/dom.js";
import { ReceiptViewer, receiptFrom } from "../components/receipt-viewer.js";
import { LineageTree, lineageFrom } from "../components/lineage-tree.js";
import { DisclosureBadge } from "../components/disclosure-badge.js";
import { show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

export const receiptDetailRoute: RouteModule = (ctx, route) => {
  const d = new Disposer();
  const workspace = route.params.workspace ?? "";
  const action = route.params.action ?? "";
  const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
  const root = h("section", { aria: { label: `Receipt ${workspace}/${action}` } },
    h("h1", { text: "Receipt" }),
    h("p", { class: "mono small muted", text: `${workspace} / ${action}` }),
    body);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  const pointer = { workspace, event: action };

  const load = async (): Promise<void> => {
    clear(body);
    const [receiptRes, lineageRes] = await Promise.all([
      ctx.client.call<Record<string, unknown>>("receipt.get", { action: pointer, disclosure: "HASHES_ONLY" })
        .catch((e) => ({ error: describeError(e) })),
      ctx.client.call<Record<string, unknown>>("lineage.query", { action: pointer, max_nodes: 64, max_depth: 16 })
        .catch((e) => ({ error: describeError(e) })),
    ]);
    if ("error" in receiptRes) {
      append(body, errorBox((receiptRes as { error: string }).error, "receipt.get failed — the action reference alone does not authorize disclosure."));
    } else {
      append(body, ReceiptViewer({ receipt: receiptFrom(receiptRes), actionRef: `${workspace}/${action}` }));
    }
    if ("error" in lineageRes) {
      append(body, errorBox((lineageRes as { error: string }).error, "lineage.query failed."));
    } else {
      append(body, LineageTree({ lineage: lineageFrom(lineageRes) }));
    }
    const disclosureBar = h("div", { class: "btn-row" },
      h("span", { class: "small muted", text: "Disclosure:" }),
      ...(["HASHES_ONLY", "REDACTED", "FULL"] as const).map((level) =>
        h("button", {
          class: "flat",
          text: level,
          on: { click: () => void refetch(level) },
        })));
    append(body, disclosureBar);
  };

  const refetch = async (disclosure: "HASHES_ONLY" | "REDACTED" | "FULL"): Promise<void> => {
    try {
      const res = await ctx.client.call<Record<string, unknown>>(
        "receipt.get", { action: pointer, disclosure });
      ctx.shell.setInspector(h("section", {},
        h("h3", { text: `Disclosure ${disclosure}` }),
        DisclosureBadge({ level: disclosure }),
        h("pre", { class: "mono", text: JSON.stringify(res, null, 2) })));
    } catch (e) {
      ctx.toasts.error(`receipt.get ${disclosure} failed: ${describeError(e)}`);
    }
  };

  void load();
  d.add(() => ctx.shell.setInspector());
  return d;
};

export function actionPointer(workspace: string, action: string): Record<string, string> {
  return { workspace, event: action };
}
