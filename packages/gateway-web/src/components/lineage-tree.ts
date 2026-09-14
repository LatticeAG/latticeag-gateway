/**
 * LineageTree — lineage.query result: typed edges as a nested list,
 * explicit gaps, and the native assessment label. Missing references
 * render as gap nodes, never invented edges (spec §9.1).
 */
import { h, append, pill } from "../lib/dom.js";
import { shortId, show } from "../lib/format.js";

export interface LineageResult {
  nodes: readonly unknown[];
  edges: readonly { from: unknown; to: unknown; type?: string }[];
  gaps: readonly string[];
  native_assessment?: string;
}

export function lineageFrom(o: Record<string, unknown>): LineageResult {
  const edgesRaw = Array.isArray(o.edges) ? o.edges : [];
  return {
    nodes: Array.isArray(o.nodes) ? o.nodes : [],
    edges: edgesRaw
      .filter((e): e is Record<string, unknown> => e !== null && typeof e === "object")
      .map((e) => ({ from: e.from ?? e.parent, to: e.to ?? e.child, type: typeof e.type === "string" ? e.type : undefined })),
    gaps: Array.isArray(o.gaps) ? o.gaps.map((g) => show(g)) : [],
    native_assessment: typeof o.native_assessment === "string" ? o.native_assessment : undefined,
  };
}

export function LineageTree(props: { lineage: LineageResult }): HTMLElement {
  const { lineage } = props;
  const el = h("section", { class: "panel", aria: { label: "Lineage" } },
    h("h3", { text: "Lineage" }),
    lineage.native_assessment
      ? h("p", {}, pill(`native assessment ${lineage.native_assessment}`, lineage.native_assessment === "NOT_EVALUATED" ? "warn" : "ok"))
      : null);
  if (lineage.nodes.length === 0) {
    append(el, h("p", { class: "muted", text: "No nodes." }));
  } else {
    const ul = h("ul", { class: "tree", role: "tree" });
    for (const n of lineage.nodes) {
      append(ul, h("li", { role: "treeitem" }, h("span", { class: "mono", text: shortId(show(n), 20, 8) })));
    }
    append(el, ul);
  }
  if (lineage.edges.length > 0) {
    const ul = h("ul", { class: "tree", aria: { label: "Edges" } });
    for (const e of lineage.edges) {
      append(ul, h("li", { class: "mono small" },
        `${shortId(show(e.from), 10, 4)} → ${shortId(show(e.to), 10, 4)}${e.type ? ` (${e.type})` : ""}`));
    }
    append(el, h("h4", { class: "small muted", text: "Edges" }), ul);
  }
  if (lineage.gaps.length > 0) {
    append(el, h("h4", { class: "small warn", text: "Explicit gaps" }),
      h("ul", { class: "tree" }, ...lineage.gaps.map((g) => h("li", { class: "mono warn", text: g }))));
  }
  return el;
}
