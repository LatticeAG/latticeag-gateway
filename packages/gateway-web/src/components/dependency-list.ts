/**
 * DependencyList — dependency edges from catalog.show/product.plan with
 * per-edge state; unavailable/conflicting edges are explicit, never
 * silently omitted.
 */
import { h, append, pill, emptyState } from "../lib/dom.js";
import { show } from "../lib/format.js";

export interface DependencyEdge {
  slug: string;
  required?: string;
  resolved?: string;
  state?: string; // satisfied | missing | conflict | blocked | adapter-unavailable
}

function tone(state: string): "ok" | "warn" | "err" | "muted" {
  if (state === "satisfied" || state === "installed") return "ok";
  if (state === "missing" || state === "adapter-unavailable") return "warn";
  if (state === "conflict" || state === "blocked") return "err";
  return "muted";
}

export function DependencyList(props: { edges: readonly DependencyEdge[] }): HTMLElement {
  if (props.edges.length === 0) return emptyState("No dependencies.");
  const ul = h("ul", { class: "tree", role: "list" });
  for (const e of props.edges) {
    const state = e.state ?? "unknown";
    append(ul, h("li", {},
      h("span", { class: "mono", text: e.slug }),
      h("span", { class: "muted", text: ` requires ${e.required ?? "*"}` }),
      e.resolved ? h("span", { text: ` → ${e.resolved}` }) : null,
      " ",
      pill(state, tone(state))));
  }
  return ul;
}

/** Parse the loose plan/catalog edge shapes into DependencyEdge[]. */
export function edgesFrom(value: unknown): DependencyEdge[] {
  if (!Array.isArray(value)) return [];
  const out: DependencyEdge[] = [];
  for (const e of value) {
    if (e === null || typeof e !== "object") continue;
    const o = e as Record<string, unknown>;
    out.push({
      slug: show(o.slug ?? o.name ?? o.product),
      required: typeof o.required === "string" ? o.required : show(o.required),
      resolved: typeof o.resolved === "string" ? o.resolved : (typeof o.version === "string" ? o.version : undefined),
      state: typeof o.state === "string" ? o.state : (typeof o.status === "string" ? o.status : undefined),
    });
  }
  return out;
}
