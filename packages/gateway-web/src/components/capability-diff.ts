/**
 * CapabilityDiff — §7.1 "grants diff": scopes/capabilities added and
 * removed between the current grant and the plan's request. Additions
 * and removals are listed separately; unchanged lines collapse.
 */
import { h, append, emptyState } from "../lib/dom.js";
import { show } from "../lib/format.js";

export interface DiffSets {
  added: readonly string[];
  removed: readonly string[];
  unchanged?: readonly string[];
}

export function diffStrings(before: readonly string[], after: readonly string[]): DiffSets {
  const b = new Set(before);
  const a = new Set(after);
  return {
    added: [...a].filter((x) => !b.has(x)),
    removed: [...b].filter((x) => !a.has(x)),
    unchanged: [...a].filter((x) => b.has(x)),
  };
}

export function CapabilityDiff(props: { diff: DiffSets; title?: string }): HTMLElement {
  const { diff } = props;
  const el = h("section", { class: "panel", aria: { label: props.title ?? "Grant changes" } },
    h("h3", { text: props.title ?? "Requested grant changes" }));
  if (diff.added.length === 0 && diff.removed.length === 0) {
    append(el, emptyState("No change to grants."));
    return el;
  }
  if (diff.added.length > 0) {
    const ul = h("ul", { class: "tree" });
    for (const s of diff.added) append(ul, h("li", { class: "diff-add mono", text: `+ ${s}` }));
    append(el, h("h4", { class: "small muted", text: "Added" }), ul);
  }
  if (diff.removed.length > 0) {
    const ul = h("ul", { class: "tree" });
    for (const s of diff.removed) append(ul, h("li", { class: "diff-del mono", text: `− ${s}` }));
    append(el, h("h4", { class: "small muted", text: "Removed" }), ul);
  }
  if (diff.unchanged !== undefined && diff.unchanged.length > 0) {
    append(el, h("p", { class: "small muted", text: `${diff.unchanged.length} grant(s) unchanged.` }));
  }
  return el;
}

/** Flatten a Scope/Capability-ish object into display lines for diffing. */
export function grantLines(value: unknown): string[] {
  if (value === null || value === undefined) return [];
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(grantLines);
  if (typeof value === "object") {
    const o = value as Record<string, unknown>;
    const parts: string[] = [];
    const perm = typeof o.permission === "string" ? o.permission : typeof o.name === "string" ? o.name : null;
    const sets = ["topics", "runs", "products", "emit", "consume", "profiles"]
      .flatMap((k) => (Array.isArray(o[k]) ? (o[k] as unknown[]).map((v) => `${k}=${show(v)}`) : []));
    parts.push([perm, ...sets].filter(Boolean).join(" ") || show(o));
    return parts;
  }
  return [show(value)];
}
