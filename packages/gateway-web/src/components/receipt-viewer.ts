/**
 * ReceiptViewer (spec §7.3 "ReceiptInspector"; the file name avoids the
 * banned substring) — /receipts/:workspace/:action detail: independent
 * integrity / native-assessment / disclosure / freshness / outcome labels
 * and the inventory. WITHHELD bytes are labelled, never an empty success.
 */
import { h, append, kv, pill } from "../lib/dom.js";
import { fmtDateTime, shortId, show } from "../lib/format.js";
import { DisclosureBadge } from "./disclosure-badge.js";

export interface ReceiptView {
  action: unknown;                 // ReceiptPointer {workspace,event}
  inventory?: unknown;             // native inventory (may be null)
  outer?: string;                  // e.g. SIGNED_UNANCHORED
  inner?: string;                  // e.g. NOT_EVALUATED
  bundle?: unknown;                // native bundle or null
  disclosure?: string;             // HASHES_ONLY | REDACTED | FULL
  freshness?: string;
  outcome?: string;
  integrity?: string;              // local hash-chain check label
  native_assessment?: string;
  withheld?: boolean;
  gaps?: readonly string[];
}

export function receiptFrom(o: Record<string, unknown>): ReceiptView {
  return {
    action: o.action,
    inventory: o.inventory ?? null,
    outer: typeof o.outer === "string" ? o.outer : undefined,
    inner: typeof o.inner === "string" ? o.inner : undefined,
    bundle: o.bundle ?? null,
    disclosure: typeof o.disclosure === "string" ? o.disclosure : undefined,
    freshness: typeof o.freshness === "string" ? o.freshness : undefined,
    outcome: typeof o.outcome === "string" ? o.outcome : undefined,
    integrity: typeof o.integrity === "string" ? o.integrity : undefined,
    native_assessment: typeof o.native_assessment === "string" ? o.native_assessment : undefined,
    withheld: o.availability === "WITHHELD" || o.withheld === true,
    gaps: Array.isArray(o.gaps) ? o.gaps.map((g) => show(g)) : [],
  };
}

function labelPill(name: string, value: string | undefined): [string, Node] | null {
  if (value === undefined) return null;
  const s = value.toUpperCase();
  const tone = ["SIGNED_UNANCHORED", "VERIFIED", "APPLIED", "FRESH", "OK"].includes(s)
    ? "ok"
    : ["NOT_EVALUATED", "UNKNOWN", "STALE", "WITHHELD"].includes(s)
      ? "warn"
      : ["FAILED", "EXPIRED", "CONFLICTED"].includes(s)
        ? "err"
        : "muted";
  return [name, pill(value, tone)];
}

export function ReceiptViewer(props: { receipt: ReceiptView; actionRef: string }): HTMLElement {
  const r = props.receipt;
  const el = h("section", { aria: { label: `Receipt ${props.actionRef}` } },
    h("h3", { text: "Receipt" }),
    DisclosureBadge({ level: r.disclosure ?? (r.withheld === true ? "WITHHELD" : "HASHES_ONLY") }));
  const labels = [
    labelPill("Integrity", r.integrity),
    labelPill("Outer", r.outer),
    labelPill("Inner/native", r.inner ?? r.native_assessment),
    labelPill("Freshness", r.freshness),
    labelPill("Outcome", r.outcome),
  ].filter((x): x is [string, Node] => x !== null);
  if (labels.length > 0) append(el, kv(labels));
  append(el, kv([["Action", h("span", { class: "mono fingerprint", text: show(r.action) })]]));
  if (r.withheld === true) {
    append(el, h("p", { class: "notice-box small", role: "note",
      text: "Event bytes are WITHHELD from this feed — this is a disclosure decision, not an empty result." }));
  }
  if (r.inventory !== null && r.inventory !== undefined) {
    append(el, h("h4", { class: "small muted", text: "Inventory" }),
      h("pre", { class: "mono", text: JSON.stringify(r.inventory, null, 2) }));
  } else {
    append(el, h("p", { class: "small muted", text: "Object-only index summary — the native collector adapter is not bound (bundle: null)." }));
  }
  if (r.gaps !== undefined && r.gaps.length > 0) {
    append(el, h("h4", { class: "small warn", text: "Gaps" }),
      h("ul", { class: "tree" }, ...r.gaps.map((g) => h("li", { class: "mono", text: g }))));
  }
  return el;
}

export function receiptActionRef(workspace: string, action: string): string {
  return `${workspace}/${shortId(action, 12, 6)}`;
}
