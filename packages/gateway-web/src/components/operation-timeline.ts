/**
 * OperationTimeline — operation.get progress: QUEUED → … → terminal, the
 * transition cursor, old/new versions, and failure detail. Accepted ≠
 * installed; terminal states are shown explicitly.
 */
import { h, append, pill } from "../lib/dom.js";
import { fmtTime, show } from "../lib/format.js";

export interface OperationView {
  operation: string;
  kind?: string;
  state: string;
  slug?: string;
  from?: string | null;
  to?: string | null;
  cursor?: string;
  error?: { code?: string; message?: string } | null;
  transitions?: readonly { state: string; at_ms?: number }[];
}

const TERMINAL = new Set(["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"]);
const ORDER = ["QUEUED", "PLANNING", "VERIFYING", "APPLYING", "SUCCEEDED"];

export function OperationTimeline(props: { op: OperationView }): HTMLElement {
  const op = props.op;
  const failed = op.state === "FAILED" || op.error !== null && op.error !== undefined;
  const terminal = TERMINAL.has(op.state);
  const el = h("section", { class: "panel", aria: { label: `Operation ${op.operation}` } },
    h("h3", { text: `Operation ${op.operation}` }),
    h("p", {},
      pill(op.state, op.state === "SUCCEEDED" ? "ok" : failed ? "err" : terminal ? "muted" : "warn"),
      " ",
      h("span", { class: "muted small", text: `${op.kind ?? "op"} ${op.slug ?? ""} ${op.from ?? "—"} → ${op.to ?? "—"}` })));
  const steps: readonly { state: string; at_ms?: number }[] = op.transitions ?? ORDER.slice(0, Math.max(1, ORDER.indexOf(op.state) + 1)).map((s) => ({ state: s }));
  const ol = h("ol", { class: "timeline" });
  for (const s of steps) {
    append(ol, h("li", { dataset: { done: s.state === op.state || ORDER.indexOf(s.state) < ORDER.indexOf(op.state) ? "true" : "false" } },
      h("span", { text: s.state }),
      s.at_ms ? h("span", { class: "muted small", text: fmtTime(s.at_ms) }) : null));
  }
  if (!steps.some((s) => s.state === op.state)) {
    append(ol, h("li", { dataset: { failed: failed ? "true" : "false", done: "true" } },
      h("span", { text: op.state })));
  }
  append(el, ol);
  if (op.error) {
    append(el, h("p", { class: "err", role: "alert", text: `${op.error.code ?? "ERROR"}: ${op.error.message ?? show(op.error)}` }));
  }
  if (op.cursor) append(el, h("p", { class: "small muted mono", text: `transition cursor ${op.cursor}` }));
  return el;
}
