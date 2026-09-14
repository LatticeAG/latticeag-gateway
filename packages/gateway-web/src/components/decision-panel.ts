/**
 * DecisionReview (spec §7.3 component) — the focused modal review a
 * decision requires: it re-binds the CURRENT revision and the exact
 * action commitment before submit (spec §7.3 "decision submit needs a
 * visible focused review control and current bound revision").
 */
import { h, append, kv, pill } from "../lib/dom.js";
import { fmtDateTime, shortId, show } from "../lib/format.js";
import type { ApprovalView } from "./approval-card.js";

export function DecisionReview(props: {
  approval: ApprovalView;
  decision: "approve" | "deny";
  busy?: boolean;
  error?: string | null;
  onSubmit: (reason: string) => void;
  onCancel: () => void;
}): HTMLElement {
  const a = props.approval;
  const reason = h("input", {
    type: "text",
    placeholder: "Reason (recorded with the decision)",
    aria: { label: "Decision reason" },
  });
  const el = h("section", { class: "dialog", role: "dialog", aria: { modal: "true", label: `Review ${props.decision} ${a.approval}` } },
    h("h2", { text: `${props.decision === "approve" ? "Approve" : "Deny"} ${a.approval}` }),
    h("p", {}, pill(props.decision.toUpperCase(), props.decision === "approve" ? "ok" : "err"),
      h("span", { class: "muted small", text: " — binds the current revision and action commitment." })),
    kv([
      ["Action hash", h("span", { class: "fingerprint", text: a.actionHash ? shortId(a.actionHash, 16, 8) : show(a.action) })],
      ["Target", a.target],
      ["Bound revision", a.revision],
      ["Native", a.native_status],
      ["Expires", a.expires_ms ? fmtDateTime(a.expires_ms) : null],
    ]),
    reason);
  if (props.error) append(el, h("p", { class: "err", role: "alert", text: props.error }));
  append(el, h("div", { class: "btn-row" },
    h("button", {
      class: props.decision === "approve" ? "primary" : "danger",
      disabled: props.busy === true,
      text: props.busy === true ? "Submitting…" : `Submit ${props.decision}`,
      on: { click: () => props.onSubmit((reason as HTMLInputElement).value) },
    }),
    h("button", { text: "Back", disabled: props.busy === true, on: { click: () => props.onCancel() } })));
  queueMicrotask(() => (reason as HTMLInputElement).focus());
  return el;
}
