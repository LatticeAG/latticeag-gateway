/**
 * ApprovalCard — §7.1 VekInbox-semantic approval card. Binds action hash,
 * target, scope, native revision, expiry, and requester; `stored`,
 * `approved`, and `applied` are shown as SEPARATE indicators (E07 ack
 * semantics — a durable store is not an applied native effect).
 *
 * §7.1: without a native decision binding the card accepts a
 * nonauthorizing operator note but DISABLES Approve for native effects;
 * without native-enrolled reviewer eligibility all decision controls are
 * disabled. Decision submission always requires a visible focused review
 * control (DecisionReview) bound to the current revision — never a key.
 */
import { h, append, kv, pill } from "../lib/dom.js";
import { fmtDateTime, shortId, show } from "../lib/format.js";

export interface ApprovalView {
  approval: string;
  revision: string;
  state: string; // PENDING | APPROVED | DENIED | CANCELLED | EXPIRED | CONFLICTED…
  action?: unknown;          // NativeRef — the exact action commitment
  actionHash?: string;       // display hash of the action binding
  target?: string;
  scope?: string;
  expires_ms?: number;
  requester?: string;
  native_status?: string;    // NOT_DISPATCHED | … | APPLIED
  stored?: boolean;          // durable projection ACK {card_id,revision,stored}
  approved?: boolean;
  applied?: boolean;
  reviewerEligible?: boolean;
  nativeBound?: boolean;     // a native decision binding exists
  outcome?: string;
}

export function approvalFrom(o: Record<string, unknown>): ApprovalView {
  const action = o.action;
  const actionHash =
    typeof o.action_hash === "string" ? o.action_hash
    : action !== null && typeof action === "object"
      ? show((action as Record<string, unknown>).hash ?? (action as Record<string, unknown>).commitment)
      : undefined;
  const native = o.native_status;
  return {
    approval: show(o.approval ?? o.id),
    revision: show(o.revision),
    state: show(o.state),
    action,
    actionHash,
    target: typeof o.target === "string" ? o.target : undefined,
    scope: typeof o.scope === "string" ? o.scope : undefined,
    expires_ms: typeof o.expires_ms === "number" ? o.expires_ms : undefined,
    requester: typeof o.requester === "string" ? o.requester : (typeof o.principal === "string" ? o.principal : undefined),
    native_status: typeof native === "string" ? native : undefined,
    stored: o.stored === true || o.projected === true,
    approved: show(o.state) === "APPROVED",
    applied: typeof native === "string" && native === "APPLIED",
    reviewerEligible: o.reviewer_eligible !== false,
    nativeBound: o.native_bound !== false && o.native !== undefined && o.native !== null,
    outcome: typeof o.outcome === "string" ? o.outcome : undefined,
  };
}

export function ApprovalCard(props: {
  approval: ApprovalView;
  mutationsEnabled: boolean;
  onDecide?: (decision: "approve" | "deny") => void;
  onCancel?: () => void;
  onNote?: (text: string) => void;
}): HTMLElement {
  const a = props.approval;
  const pending = a.state === "PENDING";
  const expired = a.state === "EXPIRED" || (a.expires_ms !== undefined && a.expires_ms <= Date.now());
  const canDecide =
    props.mutationsEnabled && pending && !expired &&
    a.reviewerEligible === true && a.nativeBound === true;

  const card = h("article", { class: "card", aria: { label: `Approval ${a.approval}` } },
    h("header", {},
      h("h3", { class: "mono", text: a.approval }),
      pill(expired && pending ? "EXPIRED" : a.state,
        a.state === "APPROVED" ? "ok" : ["DENIED", "EXPIRED", "CONFLICTED"].includes(a.state) ? "err" : "warn")),
    kv([
      ["Action hash", h("span", { class: "fingerprint", text: a.actionHash ? shortId(a.actionHash, 16, 8) : show(a.action) })],
      ["Target", a.target],
      ["Scope", a.scope],
      ["Revision", a.revision],
      ["Expires", a.expires_ms ? fmtDateTime(a.expires_ms) : null],
      ["Requester", a.requester],
      ["Native", a.native_status],
      ["Outcome", a.outcome],
    ]),
    // stored / approved / applied as three independent indicators (§7.1).
    h("p", { class: "small", aria: { label: "Lifecycle" } },
      pill(`stored ${a.stored === true ? "yes" : "no"}`, a.stored === true ? "ok" : "muted", a.stored === true ? "✓" : "○"),
      " ",
      pill(`approved ${a.approved === true ? "yes" : "no"}`, a.approved === true ? "ok" : "muted", a.approved === true ? "✓" : "○"),
      " ",
      pill(`applied ${a.applied === true ? "yes" : "no"}`, a.applied === true ? "ok" : "muted", a.applied === true ? "✓" : "○")));

  if (pending && a.nativeBound !== true) {
    append(card, h("p", { class: "notice-box small", role: "note",
      text: "No native decision binding — this projection is not an authorization service. Approve is disabled; you may attach a nonauthorizing note for the record." }));
  } else if (pending && a.reviewerEligible !== true) {
    append(card, h("p", { class: "notice-box small", role: "note",
      text: "This session is not a native-enrolled reviewer for the action's policy — read-only." }));
  }

  if (pending) {
    const row = h("div", { class: "btn-row", role: "group", aria: { label: "Decision" } },
      h("button", {
        class: "primary",
        disabled: !canDecide,
        title: canDecide ? "Open the decision review" : a.nativeBound !== true ? "Disabled — no native decision binding" : a.reviewerEligible !== true ? "Disabled — not an eligible reviewer" : "Disabled",
        text: "Approve…",
        on: { click: () => props.onDecide?.("approve") },
      }),
      h("button", {
        class: "danger",
        disabled: !(props.mutationsEnabled && a.reviewerEligible === true) || expired,
        text: "Deny…",
        on: { click: () => props.onDecide?.("deny") },
      }),
      h("button", {
        class: "flat",
        disabled: !props.mutationsEnabled || expired,
        text: "Cancel request",
        on: { click: () => props.onCancel?.() },
      }));
    append(card, row);
    if (a.nativeBound !== true) {
      const note = h("input", { type: "text", placeholder: "Nonauthorizing operator note…", aria: { label: "Operator note" } });
      append(card, h("div", { class: "btn-row" }, note,
        h("button", {
          class: "flat",
          disabled: !props.mutationsEnabled,
          text: "Attach note",
          on: { click: () => props.onNote?.((note as HTMLInputElement).value) },
        })));
    }
  }
  return card;
}
