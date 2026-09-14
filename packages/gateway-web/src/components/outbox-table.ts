/**
 * OutboxTable — durable outbox items (spec §9.2): state machine
 * PENDING→IN_FLIGHT→RETRY/BLOCKED→ACKED shown verbatim; retry delay and
 * remote-stage identity included; ACKED is terminal.
 */
import { h, append, pill } from "../lib/dom.js";
import { fmtTime, shortId, show } from "../lib/format.js";

export interface OutboxRow {
  id: string;
  stream: string;
  state: string;
  attempts: number;
  next_attempt_ms?: number;
  remote_stage?: string | null;
  cohort?: string;
  destination?: string;
  consent_revision?: string;
}

export function outboxFrom(items: unknown): OutboxRow[] {
  if (!Array.isArray(items)) return [];
  return items.filter((i): i is Record<string, unknown> => i !== null && typeof i === "object")
    .map((i) => ({
      id: show(i.id),
      stream: show(i.stream),
      state: show(i.state),
      attempts: typeof i.attempts === "number" ? i.attempts : 0,
      next_attempt_ms: typeof i.next_attempt_ms === "number" ? i.next_attempt_ms : undefined,
      remote_stage: typeof i.remote_stage === "string" ? i.remote_stage : null,
      cohort: typeof i.cohort === "string" ? i.cohort : undefined,
      destination: typeof i.destination === "string" ? i.destination : undefined,
      consent_revision: typeof i.consent_revision === "string" ? i.consent_revision : undefined,
    }));
}

function tone(state: string): "ok" | "warn" | "err" | "muted" {
  switch (state) {
    case "ACKED": return "ok";
    case "IN_FLIGHT": return "muted";
    case "RETRY": return "warn";
    case "BLOCKED": return "err";
    default: return "muted";
  }
}

export function OutboxTable(props: { items: readonly OutboxRow[] }): HTMLElement {
  const tbody = h("tbody");
  if (props.items.length === 0) {
    append(tbody, h("tr", {}, h("td", { colspan: 7, class: "muted", text: "Outbox empty — disabled streams produce no work." })));
  }
  for (const i of props.items) {
    append(tbody, h("tr", {},
      h("td", { class: "mono", text: shortId(i.id, 10, 4), title: i.id }),
      h("td", { class: "mono", text: i.stream }),
      h("td", {}, pill(i.state, tone(i.state))),
      h("td", { class: "mono", text: String(i.attempts) }),
      h("td", { class: "muted", text: i.next_attempt_ms ? fmtTime(i.next_attempt_ms) : "—" }),
      h("td", { class: "mono", text: i.remote_stage ?? "—" }),
      h("td", { class: "muted", text: i.consent_revision ?? "—" })));
  }
  return h("div", { class: "table-wrap", role: "region", aria: { label: "Sync outbox" } },
    h("table", { class: "tbl" },
      h("thead", {}, h("tr", {},
        h("th", { text: "Id" }), h("th", { text: "Stream" }), h("th", { text: "State" }),
        h("th", { text: "Attempts" }), h("th", { text: "Next attempt" }),
        h("th", { text: "Remote stage" }), h("th", { text: "Consent rev" }))),
      tbody));
}
