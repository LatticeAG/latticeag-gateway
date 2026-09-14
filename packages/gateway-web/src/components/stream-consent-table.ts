/**
 * StreamConsentTable — /sync per-stream egress state (spec §9): all six
 * streams default disabled; each row shows destination, profile, consent
 * revision, pause state and pending/in-flight/blocked/acked counts.
 * Enabling/consent changes go through review — this table only pauses,
 * resumes and flushes what already exists.
 */
import { h, append, pill } from "../lib/dom.js";
import { fmtCount, fmtTime, show } from "../lib/format.js";
import { DisclosureBadge } from "./disclosure-badge.js";

export const SYNC_STREAMS = ["runs", "receipts", "lineage", "approvals", "watch", "mesh"] as const;
export type SyncStream = (typeof SYNC_STREAMS)[number];

export interface StreamState {
  stream: SyncStream;
  enabled: boolean;
  paused: boolean;
  destination?: string;
  profile?: string;
  cohort?: string;
  consent_revision?: string;
  pending?: number;
  in_flight?: number;
  blocked?: number;
  acked?: number;
  retry_next_ms?: number;
  blocked_reason?: string;
}

export function streamsFrom(o: Record<string, unknown> | null | undefined): StreamState[] {
  const src = (o?.streams ?? o) as Record<string, unknown> | undefined;
  const out: StreamState[] = [];
  for (const name of SYNC_STREAMS) {
    const s = src?.[name];
    const r = (s !== null && typeof s === "object" ? s : {}) as Record<string, unknown>;
    out.push({
      stream: name,
      enabled: r.enabled === true || r.disabled !== true && (r.consent_revision !== undefined || r.destination !== undefined),
      paused: r.paused === true || o?.paused === true,
      destination: typeof r.destination === "string" ? r.destination : undefined,
      profile: typeof r.profile === "string" ? r.profile : undefined,
      cohort: typeof r.cohort === "string" ? r.cohort : undefined,
      consent_revision: typeof r.consent_revision === "string" ? r.consent_revision : undefined,
      pending: typeof r.pending === "number" ? r.pending : undefined,
      in_flight: typeof r.in_flight === "number" ? r.in_flight : undefined,
      blocked: typeof r.blocked === "number" ? r.blocked : undefined,
      acked: typeof r.acked === "number" ? r.acked : undefined,
      retry_next_ms: typeof r.retry_next_ms === "number" ? r.retry_next_ms : undefined,
      blocked_reason: typeof r.blocked_reason === "string" ? r.blocked_reason : undefined,
    });
  }
  return out;
}

export function StreamConsentTable(props: {
  streams: readonly StreamState[];
  cloud: unknown;
  mutationsEnabled: boolean;
  onPause?: (s: SyncStream) => void;
  onResume?: (s: SyncStream) => void;
  onFlush?: (s: SyncStream) => void;
}): HTMLElement {
  const tbody = h("tbody");
  for (const s of props.streams) {
    const stateLabel = !s.enabled ? "disabled" : s.blocked_reason ? "blocked" : s.paused ? "paused" : "active";
    const tone = !s.enabled ? "muted" : s.blocked_reason ? "err" : s.paused ? "warn" : "ok";
    append(tbody, h("tr", { dataset: { stream: s.stream } },
      h("td", { class: "mono", text: s.stream }),
      h("td", {}, pill(stateLabel, tone)),
      h("td", { text: s.destination ?? "—" }),
      h("td", {}, s.profile ? DisclosureBadge({ level: s.profile }) : h("span", { class: "muted", text: "—" })),
      h("td", { class: "mono", text: s.consent_revision ?? "—" }),
      h("td", { class: "mono", text: `${fmtCount(s.pending)}/${fmtCount(s.in_flight)}/${fmtCount(s.blocked)}/${fmtCount(s.acked)}`, title: "pending/in-flight/blocked/acked" }),
      h("td", { class: "muted", text: s.retry_next_ms ? `retry ${fmtTime(s.retry_next_ms)}` : (s.blocked_reason ?? "—") }),
      h("td", {}, h("div", { class: "btn-row" },
        s.paused
          ? h("button", { class: "flat", disabled: !props.mutationsEnabled || !s.enabled, text: "Resume", on: { click: () => props.onResume?.(s.stream) } })
          : h("button", { class: "flat", disabled: !props.mutationsEnabled || !s.enabled, text: "Pause", on: { click: () => props.onPause?.(s.stream) } }),
        h("button", { class: "flat", disabled: !props.mutationsEnabled || !s.enabled, text: "Flush", on: { click: () => props.onFlush?.(s.stream) } })))));
  }
  const wrap = h("div", { class: "table-wrap", role: "region", aria: { label: "Sync streams" } },
    h("table", { class: "tbl" },
      h("thead", {}, h("tr", {},
        h("th", { text: "Stream" }), h("th", { text: "State" }), h("th", { text: "Destination" }),
        h("th", { text: "Profile" }), h("th", { text: "Consent rev" }), h("th", { text: "P/I/B/A" }),
        h("th", { text: "Next/block" }), h("th", { text: "Actions" }))),
      tbody));
  const el = h("section", {}, wrap);
  if (props.cloud !== null && props.cloud !== undefined) {
    append(el, h("p", { class: "small muted", text: `cloud pairing: ${show(props.cloud)}` }));
  }
  return el;
}
