/**
 * TrustPanel — §7.1 "trust/provenance evidence": signature state,
 * provenance, trust freshness, adapter availability. Every label is
 * independent; there is no aggregate green.
 */
import { h, append, pill, kv } from "../lib/dom.js";
import { fmtAge, fmtDateTime, show } from "../lib/format.js";

export interface TrustFacts {
  signature?: string;      // e.g. "verified" | "unsigned" | "expired"
  provenance?: string;
  trust_freshness?: string; // e.g. "fresh" | "stale" | "expired"
  signed_ms?: number;
  expires_ms?: number;
  adapter?: string;        // adapter availability, e.g. "bound" | "CAP_ADAPTER_UNAVAILABLE"
  digest?: string;
  blocked?: string;        // enterprise/policy block reason, if any
}

function tone(v: string): "ok" | "warn" | "err" | "muted" {
  const s = v.toLowerCase();
  if (["verified", "fresh", "bound", "ok", "pinned", "anchored"].includes(s)) return "ok";
  if (["unsigned", "stale", "unknown", "not_evaluated"].includes(s)) return "warn";
  if (["expired", "invalid", "revoked", "blocked"].some((x) => s.includes(x))) return "err";
  return "muted";
}

export function TrustPanel(props: { facts: TrustFacts; title?: string }): HTMLElement {
  const f = props.facts;
  const el = h("section", { class: "panel", aria: { label: props.title ?? "Trust and provenance" } },
    h("h3", { text: props.title ?? "Trust & provenance" }));
  const rows: Array<[string, Node]> = [];
  const add = (label: string, value: string | undefined): void => {
    if (value === undefined || value === "" || value === "—") return;
    rows.push([label, pill(value, tone(value))]);
  };
  add("Signature", f.signature);
  add("Provenance", f.provenance);
  add("Trust freshness", f.trust_freshness);
  add("Adapter", f.adapter);
  if (f.blocked) rows.push(["Blocked", pill(show(f.blocked), "err")]);
  append(el, kv(rows.map(([k, v]) => [k, v] as const)));
  const extra: Array<[string, string]> = [];
  if (f.digest) extra.push(["Archive digest", f.digest]);
  if (f.signed_ms) extra.push(["Signed", `${fmtDateTime(f.signed_ms)} (${fmtAge(f.signed_ms)})`]);
  if (f.expires_ms) extra.push(["Trust expires", fmtDateTime(f.expires_ms)]);
  if (extra.length > 0) append(el, kv(extra.map(([k, v]) => [k, v] as const)));
  return el;
}

/** Lift trust-shaped fields out of a catalog entry/plan result. */
export function trustFrom(o: Record<string, unknown> | null | undefined): TrustFacts {
  if (o === null || o === undefined) return {};
  const get = (k: string): string | undefined => (typeof o[k] === "string" ? (o[k] as string) : undefined);
  const num = (k: string): number | undefined => (typeof o[k] === "number" ? (o[k] as number) : undefined);
  const nested = (o.trust ?? o.provenance_evidence) as Record<string, unknown> | undefined;
  const nget = (k: string): string | undefined =>
    nested !== null && nested !== undefined && typeof nested === "object" && typeof nested[k] === "string"
      ? (nested[k] as string)
      : undefined;
  return {
    signature: get("signature") ?? nget("signature") ?? nget("state"),
    provenance: get("provenance") ?? nget("provenance"),
    trust_freshness: get("trust_freshness") ?? get("freshness") ?? nget("freshness"),
    signed_ms: num("signed_ms") ?? num("cached_ms"),
    expires_ms: num("expires_ms") ?? num("trust_expires_ms"),
    adapter: get("adapter") ?? get("adapter_availability"),
    digest: get("digest") ?? get("archive_digest"),
    blocked: get("blocked") ?? get("enterprise_block"),
  };
}
