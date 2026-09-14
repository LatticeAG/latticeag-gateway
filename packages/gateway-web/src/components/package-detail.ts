/**
 * PackageDetail — /products/:slug header: catalog metadata, installed
 * state, health, and the action bar (plan/install/update/rollback go
 * through InstallReview first — no direct mutations here).
 */
import { h, append, pill } from "../lib/dom.js";
import { kv } from "../lib/dom.js";
import { fmtAge, fmtDateTime, show } from "../lib/format.js";

export interface PackageDetailProps {
  slug: string;
  entry: Record<string, unknown> | null;
  installed: Record<string, unknown> | null;
  health: Record<string, unknown> | null;
  healthError?: string | null;
}

export function PackageDetail(p: PackageDetailProps): HTMLElement {
  const entry = p.entry ?? {};
  const installed = p.installed ?? {};
  const version = show(installed.version ?? entry.version);
  const root = h("section", { class: "panel", aria: { label: `Package ${p.slug}` } },
    h("h2", { text: `${p.slug} ${version !== "—" ? `· ${version}` : ""}` }),
    kv([
      ["Slug", p.slug],
      ["Name", show(entry.name)],
      ["Series", show(entry.series)],
      ["Tier", show(entry.tier)],
      ["Installed", p.installed !== null ? `${version} (${show(installed.state ?? "installed")})` : "not installed"],
      ["Catalog signed age", entry.signed_ms ? fmtAge(Number(entry.signed_ms)) : (entry.cached_ms ? fmtAge(Number(entry.cached_ms)) : "—")],
      ["Refreshed", entry.refreshed_ms ? fmtDateTime(Number(entry.refreshed_ms)) : "—"],
    ]));
  if (p.health !== null || p.healthError) {
    const healthBits: Array<[string, string]> = [];
    if (p.health !== null) {
      healthBits.push(
        ["State", show(p.health.state)],
        ["Liveness", show(p.health.liveness)],
        ["Readiness", show(p.health.readiness)],
        ["Sandbox", show(p.health.sandbox)],
      );
    }
    append(root,
      h("h3", { text: "Health" }),
      p.healthError ? h("p", { class: "err small", text: `health probe failed: ${p.healthError}` }) : kv(healthBits));
  }
  return root;
}

/** Action bar for plan/commit decisions on the package page. */
export function PackageActions(props: {
  mutationsEnabled: boolean;
  retained: readonly string[];
  onAction: (kind: "install" | "update" | "uninstall" | "rollback", target?: string) => void;
}): HTMLElement {
  const bar = h("div", { class: "btn-row", role: "group", aria: { label: "Package actions" } });
  const mk = (label: string, kind: "install" | "update" | "uninstall" | "rollback", target?: string, danger = false) =>
    h("button", {
      class: danger ? "danger" : "",
      disabled: !props.mutationsEnabled,
      title: props.mutationsEnabled ? "" : "Mutations disabled — daemon disconnected or viewer session",
      on: { click: () => props.onAction(kind, target) },
      text: label,
    });
  append(bar,
    mk("Plan install", "install"),
    mk("Plan update", "update"),
    mk("Plan uninstall", "uninstall", undefined, true));
  if (props.retained.length > 0) {
    const sel = h("select", { aria: { label: "Retained version" } },
      ...props.retained.map((v) => h("option", { value: v, text: v })));
    append(bar, sel, h("button", {
      disabled: !props.mutationsEnabled,
      on: { click: () => props.onAction("rollback", (sel as HTMLSelectElement).value) },
      text: "Plan rollback",
    }));
  }
  return bar;
}
