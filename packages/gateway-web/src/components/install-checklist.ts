/**
 * InstallReview (spec §7.3 component) — the reviewed-plan confirmation
 * card: hash-bound plan summary, grants diff, disk needs, and a focused
 * commit control. Nothing here commits on a single key; confirm requires
 * an explicit button activation.
 *
 * (File is named install-checklist.ts; the exported component keeps the
 * spec name.)
 */
import { h, append, kv } from "../lib/dom.js";
import { fmtBytes, show } from "../lib/format.js";
import { CapabilityDiff, diffStrings, grantLines } from "./capability-diff.js";

export interface InstallReviewProps {
  kind: "install" | "update" | "uninstall" | "rollback";
  slug: string;
  plan: Record<string, unknown>;
  summary: Record<string, unknown> | null;
  busy?: boolean;
  error?: string | null;
  onCommit: () => void;
  onCancel: () => void;
}

export function InstallReview(props: InstallReviewProps): HTMLElement {
  const s = props.summary ?? {};
  const plan = props.plan;
  const grantsAfter = grantLines(plan.grants ?? plan.capabilities ?? s.grants);
  const grantsBefore = grantLines(s.current_grants ?? plan.current_grants);
  const el = h("section", { class: "dialog", role: "dialog", aria: { modal: "true", label: `${props.kind} ${props.slug}` } },
    h("h2", { text: `Confirm ${props.kind}: ${props.slug}` }),
    kv([
      ["Plan hash", show(plan.plan ?? plan.hash ?? plan.id)],
      ["Target", show(s.to ?? plan.version ?? plan.target)],
      ["From", show(s.from ?? plan.from)],
      ["Dependencies", show(s.dependencies ?? (Array.isArray(plan.dependencies) ? plan.dependencies.length : "—"))],
      ["Disk required", fmtBytes(s.disk_bytes ?? plan.disk_bytes)],
      ["Licenses", show(s.licenses ?? plan.licenses)],
      ["Keep data", show(s.keep_data ?? plan.keep_data)],
      ["Cascade", show(s.cascade ?? plan.cascade)],
    ]),
    CapabilityDiff({ diff: diffStrings(grantsBefore, grantsAfter), title: "Grant diff" }));
  if (props.error) {
    append(el, h("p", { class: "err", role: "alert", text: props.error }));
  }
  append(el, h("div", { class: "btn-row" },
    h("button", {
      class: "primary",
      disabled: props.busy === true,
      text: props.busy === true ? "Committing…" : `Commit ${props.kind}`,
      on: { click: () => props.onCommit() },
    }),
    h("button", { text: "Cancel", disabled: props.busy === true, on: { click: () => props.onCancel() } }),
    h("span", { class: "small muted", text: "Commits the reviewed plan exactly; a stale plan returns PLAN_STALE." })));
  return el;
}
