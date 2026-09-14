/**
 * ConfigForm — §7.1 structured config editor beside the raw JsonEditor.
 * Renders known scalar fields of the redacted document as labeled inputs;
 * masked secret references show as `•••` placeholders and are never
 * editable values (credential values are never returned by config.get).
 */
import { h, append, kv, pill } from "../lib/dom.js";
import { show } from "../lib/format.js";

export interface ConfigFormProps {
  document: Record<string, unknown> | null;
  revision: string;
  onEditRaw?: () => void;
}

const KNOWN: readonly { path: string; label: string; hint?: string }[] = [
  { path: "gateway.workspace_id", label: "Workspace id" },
  { path: "gateway.instance_id", label: "Instance id" },
  { path: "gateway.ui.port", label: "UI port" },
  { path: "gateway.ui.enabled", label: "UI enabled" },
  { path: "gateway.ui.remote", label: "Remote UI" },
  { path: "gateway.mesh.mode", label: "Mesh mode" },
  { path: "gateway.autostart", label: "Autostart" },
];

function dig(o: Record<string, unknown>, path: string): unknown {
  let cur: unknown = o;
  for (const part of path.split(".")) {
    if (cur === null || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/** True when a value is a masked/redacted secret reference. */
export function isMaskedSecret(v: unknown): boolean {
  return typeof v === "string" && /^(•+|\[redacted\]|\*{3,}|\$\{[A-Z0-9_]+\})$/i.test(v);
}

export function ConfigForm(props: ConfigFormProps): HTMLElement {
  const doc = props.document;
  const el = h("section", { class: "panel", aria: { label: "Configuration" } },
    h("h3", { text: "Configuration" }),
    h("p", { class: "small muted" },
      pill(`revision ${props.revision}`, "muted"),
      " — edits apply as one CAS document via config.apply."));
  if (doc === null) {
    append(el, h("p", { class: "muted", text: "No document loaded." }));
    return el;
  }
  const grid = h("div", { role: "group", aria: { label: "Known fields" } });
  for (const f of KNOWN) {
    const v = dig(doc, f.path);
    if (v === undefined) continue;
    append(grid, kv([[f.label, isMaskedSecret(v) ? "•••••• (masked)" : show(v)]]));
  }
  append(el, grid);
  // Masked secret inventory — visible but values never rendered.
  const masked: string[] = [];
  const walk = (o: unknown, path: string): void => {
    if (isMaskedSecret(o)) masked.push(path);
    else if (o !== null && typeof o === "object" && !Array.isArray(o)) {
      for (const [k, v] of Object.entries(o)) walk(v, path === "" ? k : `${path}.${k}`);
    }
  };
  walk(doc, "");
  if (masked.length > 0) {
    append(el, h("p", { class: "small muted", text: `Masked secret refs: ${masked.join(", ")}` }));
  }
  if (props.onEditRaw) {
    append(el, h("button", { class: "flat", text: "Edit raw JSON", on: { click: () => props.onEditRaw!() } }));
  }
  return el;
}
