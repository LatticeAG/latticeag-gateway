/**
 * Minimal hyperscript — every component builds DOM through here so
 * untrusted data only ever lands in textContent / createElement, never
 * an HTML-parsing sink (spec §7.2: no HTML parsing of events, and by
 * extension of any server-supplied value).
 */

export type Child = Node | string | number | null | undefined | false;

export interface Attrs {
  class?: string;
  text?: string;
  title?: string;
  type?: string;
  href?: string;
  src?: string;
  alt?: string;
  role?: string;
  id?: string;
  name?: string;
  value?: string;
  placeholder?: string;
  for?: string;
  colspan?: number;
  rowspan?: number;
  disabled?: boolean;
  checked?: boolean;
  selected?: boolean;
  open?: boolean;
  autofocus?: boolean;
  spellcheck?: string;
  readonly?: boolean;
  required?: boolean;
  hidden?: boolean;
  tabindex?: number;
  min?: string | number;
  max?: string | number;
  step?: string | number;
  rows?: number;
  dataset?: Record<string, string>;
  aria?: Record<string, string | boolean | number>;
  on?: Partial<Record<string, (ev: Event) => void>>;
  style?: string;
}

const PROP_KEYS = new Set([
  "text", "value", "checked", "selected", "open", "disabled", "hidden",
  "readonly", "required", "autofocus", "tabindex", "colspan", "rowspan",
]);

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v as string;
    else if (k === "text") el.textContent = String(v);
    else if (k === "dataset") {
      for (const [dk, dv] of Object.entries(v as Record<string, string>)) {
        el.dataset[dk] = dv;
      }
    } else if (k === "aria") {
      for (const [ak, av] of Object.entries(v as Record<string, string | boolean | number>)) {
        el.setAttribute(`aria-${ak}`, String(av));
      }
    } else if (k === "on") {
      for (const [ev, fn] of Object.entries(v as Record<string, (e: Event) => void>)) {
        if (fn) el.addEventListener(ev, fn);
      }
    } else if (k === "style") {
      el.setAttribute("style", String(v));
    } else if (k === "for") {
      (el as HTMLLabelElement).htmlFor = String(v);
    } else if (PROP_KEYS.has(k)) {
      (el as unknown as Record<string, unknown>)[k] = v;
      if (k === "disabled" || k === "readonly" || k === "required" || k === "autofocus" || k === "hidden") {
        el.setAttribute(k, "");
      }
    } else {
      el.setAttribute(k, String(v));
    }
  }
  append(el, ...children);
  return el;
}

export function append(el: Node, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
  }
}

/** Empty an element without touching HTML parsing. */
export function clear(el: ParentNode): void {
  el.replaceChildren();
}

/** status glyph+label pill — status is never color alone (§7.3). */
export function pill(label: string, tone: "ok" | "warn" | "err" | "accent" | "muted" = "muted", glyph?: string): HTMLElement {
  const g = glyph ?? { ok: "●", warn: "▲", err: "✖", accent: "◆", muted: "○" }[tone];
  return h("span", { class: "pill", dataset: { tone }, aria: { label: `state: ${label}` } },
    h("span", { class: "glyph", aria: { hidden: "true" }, text: g }),
    h("span", { text: label }));
}

export function field(labelText: string, input: HTMLElement, hint?: string): HTMLElement {
  const id = input.id || `f-${Math.random().toString(36).slice(2, 10)}`;
  input.id = id;
  const kids: Child[] = [h("span", { text: labelText }), input];
  if (hint) kids.push(h("span", { class: "small muted", text: hint }));
  return h("label", { class: "field", for: id }, ...kids);
}

export function emptyState(message: string): HTMLElement {
  return h("div", { class: "empty", role: "note", text: message });
}

export function errorBox(code: string, message: string): HTMLElement {
  return h("div", { class: "error-box", role: "alert" },
    h("div", { class: "code", text: code }),
    h("div", { text: message }));
}

export function kv(pairs: ReadonlyArray<readonly [string, string | Node | null | undefined]>): HTMLElement {
  const el = h("dl", { class: "kv" });
  for (const [k, v] of pairs) {
    if (v === null || v === undefined) continue;
    append(el, h("dt", { text: k }), h("dd", {}, typeof v === "string" ? v : v));
  }
  return el;
}
