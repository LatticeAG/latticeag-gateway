/**
 * JsonEditor — raw config document editor: textarea + local parse check,
 * unsaved-diff indicator, JSON Pointer errors surfaced via
 * SchemaErrorList (config.validate), CAS apply via expected_revision.
 */
import { h, append, pill } from "../lib/dom.js";

export class JsonEditor {
  readonly el: HTMLElement;
  private readonly area: HTMLTextAreaElement;
  private readonly statusEl: HTMLElement;
  private original = "";
  onDirty: (dirty: boolean) => void;

  constructor(opts: { onDirty?: (dirty: boolean) => void; ariaLabel?: string } = {}) {
    this.onDirty = opts.onDirty ?? (() => undefined);
    this.statusEl = h("p", { class: "small muted", role: "status", aria: { live: "polite" } });
    this.area = h("textarea", {
      class: "mono",
      spellcheck: "false",
      aria: { label: opts.ariaLabel ?? "Raw JSON document" },
      on: {
        input: () => this.checkDirty(),
      },
    }) as HTMLTextAreaElement;
    this.el = h("div", {}, this.area, this.statusEl);
  }

  setValue(text: string): void {
    this.original = text;
    this.area.value = text;
    this.checkDirty();
  }

  getText(): string {
    return this.area.value;
  }

  dirty(): boolean {
    return this.area.value !== this.original;
  }

  /** Parse the current text; returns undefined + sets status on error. */
  parse(): { ok: true; value: unknown } | { ok: false; error: string } {
    try {
      return { ok: true, value: JSON.parse(this.area.value) };
    } catch (e) {
      const msg = e instanceof Error ? e.message : "invalid JSON";
      this.setStatus(`Parse error: ${msg}`);
      return { ok: false, error: msg };
    }
  }

  setStatus(text: string): void {
    this.statusEl.textContent = text;
  }

  private checkDirty(): void {
    const d = this.dirty();
    this.statusEl.textContent = d ? "Unsaved changes — not yet validated or applied." : "No unsaved changes.";
    this.onDirty(d);
  }
}

export function diffSummary(before: unknown, after: unknown): string {
  try {
    return JSON.stringify(before) === JSON.stringify(after) ? "no changes" : "document changed";
  } catch {
    return "changed";
  }
}

export function unsavedPill(dirty: boolean): HTMLElement {
  return pill(dirty ? "unsaved changes" : "clean", dirty ? "warn" : "muted");
}
