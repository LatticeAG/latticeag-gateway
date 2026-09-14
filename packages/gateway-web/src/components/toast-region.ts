/**
 * ToastRegion — §7.3 "announce operation/connection status through
 * throttled aria-live, and keep toast errors until dismissed": info/
 * success toasts expire; error toasts persist with an explicit dismiss.
 */
import { h, append } from "../lib/dom.js";

export type ToastTone = "ok" | "warn" | "err";

export class ToastRegion {
  readonly el: HTMLElement;
  private readonly timeouts = new Set<ReturnType<typeof setTimeout>>();

  constructor() {
    this.el = h("div", { class: "toasts", role: "region", aria: { label: "Notifications" } });
  }

  push(tone: ToastTone, text: string): void {
    const live = h("span", { role: tone === "err" ? "alert" : "status", text });
    const dismiss = h("button", {
      class: "flat",
      aria: { label: "Dismiss notification" },
      text: "✕",
      on: { click: () => t.remove() },
    });
    const t = h("div", { class: "toast", dataset: { tone } }, live, dismiss);
    append(this.el, t);
    if (tone !== "err") {
      // Errors persist until dismissed; informational toasts expire.
      const to = setTimeout(() => t.remove(), 8_000);
      this.timeouts.add(to);
    }
  }

  info(text: string): void { this.push("ok", text); }
  warn(text: string): void { this.push("warn", text); }
  error(text: string): void { this.push("err", text); }

  dispose(): void {
    for (const to of this.timeouts) clearTimeout(to);
    this.timeouts.clear();
  }
}
