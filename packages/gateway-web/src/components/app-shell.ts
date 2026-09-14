/**
 * AppShell — §7.2 desktop shell: 216 px nav / flexible main / optional
 * 360 px inspector, landmark roles, skip link target, narrow-viewport
 * drawer (<720 px) and 64 px rail (<1000 px) handled in tokens.css.
 */
import { h, append, clear, type Child } from "../lib/dom.js";
import type { RouteName } from "../lib/router.js";

export interface NavItem {
  route: RouteName;
  path: string;
  label: string;
  /** Short monospace hint shown in the nav (e.g. "g p"). */
  keys?: string;
  badge?: () => number;
}

export const NAV_ITEMS: readonly NavItem[] = [
  { route: "overview", path: "/", label: "Overview" },
  { route: "products", path: "/products", label: "Products", keys: "g p" },
  { route: "events", path: "/events", label: "Events", keys: "g e" },
  { route: "agents", path: "/agents", label: "Agents", keys: "g a" },
  { route: "inbox", path: "/inbox", label: "Inbox", keys: "g i" },
  { route: "config", path: "/config", label: "Config", keys: "g c" },
  { route: "receipts", path: "/receipts", label: "Receipts", keys: "g r" },
  { route: "sync", path: "/sync", label: "Sync" },
];

export class AppShell {
  readonly el: HTMLElement;
  readonly navEl: HTMLElement;
  readonly mainEl: HTMLElement;
  readonly inspectorEl: HTMLElement;
  readonly bannerEl: HTMLElement;
  private readonly navToggle: HTMLElement;
  private backdrop: HTMLElement | null = null;
  private activePath = "/";

  constructor(opts: { banner?: Child; pendingBadge?: () => number } = {}) {
    this.bannerEl = h("div", { class: "banner-slot" });
    if (opts.banner !== undefined && opts.banner !== null && opts.banner !== false) {
      append(this.bannerEl, opts.banner);
    }
    this.navToggle = h("button", {
      class: "nav-toggle flat",
      aria: { label: "Open navigation", expanded: "false", controls: "nav" },
      text: "☰",
      on: { click: () => this.setDrawer(true) },
    });
    this.navEl = h("nav", { id: "nav", aria: { label: "Primary" } },
      h("div", { class: "brand" }, h("span", { class: "nav-label", text: "LatticeAG Gateway" }), this.navToggle),
      h("ul"));
    this.mainEl = h("main", { id: "main", tabindex: -1, aria: { label: "Content" } });
    this.inspectorEl = h("aside", { aria: { label: "Detail" } });
    this.el = h("div", { class: "shell" }, this.navEl, this.bannerEl, this.mainEl, this.inspectorEl);
  }

  private setDrawer(open: boolean): void {
    this.navEl.dataset.open = open ? "true" : "false";
    this.navToggle.setAttribute("aria-expanded", String(open));
    if (open && this.backdrop === null) {
      this.backdrop = h("div", { class: "nav-backdrop", on: { click: () => this.setDrawer(false) } });
      this.el.appendChild(this.backdrop);
    } else if (!open && this.backdrop !== null) {
      this.backdrop.remove();
      this.backdrop = null;
    }
  }

  /** Rebuild the nav list, marking the current route. */
  renderNav(items: readonly NavItem[] = NAV_ITEMS): void {
    const ul = this.navEl.querySelector("ul")!;
    clear(ul);
    for (const item of items) {
      const badge = item.badge?.() ?? 0;
      const a = h("a", {
        href: item.path,
        aria: item.path === this.activePath ? { current: "page" } : {},
        dataset: { route: item.route },
      },
        h("span", { class: "nav-label", text: item.label }),
        badge > 0 ? h("span", { class: "pill", dataset: { tone: "warn" }, text: String(badge) }) : null,
        item.keys ? h("span", { class: "nav-label small muted", text: item.keys }) : null);
      append(ul, h("li", {}, a));
    }
  }

  setActive(path: string): void {
    this.activePath = path;
    for (const a of this.navEl.querySelectorAll("a[href]")) {
      if (a.getAttribute("href") === path) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    this.setDrawer(false);
  }

  setMain(...children: Child[]): void {
    clear(this.mainEl);
    append(this.mainEl, ...children);
  }

  setInspector(...children: Child[]): void {
    clear(this.inspectorEl);
    append(this.inspectorEl, ...children);
    this.el.classList.toggle("no-inspector", this.inspectorEl.childNodes.length === 0);
  }

  focusMain(): void {
    this.mainEl.focus();
  }
}
