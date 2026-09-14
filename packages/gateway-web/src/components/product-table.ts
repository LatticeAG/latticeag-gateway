/**
 * ProductTable — §7.1 searchable catalog/installed table. 36 px rows,
 * windowed rendering once the row count exceeds 200 (spec §7.2
 * "virtualize after 200 rows"), hard-capped at 2000 visible rows.
 */
import { h, clear, append } from "../lib/dom.js";
import { pill } from "../lib/dom.js";
import { fmtAge, shortId } from "../lib/format.js";

export interface ProductRow {
  slug: string;
  name?: string;
  version?: string;
  series?: string;
  /** installed state: "installed" | "available" | "stub" | "blocked" etc. */
  state?: string;
  tier?: string;
  /** Signed-catalog cache age (ms since epoch). */
  cached_ms?: number;
  installed?: boolean;
  enterpriseBlocked?: boolean;
}

const ROW_H = 36;
const VIRTUALIZE_AT = 200;
const MAX_ROWS = 2_000;
const OVERSCAN = 8;

export class ProductTable {
  readonly el: HTMLElement;
  private readonly tbody: HTMLElement;
  private readonly wrap: HTMLElement;
  private rows: ProductRow[] = [];
  private readonly onOpen?: (slug: string) => void;
  private scrollTop = 0;
  private viewH = 600;

  constructor(opts: { onOpen?: (slug: string) => void } = {}) {
    this.onOpen = opts.onOpen;
    this.tbody = h("tbody");
    this.wrap = h("div", { class: "table-wrap", tabindex: 0, role: "region", aria: { label: "Products" } },
      h("table", { class: "tbl" },
        h("thead", {}, h("tr", {},
          h("th", { text: "Slug" }),
          h("th", { text: "Name" }),
          h("th", { text: "Version" }),
          h("th", { text: "Series" }),
          h("th", { text: "State" }),
          h("th", { text: "Tier" }),
          h("th", { text: "Catalog age" }))),
        this.tbody));
    this.wrap.addEventListener("scroll", () => {
      this.scrollTop = this.wrap.scrollTop;
      this.viewH = this.wrap.clientHeight || this.viewH;
      if (this.rows.length > VIRTUALIZE_AT) this.renderRows();
    });
    this.el = this.wrap;
  }

  setRows(rows: readonly ProductRow[]): void {
    this.rows = rows.slice(0, MAX_ROWS);
    this.renderRows();
  }

  private rowEl(r: ProductRow): HTMLElement {
    const state = r.enterpriseBlocked === true ? "enterprise blocked" : (r.state ?? (r.installed ? "installed" : "available"));
    const tone = r.enterpriseBlocked === true ? "err" : state === "installed" ? "ok" : state === "stub" ? "warn" : "muted";
    const tr = h("tr", { class: "row-link", tabindex: 0, role: "link", aria: { label: `open ${r.slug}` } },
      h("td", { class: "mono", text: r.slug }),
      h("td", { text: r.name ?? "—" }),
      h("td", { class: "mono", text: r.version ?? "—" }),
      h("td", { text: r.series ?? "—" }),
      h("td", {}, pill(state, tone)),
      h("td", { text: r.tier ?? "—" }),
      h("td", { class: "muted", text: r.cached_ms ? fmtAge(r.cached_ms) : "—" }));
    const open = () => this.onOpen?.(r.slug);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Enter") open();
    });
    return tr;
  }

  private renderRows(): void {
    clear(this.tbody);
    const n = this.rows.length;
    if (n <= VIRTUALIZE_AT) {
      for (const r of this.rows) append(this.tbody, this.rowEl(r));
      return;
    }
    // Windowed render: spacer rows preserve scroll height; each row 36 px.
    const first = Math.max(0, Math.floor(this.scrollTop / ROW_H) - OVERSCAN);
    const count = Math.ceil(this.viewH / ROW_H) + OVERSCAN * 2;
    const last = Math.min(n, first + count);
    const top = h("tr", { aria: { hidden: "true" } }, h("td", { colspan: 7, style: `height:${first * ROW_H}px;padding:0;border:0` }));
    const bottom = h("tr", { aria: { hidden: "true" } }, h("td", { colspan: 7, style: `height:${(n - last) * ROW_H}px;padding:0;border:0` }));
    append(this.tbody, top);
    for (let i = first; i < last; i += 1) append(this.tbody, this.rowEl(this.rows[i]!));
    append(this.tbody, bottom);
  }
}

/** Compact static table variant for small lists. */
export function productRows(rows: readonly ProductRow[], onOpen?: (slug: string) => void): HTMLElement {
  const t = new ProductTable({ onOpen });
  t.setRows(rows);
  return t.el;
}

export function slugOf(row: Record<string, unknown>): string {
  return typeof row.slug === "string" ? row.slug : shortId(JSON.stringify(row));
}
