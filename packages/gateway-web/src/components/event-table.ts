/**
 * EventTable — /events live table (spec §7.1/§7.2): pause indicator,
 * explicit gap rows (dropped-buffer + CURSOR_GONE), raw-data access
 * denial, ≤2000 retained rows, windowed rendering past 200.
 */
import { h, append, clear, pill } from "../lib/dom.js";
import { fmtTime, shortId, show } from "../lib/format.js";
import type { BufferedEvent } from "../lib/sse.js";

const ROW_H = 36;
const VIRTUALIZE_AT = 200;
const OVERSCAN = 8;

export interface EventTableCallbacks {
  onSelect?: (ev: BufferedEvent) => void;
}

export class EventTable {
  readonly el: HTMLElement;
  private readonly tbody: HTMLElement;
  private readonly wrap: HTMLElement;
  private rows: readonly BufferedEvent[] = [];
  private dropped = 0;
  private readonly cb: EventTableCallbacks;
  private scrollTop = 0;
  private viewH = 600;

  constructor(cb: EventTableCallbacks = {}) {
    this.cb = cb;
    this.tbody = h("tbody");
    this.wrap = h("div", { class: "table-wrap", tabindex: 0, role: "region", aria: { label: "Events", live: "off" } },
      h("table", { class: "tbl" },
        h("thead", {}, h("tr", {},
          h("th", { text: "Cursor" }),
          h("th", { text: "Topic" }),
          h("th", { text: "Profile" }),
          h("th", { text: "Record" }),
          h("th", { text: "Availability" }))),
        this.tbody));
    this.wrap.addEventListener("scroll", () => {
      this.scrollTop = this.wrap.scrollTop;
      this.viewH = this.wrap.clientHeight || this.viewH;
      if (this.rows.length > VIRTUALIZE_AT) this.render();
    });
    this.el = this.wrap;
  }

  setRows(rows: readonly BufferedEvent[], dropped: number): void {
    this.rows = rows;
    this.dropped = dropped;
    this.render();
  }

  private rowEl(ev: BufferedEvent): HTMLElement {
    const f = ev.frame;
    const withheld = f.availability !== "INLINE" && f.availability !== "OBJECT";
    const tr = h("tr", { class: "row-link", tabindex: 0, dataset: { ordinal: String(ev.ordinal) } },
      h("td", { class: "mono", text: f.cursor }),
      h("td", { text: f.topic }),
      h("td", { class: "mono", text: f.profile }),
      h("td", { class: "mono", text: shortId(show(f.record_ref), 14, 6) }),
      h("td", {}, pill(withheld ? "withheld" : f.availability, withheld ? "warn" : "muted", withheld ? "◌" : "●")));
    const open = () => this.cb.onSelect?.(ev);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Enter") open();
    });
    return tr;
  }

  private gapRow(count: number): HTMLElement {
    return h("tr", { class: "gap-row" },
      h("td", { colspan: 5, text: `… ${count} earlier row(s) beyond the 2000-row retention window — replay via cursor …` }));
  }

  private render(): void {
    clear(this.tbody);
    const n = this.rows.length;
    const renderRange = (first: number, last: number): void => {
      if (first > 0 || this.dropped > 0) append(this.tbody, this.gapRow(this.dropped + first));
      for (let i = first; i < last; i += 1) append(this.tbody, this.rowEl(this.rows[i]!));
    };
    if (n <= VIRTUALIZE_AT) {
      renderRange(0, n);
      return;
    }
    const first = Math.max(0, Math.floor(this.scrollTop / ROW_H) - OVERSCAN);
    const count = Math.ceil(this.viewH / ROW_H) + OVERSCAN * 2;
    const last = Math.min(n, first + count);
    append(this.tbody, h("tr", { aria: { hidden: "true" } }, h("td", { colspan: 5, style: `height:${first * ROW_H}px;padding:0;border:0` })));
    renderRange(first, last);
    append(this.tbody, h("tr", { aria: { hidden: "true" } }, h("td", { colspan: 5, style: `height:${(n - last) * ROW_H}px;padding:0;border:0` })));
  }
}

/** Stream toolbar: live/paused state, counts, explicit controls. */
export function streamBar(props: {
  phase: string;
  paused: boolean;
  buffered: number;
  dropped: number;
  onPauseToggle: () => void;
}): HTMLElement {
  const bar = h("div", { class: "streambar", dataset: { paused: String(props.paused) }, role: "status", aria: { live: "polite" } },
    pill(props.paused ? "paused" : props.phase, props.paused ? "warn" : props.phase === "open" ? "ok" : props.phase === "gap" ? "err" : "muted"),
    h("span", { class: "muted", text: `${props.buffered} buffered${props.dropped > 0 ? ` · ${props.dropped} dropped` : ""}` }),
    h("span", { class: "grow", style: "flex:1" }),
    h("button", {
      class: "flat",
      text: props.paused ? "Resume (Space)" : "Pause (Space)",
      on: { click: () => props.onPauseToggle() },
    }));
  return bar;
}
