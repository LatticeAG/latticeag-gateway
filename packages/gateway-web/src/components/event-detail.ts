/**
 * EventDetail — inspector view for one stream frame: cursor, topic,
 * profile, record ref, availability. Raw object bytes require a separate
 * authorized objects.get — WITHHELD shows the denial state, never an
 * empty "success" (spec §7.1).
 */
import { h, append, kv, pill } from "../lib/dom.js";
import { show } from "../lib/format.js";
import type { BusEventData } from "../lib/sse.js";

export function EventDetail(props: {
  frame: BusEventData;
  object?: unknown;
  objectState?: "none" | "loading" | "denied" | "loaded";
  objectError?: string | null;
}): HTMLElement {
  const f = props.frame;
  const el = h("section", { aria: { label: `Event ${f.cursor}` } },
    h("h3", { text: "Event detail" }),
    kv([
      ["Cursor", f.cursor],
      ["Topic", f.topic],
      ["Profile", f.profile],
      ["Record ref", show(f.record_ref)],
      ["Availability", f.availability],
    ]));
  const state = props.objectState ?? "none";
  if (state === "loading") {
    append(el, h("p", { class: "muted", text: "Loading object…" }));
  } else if (state === "denied" || props.objectError) {
    append(el, h("div", { class: "notice-box", role: "note" },
      h("p", { text: "Raw event bytes are not disclosed to this session." }),
      props.objectError ? h("p", { class: "small muted", text: props.objectError }) : null,
      h("p", { class: "small muted", text: "Reference notifications keep private raw data out of the browser; authorized lookup still validates the native profile." })));
  } else if (state === "loaded" && props.object !== undefined) {
    append(el, h("h4", { class: "small muted", text: "Disclosed object" }),
      h("pre", { class: "mono", text: JSON.stringify(props.object, null, 2) }));
  } else {
    append(el, h("p", { class: "small muted" },
      f.availability === "WITHHELD"
        ? pill("bytes withheld", "warn", "◌")
        : h("span", { text: "Object not fetched — request requires an authorized reference." })));
  }
  return el;
}
