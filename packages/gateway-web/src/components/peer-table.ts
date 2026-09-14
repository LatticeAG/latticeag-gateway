/**
 * PeerTable — §7.1 agents table synchronized with PeerGraph: transport,
 * key identity, effective scopes, native-adapter availability, revoked.
 */
import { h, append, pill } from "../lib/dom.js";
import { fingerprint, fmtAge, shortId } from "../lib/format.js";
import type { PeerRow } from "./peer-graph.js";

export function PeerTable(props: {
  peers: readonly PeerRow[];
  selected?: string | null;
  mutationsEnabled: boolean;
  onSelect?: (id: string) => void;
  onRevoke?: (id: string) => void;
  onDisconnect?: (id: string) => void;
}): HTMLElement {
  const tbody = h("tbody");
  for (const p of props.peers) {
    const state = p.state ?? "REGISTERED";
    const revoked = state === "REVOKED";
    const tr = h("tr", {
      class: "row-link",
      tabindex: 0,
      aria: { selected: props.selected === p.id ? "true" : "false" },
      dataset: { peer: p.id },
    },
      h("td", { class: "mono", text: shortId(p.id, 10, 4), title: p.id }),
      h("td", { class: "mono fingerprint", text: fingerprint(p.key) }),
      h("td", { text: p.role ?? "agent" }),
      h("td", {}, pill(state, state === "CONNECTED" ? "ok" : revoked ? "err" : "warn")),
      h("td", { text: p.transport ?? "—" }),
      h("td", {}, p.mesh ? pill(p.mesh, p.mesh === "CONNECTED" ? "ok" : "warn") : h("span", { class: "muted", text: "—" })),
      h("td", { text: `${p.scopes?.length ?? 0} scope(s)` }),
      h("td", { class: "muted", text: p.last_seen_ms ? fmtAge(p.last_seen_ms) : "—" }),
      h("td", {}, h("div", { class: "btn-row" },
        h("button", {
          class: "flat",
          disabled: !props.mutationsEnabled || revoked || state !== "CONNECTED",
          text: "Disconnect",
          on: { click: (e) => { e.stopPropagation(); props.onDisconnect?.(p.id); } },
        }),
        h("button", {
          class: "flat danger",
          disabled: !props.mutationsEnabled || revoked,
          text: "Revoke",
          on: { click: (e) => { e.stopPropagation(); props.onRevoke?.(p.id); } },
        }))));
    const sel = () => props.onSelect?.(p.id);
    tr.addEventListener("click", sel);
    tr.addEventListener("keydown", (e) => {
      if ((e as KeyboardEvent).key === "Enter") sel();
    });
    append(tbody, tr);
  }
  return h("div", { class: "table-wrap", role: "region", aria: { label: "Peers table" } },
    h("table", { class: "tbl" },
      h("thead", {}, h("tr", {},
        h("th", { text: "Peer" }), h("th", { text: "Key" }), h("th", { text: "Role" }),
        h("th", { text: "State" }), h("th", { text: "Transport" }), h("th", { text: "Mesh" }),
        h("th", { text: "Scopes" }), h("th", { text: "Last seen" }), h("th", { text: "Actions" }))),
      tbody));
}
