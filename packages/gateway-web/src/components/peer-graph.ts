/**
 * PeerGraph — §7.2: "map has a synchronized keyboard-accessible table,
 * not a canvas-only truth source". The map is rendered as a DOM list of
 * nodes (keyboard-focusable, selection synchronized with PeerTable);
 * no canvas is used at all, so the DOM is the single truth source.
 */
import { h, append, pill } from "../lib/dom.js";
import { fingerprint, fmtAge, show } from "../lib/format.js";

export interface PeerRow {
  id: string;
  source?: string;
  key?: string;
  role?: string;
  state?: string;
  transport?: string;
  scopes?: readonly unknown[];
  capabilities?: readonly unknown[];
  grant_revision?: string;
  last_seen_ms?: number;
  mesh?: string; // e.g. "CONNECTED" | "ADAPTER_REQUIRED"
}

export function peerFrom(o: Record<string, unknown>): PeerRow {
  return {
    id: show(o.id ?? o.peer),
    source: typeof o.source === "string" ? o.source : undefined,
    key: typeof o.key === "string" ? o.key : undefined,
    role: typeof o.role === "string" ? o.role : undefined,
    state: typeof o.state === "string" ? o.state : undefined,
    transport: typeof o.transport === "string" ? o.transport : (typeof o.family === "string" ? o.family : undefined),
    scopes: Array.isArray(o.scopes) ? o.scopes : [],
    capabilities: Array.isArray(o.capabilities) ? o.capabilities : [],
    grant_revision: typeof o.grant_revision === "string" ? o.grant_revision : undefined,
    last_seen_ms: typeof o.last_seen_ms === "number" ? o.last_seen_ms : undefined,
    mesh: typeof o.mesh === "string" ? o.mesh : undefined,
  };
}

export function PeerGraph(props: {
  peers: readonly PeerRow[];
  selected?: string | null;
  onSelect?: (id: string) => void;
}): HTMLElement {
  const el = h("section", { class: "panel", aria: { label: "Agent connection map" } },
    h("h3", { text: "Connection map" }));
  if (props.peers.length === 0) {
    append(el, h("p", { class: "muted", text: "No peers enrolled." }));
    return el;
  }
  const map = h("div", { class: "peer-map", role: "list", aria: { label: "Peers" } });
  for (const p of props.peers) {
    const state = p.state ?? "REGISTERED";
    const node = h("div", {
      class: "peer-node",
      role: "listitem button",
      tabindex: 0,
      dataset: { state, peer: p.id },
      aria: { selected: props.selected === p.id ? "true" : "false", label: `peer ${p.id} ${state}` },
    },
      pill(state, state === "CONNECTED" ? "ok" : state === "REVOKED" ? "err" : "warn"),
      h("span", { class: "mono fingerprint", text: fingerprint(p.key ?? p.id) }),
      h("span", { class: "muted small", text: `${p.role ?? "agent"} · ${p.transport ?? "loopback"}` }),
      p.mesh ? pill(p.mesh, p.mesh === "CONNECTED" ? "ok" : "warn") : null,
      p.last_seen_ms ? h("span", { class: "muted small", text: fmtAge(p.last_seen_ms) }) : null);
    const sel = () => props.onSelect?.(p.id);
    node.addEventListener("click", sel);
    node.addEventListener("keydown", (e) => {
      const k = (e as KeyboardEvent).key;
      if (k === "Enter" || k === " ") {
        e.preventDefault();
        sel();
      }
    });
    append(map, node);
  }
  append(el, map,
    h("p", { class: "small muted", text: "Family/transport labels are untrusted connector metadata — identity is the key fingerprint." }));
  return el;
}
