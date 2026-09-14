/**
 * PairingPanel — /pair/:id enrollment review (spec §4.2/§7.1): shows the
 * key fingerprint, proposal hash H(J({key,profiles,interfaces,
 * capabilities})), requested scopes, and expiry verbatim. States:
 * CREATED/AWAITING_OPERATOR/APPROVED/CONSUMED/CANCELLED/EXPIRED/LOCKED.
 *
 * agent.pair.approve/cancel are L-role (local operator proof) calls —
 * the browser session is V/O, so commit controls render DISABLED with
 * the CLI command to finish the ceremony. The panel is still the exact
 * review surface the operator reads before approving on the socket.
 */
import { h, append, kv, pill } from "../lib/dom.js";
import { fingerprint, fmtDateTime, show } from "../lib/format.js";

export interface PairingView {
  pair: string;
  state: string;
  code?: string | null;
  key?: string | null;          // key id / public key hash → fingerprint
  proposal?: string | null;     // proposal hash
  scopes?: readonly unknown[];
  capabilities?: readonly unknown[];
  expires_ms?: number;
  changed?: boolean;            // proposal changed after approval
}

export function pairingFrom(o: Record<string, unknown>): PairingView {
  const scopes = o.scopes ?? o.proposal_scopes;
  return {
    pair: show(o.pair ?? o.id),
    state: show(o.state),
    key: typeof o.key === "string" ? o.key : null,
    proposal: typeof o.proposal === "string" ? o.proposal : (typeof o.proposal_hash === "string" ? o.proposal_hash : null),
    scopes: Array.isArray(scopes) ? scopes : [],
    capabilities: Array.isArray(o.capabilities) ? o.capabilities : [],
    expires_ms: typeof o.expires_ms === "number" ? o.expires_ms : undefined,
    changed: o.changed === true,
  };
}

export function PairingPanel(props: {
  pair: PairingView;
  /** Local-operator (L) capability is never held by a browser session. */
  localOperatorProof: boolean;
  onApprove?: () => void;
  onCancel?: () => void;
}): HTMLElement {
  const p = props.pair;
  const terminal = ["CONSUMED", "CANCELLED", "EXPIRED", "LOCKED"].includes(p.state);
  const el = h("section", { class: "panel", aria: { label: `Pairing ${p.pair}` } },
    h("h2", { text: `Pairing review ${p.pair}` }),
    h("p", {}, pill(p.state, p.state === "AWAITING_OPERATOR" ? "warn" : terminal ? "err" : "ok"),
      p.changed === true ? h("span", { class: "warn", text: " — proposal changed after a previous approval; review again." }) : null),
    kv([
      ["Key fingerprint", h("span", { class: "fingerprint", text: fingerprint(p.key) })],
      ["Proposal hash", h("span", { class: "fingerprint", text: p.proposal ?? "—" })],
      ["Expires", p.expires_ms ? fmtDateTime(p.expires_ms) : "—"],
    ]));
  const scopes = p.scopes ?? [];
  append(el, h("h3", { text: "Requested scopes" }),
    scopes.length === 0
      ? h("p", { class: "muted", text: "None." })
      : h("ul", { class: "tree" }, ...scopes.map((s) => h("li", { class: "mono", text: show(s) }))));
  const caps = p.capabilities ?? [];
  if (caps.length > 0) {
    append(el, h("h3", { text: "Declared capabilities" }),
      h("ul", { class: "tree" }, ...caps.map((c) => h("li", { class: "mono", text: show(c) }))),
      h("p", { class: "small muted", text: "Effective grant = requested ∩ operator-approved ∩ configured policy ∩ native capability binding." }));
  }
  if (p.state === "LOCKED") {
    append(el, h("p", { class: "err", text: "Invitation locked after five failed attempts — create a new one." }));
  }
  const needsL = !props.localOperatorProof;
  append(el, h("div", { class: "btn-row" },
    h("button", {
      class: "primary",
      disabled: needsL || terminal || p.state === "APPROVED",
      title: needsL ? "Requires local-operator proof — approve via the CLI/socket" : "",
      text: "Approve pairing",
      on: { click: () => props.onApprove?.() },
    }),
    h("button", {
      class: "danger",
      disabled: needsL || terminal,
      title: needsL ? "Requires local-operator proof — cancel via the CLI/socket" : "",
      text: "Cancel invitation",
      on: { click: () => props.onCancel?.() },
    })));
  if (needsL && !terminal) {
    append(el, h("p", { class: "small muted" },
      h("span", { text: "Browser sessions hold viewer/operator roles only. To commit this review run " }),
      h("code", { class: "mono", text: `latticeag gateway agent pair --approve ${p.pair}` }),
      h("span", { text: " on the local socket." })));
  }
  return el;
}
