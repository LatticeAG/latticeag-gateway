/**
 * `/pair/:id` — exact key/scopes enrollment review (spec §4.2/§7.1):
 * fingerprint + proposal hash + requested scopes; expired/locked/
 * changed-fingerprint states explicit. Commit (agent.pair.approve) needs
 * L — the panel explains the socket path instead of faking a button.
 */
import { h, append, clear, errorBox, pill } from "../lib/dom.js";
import { PairingPanel, pairingFrom, type PairingView } from "../components/pairing-panel.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

export const pairRoute: RouteModule = (ctx, route) => {
  const d = new Disposer();
  const pairId = route.params.id ?? "";
  const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
  const root = h("section", { aria: { label: `Pairing ${pairId}` } }, body);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  // The browser session is V/O — never L — so proposal review here is
  // read-only; approve/cancel execute on the owner socket via the CLI.
  const localOperatorProof = false;

  const load = async (): Promise<void> => {
    try {
      // agent.pair.get allows a nullable code for L; the browser sends
      // none — an L-only read may legitimately return FORBIDDEN, in which
      // case we show the ceremony instructions rather than a bare 403.
      const res = await ctx.client.call<Record<string, unknown>>("agent.pair.get", { pair: pairId, code: null });
      render(pairingFrom(res));
    } catch (e) {
      clear(body);
      append(body, errorBox(describeError(e), "agent.pair.get requires local-operator authority."),
        h("div", { class: "panel" },
          h("h3", { text: "Finish the ceremony on the owner socket" }),
          h("p", {}, h("code", { class: "mono", text: `latticeag gateway agent pair --approve ${pairId}` })),
          h("p", { class: "small muted", text: "The browser review surface never holds the local-operator (L) role; approval binds fingerprint + proposal hash + narrowed scopes on the socket." })));
    }
  };

  const render = (p: PairingView): void => {
    clear(body);
    append(body,
      PairingPanel({
        pair: p,
        localOperatorProof,
        onApprove: () => void act("agent.pair.approve", { pair: p.pair, proposal: p.proposal, key: p.key, scopes: p.scopes }),
        onCancel: () => void act("agent.pair.cancel", { pair: p.pair }),
      }),
      p.state === "EXPIRED" ? h("p", { class: "err", role: "alert", text: "Invitation expired (300 s window)." }) : null,
      p.state === "LOCKED" ? h("p", { class: "err", role: "alert", text: "Invitation locked after five failed attempts." }) : null);
  };

  const act = async (method: string, params: unknown): Promise<void> => {
    try {
      const r = await ctx.client.call<Record<string, unknown>>(method, params);
      ctx.toasts.info(`${method}: state ${String(r.state ?? "?")}`);
      await load();
    } catch (e) {
      ctx.toasts.error(`${method} failed: ${describeError(e)}`);
    }
  };

  void load();
  d.every(10_000, () => void load());
  return d;
};

export function pairStatePill(state: string): HTMLElement {
  return pill(state, state === "AWAITING_OPERATOR" ? "warn" : ["CONSUMED", "CANCELLED", "EXPIRED", "LOCKED"].includes(state) ? "err" : "ok");
}
