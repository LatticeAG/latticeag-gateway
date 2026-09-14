/**
 * `/agents` — capability connection map + synchronized table (spec §7.1):
 * agent.list plus revocation/disconnect. Local/federated transport, key
 * identity, effective scopes, native-adapter availability, revoked.
 * Invitation creation/approval are L-role socket ceremonies — the UI
 * links to /pair/:id for review and explains the CLI path.
 */
import { h, append, clear, emptyState, errorBox, kv, pill } from "../lib/dom.js";
import { PeerGraph, peerFrom, type PeerRow } from "../components/peer-graph.js";
import { PeerTable } from "../components/peer-table.js";
import { show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

export const agentsRoute: RouteModule = (ctx) => {
  const d = new Disposer();
  const root = h("section", { aria: { label: "Agents" } },
    h("h1", { text: "Agents" }));
  const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
  append(root, body);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  let peers: PeerRow[] = [];
  let selected: string | null = null;
  let err: string | null = null;

  const mutationsEnabled = () => ctx.store.get().mutationsEnabled;

  const showPeer = (id: string): void => {
    selected = id;
    const p = peers.find((x) => x.id === id);
    if (p === undefined) {
      ctx.shell.setInspector();
      return;
    }
    ctx.shell.setInspector(h("section", { aria: { label: `Peer ${p.id}` } },
      h("h3", { class: "mono", text: p.id }),
      kv([
        ["Source", p.source],
        ["Role", p.role],
        ["Grant revision", p.grant_revision],
        ["Transport", p.transport],
        ["Mesh", p.mesh],
      ]),
      h("h4", { class: "small muted", text: "Effective scopes" }),
      (p.scopes ?? []).length === 0
        ? h("p", { class: "muted", text: "No scopes." })
        : h("ul", { class: "tree" }, ...(p.scopes ?? []).map((s) => h("li", { class: "mono", text: show(s) }))),
      (p.capabilities ?? []).length > 0
        ? h("div", {}, h("h4", { class: "small muted", text: "Capabilities" }),
            h("ul", { class: "tree" }, ...(p.capabilities ?? []).map((c) => h("li", { class: "mono", text: show(c) }))))
        : null));
    render();
  };

  const render = (): void => {
    clear(body);
    if (err !== null) {
      append(body, errorBox(err, "agent.list failed."));
      return;
    }
    append(body, h("div", { class: "panel" },
      h("p", { class: "small muted" },
        h("span", { text: "Invitations are created and approved on the local operator socket: " }),
        h("code", { class: "mono", text: "latticeag gateway agent pair --key <file>" }),
        h("span", { text: ". Pending proposals appear under /pair/<id>." }))));
    if (peers.length === 0) {
      append(body, emptyState("No agents enrolled."));
      return;
    }
    append(body, PeerGraph({ peers, selected, onSelect: showPeer }));
    append(body, PeerTable({
      peers,
      selected,
      mutationsEnabled: mutationsEnabled(),
      onSelect: showPeer,
      onRevoke: (id) => void revoke(id),
      onDisconnect: (id) => void disconnect(id),
    }));
    append(body, h("p", { class: "small muted" },
      pill("revocation commits before connections close", "muted"),
      " — queued deliveries are discarded; delivered bytes cannot be recalled."));
  };

  const revoke = async (peer: string): Promise<void> => {
    if (!window.confirm(`Revoke ${peer}? The grant is destroyed before its connections close.`)) return;
    try {
      await ctx.client.call("agent.revoke", { peer, reason: "operator_requested" });
      ctx.toasts.info(`revoked ${peer}`);
      await load();
    } catch (e) {
      ctx.toasts.error(`agent.revoke failed: ${describeError(e)}`);
    }
  };

  const disconnect = async (peer: string): Promise<void> => {
    try {
      await ctx.client.call("agent.disconnect", { peer });
      ctx.toasts.info(`disconnected ${peer}`);
      await load();
    } catch (e) {
      ctx.toasts.error(`agent.disconnect failed: ${describeError(e)}`);
    }
  };

  const load = async (): Promise<void> => {
    try {
      const page = await ctx.client.call<{ items?: Record<string, unknown>[] }>("agent.list", { after: null, limit: 200 });
      peers = (page.items ?? []).map(peerFrom);
      err = null;
    } catch (e) {
      err = describeError(e);
    }
    render();
  };

  void load();
  d.every(10_000, () => void load());
  d.add(() => ctx.shell.setInspector());
  return d;
};
