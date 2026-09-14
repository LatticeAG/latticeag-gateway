/**
 * Composition root (spec §7.1/§7.2): `#bootstrap=` exchange → AppShell +
 * ConnectionBanner (daemon.status poll + SSE health) → route mount.
 * With no session and no bootstrap fragment the app renders the
 * "pair this browser" instructions — it cannot mint its own session
 * (ui.session.create is an L-role socket call).
 */
import "./styles/tokens.css";
import { h, append, clear } from "./lib/dom.js";
import { RpcClient, bootstrapFromLocation, parseBootstrapFragment, type Session } from "./lib/rpc.js";
import { Router, matchRoute, type Route } from "./lib/router.js";
import { Store, initialAppState } from "./lib/state.js";
import { installKeys } from "./lib/keys.js";
import { AppShell, NAV_ITEMS } from "./components/app-shell.js";
import { ConnectionBanner } from "./components/connection-banner.js";
import { CommandPalette, type PaletteCommand } from "./components/command-palette.js";
import { ToastRegion } from "./components/toast-region.js";
import type { RouteCtx, RouteHandle } from "./routes/ctx.js";
import { overviewRoute } from "./routes/overview.js";
import { productsRoute } from "./routes/products.js";
import { productDetailRoute } from "./routes/product-detail.js";
import { eventsRoute } from "./routes/events.js";
import { agentsRoute } from "./routes/agents.js";
import { inboxRoute } from "./routes/inbox.js";
import { configRoute } from "./routes/config.js";
import { receiptsRoute } from "./routes/receipts.js";
import { receiptDetailRoute } from "./routes/receipt-detail.js";
import { syncRoute } from "./routes/sync.js";
import { pairRoute } from "./routes/pair.js";
import { emptyState, errorBox } from "./lib/dom.js";
import { describeError, type RouteModule } from "./routes/ctx.js";

const ROUTE_MODULES: Record<string, RouteModule> = {
  overview: overviewRoute,
  products: productsRoute,
  product: productDetailRoute,
  events: eventsRoute,
  agents: agentsRoute,
  inbox: inboxRoute,
  config: configRoute,
  receipts: receiptsRoute,
  receipt: receiptDetailRoute,
  sync: syncRoute,
  pair: pairRoute,
};

/** "Pair this browser" — the only view reachable without a session. */
function renderPairView(root: HTMLElement, detail: string | null, onRetryWorkspace: (ws: string) => void): void {
  clear(root);
  const wsInput = h("input", {
    type: "text", placeholder: "workspace id (only if not “default”)",
    aria: { label: "Workspace id" }, class: "mono",
  }) as HTMLInputElement;
  append(root, h("div", { class: "pair-view" },
    h("h1", { text: "Pair this browser" }),
    h("p", { text: "This workbench has no live session. Browser sessions are minted by the local operator on the daemon socket — the page cannot bootstrap itself." }),
    h("div", { class: "panel" },
      h("h3", { text: "Open a session" }),
      h("ol", {},
        h("li", {}, h("code", { class: "mono", text: "latticeag gateway ui open" }), h("span", { class: "muted", text: " — prints a one-use loopback URL" })),
        h("li", { text: "Open that URL here; its #bootstrap token is exchanged once for an HttpOnly session cookie plus a memory-only CSRF secret." })),
      h("p", { class: "small muted", text: "The CSRF secret is never persisted: after a reload you need a fresh bootstrap URL even though the cookie may still be alive." })),
    detail !== null ? h("div", { class: "error-box", role: "alert" },
      h("div", { class: "code", text: detail }),
      h("div", { text: "The bootstrap token is single-use and expires after 60 s — mint a fresh URL." }),
      h("div", { class: "btn-row" }, wsInput,
        h("button", { text: "Retry with workspace", on: { click: () => onRetryWorkspace(wsInput.value.trim() || "default") } }))) : null));
}

export async function main(root: HTMLElement): Promise<void> {
  const store = new Store(initialAppState(matchRoute(location.pathname)));
  const toasts = new ToastRegion();

  // ── §7.2 bootstrap: fragment → exchange → in-memory session ─────────
  let session: Session | null = null;
  if (parseBootstrapFragment(location.hash) !== null) {
    try {
      const res = await bootstrapFromLocation({ location, history });
      session = res?.session ?? null;
    } catch (e) {
      renderPairView(root, describeError(e), (ws) => {
        void retryExchange(root, ws);
      });
      return;
    }
  }
  if (session === null) {
    renderPairView(root, null, () => undefined);
    return;
  }
  mountShell(root, store, toasts, session);
}

async function retryExchange(root: HTMLElement, workspace: string): Promise<void> {
  // The fragment was already cleared; the user re-pastes nothing — the
  // one-use token is gone. The honest answer is a fresh bootstrap URL.
  renderPairView(root, `workspace “${workspace}” — request a fresh bootstrap URL carrying it`, () => undefined);
}

function mountShell(root: HTMLElement, store: Store<ReturnType<typeof initialAppState>>, toasts: ToastRegion, session: Session): void {
  clear(root);
  store.set({ session });
  const banner = new ConnectionBanner();
  const shell = new AppShell();
  append(root, shell.el, toasts.el);
  shell.bannerEl.replaceChildren(banner.el);
  shell.renderNav(NAV_ITEMS.map((n) => n.route === "inbox" ? { ...n, badge: () => store.get().pendingApprovals } : n));

  const client = new RpcClient({
    workspace: () => store.get().session?.workspace ?? "default",
    csrf: () => store.get().session?.csrf ?? null,
  });

  let current: RouteHandle | null = null;
  const ctx: RouteCtx = {
    client, store, shell, toasts,
    navigate: (path, opts) => router.navigate(path, opts),
  };

  const mountRoute = (route: Route): void => {
    store.set({ route });
    current?.dispose();
    current = null;
    shell.setActive(route.path === "/" ? "/" : `/${route.path.split("/").filter(Boolean)[0] ?? ""}`);
    const mod = ROUTE_MODULES[route.name];
    if (mod === undefined) {
      shell.setMain(emptyState(`No view for ${route.path}.`));
      shell.setInspector();
      return;
    }
    current = mod(ctx, route) ?? null;
    shell.focusMain();
  };

  const router = new Router({ location, history, window, onRoute: mountRoute });
  const unlink = router.interceptLinks(shell.el);

  // ── ConnectionBanner: daemon.status poll + stream health ────────────
  const pollStatus = async (): Promise<void> => {
    try {
      const res = await client.call<Record<string, unknown>>("daemon.status");
      const st = typeof res.state === "string" ? res.state : "UNKNOWN";
      const conn = store.get().connection;
      store.set({
        connection: {
          ...conn,
          phase: st === "READY" ? "online" : "degraded",
          daemonState: st,
          detail: "",
          lastOkMs: Date.now(),
          consecutiveFailures: 0,
        },
        mutationsEnabled: store.get().session?.role === "operator",
      });
    } catch (e) {
      const conn = store.get().connection;
      const failures = conn.consecutiveFailures + 1;
      store.set({
        connection: {
          ...conn,
          phase: failures >= 1 && conn.phase !== "connecting" ? "offline" : "connecting",
          detail: describeError(e),
          consecutiveFailures: failures,
        },
        // A stale/disconnected UI disables mutations immediately (§7.2).
        mutationsEnabled: false,
      });
      const code = (e as { code?: string }).code;
      if (code === "AUTH_REQUIRED" || code === "TOKEN_EXPIRED" || code === "TOKEN_REVOKED") {
        store.set({ session: null });
        dispose();
        renderPairView(root, `session ended (${code})`, () => undefined);
      }
    }
    banner.update({ ...store.get().connection, streamStale: false });
  };
  const statusTimer = setInterval(() => void pollStatus(), 5_000);
  void pollStatus();

  store.subscribe((s) => {
    banner.update({ ...s.connection, streamStale: s.stream.phase === "open" && s.stream.lastActivityMs > 0 && Date.now() - s.stream.lastActivityMs > 45_000 });
    if (s.pendingApprovals > 0) shell.renderNav(NAV_ITEMS.map((n) => n.route === "inbox" ? { ...n, badge: () => s.pendingApprovals } : n));
  });

  // ── command palette ──────────────────────────────────────────────────
  const palette = new CommandPalette();
  palette.mount(shell.el);
  palette.setCommands([
    ...NAV_ITEMS.map((n) => ({
      id: `go-${n.route}`, label: `Go to ${n.label}`, keys: n.keys,
      run: () => router.navigate(n.path),
    })),
    { id: "pause-stream", label: "Toggle stream pause", keys: "Space", run: () => store.update((s) => ({ stream: { ...s.stream, paused: !s.stream.paused } })) },
    { id: "focus-search", label: "Focus search", keys: "/", run: () => focusSearch() },
  ] satisfies PaletteCommand[]);

  function focusSearch(): boolean {
    const el = shell.mainEl.querySelector<HTMLElement>("[data-search]");
    if (el === null) return false;
    el.focus();
    return true;
  }

  // ── keys ─────────────────────────────────────────────────────────────
  const keys = installKeys(window, {
    navigate: (p) => router.navigate(p),
    focusSearch,
    toggleStreamPause: () => store.update((s) => ({ stream: { ...s.stream, paused: !s.stream.paused } })),
    closeOverlay: () => {
      if (palette.visible) {
        palette.close();
        return true;
      }
      if (shell.inspectorEl.childNodes.length > 0) {
        shell.setInspector();
        return true;
      }
      return false;
    },
    openPalette: () => palette.open(),
  });

  function dispose(): void {
    clearInterval(statusTimer);
    keys.dispose();
    unlink();
    router.dispose();
    current?.dispose();
    toasts.dispose();
  }

  router.start();
}

// Auto-boot in the browser; tests import the pieces without booting.
if (typeof document !== "undefined" && typeof location !== "undefined") {
  const root = document.getElementById("app");
  if (root !== null) void main(root);
}
