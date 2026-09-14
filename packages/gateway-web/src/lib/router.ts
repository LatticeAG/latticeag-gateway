/**
 * Tiny history router (spec §7.1). Path-based — no hash routing — because
 * the bridge serves dist/index.html for `/`; client-side navigation uses
 * history.pushState so a deep link never leaves the loopback origin.
 *
 * Routes:
 *   / /products /products/:slug /events /agents /inbox /config
 *   /receipts /receipts/:workspace/:action /sync /pair/:id
 */

export type RouteName =
  | "overview"
  | "products"
  | "product"
  | "events"
  | "agents"
  | "inbox"
  | "config"
  | "receipts"
  | "receipt"
  | "sync"
  | "pair"
  | "not-found";

export interface Route {
  name: RouteName;
  params: Record<string, string>;
  path: string;
}

interface Pattern {
  name: RouteName;
  segments: string[]; // literal or ":param"
}

const ROUTES: readonly Pattern[] = [
  { name: "overview", segments: [] },
  { name: "products", segments: ["products"] },
  { name: "product", segments: ["products", ":slug"] },
  { name: "events", segments: ["events"] },
  { name: "agents", segments: ["agents"] },
  { name: "inbox", segments: ["inbox"] },
  { name: "config", segments: ["config"] },
  { name: "receipts", segments: ["receipts"] },
  { name: "receipt", segments: ["receipts", ":workspace", ":action"] },
  { name: "sync", segments: ["sync"] },
  { name: "pair", segments: ["pair", ":id"] },
];

function splitPath(pathname: string): string[] {
  return pathname.split("/").filter((s) => s.length > 0);
}

/** Match a pathname against the §7.1 route table. */
export function matchRoute(pathname: string): Route {
  const parts = splitPath(pathname);
  for (const p of ROUTES) {
    if (p.segments.length !== parts.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < p.segments.length; i += 1) {
      const seg = p.segments[i]!;
      const got = parts[i]!;
      if (seg.startsWith(":")) {
        let decoded = got;
        try {
          decoded = decodeURIComponent(got);
        } catch {
          /* keep raw */
        }
        params[seg.slice(1)] = decoded;
      } else if (seg !== got) {
        ok = false;
        break;
      }
    }
    if (ok) return { name: p.name, params, path: pathname };
  }
  return { name: "not-found", params: {}, path: pathname };
}

export interface RouterOptions {
  location: Pick<Location, "pathname">;
  history: Pick<History, "pushState" | "replaceState">;
  window: Pick<Window, "addEventListener" | "removeEventListener">;
  onRoute: (route: Route) => void;
}

export class Router {
  readonly opts: RouterOptions;
  private readonly onPop = (): void => this.emit();
  private started = false;

  constructor(opts: RouterOptions) {
    this.opts = opts;
  }

  current(): Route {
    return matchRoute(this.opts.location.pathname);
  }

  private emit(): void {
    this.opts.onRoute(this.current());
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    this.opts.window.addEventListener("popstate", this.onPop);
    this.emit();
  }

  dispose(): void {
    this.opts.window.removeEventListener("popstate", this.onPop);
    this.started = false;
  }

  navigate(path: string, opts: { replace?: boolean } = {}): void {
    if (opts.replace === true) {
      this.opts.history.replaceState(null, "", path);
    } else {
      this.opts.history.pushState(null, "", path);
    }
    this.emit();
  }

  /**
   * Intercept same-origin internal links inside `root` (no modifier keys,
   * no target) and route them through pushState. Returns a disposer.
   */
  interceptLinks(root: HTMLElement): () => void {
    const onClick = (ev: Event): void => {
      const me = ev as MouseEvent;
      if (me.button !== 0 || me.metaKey || me.ctrlKey || me.shiftKey || me.altKey) return;
      const a = (me.target as HTMLElement | null)?.closest?.("a[href]");
      if (a === null || a === undefined) return;
      const href = a.getAttribute("href") ?? "";
      if (a.getAttribute("target") !== null || href === "" || href.startsWith("#")) return;
      if (!href.startsWith("/")) return; // same-origin absolute or external → default
      me.preventDefault();
      this.navigate(href);
    };
    root.addEventListener("click", onClick);
    return () => root.removeEventListener("click", onClick);
  }
}
