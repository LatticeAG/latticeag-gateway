/**
 * `/products` — searchable catalog + installed list (spec §7.1):
 * catalog.search/show + product.list. States: signed cached age,
 * available/stub, installed, OSS/paid surface, enterprise blocked.
 */
import { h, append, clear } from "../lib/dom.js";
import { emptyState, errorBox } from "../lib/dom.js";
import { ProductTable, type ProductRow } from "../components/product-table.js";
import { show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

function rowFromCatalog(e: Record<string, unknown>, installed: Set<string>): ProductRow {
  const tier = typeof e.tier === "string" ? e.tier : typeof e.usage_tier === "string" ? e.usage_tier : undefined;
  return {
    slug: show(e.slug),
    name: typeof e.name === "string" ? e.name : undefined,
    version: typeof e.version === "string" ? e.version : undefined,
    series: typeof e.series === "string" ? e.series : undefined,
    state: installed.has(show(e.slug)) ? "installed" : typeof e.status === "string" ? e.status : "available",
    tier,
    cached_ms: typeof e.cached_ms === "number" ? e.cached_ms : (typeof e.signed_ms === "number" ? e.signed_ms : undefined),
    installed: installed.has(show(e.slug)),
    enterpriseBlocked: e.enterprise_blocked === true || e.blocked === "enterprise",
  };
}

export const productsRoute: RouteModule = (ctx) => {
  const d = new Disposer();
  const table = new ProductTable({ onOpen: (slug) => ctx.navigate(`/products/${encodeURIComponent(slug)}`) });
  const search = h("input", {
    type: "search",
    placeholder: "Search catalog… (/)",
    dataset: { search: "products" },
    aria: { label: "Search products" },
  }) as HTMLInputElement;
  const statusEl = h("p", { class: "small muted", role: "status" });
  const results = h("div");
  append(results, table.el);
  const root = h("section", { aria: { label: "Products" } },
    h("h1", { text: "Products" }),
    h("div", { class: "toolbar" }, h("div", { class: "grow", style: "flex:1" }, search),
      h("button", { text: "Refresh catalog", class: "flat", on: { click: () => void refreshCatalog() } })),
    statusEl,
    results);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  let installedSlugs = new Set<string>();
  let catalogItems: Record<string, unknown>[] = [];

  const rerender = (): void => {
    const q = search.value.trim();
    let items = catalogItems.map((e) => rowFromCatalog(e, installedSlugs));
    if (q !== "") {
      const ql = q.toLowerCase();
      items = items.filter((r) => r.slug.toLowerCase().includes(ql) || (r.name ?? "").toLowerCase().includes(ql));
    }
    if (items.length === 0) {
      clear(results);
      append(results, emptyState(q === "" ? "Catalog is empty or not cached — refresh may require network." : `No products match “${q}”.`));
      return;
    }
    if (results.firstChild !== table.el) {
      clear(results);
      append(results, table.el);
    }
    table.setRows(items);
  };
  search.addEventListener("input", rerender);

  const load = async (): Promise<void> => {
    statusEl.textContent = "Loading…";
    const [cat, inst] = await Promise.all([
      ctx.client.call<{ items?: Record<string, unknown>[]; next?: string | null }>(
        "catalog.search", { q: search.value.trim() || "", series: null, after: null, limit: 200 }).catch((e) => ({ error: describeError(e) }) as { error?: string; items?: Record<string, unknown>[] }),
      ctx.client.call<{ items?: Record<string, unknown>[] }>("product.list", { after: null, limit: 200 }).catch(() => ({ items: [] })),
    ]);
    if ("error" in cat && typeof cat.error === "string") {
      clear(results);
      append(results, errorBox(cat.error, "Catalog search failed — the signed cache may be absent or offline."));
      statusEl.textContent = "";
      return;
    }
    catalogItems = cat.items ?? [];
    installedSlugs = new Set((inst.items ?? []).map((i) => show(i.slug)));
    // Installed-but-not-in-catalog entries still surface.
    const catalogSlugs = new Set(catalogItems.map((i) => show(i.slug)));
    for (const i of inst.items ?? []) {
      const slug = show(i.slug);
      if (!catalogSlugs.has(slug)) {
        catalogItems.push({ slug, version: i.version, status: "installed" });
      }
    }
    statusEl.textContent = `${catalogItems.length} catalog entr(ies), ${installedSlugs.size} installed — signed cache, ages shown per row.`;
    rerender();
  };

  const refreshCatalog = async (): Promise<void> => {
    try {
      const r = await ctx.client.call<Record<string, unknown>>("catalog.refresh", { source: "configured", offline: true });
      ctx.toasts.info(`catalog refreshed (revision ${show(r.revision)}, ${show(r.freshness)})`);
      await load();
    } catch (e) {
      ctx.toasts.error(`catalog.refresh failed: ${describeError(e)}`);
    }
  };

  void load();
  return d;
};
