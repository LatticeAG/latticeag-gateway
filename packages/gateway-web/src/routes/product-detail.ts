/**
 * `/products/:slug` — package detail + plan/commit flow (spec §7.1):
 * trust/provenance evidence, dependency graph, grants diff, progress via
 * operation.get polling, failure state, retained versions for rollback.
 * Every commit goes through InstallReview — nothing mutates directly.
 */
import { h, append, clear, emptyState, errorBox } from "../lib/dom.js";
import { PackageDetail, PackageActions } from "../components/package-detail.js";
import { TrustPanel, trustFrom } from "../components/trust-panel.js";
import { DependencyList, edgesFrom } from "../components/dependency-list.js";
import { InstallReview } from "../components/install-checklist.js";
import { OperationTimeline, type OperationView } from "../components/operation-timeline.js";
import { show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

type PlanKind = "install" | "update" | "uninstall" | "rollback";

const COMMIT_RPC: Readonly<Record<PlanKind, string>> = {
  install: "product.install",
  update: "product.update",
  uninstall: "product.uninstall",
  rollback: "product.rollback",
};

export const productDetailRoute: RouteModule = (ctx, route) => {
  const d = new Disposer();
  const slug = route.params.slug ?? "";
  const root = h("section", { aria: { label: `Package ${slug}` } }, h("h1", { class: "mono", text: slug }));
  const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
  append(root, body);
  ctx.shell.setMain(root);

  const mutationsEnabled = () => ctx.store.get().mutationsEnabled;

  const load = async (): Promise<void> => {
    const [entryRes, instRes] = await Promise.all([
      ctx.client.call<{ entry?: Record<string, unknown> }>("catalog.show", { slug, version: null }).catch((e) => ({ error: describeError(e) })),
      ctx.client.call<{ items?: Record<string, unknown>[] }>("product.list", { after: null, limit: 200 }).catch(() => ({ items: [] })),
    ]);
    clear(body);
    const installed = (instRes.items ?? []).find((i) => show(i.slug) === slug) ?? null;
    const entry = "error" in entryRes ? null : (entryRes.entry ?? null);
    if (entry === null && installed === null) {
      append(body, errorBox("error" in entryRes ? (entryRes as { error: string }).error : "NOT_FOUND", `No catalog entry or installed instance for “${slug}”.`));
      return;
    }
    let health: Record<string, unknown> | null = null;
    let healthError: string | null = null;
    if (installed !== null) {
      try {
        health = await ctx.client.call<Record<string, unknown>>("product.health", { slug });
      } catch (e) {
        healthError = describeError(e);
      }
    }
    append(body, PackageDetail({ slug, entry, installed, health, healthError }));
    append(body, TrustPanel({ facts: { ...trustFrom(entry), ...trustFrom(installed) } }));
    const edges = edgesFrom(entry?.dependencies ?? entry?.requires);
    if (edges.length > 0 || entry !== null) {
      append(body, h("section", { class: "panel" }, h("h3", { text: "Dependencies" }), DependencyList({ edges })));
    }
    const retained = Array.isArray(installed?.retained) ? (installed!.retained as unknown[]).map(show) : [];
    append(body, PackageActions({
      mutationsEnabled: mutationsEnabled(),
      retained,
      onAction: (kind, target) => void plan(kind, target),
    }));
    if (!mutationsEnabled()) {
      append(body, h("p", { class: "small muted", text: "Viewer session or disconnected daemon — actions are disabled." }));
    }
  };

  const plan = async (kind: PlanKind, target?: string): Promise<void> => {
    const params: Record<string, unknown> = { kind, source: slug, cascade: false, keep_data: true };
    if (target) params.version = target;
    if (kind === "rollback" && target) params.target = target;
    let res: { plan?: Record<string, unknown>; summary?: Record<string, unknown> };
    try {
      res = await ctx.client.call("product.plan", params);
    } catch (e) {
      ctx.toasts.error(`product.plan ${kind} failed: ${describeError(e)}`);
      return;
    }
    showReview(kind, res.plan ?? {}, res.summary ?? null);
  };

  const showReview = (kind: PlanKind, planDoc: Record<string, unknown>, summary: Record<string, unknown> | null): void => {
    let busy = false;
    const mount = (error: string | null = null): void => {
      ctx.shell.setInspector(InstallReview({
        kind,
        slug,
        plan: planDoc,
        summary,
        busy,
        error,
        onCancel: () => ctx.shell.setInspector(),
        onCommit: () => void commit(kind, planDoc, (err) => { busy = true; mount(err); }),
      }));
      // Focus the review's commit control (visible focused review control).
      const btn = ctx.shell.inspectorEl.querySelector("button.primary");
      if (btn instanceof HTMLElement) btn.focus();
    };
    mount();
  };

  const commit = async (kind: PlanKind, planDoc: Record<string, unknown>, onError: (e: string | null) => void): Promise<void> => {
    onError(null);
    try {
      const acc = await ctx.client.call<{ operation?: string; state?: string }>(COMMIT_RPC[kind], { plan: planDoc });
      ctx.toasts.info(`${kind} admitted as ${acc.operation ?? "operation"} (QUEUED — poll for terminal state)`);
      ctx.shell.setInspector();
      pollOperation(acc.operation ?? null);
    } catch (e) {
      onError(`commit failed: ${describeError(e)}`);
      ctx.toasts.error(`${COMMIT_RPC[kind]} failed: ${describeError(e)}`);
    }
  };

  const pollOperation = (operation: string | null): void => {
    if (operation === null) return;
    const slot = h("div");
    append(body, slot);
    const tick = async (): Promise<void> => {
      try {
        const op = await ctx.client.call<OperationView>("operation.get", { operation });
        clear(slot);
        append(slot, OperationTimeline({ op }));
        if (["SUCCEEDED", "FAILED", "CANCELLED"].includes(op.state)) {
          clearInterval(t);
          await load(); // re-read installed state after terminal
        }
      } catch (e) {
        clear(slot);
        append(slot, errorBox(describeError(e), "operation.get failed — the job may still be running; poll state lost."));
        clearInterval(t);
      }
    };
    const t = setInterval(() => void tick(), 1_000);
    d.add(() => clearInterval(t));
    void tick();
  };

  void load();
  d.add(() => ctx.shell.setInspector());
  return d;
};
