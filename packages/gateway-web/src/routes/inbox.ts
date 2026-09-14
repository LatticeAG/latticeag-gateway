/**
 * `/inbox` — VekInbox-semantic approval inbox (spec §7.1): approval.list/
 * get/decide/cancel. Pending / expired / denied / conflicted-revision /
 * native-pending-ACK / nonreviewer read-only states are all distinct.
 * Decision submission always goes through the DecisionReview dialog
 * bound to the current revision.
 */
import { h, append, clear, emptyState, errorBox } from "../lib/dom.js";
import { ApprovalCard, approvalFrom, type ApprovalView } from "../components/approval-card.js";
import { DecisionReview } from "../components/decision-panel.js";
import { show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

type Filter = "PENDING" | "all";

export const inboxRoute: RouteModule = (ctx) => {
  const d = new Disposer();
  const filter = h("select", { aria: { label: "Approval state filter" } },
    h("option", { value: "PENDING", text: "pending" }),
    h("option", { value: "all", text: "all" })) as HTMLSelectElement;
  const root = h("section", { aria: { label: "Approval inbox" } },
    h("h1", { text: "Inbox" }),
    h("div", { class: "toolbar" }, filter));
  const body = h("div", {}, h("p", { class: "muted", text: "Loading…" }));
  append(root, body);
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  let items: ApprovalView[] = [];
  /** Local nonauthorizing notes — UI-only, never an authorization. */
  const notes = new Map<string, string>();

  const mutationsEnabled = () => ctx.store.get().mutationsEnabled;

  const openDecision = (a: ApprovalView, decision: "approve" | "deny"): void => {
    // Re-fetch the exact current revision at review time — a stale
    // decision is a conflict, never an auto-retry (spec §7.2).
    let busy = false;
    const mount = async (error: string | null = null): Promise<void> => {
      let fresh = a;
      try {
        const got = await ctx.client.call<Record<string, unknown>>("approval.get", { approval: a.approval });
        fresh = approvalFrom(got);
        if (fresh.revision !== a.revision || fresh.state !== a.state) {
          ctx.toasts.warn(`approval ${a.approval} changed (rev ${a.revision}→${fresh.revision}, ${a.state}→${fresh.state}) — review refreshed`);
        }
      } catch (e) {
        error = `could not re-read approval: ${describeError(e)}`;
      }
      ctx.shell.setInspector(DecisionReview({
        approval: fresh,
        decision,
        busy,
        error,
        onCancel: () => ctx.shell.setInspector(),
        onSubmit: (reason) => {
          busy = true;
          void submit(fresh, decision, reason);
        },
      }));
      const first = ctx.shell.inspectorEl.querySelector("input,button");
      if (first instanceof HTMLElement) first.focus();
    };
    const submit = async (cur: ApprovalView, dec: "approve" | "deny", reason: string): Promise<void> => {
      try {
        await ctx.client.call("approval.decide", {
          approval: cur.approval,
          expected_revision: cur.revision,
          action: cur.action,
          decision: dec,
          reason: reason === "" ? null : reason,
        });
        ctx.toasts.info(`${dec === "approve" ? "approved" : "denied"} ${cur.approval} at revision ${cur.revision}`);
        ctx.shell.setInspector();
        await load();
      } catch (e) {
        const code = describeError(e);
        ctx.shell.setInspector(DecisionReview({
          approval: cur, decision, busy: false,
          error: `decision failed: ${code}`,
          onCancel: () => ctx.shell.setInspector(),
          onSubmit: (r) => { busy = true; void submit(cur, dec, r); },
        }));
      }
    };
    void mount();
  };

  const cancelReq = async (a: ApprovalView): Promise<void> => {
    try {
      await ctx.client.call("approval.cancel", { approval: a.approval, expected_revision: a.revision });
      ctx.toasts.info(`cancelled ${a.approval}`);
      await load();
    } catch (e) {
      ctx.toasts.error(`approval.cancel failed: ${describeError(e)}`);
    }
  };

  const render = (): void => {
    clear(body);
    const list = filter.value === "PENDING" ? items.filter((i) => i.state === "PENDING") : items;
    ctx.store.set({ pendingApprovals: items.filter((i) => i.state === "PENDING").length });
    if (list.length === 0) {
      append(body, emptyState(filter.value === "PENDING" ? "No pending approvals." : "No approvals."));
      return;
    }
    for (const a of list) {
      const card = ApprovalCard({
        approval: a,
        mutationsEnabled: mutationsEnabled(),
        onDecide: (dec) => openDecision(a, dec),
        onCancel: () => void cancelReq(a),
        onNote: (text) => {
          if (text.trim() === "") return;
          notes.set(a.approval, text.trim());
          ctx.toasts.info("note attached locally — nonauthorizing, not sent to any reviewer");
          render();
        },
      });
      const note = notes.get(a.approval);
      if (note !== undefined) {
        append(card, h("p", { class: "small muted", text: `local note: ${note}` }));
      }
      append(body, card);
    }
  };
  filter.addEventListener("change", render);

  const load = async (): Promise<void> => {
    try {
      const page = await ctx.client.call<{ items?: Record<string, unknown>[] }>(
        "approval.list", { state: filter.value === "all" ? null : "PENDING", after: null, limit: 200 });
      items = (page.items ?? []).map(approvalFrom);
      clear(body);
      render();
    } catch (e) {
      clear(body);
      append(body, errorBox(describeError(e), "approval.list failed."));
    }
  };

  void load();
  d.every(7_500, () => void load());
  d.add(() => ctx.shell.setInspector());
  return d;
};
