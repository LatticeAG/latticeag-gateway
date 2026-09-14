/**
 * `/config` — structured + raw config editor (spec §7.1): config.get /
 * validate / apply. JSON Pointer errors, unsaved-diff indicator,
 * REVISION_CONFLICT re-read, restart-required plan, masked secret refs.
 */
import { h, append, clear, errorBox } from "../lib/dom.js";
import { ConfigForm } from "../components/config-form.js";
import { JsonEditor, unsavedPill } from "../components/json-editor.js";
import { SchemaErrorList, errorsFrom } from "../components/schema-error-list.js";
import { show } from "../lib/format.js";
import type { RouteModule } from "./ctx.js";
import { Disposer, describeError } from "./ctx.js";

export const configRoute: RouteModule = (ctx) => {
  const d = new Disposer();
  const editor = new JsonEditor({ ariaLabel: "Config document JSON" });
  const summary = h("div");
  const errors = h("div");
  const applyBtn = h("button", {
    class: "primary",
    disabled: true,
    text: "Validate & apply",
    on: { click: () => void validateThenApply() },
  }) as HTMLButtonElement;
  const statusEl = h("p", { class: "small muted", role: "status", aria: { live: "polite" } });
  const root = h("section", { aria: { label: "Configuration" } },
    h("h1", { text: "Config" }),
    summary,
    h("div", { class: "panel" },
      h("h3", { text: "Document (raw JSON)" }),
      editor.el,
      errors,
      h("div", { class: "btn-row" },
        h("button", { class: "flat", text: "Validate", on: { click: () => void validate(false) } }),
        applyBtn),
      statusEl));
  ctx.shell.setMain(root);
  ctx.shell.setInspector();

  let revision = "0";
  let doc: Record<string, unknown> | null = null;
  let dirty = false;

  const mutationsEnabled = () => ctx.store.get().mutationsEnabled;

  const refreshApply = (): void => {
    applyBtn.disabled = !mutationsEnabled() || doc === null || !dirty;
  };
  editor.onDirty = (dd) => {
    dirty = dd;
    refreshApply();
    if (dd) clear(errors);
  };

  const load = async (): Promise<void> => {
    try {
      const res = await ctx.client.call<{ revision?: string; document?: Record<string, unknown> }>("config.get");
      revision = res.revision ?? "0";
      doc = res.document ?? null;
      editor.setValue(JSON.stringify(doc, null, 2));
      dirty = false;
      clear(summary);
      append(summary, ConfigForm({ document: doc, revision, onEditRaw: () => editor.el.scrollIntoView() }));
      clear(errors);
      statusEl.textContent = `Loaded revision ${revision}.`;
      refreshApply();
    } catch (e) {
      clear(summary);
      append(summary, errorBox(describeError(e), "config.get failed — a viewer session cannot read config."));
      statusEl.textContent = "";
    }
  };

  const validate = async (applyAfter: boolean): Promise<boolean> => {
    const parsed = editor.parse();
    if (!parsed.ok) return false;
    let res: { valid?: boolean; errors?: unknown };
    try {
      res = await ctx.client.call("config.validate", { document: parsed.value });
    } catch (e) {
      clear(errors);
      append(errors, errorBox(describeError(e), "config.validate failed."));
      return false;
    }
    const errs = errorsFrom(res.errors);
    clear(errors);
    append(errors, SchemaErrorList({ errors: errs }));
    if (errs.length > 0 || res.valid !== true) {
      statusEl.textContent = "Validation failed — fix the JSON Pointer errors above.";
      return false;
    }
    statusEl.textContent = "Document validates.";
    if (applyAfter) await applyNow(parsed.value);
    return true;
  };

  const validateThenApply = async (): Promise<void> => {
    await validate(true);
  };

  const applyNow = async (document: unknown): Promise<void> => {
    try {
      const res = await ctx.client.call<{ revision?: string; restart_required?: boolean }>(
        "config.apply", { expected_revision: revision, document });
      revision = res.revision ?? revision;
      dirty = false;
      editor.setValue(JSON.stringify(document, null, 2));
      statusEl.textContent = `Applied — now revision ${revision}.${res.restart_required === true ? " Restart required for some fields." : ""}`;
      ctx.toasts.info(`config applied (revision ${revision})${res.restart_required === true ? " — restart required" : ""}`);
      clear(summary);
      append(summary, ConfigForm({ document: document as Record<string, unknown>, revision }));
      refreshApply();
    } catch (e) {
      const code = describeError(e);
      if ((e as { code?: string }).code === "REVISION_CONFLICT") {
        statusEl.textContent = "REVISION_CONFLICT — the document changed elsewhere; re-reading before any retry.";
        ctx.toasts.error("config.apply conflict: external revision changed; reloaded.");
        await load(); // re-read — never blind-retry a CAS write
      } else {
        statusEl.textContent = `config.apply failed: ${code}`;
        ctx.toasts.error(`config.apply failed: ${code}`);
      }
    }
  };

  void load();
  return d;
};

export function redactedShow(v: unknown): string {
  return show(v);
}
