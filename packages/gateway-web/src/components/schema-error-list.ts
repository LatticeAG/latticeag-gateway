/**
 * SchemaErrorList — config.validate errors rendered as JSON Pointer +
 * message rows; each row can focus the offending path in the editor.
 */
import { h, append, emptyState } from "../lib/dom.js";
import { show } from "../lib/format.js";

export interface SchemaError {
  pointer?: string;   // JSON Pointer, e.g. "/gateway/ui/port"
  message?: string;
  code?: string;
}

export function errorsFrom(value: unknown): SchemaError[] {
  if (!Array.isArray(value)) return [];
  return value.filter((e): e is Record<string, unknown> => e !== null && typeof e === "object")
    .map((e) => ({
      pointer: typeof e.pointer === "string" ? e.pointer : typeof e.path === "string" ? e.path : undefined,
      message: typeof e.message === "string" ? e.message : show(e),
      code: typeof e.code === "string" ? e.code : undefined,
    }));
}

export function SchemaErrorList(props: {
  errors: readonly SchemaError[];
  onFocusPointer?: (pointer: string) => void;
}): HTMLElement {
  if (props.errors.length === 0) {
    return h("p", { class: "ok small", role: "status", text: "✓ document validates" });
  }
  const ul = h("ul", { class: "tree", role: "list", aria: { label: "Schema errors" } });
  for (const e of props.errors) {
    const li = h("li", { class: "err" },
      h("code", { class: "mono", text: e.pointer ?? "/" }),
      h("span", { text: ` ${e.message ?? ""}` }));
    if (e.pointer && props.onFocusPointer) {
      li.tabIndex = 0;
      li.setAttribute("role", "button");
      li.addEventListener("click", () => props.onFocusPointer!(e.pointer!));
      li.addEventListener("keydown", (ev) => {
        if ((ev as KeyboardEvent).key === "Enter") props.onFocusPointer!(e.pointer!);
      });
    }
    append(ul, li);
  }
  return h("div", {}, h("h4", { class: "small err", text: `${props.errors.length} schema error(s)` }), ul);
}

export function emptyErrors(): HTMLElement {
  return emptyState("");
}
