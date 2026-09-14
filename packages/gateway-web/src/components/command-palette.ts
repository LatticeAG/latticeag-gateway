/**
 * CommandPalette — Ctrl/Cmd+K overlay: filterable command list with
 * arrow/enter/escape handling, focus trapped while open and restored to
 * the invoking control on close (spec §7.3).
 */
import { h, append, clear } from "../lib/dom.js";

export interface PaletteCommand {
  id: string;
  label: string;
  hint?: string;
  keys?: string;
  run: () => void;
}

export class CommandPalette {
  readonly el: HTMLElement;
  private readonly input: HTMLInputElement;
  private readonly listEl: HTMLElement;
  private commands: readonly PaletteCommand[] = [];
  private filtered: readonly PaletteCommand[] = [];
  private selected = 0;
  private isOpen = false;
  private invoker: HTMLElement | null = null;
  private readonly backdrop: HTMLElement;

  constructor(private readonly onClose?: () => void) {
    this.input = h("input", {
      type: "text",
      placeholder: "Type a command…",
      role: "combobox",
      aria: { label: "Command palette", expanded: "true", controls: "palette-list", autocomplete: "none" },
      on: { input: () => this.refilter() },
    }) as HTMLInputElement;
    this.listEl = h("ul", { id: "palette-list", role: "listbox" });
    this.el = h("div", {
      class: "palette",
      role: "dialog",
      aria: { modal: "true", label: "Command palette" },
      hidden: true,
    }, this.input, this.listEl);
    this.backdrop = h("div", { class: "overlay-backdrop", hidden: true, on: { click: () => this.close() } });
    this.el.addEventListener("keydown", (e) => this.onKey(e as KeyboardEvent));
  }

  mount(root: HTMLElement): void {
    root.appendChild(this.backdrop);
    root.appendChild(this.el);
  }

  setCommands(commands: readonly PaletteCommand[]): void {
    this.commands = commands;
    this.refilter();
  }

  open(invoker?: HTMLElement | null): void {
    this.isOpen = true;
    this.invoker = invoker ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    this.el.removeAttribute("hidden");
    this.backdrop.removeAttribute("hidden");
    this.input.value = "";
    this.refilter();
    this.input.focus();
  }

  close(): void {
    if (!this.isOpen) return;
    this.isOpen = false;
    this.el.setAttribute("hidden", "");
    this.backdrop.setAttribute("hidden", "");
    // Restore focus to the invoking control (spec §7.3).
    this.invoker?.focus?.();
    this.invoker = null;
    this.onClose?.();
  }

  get open_(): boolean {
    return this.isOpen;
  }

  get visible(): boolean {
    return this.isOpen;
  }

  private refilter(): void {
    const q = this.input.value.trim().toLowerCase();
    this.filtered = this.commands.filter((c) =>
      q === "" || c.label.toLowerCase().includes(q) || c.id.toLowerCase().includes(q));
    this.selected = 0;
    this.renderList();
  }

  private renderList(): void {
    clear(this.listEl);
    this.filtered.forEach((c, i) => {
      const li = h("li", {
        role: "option",
        id: `pal-${i}`,
        aria: { selected: i === this.selected ? "true" : "false" },
        on: { click: () => this.runAt(i), mousemove: () => { this.selected = i; this.renderList(); } },
      }, h("span", { text: c.label }), h("span", { class: "keys", text: c.keys ?? c.hint ?? "" }));
      append(this.listEl, li);
    });
    this.input.setAttribute("aria-activedescendant", `pal-${this.selected}`);
  }

  private runAt(i: number): void {
    const cmd = this.filtered[i];
    if (cmd === undefined) return;
    this.close();
    cmd.run();
  }

  private onKey(e: KeyboardEvent): void {
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        this.selected = Math.min(this.filtered.length - 1, this.selected + 1);
        this.renderList();
        break;
      case "ArrowUp":
        e.preventDefault();
        this.selected = Math.max(0, this.selected - 1);
        this.renderList();
        break;
      case "Enter":
        e.preventDefault();
        this.runAt(this.selected);
        break;
      case "Escape":
        e.preventDefault();
        this.close();
        break;
      case "Tab": {
        // Minimal focus trap: keep Tab inside the palette (§7.3).
        e.preventDefault();
        this.input.focus();
        break;
      }
      default:
        break;
    }
  }
}
