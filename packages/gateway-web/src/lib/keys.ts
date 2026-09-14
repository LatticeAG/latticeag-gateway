/**
 * Global keyboard map (spec §7.3):
 *   g p products · g e events · g a agents · g i inbox · g c config · g r receipts
 *   / focuses the current view's search · Space pauses the live stream
 *   Escape closes the top overlay · Ctrl/Cmd+K opens the command palette
 *
 * Shortcuts are ignored while editing text or during IME composition, and
 * no destructive action ever binds to a single key.
 */

export interface KeyHandlers {
  navigate: (path: string) => void;
  /** Focus the visible search input (data-search) — return false if none. */
  focusSearch: () => boolean;
  toggleStreamPause: () => void;
  /** Close the topmost overlay; return false when nothing was open. */
  closeOverlay: () => boolean;
  openPalette: () => void;
}

const G_TIMEOUT_MS = 1_000;

const GO_KEYS: Readonly<Record<string, string>> = {
  p: "/products",
  e: "/events",
  a: "/agents",
  i: "/inbox",
  c: "/config",
  r: "/receipts",
};

/** True when the event target is editable or IME-managed. */
export function isEditingTarget(target: EventTarget | null): boolean {
  if (target === null || !(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  if (tag === "TEXTAREA" || tag === "SELECT") return true;
  if (tag === "INPUT") {
    const t = (target.getAttribute("type") ?? "text").toLowerCase();
    return !["checkbox", "radio", "button", "range", "color"].includes(t);
  }
  return target.closest("[data-keys-capture]") !== null;
}

export interface KeysBinding {
  dispose(): void;
  /** Test seam: the pending `g`-prefix state. */
  pendingGo(): boolean;
}

export function installKeys(
  target: Pick<Window, "addEventListener" | "removeEventListener">,
  handlers: KeyHandlers,
  opts: { now?: () => number } = {},
): KeysBinding {
  const now = opts.now ?? Date.now;
  let goAt = 0;

  const onKeydown = (ev: Event): void => {
    const e = ev as KeyboardEvent;
    // IME composition and editable targets never trigger global keys.
    if (e.isComposing || (e as unknown as { keyCode?: number }).keyCode === 229) return;

    if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      handlers.openPalette();
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey) return;

    if (e.key === "Escape") {
      // Always allowed — closes the topmost overlay if any.
      handlers.closeOverlay();
      return;
    }
    if (isEditingTarget(e.target)) return;

    const at = now();
    if (e.key === "g" && !e.shiftKey) {
      goAt = at;
      return;
    }
    if (goAt > 0 && at - goAt <= G_TIMEOUT_MS && e.key in GO_KEYS) {
      goAt = 0;
      e.preventDefault();
      handlers.navigate(GO_KEYS[e.key]!);
      return;
    }
    goAt = 0;

    if (e.key === "/") {
      if (handlers.focusSearch()) e.preventDefault();
      return;
    }
    if (e.key === " ") {
      e.preventDefault();
      handlers.toggleStreamPause();
    }
  };

  target.addEventListener("keydown", onKeydown);
  return {
    dispose: () => target.removeEventListener("keydown", onKeydown),
    pendingGo: () => goAt > 0 && now() - goAt <= G_TIMEOUT_MS,
  };
}
