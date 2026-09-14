import { describe, expect, test, vi } from "vitest";
import { installKeys, isEditingTarget, type KeyHandlers } from "./keys.js";

function handlers(): KeyHandlers & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    navigate: (p) => void calls.push(`nav:${p}`),
    focusSearch: () => (calls.push("search"), true),
    toggleStreamPause: () => void calls.push("pause"),
    closeOverlay: () => (calls.push("close"), true),
    openPalette: () => void calls.push("palette"),
  };
}

function key(k: string, init: KeyboardEventInit = {}, target?: EventTarget): KeyboardEvent {
  const e = new KeyboardEvent("keydown", { key: k, bubbles: true, ...init });
  if (target !== undefined) {
    Object.defineProperty(e, "target", { value: target });
  }
  return e;
}

describe("installKeys", () => {
  test("g-prefixed navigation chords", () => {
    const h = handlers();
    const b = installKeys(window, h);
    window.dispatchEvent(key("g"));
    window.dispatchEvent(key("p"));
    window.dispatchEvent(key("g"));
    window.dispatchEvent(key("e"));
    window.dispatchEvent(key("g"));
    window.dispatchEvent(key("a"));
    window.dispatchEvent(key("g"));
    window.dispatchEvent(key("i"));
    window.dispatchEvent(key("g"));
    window.dispatchEvent(key("c"));
    window.dispatchEvent(key("g"));
    window.dispatchEvent(key("r"));
    expect(h.calls).toEqual([
      "nav:/products", "nav:/events", "nav:/agents", "nav:/inbox", "nav:/config", "nav:/receipts",
    ]);
    b.dispose();
  });

  test("chord times out (1 s)", () => {
    let t = 1_000;
    const h = handlers();
    installKeys(window, h, { now: () => t });
    window.dispatchEvent(key("g"));
    t += 2_000;
    window.dispatchEvent(key("p"));
    expect(h.calls).toEqual([]);
  });

  test("/ focuses search, Space pauses, Escape closes, Ctrl+K palette", () => {
    const h = handlers();
    installKeys(window, h);
    window.dispatchEvent(key("/"));
    window.dispatchEvent(key(" "));
    window.dispatchEvent(key("Escape"));
    window.dispatchEvent(key("k", { ctrlKey: true }));
    window.dispatchEvent(key("K", { metaKey: true }));
    expect(h.calls).toEqual(["search", "pause", "close", "palette", "palette"]);
  });

  test("shortcuts ignored while editing text", () => {
    const h = handlers();
    installKeys(window, h);
    const input = document.createElement("input");
    input.type = "text";
    document.body.appendChild(input);
    window.dispatchEvent(key("g", {}, input));
    window.dispatchEvent(key("p", {}, input));
    window.dispatchEvent(key("/", {}, input));
    window.dispatchEvent(key(" ", {}, input));
    expect(h.calls).toEqual([]);
    input.remove();
  });

  test("IME composition (keyCode 229) ignored", () => {
    const h = handlers();
    installKeys(window, h);
    const e = key("g");
    Object.defineProperty(e, "keyCode", { value: 229 });
    window.dispatchEvent(e);
    window.dispatchEvent(key("p"));
    expect(h.calls).toEqual([]);
  });

  test("isEditingTarget covers input/textarea/select/contenteditable", () => {
    const i = document.createElement("input");
    const ta = document.createElement("textarea");
    const sel = document.createElement("select");
    const ce = document.createElement("div");
    ce.setAttribute("contenteditable", "true");
    const btn = document.createElement("button");
    document.body.append(i, ta, sel, ce, btn);
    expect(isEditingTarget(i)).toBe(true);
    expect(isEditingTarget(ta)).toBe(true);
    expect(isEditingTarget(sel)).toBe(true);
    expect(isEditingTarget(ce)).toBe(true);
    expect(isEditingTarget(btn)).toBe(false);
    expect(isEditingTarget(null)).toBe(false);
    [i, ta, sel, ce, btn].forEach((x) => x.remove());
  });
});
