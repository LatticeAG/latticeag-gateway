import { describe, expect, test, vi } from "vitest";
import { matchRoute, Router } from "./router.js";

describe("matchRoute", () => {
  test.each([
    ["/", "overview", {}],
    ["/products", "products", {}],
    ["/products/lexverdict", "product", { slug: "lexverdict" }],
    ["/events", "events", {}],
    ["/agents", "agents", {}],
    ["/inbox", "inbox", {}],
    ["/config", "config", {}],
    ["/receipts", "receipts", {}],
    ["/receipts/ws1/act9", "receipt", { workspace: "ws1", action: "act9" }],
    ["/sync", "sync", {}],
    ["/pair/pair1", "pair", { id: "pair1" }],
  ])("%s → %s", (path, name, params) => {
    const r = matchRoute(path);
    expect(r.name).toBe(name);
    expect(r.params).toEqual(params);
    expect(r.path).toBe(path);
  });

  test("decodes URI params", () => {
    expect(matchRoute("/products/a%20b").params.slug).toBe("a b");
  });

  test("unknown/deep paths → not-found", () => {
    expect(matchRoute("/nope").name).toBe("not-found");
    expect(matchRoute("/products/a/b").name).toBe("not-found");
    expect(matchRoute("/receipts/onlyone").name).toBe("not-found");
    expect(matchRoute("").name).toBe("overview"); // "" splits to [] — same as /
  });
});

describe("Router", () => {
  function fakeWindow() {
    const handlers = new Map<string, Set<EventListener>>();
    return {
      addEventListener: (t: string, fn: EventListener) => {
        const set = handlers.get(t) ?? new Set<EventListener>();
        set.add(fn);
        handlers.set(t, set);
      },
      removeEventListener: (t: string, fn: EventListener) => void handlers.get(t)?.delete(fn),
      emit: (t: string) => { for (const fn of handlers.get(t) ?? []) fn(new Event(t)); },
    };
  }

  test("navigate pushState + emits; popstate emits", () => {
    const loc = { pathname: "/" };
    const pushState = vi.fn((_d: unknown, _t: string, url: string) => { loc.pathname = url.split("#")[0] ?? url; });
    const replaceState = vi.fn((_d: unknown, _t: string, url: string) => { loc.pathname = url.split("#")[0] ?? url; });
    const win = fakeWindow();
    const seen: string[] = [];
    const r = new Router({
      location: loc as Location,
      history: { pushState, replaceState } as unknown as History,
      window: win as unknown as Window,
      onRoute: (route) => seen.push(`${route.name}:${route.path}`),
    });
    r.start();
    expect(seen).toEqual(["overview:/"]);
    r.navigate("/products/lex");
    expect(pushState).toHaveBeenCalledWith(null, "", "/products/lex");
    expect(seen.at(-1)).toBe("product:/products/lex");
    loc.pathname = "/events";
    win.emit("popstate");
    expect(seen.at(-1)).toBe("events:/events");
    r.navigate("/", { replace: true });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
    expect(seen.at(-1)).toBe("overview:/");
    r.dispose();
    const n = seen.length;
    win.emit("popstate");
    expect(seen.length).toBe(n); // no route emit after dispose
  });
});
