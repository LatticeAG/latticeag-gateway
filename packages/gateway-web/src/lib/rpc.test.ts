import { describe, expect, test, vi } from "vitest";
import {
  RpcClient,
  RpcError,
  bootstrapFromLocation,
  newRequestId,
  parseBootstrapFragment,
  CSRF_HEADER,
} from "./rpc.js";

function fakeFetch(impl: (url: string, init: RequestInit) => unknown): typeof fetch {
  return vi.fn(async (url: unknown, init: unknown) => {
    const out = impl(url as string, init as RequestInit);
    if (out instanceof Error) throw out;
    return { ok: true, status: 200, json: async () => out } as Response;
  }) as unknown as typeof fetch;
}

function lastCallBody(fn: ReturnType<typeof vi.fn>): Record<string, unknown> {
  const [, init] = fn.mock.calls.at(-1)! as [string, RequestInit];
  return JSON.parse(init.body as string) as Record<string, unknown>;
}

describe("RpcClient", () => {
  test("sends the closed v2 envelope with CSRF header", async () => {
    const fn = fakeFetch(() => ({ v: 2, id: "x", ok: true, result: { state: "READY" }, receipt: null }));
    const client = new RpcClient({ workspace: () => "ws1", csrf: () => "csrf-1", fetchFn: fn });
    const r = await client.call<{ state: string }>("daemon.status", {});
    expect(r.state).toBe("READY");
    const [url, init] = vi.mocked(fn).mock.calls.at(-1)! as unknown as [string, RequestInit];
    expect(url).toBe("/v2/rpc");
    expect((init.headers as Record<string, string>)[CSRF_HEADER]).toBe("csrf-1");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    const body = lastCallBody(fn as never);
    expect(body.v).toBe(2);
    expect(body.method).toBe("daemon.status");
    expect(body.workspace).toBe("ws1");
    expect(body.params).toEqual({});
    expect(String(body.id)).toMatch(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/);
  });

  test("success envelope resolves the result", async () => {
    const fn = fakeFetch(() => ({ v: 2, id: "q", ok: true, result: 42, receipt: null }));
    const client = new RpcClient({ workspace: () => "ws1", fetchFn: fn });
    await expect(client.call<number>("x.y")).resolves.toBe(42);
  });

  test("failure envelope throws RpcError with code/retryable/field", async () => {
    const fn = fakeFetch(() => ({
      v: 2, id: "q", ok: false,
      error: { code: "REVISION_CONFLICT", retryable: false, field: "expected_revision" },
      receipt: null,
    }));
    const client = new RpcClient({ workspace: () => "ws1", fetchFn: fn });
    const err = await client.call("config.apply", {}).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(RpcError);
    expect((err as RpcError).code).toBe("REVISION_CONFLICT");
    expect((err as RpcError).field).toBe("expected_revision");
    expect((err as RpcError).retryable).toBe(false);
  });

  test("maps retryable failure + transport failure", async () => {
    const fn = fakeFetch(() => ({
      v: 2, id: null, ok: false,
      error: { code: "BACKPRESSURE", retryable: true, field: null }, receipt: null,
    }));
    const client = new RpcClient({ workspace: () => "ws1", fetchFn: fn });
    const err = await client.call("events.publish", {}).then(() => null, (e: unknown) => e as RpcError);
    expect(err!.code).toBe("BACKPRESSURE");
    expect(err!.retryable).toBe(true);
    const net = new RpcClient({ workspace: () => "w", fetchFn: (() => Promise.reject(new Error("down"))) as never });
    await expect(net.call("daemon.status")).rejects.toMatchObject({ code: "NETWORK_UNAVAILABLE" });
  });

  test("exchange call omits the CSRF header (bootstrap-exempt)", async () => {
    const fn = fakeFetch(() => ({ v: 2, id: "q", ok: true, result: {}, receipt: null }));
    const client = new RpcClient({ workspace: () => "ws1", csrf: () => "csrf", fetchFn: fn });
    await client.call("ui.session.exchange", { bootstrap: "t" });
    const [, init] = vi.mocked(fn).mock.calls.at(-1)! as unknown as [string, RequestInit];
    expect((init.headers as Record<string, string>)[CSRF_HEADER]).toBeUndefined();
  });

  test("request ids are unique and grammar-shaped", () => {
    const ids = new Set(Array.from({ length: 64 }, () => newRequestId()));
    expect(ids.size).toBe(64);
    for (const id of ids) expect(id).toMatch(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/);
  });
});

describe("bootstrapFromLocation", () => {
  const loc = (hash: string): Pick<Location, "hash" | "pathname" | "search"> =>
    ({ hash, pathname: "/", search: "" });

  test("parses #bootstrap= plus optional &workspace=", () => {
    expect(parseBootstrapFragment("#bootstrap=abc")).toEqual({ bootstrap: "abc", workspace: undefined });
    expect(parseBootstrapFragment("#bootstrap=abc&workspace=ws9")).toEqual({ bootstrap: "abc", workspace: "ws9" });
    expect(parseBootstrapFragment("")).toBeNull();
    expect(parseBootstrapFragment("#other=1")).toBeNull();
  });

  test("exchanges fragment → session; replaceState clears the fragment", async () => {
    const fn = fakeFetch((url, init) => {
      const body = JSON.parse((init.body as string) ?? "{}") as { method: string; params: { bootstrap: string }; workspace: string };
      expect(body.method).toBe("ui.session.exchange");
      expect(body.params.bootstrap).toBe("tok-1");
      expect(body.workspace).toBe("ws9");
      return { v: 2, id: "q", ok: true, result: { session: "s1", role: "viewer", csrf: "c1", expires_ms: 1 }, receipt: null };
    });
    const replaceState = vi.fn();
    const res = await bootstrapFromLocation({
      location: loc("#bootstrap=tok-1&workspace=ws9"),
      history: { replaceState },
      fetchFn: fn,
    });
    expect(res?.session.session).toBe("s1");
    expect(res?.session.csrf).toBe("c1");
    expect(res?.session.role).toBe("viewer");
    expect(res?.session.workspace).toBe("ws9");
    // Fragment cleared via replaceState to pathname+search (no #bootstrap).
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
  });

  test("clears the fragment even when the exchange fails", async () => {
    const fn = fakeFetch(() => ({
      v: 2, id: null, ok: false,
      error: { code: "AUTH_REQUIRED", retryable: false, field: "bootstrap" }, receipt: null,
    }));
    const replaceState = vi.fn();
    await expect(bootstrapFromLocation({
      location: loc("#bootstrap=dead"),
      history: { replaceState },
      fetchFn: fn,
    })).rejects.toMatchObject({ code: "AUTH_REQUIRED" });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
  });

  test("no fragment → null, no fetch", async () => {
    const fn = vi.fn();
    const res = await bootstrapFromLocation({
      location: loc(""),
      history: { replaceState: vi.fn() },
      fetchFn: fn as never,
    });
    expect(res).toBeNull();
    expect(fn).not.toHaveBeenCalled();
  });

  test("defaults the workspace when the fragment lacks one", async () => {
    const fn = fakeFetch((_u, init) => {
      const body = JSON.parse(init.body as string) as { workspace: string };
      expect(body.workspace).toBe("default");
      return { v: 2, id: "q", ok: true, result: { session: "s", role: "operator", csrf: "c" }, receipt: null };
    });
    const res = await bootstrapFromLocation({
      location: loc("#bootstrap=t"),
      history: { replaceState: vi.fn() },
      fetchFn: fn,
    });
    expect(res?.session.workspace).toBe("default");
  });
});
