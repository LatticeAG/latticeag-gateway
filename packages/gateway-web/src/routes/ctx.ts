/**
 * Route wiring context: each route module mounts into the shell's main
 * (and optionally the inspector) and returns a disposer.
 */
import type { RpcClient } from "../lib/rpc.js";
import type { Store, AppState } from "../lib/state.js";
import type { Route } from "../lib/router.js";
import type { AppShell } from "../components/app-shell.js";
import type { ToastRegion } from "../components/toast-region.js";
import type { RpcError } from "../lib/rpc.js";

export interface RouteCtx {
  client: RpcClient;
  store: Store<AppState>;
  shell: AppShell;
  toasts: ToastRegion;
  navigate: (path: string, opts?: { replace?: boolean }) => void;
}

export interface RouteHandle {
  dispose(): void;
}

export type RouteModule = (ctx: RouteCtx, route: Route) => RouteHandle | void;

/** Compose route cleanup from timers/streams/subscriptions. */
export class Disposer implements RouteHandle {
  private fns: (() => void)[] = [];
  private disposed = false;
  add(fn: () => void): void {
    if (this.disposed) fn();
    else this.fns.push(fn);
  }
  every(ms: number, fn: () => void): void {
    const t = setInterval(fn, ms);
    this.add(() => clearInterval(t));
  }
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    for (const f of this.fns.splice(0)) f();
  }
}

export function describeError(e: unknown): string {
  const err = e as Partial<RpcError>;
  if (typeof err?.code === "string") return `${err.code}${err.field ? ` (${err.field})` : ""}`;
  return "request failed";
}

/** True when the failure means the session itself is gone. */
export function isAuthFailure(e: unknown): boolean {
  const code = (e as { code?: string })?.code;
  return code === "AUTH_REQUIRED" || code === "TOKEN_EXPIRED" || code === "TOKEN_REVOKED";
}
