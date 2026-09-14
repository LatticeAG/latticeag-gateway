/**
 * Tiny observable store + the URL-state-driven app view model (spec §7:
 * "use URL state and a small typed RPC client" — no framework store).
 */
import type { Route } from "./router.js";
import type { Session } from "./rpc.js";
import type { StreamPhase } from "./sse.js";

export class Store<T extends object> {
  private state: T;
  private readonly subs = new Set<(s: Readonly<T>) => void>();

  constructor(initial: T) {
    this.state = initial;
  }

  get(): Readonly<T> {
    return this.state;
  }

  set(patch: Partial<T>): void {
    this.state = { ...this.state, ...patch };
    for (const fn of this.subs) fn(this.state);
  }

  update(fn: (s: Readonly<T>) => Partial<T>): void {
    this.set(fn(this.state));
  }

  subscribe(fn: (s: Readonly<T>) => void): () => void {
    this.subs.add(fn);
    return () => this.subs.delete(fn);
  }
}

export type ConnectionPhase = "connecting" | "online" | "degraded" | "offline";

export interface AppState {
  /** Memory-only session; null until bootstrap exchange succeeds. */
  session: Session | null;
  route: Route;
  /** Daemon reachability + state (from daemon.status polls). */
  connection: {
    phase: ConnectionPhase;
    daemonState: string | null;
    detail: string;
    lastOkMs: number;
    consecutiveFailures: number;
  };
  /** Live SSE health for the events view. */
  stream: {
    phase: StreamPhase;
    paused: boolean;
    buffered: number;
    dropped: number;
    lastActivityMs: number;
  };
  /** When false every mutation control must render disabled. */
  mutationsEnabled: boolean;
  /** Pending approval count surfaced in nav (0 hides the badge). */
  pendingApprovals: number;
}

export function initialAppState(route: Route): AppState {
  return {
    session: null,
    route,
    connection: {
      phase: "connecting",
      daemonState: null,
      detail: "",
      lastOkMs: 0,
      consecutiveFailures: 0,
    },
    stream: { phase: "idle", paused: false, buffered: 0, dropped: 0, lastActivityMs: 0 },
    mutationsEnabled: false,
    pendingApprovals: 0,
  };
}
