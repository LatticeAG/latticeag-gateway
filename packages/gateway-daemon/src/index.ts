/**
 * @latticeag/gateway-daemon — Gateway v2 daemon package.
 *
 * `src/store/**` is the durable storage layer; `src/lock.ts`, `src/net/**`,
 * `src/rpc/**`, `src/runtime.ts`, and `src/daemon.ts` implement the Gateway
 * v2 protocol server on top of it (§1.2 lock, §3.1 dispatch pipeline,
 * §4.3 peer proofs, §6 bridge/SSE, §1.3 lifecycle).
 */
export * from "./store/errors.js";
export * from "./store/util.js";
export * from "./store/layout.js";
export * from "./store/objects.js";
export * from "./store/journal.js";
export * from "./store/lanes.js";
export * from "./store/registry.js";
export * from "./store/outbox.js";
export * from "./store/recovery.js";
export * from "./store/store.js";

// ── daemon protocol server ───────────────────────────────────────────────
export * from "./lock.js";
export * from "./net/strict-json.js";
export * from "./net/http-util.js";
export * from "./net/socket-server.js";
export * from "./net/sse.js";
export * from "./net/bridge.js";
export * from "./rpc/auth.js";
export * from "./rpc/dispatch.js";
export * from "./runtime.js";
export * from "./daemon.js";
