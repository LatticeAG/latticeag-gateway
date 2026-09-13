/**
 * UiService — ui.session.create / exchange / revoke (spec §3.2, §7.2).
 *
 * Bootstrap is a random one-use 32-byte fragment value with a 60 s life;
 * exchange consumes it atomically exactly once (replay or expiry at
 * equality → AUTH_REQUIRED, P10) and returns the session token plus a
 * memory-only CSRF secret. Bearer material is never stored in plaintext —
 * the session store keys everything by token hash. Cookie/Origin/Host/CSRF
 * header enforcement is the HTTP bridge's job; this layer owns mint,
 * consume, expiry, revocation, and closing the session owner's stream
 * leases.
 *
 * Lifetimes (§7.2): viewer 8 h absolute / 30 min idle; operator 10 min /
 * 5 min idle.
 */
import type { Id } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type { UiService } from "../protocol/services.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import type { Json } from "../protocol/refs.js";
import type {
  PlatformPorts,
  PlatformSessionRecord,
  ServiceContext,
} from "./ports.js";
import { LOCAL_OPERATOR_CONTEXT } from "./ports.js";

/**
 * P10 expiry at equality: a session is live iff `now < expires_ms` (the
 * absolute bound) and `now < idle_expires_ms`. Called by the HTTP bridge
 * on every authenticated browser request.
 */
export function sessionIsLive(
  record: PlatformSessionRecord,
  now: number,
): boolean {
  return (
    record.state === "ACTIVE" &&
    now < record.expires_ms &&
    now < record.idle_expires_ms
  );
}

/** Bootstrap fragment lifetime (§3.2): one-use, 60 s. */
export const BOOTSTRAP_TTL_MS = 60_000;
/** Viewer session: 8 h absolute, 30 min idle (§7.2). */
export const VIEWER_SESSION_MS = 28_800_000;
export const VIEWER_IDLE_MS = 1_800_000;
/** Operator elevation: 10 min absolute, 5 min idle (§7.2). */
export const OPERATOR_SESSION_MS = 600_000;
export const OPERATOR_IDLE_MS = 300_000;

export function createUiService(
  ports: PlatformPorts,
  ctx: ServiceContext = LOCAL_OPERATOR_CONTEXT,
): UiService {
  return {
    /**
     * Mint a one-use bootstrap. Caller is the local socket operator (L);
     * role is viewer unless explicitly "operator".
     */
    async sessionCreate(params: { role: "viewer" | "operator" }) {
      const role = params?.role ?? "viewer";
      if (role !== "viewer" && role !== "operator") {
        throw new RpcError(
          "SCHEMA_INVALID",
          "role must be viewer or operator",
          { field: "role" },
        );
      }
      if (ports.uiEndpoint === null) {
        throw new RpcError("STATE_TRANSITION", "the UI endpoint is not bound", {
          field: null,
        });
      }
      const bootstrap = ports.newToken();
      const expires_ms = ports.clock() + BOOTSTRAP_TTL_MS;
      await ports.sessionStore.bootstrapPut({
        hash: sha256Hex(bootstrap),
        role,
        expires_ms,
      });
      return {
        bootstrap,
        expires_ms,
        url: `${ports.uiEndpoint}/#bootstrap=${bootstrap}`,
      };
    },

    /**
     * Same-origin exchange: consume the bootstrap exactly once. Expired or
     * already-consumed/replayed/unknown bootstraps are all AUTH_REQUIRED.
     */
    async sessionExchange(params: { bootstrap: string }) {
      if (
        typeof params?.bootstrap !== "string" ||
        params.bootstrap.length === 0
      ) {
        throw new RpcError("SCHEMA_INVALID", "bootstrap must be a token", {
          field: "bootstrap",
        });
      }
      const record = await ports.sessionStore.bootstrapTake(
        sha256Hex(params.bootstrap),
      );
      if (record === null || ports.clock() >= record.expires_ms) {
        throw new RpcError(
          "AUTH_REQUIRED",
          "bootstrap is unknown, consumed, or expired",
          { field: "bootstrap" },
        );
      }
      const session = ports.newToken();
      const csrf = ports.newToken();
      const absolute =
        record.role === "operator" ? OPERATOR_SESSION_MS : VIEWER_SESSION_MS;
      const idle =
        record.role === "operator" ? OPERATOR_IDLE_MS : VIEWER_IDLE_MS;
      const now = ports.clock();
      const expires_ms = now + absolute;
      await ports.sessionStore.sessionPut({
        hash: sha256Hex(session),
        role: record.role,
        csrf_sha256: sha256Hex(csrf),
        owner: ctx.principal.id,
        expires_ms,
        idle_expires_ms: now + idle,
        created_ms: now,
        state: "ACTIVE",
      });
      return { session, role: record.role, csrf, expires_ms };
    },

    /**
     * Revoke a session: the session's owner or the local operator may
     * revoke; associated open subscriptions close with it.
     */
    async sessionRevoke(params: { session: Id }) {
      if (typeof params?.session !== "string" || params.session === "") {
        throw new RpcError("SCHEMA_INVALID", "session is required", {
          field: "session",
        });
      }
      const hash = sha256Hex(params.session);
      const record = await ports.sessionStore.sessionGet(hash);
      if (record === null) {
        throw new RpcError("NOT_FOUND", "session is unknown", {
          field: "session",
        });
      }
      const isOperator =
        ctx.principal.role === "operator" ||
        ctx.principal.role === "local_operator";
      if (record.owner !== ctx.principal.id && !isOperator) {
        throw new RpcError("FORBIDDEN", "cannot revoke another's session", {
          field: "session",
        });
      }
      await ports.sessionStore.sessionRevoke(hash);
      // Close the owner's open stream leases — streaming connections die
      // with the session (§3.2 ui.session.revoke).
      const subs = await ports.store.registry.subscriptionsByOwner(
        record.owner,
      );
      const open = subs.filter((s) => s.state === "OPEN");
      if (open.length > 0) {
        await ports.store.commit({
          mutation: {
            v: 1,
            kind: "subscriptions",
            subscriptions: open.map((s) => ({ ...s, state: "CLOSED" })),
          } as unknown as Json,
          result_sha256: sha256Hex(
            canonicalJson({ session: params.session, state: "REVOKED" }),
          ),
        });
      }
      return { session: params.session, state: "REVOKED" };
    },
  };
}
