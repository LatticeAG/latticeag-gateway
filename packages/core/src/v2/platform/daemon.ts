/**
 * DaemonService — daemon.hello / daemon.status / daemon.stop (spec §3.2).
 *
 * Role gates live in the dispatcher (V/A/O for hello, V/O for status,
 * L for stop); this layer owns the deterministic result shapes of §3.3.
 */
import { RpcError } from "../protocol/errors.js";
import type {
  DaemonHelloParams,
  DaemonHelloResult,
  DaemonService,
  DaemonStatusResult,
} from "../protocol/services.js";
import { GRACE } from "../protocol/lifecycle.js";
import type { PlatformPorts, ServiceContext } from "./ports.js";

/** kv key holding the daemon lifecycle state (READY/DRAINING/STOPPED/...). */
export const KV_DAEMON_STATE = "daemon:state";
/** kv key holding the CAS config revision (shared with ConfigService). */
export const KV_CONFIG_REVISION = "config:revision";

export const CONTROL_PROTOCOL = "gateway-control/2";
export const INTERFACES_PROFILE = "interfaces/1";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function createDaemonService(
  ports: PlatformPorts,
  _ctx: ServiceContext | undefined = undefined,
): DaemonService {
  void _ctx;
  return {
    /**
     * Advertise `gateway-control/2` and choose the intersection of
     * explicitly advertised profiles (§2.2). No common required profile or
     * an interfaces-version mismatch → SCHEMA_UNSUPPORTED before any
     * registration or publish can occur.
     */
    hello(params: DaemonHelloParams): Promise<DaemonHelloResult> {
      if (!isPlainObject(params)) {
        throw new RpcError("SCHEMA_INVALID", "params must be an object");
      }
      const requested = Array.isArray(params.profiles)
        ? params.profiles.filter((p): p is string => typeof p === "string")
        : [];
      if (params.interfaces !== INTERFACES_PROFILE) {
        throw new RpcError(
          "SCHEMA_UNSUPPORTED",
          `interfaces must be ${INTERFACES_PROFILE}`,
          { field: "interfaces" },
        );
      }
      const profiles = ports.profiles.filter((p) => requested.includes(p));
      if (profiles.length === 0) {
        throw new RpcError(
          "SCHEMA_UNSUPPORTED",
          "no common evidence profile",
          { field: "profiles" },
        );
      }
      return Promise.resolve({
        protocol: CONTROL_PROTOCOL,
        profiles,
        interfaces: INTERFACES_PROFILE,
        mesh: { ...ports.mesh },
      });
    },

    /** Instance/state/counts/current endpoint; no tokens or peer detail. */
    async status(
      _params: Record<string, never>,
    ): Promise<DaemonStatusResult> {
      const state =
        (await ports.store.registry.kvGet(KV_DAEMON_STATE)) ?? "READY";
      let configRevision = await ports.store.registry.kvGet(
        KV_CONFIG_REVISION,
      );
      if (configRevision === null) {
        // Config document seeded from disk implies revision "1".
        configRevision = (await ports.store.registry.kvGet(
          "config:document",
        )) !== null
          ? "1"
          : "0";
      }
      return {
        instance: ports.instance,
        state,
        config_revision: configRevision,
        products: await ports.store.registry.countProducts(),
        peers: await ports.store.registry.countPeers(),
        ui: ports.uiEndpoint,
      };
    },

    /**
     * Graceful stop: READY/DEGRADED → DRAINING durably first; the actual
     * termination callback is scheduled only after the response is
     * committed, so the {state:"DRAINING"} answer always precedes shutdown.
     */
    async stop(params: { grace_ms: number }): Promise<{ state: string }> {
      const grace = params?.grace_ms;
      if (
        typeof grace !== "number" ||
        !Number.isSafeInteger(grace) ||
        grace < GRACE.daemonStopMinMs ||
        grace > GRACE.daemonStopMaxMs
      ) {
        throw new RpcError(
          "SCHEMA_INVALID",
          `grace_ms must be an integer ${GRACE.daemonStopMinMs}–${GRACE.daemonStopMaxMs}`,
          { field: "grace_ms" },
        );
      }
      await ports.store.registry.kvSet(KV_DAEMON_STATE, "DRAINING");
      if (ports.onStop !== undefined) {
        const onStop = ports.onStop;
        const timer = setTimeout(() => {
          onStop(grace);
        }, 0);
        // Never let the scheduled shutdown keep a test process alive.
        (timer as unknown as { unref?: () => void }).unref?.();
      }
      return { state: "DRAINING" };
    },
  };
}
