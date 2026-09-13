/**
 * RunService — run.register / run.heartbeat / run.finish (spec §3.2, §5).
 *
 * The protocol-level lease (deadline math, renewals, reclaim sweep) lives
 * at the transport layer; these methods keep the run row and its owner
 * binding, enforce the owner-only fencing rule (P02: only the live owner
 * may mutate a run), and the monotonic spool sequence. Registering a
 * `run_id` owned by a different *live* run is a conflict; a FINISHED row
 * frees the id for replay. Heartbeats are accepted at the 10 s cadence or
 * earlier and only record the sample — expiry is the lease layer's job.
 */
import type { Count, Id, Json } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type {
  RunRegisterParams,
  RunService,
} from "../protocol/services.js";
import { sha256Hex } from "../crypto/hash.js";
import { canonicalJson } from "../crypto/canonical.js";
import type {
  PlatformPorts,
  PlatformRunEntry,
} from "./ports.js";

/** Heartbeat cadence bound (spec §5): every 10 s or earlier. */
export const HEARTBEAT_MAX_MS = 10_000;

/** Legacy run ids are ULIDs: 26 Crockford-base32 chars (no I/L/O/U). */
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const ID_RE_LOCAL = /^[a-z][a-z0-9_-]{0,63}$/;

function asCount(v: unknown, field: string): Count {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) {
    throw new RpcError("SCHEMA_INVALID", `${field} must be a decimal Count`, {
      field,
    });
  }
  return v;
}

function asOwner(v: unknown, field: string): Id {
  if (typeof v !== "string" || !ID_RE_LOCAL.test(v)) {
    throw new RpcError("SCHEMA_INVALID", `${field} must be an Id`, { field });
  }
  return v;
}

async function commitMutation(
  ports: PlatformPorts,
  mutation: object,
  result: unknown,
): Promise<void> {
  await ports.store.commit({
    mutation: mutation as Json,
    result_sha256: sha256Hex(canonicalJson(result)),
  });
}

export function createRunService(ports: PlatformPorts): RunService {
  const lastHeartbeat = new Map<string, number>();

  async function ownedRun(
    runId: string,
    owner: Id,
  ): Promise<PlatformRunEntry> {
    const run = await ports.store.registry.runGet(runId);
    if (run === null) {
      throw new RpcError("NOT_FOUND", `run ${runId} unknown`, {
        field: "run_id",
      });
    }
    if (run.owner !== owner) {
      // Only the live owner may mutate a run (P02 fencing).
      throw new RpcError("POLICY_DENIED", `run ${runId} owned by ${run.owner}`);
    }
    return run;
  }

  return {
    /**
     * Register a writer's spool owner: exact ULID run id, kit name,
     * owner id, resume flag. A different live owner is rejected; replay
     * under a FINISHED row is allowed.
     */
    async register(params: RunRegisterParams) {
      if (!ULID_RE.test(params.run_id)) {
        throw new RpcError("SCHEMA_INVALID", "run_id must be a ULID", {
          field: "run_id",
        });
      }
      const owner = asOwner(params.owner, "owner");
      if (
        typeof params.kit !== "string" ||
        !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(params.kit)
      ) {
        throw new RpcError("SCHEMA_INVALID", "kit must be a package id", {
          field: "kit",
        });
      }
      if (typeof params.resume !== "boolean") {
        throw new RpcError("SCHEMA_INVALID", "resume must be a boolean", {
          field: "resume",
        });
      }
      const existing = await ports.store.registry.runGet(params.run_id);
      if (
        existing !== null &&
        existing.owner !== owner &&
        existing.state === "RUNNING"
      ) {
        throw new RpcError(
          "POLICY_DENIED",
          `run ${params.run_id} is owned by ${existing.owner}`,
          { field: "run_id" },
        );
      }
      const result = {
        run_id: params.run_id,
        owner,
        mode: "gateway",
      };
      await commitMutation(
        ports,
        {
          v: 1,
          kind: "runs",
          runs: [
            {
              run_id: params.run_id,
              owner,
              kit: params.kit,
              state: "RUNNING",
              spool_seq: "0",
              exit_code: null,
              signal: null,
              pending_sync: 0,
            },
          ],
        },
        result,
      );
      return result;
    },

    /**
     * Owner-only liveness sample: spool_seq must not regress; the sample
     * is recorded. Heartbeats arrive every 10 s or earlier — a late sample
     * is still recorded (lease expiry is enforced elsewhere).
     */
    async heartbeat(params: {
      run_id: string;
      owner: Id;
      spool_seq: Count;
    }) {
      const seq = asCount(params.spool_seq, "spool_seq");
      const run = await ownedRun(params.run_id, params.owner);
      if (run.state !== "RUNNING") {
        throw new RpcError(
          "STATE_TRANSITION",
          `run ${params.run_id} is FINISHED`,
        );
      }
      if (BigInt(seq) < BigInt(run.spool_seq)) {
        throw new RpcError(
          "REVISION_CONFLICT",
          `spool_seq regressed from ${run.spool_seq} to ${seq}`,
          { field: "spool_seq" },
        );
      }
      lastHeartbeat.set(params.run_id, ports.clock());
      await commitMutation(
        ports,
        {
          v: 1,
          kind: "runs",
          runs: [{ ...run, spool_seq: seq }],
        },
        { accepted: true },
      );
      return { accepted: true as const };
    },

    /** Owner-only completion; reports the run's pending sync intents. */
    async finish(params: {
      run_id: string;
      owner: Id;
      exit_code: number | null;
      signal: string | null;
      spool_seq: Count;
    }) {
      const seq = asCount(params.spool_seq, "spool_seq");
      const run = await ownedRun(params.run_id, params.owner);
      if (BigInt(seq) < BigInt(run.spool_seq)) {
        throw new RpcError(
          "REVISION_CONFLICT",
          `spool_seq regressed from ${run.spool_seq} to ${seq}`,
          { field: "spool_seq" },
        );
      }
      const result = {
        state: "FINISHED",
        pending_sync: run.pending_sync,
      };
      await commitMutation(
        ports,
        {
          v: 1,
          kind: "runs",
          runs: [
            {
              ...run,
              state: "FINISHED",
              exit_code: params.exit_code,
              signal: params.signal,
              spool_seq: seq,
            },
          ],
        },
        result,
      );
      return result;
    },
  };
}
