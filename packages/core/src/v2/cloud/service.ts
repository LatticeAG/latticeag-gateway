/**
 * Gateway v2 cloud — CloudService implementation (spec §3.2/§3.3, §9.3).
 *
 * Exchange shapes (§3.3):
 *  - cloud.pair.begin    {provider,streams,remote_ui} →
 *    {enrollment,state:"AWAITING_PROVIDER",user_code}
 *  - cloud.pair.complete {enrollment,binding,review} →
 *    {cloud,state:"PAIRED",remote_ui}
 *  - cloud.pair.revoke   {cloud} →
 *    {cloud,state:"REVOKED",remote_notice:"QUEUED"}
 *
 * Enforcement (§9.3/§10.2):
 *  - cloud pairing is a viewer-only native capability — it never grants
 *    operator authority, and hosted status never widens local roles;
 *  - remote_ui requires the separately scoped `gateway.ui.remote` config
 *    grant, re-checked at completion (a revoked grant closes remote
 *    sessions immediately);
 *  - no inbound listener changes are ever made here — remote requests
 *    arrive over an authenticated outbound relay;
 *  - enrollment is user-initiated through a pinned provider binding;
 *  - offline revoke queues the remote notice but revokes locally now.
 */

import type { NativeRef } from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type { CloudService } from "../protocol/services.js";
import { isStreamName } from "../protocol/sync.js";
import type { StreamName } from "../protocol/sync.js";
import { isId } from "../crypto/ids.js";
import type { CloudPorts, CloudEnrollment, CloudPairing } from "./ports.js";

function isNativeRefShape(value: unknown): value is NativeRef {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const obj = value as Record<string, unknown>;
  return (
    typeof obj.profile === "string" &&
    typeof obj.namespace === "string" &&
    typeof obj.object_id === "string" &&
    (typeof obj.commitment === "string" || obj.commitment === null) &&
    typeof obj.raw_sha256 === "string" &&
    typeof obj.bytes === "string"
  );
}

function requireStreams(value: unknown): StreamName[] {
  if (!Array.isArray(value)) {
    throw new RpcError("SCHEMA_INVALID", "streams must be an array", {
      retryable: false,
      field: "streams",
    });
  }
  const out: StreamName[] = [];
  for (const name of value) {
    if (typeof name !== "string" || !isStreamName(name)) {
      throw new RpcError("SCHEMA_INVALID", `unknown stream ${String(name)}`, {
        retryable: false,
        field: "streams",
      });
    }
    if (out.includes(name)) {
      throw new RpcError("SCHEMA_INVALID", `duplicate stream ${name}`, {
        retryable: false,
        field: "streams",
      });
    }
    out.push(name);
  }
  return out;
}

export function createCloudService(ports: CloudPorts): CloudService {
  return {
    async pairBegin(params: {
      provider: string;
      streams: StreamName[];
      remote_ui: boolean;
    }) {
      if (typeof params.provider !== "string" || params.provider.length === 0) {
        throw new RpcError("SCHEMA_INVALID", "provider is required", {
          retryable: false,
          field: "provider",
        });
      }
      const streams = requireStreams(params.streams);
      if (typeof params.remote_ui !== "boolean") {
        throw new RpcError("SCHEMA_INVALID", "remote_ui must be a boolean", {
          retryable: false,
          field: "remote_ui",
        });
      }
      // Enrollment requires a pinned provider binding (§3.2); an unknown
      // provider is never enrolled from a claimed URL.
      if (!ports.providers().has(params.provider)) {
        throw new RpcError(
          "NOT_FOUND",
          `no pinned provider binding for ${params.provider}`,
          { retryable: false, field: "provider" },
        );
      }
      // remote_ui is separately scoped by the local ui.remote grant.
      if (params.remote_ui && !ports.uiRemoteGranted()) {
        throw new RpcError(
          "FORBIDDEN",
          "remote_ui requires the gateway.ui.remote config grant",
          { retryable: false, field: "remote_ui" },
        );
      }
      const now = ports.now();
      const enrollment: CloudEnrollment = {
        id: ports.newId(),
        provider: params.provider,
        streams,
        remote_ui: params.remote_ui,
        user_code: ports.pairCode(),
        state: "AWAITING_PROVIDER",
        created_ms: now,
        expires_ms: now + ports.enrollmentTtlMs(),
      };
      ports.putEnrollment(enrollment);
      return {
        enrollment: enrollment.id,
        state: "AWAITING_PROVIDER",
        user_code: enrollment.user_code,
      };
    },

    async pairComplete(params: {
      enrollment: string;
      binding: NativeRef;
      review: NativeRef;
    }) {
      if (typeof params.enrollment !== "string" || !isId(params.enrollment)) {
        throw new RpcError("SCHEMA_INVALID", "enrollment must be an Id", {
          retryable: false,
          field: "enrollment",
        });
      }
      const enrollment = ports.getEnrollment(params.enrollment);
      if (enrollment === undefined) {
        throw new RpcError(
          "NOT_FOUND",
          `no enrollment ${params.enrollment}`,
          { retryable: false, field: "enrollment" },
        );
      }
      if (enrollment.state !== "AWAITING_PROVIDER") {
        throw new RpcError(
          "REVISION_CONFLICT",
          `enrollment ${enrollment.id} is ${enrollment.state}`,
          { retryable: false, field: "enrollment" },
        );
      }
      if (ports.now() >= enrollment.expires_ms) {
        enrollment.state = "EXPIRED";
        ports.putEnrollment(enrollment);
        throw new RpcError("PAIRING_EXPIRED", "enrollment has expired", {
          retryable: false,
          field: "enrollment",
        });
      }
      if (!isNativeRefShape(params.binding)) {
        throw new RpcError(
          "SCHEMA_INVALID",
          "binding must be a NativeRef",
          { retryable: false, field: "binding" },
        );
      }
      const { review: _r, ...sansReview } = params;
      const valid =
        ports.validateReview !== undefined
          ? ports.validateReview("cloud.pair.complete", sansReview, params.review)
          : isNativeRefShape(params.review);
      if (!valid) {
        throw new RpcError(
          "POLICY_DENIED",
          "cloud.pair.complete review binding invalid",
          { retryable: false, field: "review" },
        );
      }
      // Re-check the separately scoped remote grant at completion: a
      // grant revoked since pair.begin must not carry through (§9.3).
      if (enrollment.remote_ui && !ports.uiRemoteGranted()) {
        throw new RpcError(
          "FORBIDDEN",
          "gateway.ui.remote grant is not configured",
          { retryable: false, field: "remote_ui" },
        );
      }
      enrollment.state = "CONSUMED";
      ports.putEnrollment(enrollment);
      const cloud: CloudPairing = {
        id: ports.newId(),
        provider: enrollment.provider,
        binding: params.binding,
        streams: enrollment.streams,
        remote_ui: enrollment.remote_ui,
        // Viewer-only by default: cloud pairing can never grant operator
        // authority, and the remote flag stays separately scoped (§9.3).
        role: "viewer",
        state: "PAIRED",
        paired_ms: ports.now(),
        remote_notice: null,
      };
      ports.putCloud(cloud);
      return { cloud: cloud.id, state: "PAIRED", remote_ui: cloud.remote_ui };
    },

    async pairRevoke(params: { cloud: string }) {
      if (typeof params.cloud !== "string" || !isId(params.cloud)) {
        throw new RpcError("SCHEMA_INVALID", "cloud must be an Id", {
          retryable: false,
          field: "cloud",
        });
      }
      const cloud = ports.getCloud(params.cloud);
      if (cloud === undefined) {
        throw new RpcError("NOT_FOUND", `no cloud pairing ${params.cloud}`, {
          retryable: false,
          field: "cloud",
        });
      }
      if (cloud.state === "REVOKED") {
        return {
          cloud: cloud.id,
          state: "REVOKED",
          remote_notice: cloud.remote_notice ?? "QUEUED",
        };
      }
      // Durable local revocation first — relay disconnect/revocation
      // closes remote sessions immediately; an offline provider queues
      // the remote notice (§9.3).
      cloud.state = "REVOKED";
      const delivered = await ports.notifyRevocation(cloud);
      cloud.remote_notice = delivered ? "SENT" : "QUEUED";
      ports.putCloud(cloud);
      return {
        cloud: cloud.id,
        state: "REVOKED",
        remote_notice: cloud.remote_notice,
      };
    },
  };
}
