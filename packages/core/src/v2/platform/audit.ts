/**
 * Audit receipt writer (spec §2.1 lines 152–154, §3.1; fixture harness
 * `exchange` construction).
 *
 * Every semantic Gateway action — including rejected authorized mutations
 * and sensitive disclosures — emits a native Proof history
 * RunOpened → StepOpened → ObservationRecorded → StepClosed → RunClosed
 * on the audit partition (workspace `audit1`, source `gateway1`). Each
 * action gets its own stream named for the request id, so every history
 * is a fresh genesis chain of five events.
 *
 * The ObservationRecorded event joins a committed object carrying the
 * closed `gateway.action/1` payload:
 * `{v:1, method, principal, request, operation, redacted_params_sha256,
 *   result_sha256, outcome, code, previous_action}`.
 * `redacted_params_sha256` commits to the *scrubbed* params alone; the
 * RunOpened intent object is the `{method, params}` document. The
 * returned ReceiptPointer addresses the StepClosed event — the same
 * shape as `ref(F.events[3])` in the fixture. The dispatcher calls this
 * for every audited method after the result is known.
 */
import { Buffer } from "node:buffer";
import type { KeyObject } from "node:crypto";
import type {
  Id,
  Json,
  NativeRef,
  ObjectRef,
} from "../protocol/refs.js";
import type { ReceiptPointer } from "../protocol/envelope.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import {
  eventRefOf,
  proofBody,
  sealProofEvent,
  type ProofEvent,
} from "../crypto/proof.js";
import { publicKeyOf, keyIdOfPublic } from "../crypto/ed25519.js";
import type { PlatformPorts, ServiceContext } from "./ports.js";

/** Audit partition cap (spec §2.2): at most 10000 events per partition. */
export const AUDIT_PARTITION_MAX_EVENTS = 10_000;
/** One action reserves exactly five events. */
export const AUDIT_HISTORY_EVENTS = 5;

export interface AuditReceiptInput {
  /** RPC method name, e.g. "config.apply". */
  method: string;
  /** Envelope request id, or null when unavailable. */
  request: Id | null;
  /** Durable operation id the action drove, or null. */
  operation: Id | null;
  /** Request params *already scrubbed* of credential material. */
  params: Json;
  /** The method's result value, already scrubbed (never tokens). */
  result: Json;
  /** "SUCCEEDED" | "FAILED" | "UNKNOWN" | "CANCELLED". */
  outcome: string;
  /** Registry error code, or "OK" on success. */
  code: string;
  /** NativeRef of the previous linked action, or null. */
  previous_action?: NativeRef | null;
}

function objectRefOf(bytes: Uint8Array): ObjectRef {
  return { digest: sha256Hex(bytes), bytes: String(bytes.length), media: "application/json" };
}

function sealAuditEvent(
  bodyParts: Parameters<typeof proofBody>[0],
  auditKey: KeyObject,
): ProofEvent {
  return sealProofEvent(proofBody(bodyParts), auditKey);
}

/**
 * Commit the five-event audit history and return the StepClosed pointer.
 * The stream is named for the request id (`q1`-style) and each history is
 * a fresh five-event chain; `previous_action` carries cross-action
 * linkage inside the observation object, never as a cross-lane parent.
 */
export async function emitAuditReceipt(
  ports: PlatformPorts,
  ctx: ServiceContext,
  input: AuditReceiptInput,
): Promise<ReceiptPointer> {
  const workspace = ports.receiptWorkspace; // "audit1"
  const source = ports.auditSource; // "gateway1"
  const stream = input.request ?? ports.newId();
  const runId = `op_${stream}`;
  const keyId = keyIdOfPublic(publicKeyOf(ports.auditKey));
  const genesis = "0".repeat(64);

  const redactedParamsSha = sha256Hex(canonicalJson(input.params));
  const resultSha = sha256Hex(canonicalJson(input.result));
  const payload = {
    v: 1,
    method: input.method,
    principal: ctx.principal.id,
    request: input.request,
    operation: input.operation,
    redacted_params_sha256: redactedParamsSha,
    result_sha256: resultSha,
    outcome: input.outcome,
    code: input.code,
    previous_action: input.previous_action ?? null,
  };
  const intentBytes = Buffer.from(
    canonicalJson({ method: input.method, params: input.params }),
    "utf8",
  );
  const payloadBytes = Buffer.from(canonicalJson(payload), "utf8");
  const intentRef = objectRefOf(intentBytes);
  const observationRef = objectRefOf(payloadBytes);

  // The chain is sealed strictly in order: every body's prev is the prior
  // event's hash (genesis zeros for the first), lamport equals seq.
  const events: ProofEvent[] = [];
  const seal = (
    seq: number,
    data: unknown,
    parents: ProofEvent[] = [],
  ): ProofEvent => {
    const event = sealAuditEvent(
      {
        workspace,
        source,
        stream,
        seq: String(seq),
        prev: seq === 1 ? genesis : events[seq - 2]!.hash,
        lamport: String(seq),
        key: keyId,
        parents: parents.map(eventRefOf),
        data,
      },
      ports.auditKey,
    );
    events.push(event);
    return event;
  };

  seal(1, {
    kind: "RunOpened",
    run: runId,
    intent: intentRef,
    policy: null,
    hypothetical: false,
  });
  seal(2, {
    kind: "StepOpened",
    run: runId,
    step: "step1",
    operation: "compute",
    input: null,
  });
  seal(3, {
    kind: "ObservationRecorded",
    run: runId,
    step: "step1",
    value: observationRef,
  });
  seal(
    4,
    {
      kind: "StepClosed",
      run: runId,
      step: "step1",
      outcome: input.outcome,
      observation: eventRefOf(events[2]!),
    },
    [events[2]!],
  );
  seal(5, { kind: "RunClosed", run: runId, outcome: input.outcome });

  const records = events.map((e) => ({
    lane: "proof",
    partition: workspace,
    data: Buffer.from(canonicalJson(e), "utf8") as Uint8Array,
  }));
  const anchor = events[3]!; // StepClosed anchors the receipt pointer.
  const anchorBytes = Buffer.from(canonicalJson(anchor), "utf8");
  const pointer: ReceiptPointer = {
    workspace,
    event: eventRefOf(anchor),
  };
  const nativeRef: NativeRef = {
    profile: "gateway.action/1",
    namespace: workspace,
    object_id: runId,
    commitment: anchor.hash,
    raw_sha256: sha256Hex(anchorBytes),
    bytes: String(anchorBytes.length),
  };

  await ports.store.commit({
    records,
    objects: [intentBytes, payloadBytes],
    mutation: {
      v: 1,
      kind: "batch",
      mutations: [
        {
          v: 1,
          kind: "events",
          events: events.map((e, i) => ({
            workspace,
            source,
            stream,
            seq: e.body.seq,
            hash: e.hash,
            raw_sha256: sha256Hex(records[i]!.data),
            topic: "gateway.action",
            profile: "proof-evidence/1",
            media: "application/json",
            record_bytes: String(records[i]!.data.length),
            record: i,
          })),
        },
        {
          v: 1,
          kind: "actions",
          actions: [
            {
              pointer,
              nativeRef,
              previous: input.previous_action ?? null,
              principal: ctx.principal.id,
              method: input.method,
            },
          ],
        },
      ],
    } as unknown as Json,
    result_sha256: resultSha,
  });
  return pointer;
}
