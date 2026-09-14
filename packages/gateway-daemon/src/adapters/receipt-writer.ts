/**
 * `receipt-writer.ts` — the dispatcher's durable receipt sink backed by
 * the core five-event audit history (spec §2.1 lines 152–154, §3.1).
 *
 * This is `emitAuditReceipt` from `@latticeag/core` ported onto the
 * daemon's `ReceiptWriter` seam with one addition: the idempotency
 * binding row (`operations` mutation) is folded into the SAME batch the
 * history commits, so a semantic replay sees its saved result exactly
 * when — and only when — the receipt is durable. The pointer returned to
 * the caller addresses the StepClosed event of the committed chain.
 *
 * Concurrency: every history is a fresh genesis chain (seq 1..5, prev
 * zeros), so commits need no cross-history serialization — the store's
 * single-writer mutex orders the markers.
 */
import { Buffer } from "node:buffer";
import type {
  PlatformPorts,
  ServiceContext,
} from "../../../core/dist/v2/platform/ports.js";
import type { NativeRef } from "../../../core/dist/v2/protocol/refs.js";
import type { ReceiptPointer } from "../../../core/dist/v2/protocol/envelope.js";
import {
  canonicalJson,
  eventRefOf,
  keyIdOfPublic,
  proofBody,
  publicKeyOf,
  sealProofEvent,
  sha256Hex,
  type ProofEvent,
} from "../core-v2.js";
import type {
  AuditAction,
  ReceiptWriter,
} from "../rpc/dispatch.js";
import type { Json as StoreJson } from "../store/util.js";
import type { GatewayStore } from "../store/store.js";

const GENESIS = "0".repeat(64);

function objectRefOf(bytes: Uint8Array): {
  digest: string;
  bytes: string;
  media: string;
} {
  return {
    digest: sha256Hex(bytes),
    bytes: String(bytes.length),
    media: "application/json",
  };
}

export interface BoundAuditInput {
  method: string;
  request: string | null;
  operation: string | null;
  /** Scrubbed params (credential fields already replaced). */
  params: unknown;
  /** Scrubbed result (tokens never appear). */
  result: unknown;
  outcome: string;
  code: string;
  previous_action?: NativeRef | null;
  /** Principal executing the action (service context). */
  principal: string;
}

/**
 * Seal one five-event audit history and commit it — records, objects,
 * event index, action index, and the optional idempotency binding — in a
 * single `commit`. Returns the StepClosed pointer.
 */
export async function commitBoundAuditReceipt(
  ports: Pick<
    PlatformPorts,
    "receiptWorkspace" | "auditSource" | "auditKey" | "newId" | "store"
  >,
  store: GatewayStore,
  input: BoundAuditInput,
  bind: {
    principalKey: string;
    id: string;
    requestHash: string;
    makeResultJson: (receipt: ReceiptPointer) => string;
  } | null,
): Promise<ReceiptPointer> {
  const workspace = ports.receiptWorkspace; // "audit1"
  const source = ports.auditSource; // "gateway1"
  const stream = input.request ?? ports.newId();
  const runId = `op_${stream}`;
  const keyId = keyIdOfPublic(publicKeyOf(ports.auditKey));
  const redactedParamsSha = sha256Hex(canonicalJson(input.params ?? null));
  const resultSha = sha256Hex(canonicalJson(input.result ?? null));
  const payload = {
    v: 1,
    method: input.method,
    principal: input.principal,
    request: input.request,
    operation: input.operation,
    redacted_params_sha256: redactedParamsSha,
    result_sha256: resultSha,
    outcome: input.outcome,
    code: input.code,
    previous_action: input.previous_action ?? null,
  };
  const intentBytes = Buffer.from(
    canonicalJson({ method: input.method, params: input.params ?? null }),
    "utf8",
  );
  const payloadBytes = Buffer.from(canonicalJson(payload), "utf8");
  const intentRef = objectRefOf(intentBytes);
  const observationRef = objectRefOf(payloadBytes);

  const events: ProofEvent[] = [];
  const seal = (
    seq: number,
    data: unknown,
    parents: ProofEvent[] = [],
  ): ProofEvent => {
    const event = sealProofEvent(
      proofBody({
        workspace,
        source,
        stream,
        seq: String(seq),
        prev: seq === 1 ? GENESIS : events[seq - 2]!.hash,
        lamport: String(seq),
        key: keyId,
        parents: parents.map(eventRefOf),
        data: data as Parameters<typeof proofBody>[0]["data"],
      }),
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
    lane: "proof" as const,
    partition: workspace,
    data: Buffer.from(canonicalJson(e), "utf8"),
  }));
  const anchor = events[3]!; // StepClosed anchors the receipt pointer.
  const anchorBytes = Buffer.from(canonicalJson(anchor), "utf8");
  const pointer: ReceiptPointer = {
    workspace,
    event: eventRefOf(anchor),
  };
  const nativeRef = {
    profile: "gateway.action/1",
    namespace: workspace,
    object_id: runId,
    commitment: anchor.hash,
    raw_sha256: sha256Hex(anchorBytes),
    bytes: String(anchorBytes.length),
  };

  const mutations: StoreJson[] = [
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
          principal: input.principal,
          method: input.method,
        },
      ],
    },
  ];
  if (bind !== null) {
    mutations.push({
      v: 1,
      kind: "operations",
      operations: [
        {
          principal: bind.principalKey,
          id: bind.id,
          request_hash: bind.requestHash,
          result_json: bind.makeResultJson(pointer),
          state: "COMPLETED",
        },
      ],
    });
  }

  await store.commit({
    records,
    objects: [intentBytes, payloadBytes],
    mutation: { v: 1, kind: "batch", mutations } as StoreJson,
    result_sha256: resultSha,
  });
  return pointer;
}

/**
 * `ReceiptWriter` over the bound audit history. The dispatcher passes the
 * action plus the already-scrubbed params/result; the writer seals,
 * indexes, and binds them in one commit.
 */
export class CoreReceiptWriter implements ReceiptWriter {
  private readonly ports: Pick<
    PlatformPorts,
    "receiptWorkspace" | "auditSource" | "auditKey" | "newId" | "store"
  >;
  private readonly store: GatewayStore;
  /** Cross-action linkage kept in memory (boot-scoped best effort). */
  private lastAction: NativeRef | null = null;

  constructor(
    store: GatewayStore,
    ports: Pick<
      PlatformPorts,
      "receiptWorkspace" | "auditSource" | "auditKey" | "newId" | "store"
    >,
  ) {
    this.store = store;
    this.ports = ports;
  }

  async commitAction(
    action: AuditAction,
    bind: {
      principalKey: string;
      id: string;
      requestHash: string;
      makeResultJson: (receipt: ReceiptPointer) => string;
    } | null,
    material?: { params: unknown; result: unknown },
  ): Promise<ReceiptPointer> {
    const pointer = await commitBoundAuditReceipt(
      this.ports,
      this.store,
      {
        method: action.method,
        request: action.request,
        operation: action.operation,
        params: material?.params ?? null,
        result: material?.result ?? null,
        outcome: action.outcome,
        code: action.code,
        previous_action: this.lastAction,
        principal: action.principal,
      },
      bind,
    );
    this.lastAction = {
      profile: "gateway.action/1",
      namespace: pointer.workspace,
      object_id: `op_${action.request ?? pointer.event.stream}`,
      commitment: pointer.event.hash,
      raw_sha256: "",
      bytes: "0",
    };
    return pointer;
  }

  /** Mutation-only idempotency binding (NO_RECEIPT mutations). */
  async commitBind(bind: {
    principalKey: string;
    id: string;
    requestHash: string;
    resultJson: string;
  }): Promise<void> {
    await this.store.commit({
      records: [],
      mutation: {
        v: 1,
        kind: "operations",
        operations: [
          {
            principal: bind.principalKey,
            id: bind.id,
            request_hash: bind.requestHash,
            result_json: bind.resultJson,
            state: "COMPLETED",
          },
        ],
      } as StoreJson,
      result_sha256: sha256Hex(bind.resultJson),
    });
  }
}

/** Helper: the ServiceContext a receipt write needs (principal only). */
export function ctxForPrincipal(id: string): ServiceContext {
  return {
    principal: {
      id,
      role: "local_operator",
    } as ServiceContext["principal"],
  };
}
