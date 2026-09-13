/**
 * Gateway v2 — connector-family table and transcript validation (§4.4).
 *
 * The six connector families are data, not code paths: each entry records
 * the §4.4 identity/hook mapping, approval semantics, and resume rules.
 * Family/transport labels are untrusted connector metadata — never
 * identity evidence. `familyAssertions` returns the per-family check
 * descriptors used by the TV-GW-57..62 vector tests;
 * `peerTranscriptValidation` validates a captured §4.4 `peerTranscript`
 * output (header line + ten exchange lines) against the family rules.
 */
import { RpcError } from "../protocol/errors.js";
import type { Json } from "../protocol/refs.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import { verifyRequest } from "../crypto/pairing.js";

/** The six connector families (§4.4 table order). */
export const CONNECTOR_FAMILY_NAMES = [
  "openai-completions",
  "openai-agents",
  "hermes",
  "langgraph",
  "custom-http",
  "custom-wss",
] as const;

export type ConnectorFamilyName = (typeof CONNECTOR_FAMILY_NAMES)[number];

export function isConnectorFamily(name: string): name is ConnectorFamilyName {
  return (CONNECTOR_FAMILY_NAMES as readonly string[]).includes(name);
}

/** §4.4 "Hook/identity mapping" column as data. */
export interface FamilyIdentity {
  /** How the connector binds provider/native ids. */
  readonly hook: string;
  /** Native id kinds the connector must retain verbatim as text. */
  readonly retainedIds: readonly string[];
  /**
   * The peer key is always the connector-owned Ed25519 key — never the
   * model-provider API key (§4.1/§4.4).
   */
  readonly providerKeyIsIdentity: false;
}

/** §4.4 approval semantics as data. */
export interface FamilyApproval {
  /**
   * The family's real interception point that must be proven before an
   * approval-enforcing capability may be advertised; an instrumentation
   * callback after execution is not an approval gate.
   */
  readonly enforcementPoint: string;
  /** What approval interrupts/resumes. */
  readonly resumeBinding: string;
  /**
   * Compatibility-fixture approvals are marked hypothetical/local-fixture,
   * never satisfy a live native approval, and are excluded from hosted
   * authority channels.
   */
  readonly fixtureApprovalIsHypothetical: true;
}

/** §4.4 consume/resume rules as data. */
export interface FamilyResume {
  readonly transport: string;
  /** Ordering/dedup contract on reconnect. */
  readonly rule: string;
  /** Things a resume must never do. */
  readonly never: readonly string[];
}

export interface ConnectorFamily {
  readonly family: ConnectorFamilyName;
  readonly identity: FamilyIdentity;
  readonly approval: FamilyApproval;
  readonly resume: FamilyResume;
  /** §13.x vector ids covering this family. */
  readonly vectors: readonly string[];
}

/** The §4.4 connector-family table, transcribed as data. */
export const CONNECTOR_FAMILIES: Readonly<
  Record<ConnectorFamilyName, ConnectorFamily>
> = {
  "openai-completions": {
    family: "openai-completions",
    identity: {
      hook:
        "Connector maps request/completion/tool-call ids within the provider namespace; emits existing kit-validated observations, never fabricated SDK events.",
      retainedIds: ["completion_id", "request_id", "tool_call_id"],
      providerKeyIsIdentity: false,
    },
    approval: {
      enforcementPoint:
        "Explicit tool-call mediator requests approval before its own tool executes",
      resumeBinding: "mediated tool call",
      fixtureApprovalIsHypothetical: true,
    },
    resume: {
      transport: "loopback-http-sse",
      rule: "Streaming tokens are telemetry; reconnect never repeats a completion.",
      never: ["re-execute a completion", "respawn the process", "fabricate SDK events"],
    },
    vectors: ["TV-GW-57"],
  },
  "openai-agents": {
    family: "openai-agents",
    identity: {
      hook:
        "Connector uses registered run/trace/tool hooks and retains native ids as text; its own key, not the model-provider API key.",
      retainedIds: ["run_id", "trace_id", "tool_call_id", "handoff_id"],
      providerKeyIsIdentity: false,
    },
    approval: {
      enforcementPoint:
        "Handoffs advertise native capabilities; approval interrupts resume only the exact suspended tool call after fresh checks",
      resumeBinding: "exact suspended tool call",
      fixtureApprovalIsHypothetical: true,
    },
    resume: {
      transport: "loopback-http-sse",
      rule: "Trace export is separately consented; transport reconnect does not reexecute tools.",
      never: ["reexecute a tool on reconnect", "export traces without consent"],
    },
    vectors: ["TV-GW-58"],
  },
  hermes: {
    family: "hermes",
    identity: {
      hook:
        "Persistent sidecar/plugin binds Hermes session and tool-call ids; no need for `latticeag run --cmd`.",
      retainedIds: ["session_id", "tool_call_id"],
      providerKeyIsIdentity: false,
    },
    approval: {
      enforcementPoint:
        "Local approval signal goes through Hermes's actual interception point; a missing interceptor is observational-only",
      resumeBinding: "Hermes interception point",
      fixtureApprovalIsHypothetical: true,
    },
    resume: {
      transport: "loopback-http-sse",
      rule: "Reconnect reads the same durable cursor.",
      never: ["advertise enforcement without a real interceptor"],
    },
    vectors: ["TV-GW-59"],
  },
  langgraph: {
    family: "langgraph",
    identity: {
      hook:
        "Connector binds thread_id, checkpoint namespace, checkpoint_id, and node attempt; distinct attempts are not deduplicated by node name.",
      retainedIds: ["thread_id", "checkpoint_ns", "checkpoint_id", "node", "attempt"],
      providerKeyIsIdentity: false,
    },
    approval: {
      enforcementPoint:
        "Native interrupt/resume binding must match checkpoint and action hash",
      resumeBinding: "checkpoint + action hash",
      fixtureApprovalIsHypothetical: true,
    },
    resume: {
      transport: "loopback-http-sse",
      rule: "A moved checkpoint returns REVISION_CONFLICT and requires a new request.",
      never: ["resume a moved checkpoint", "dispatch after REVISION_CONFLICT"],
    },
    vectors: ["TV-GW-60"],
  },
  "custom-http": {
    family: "custom-http",
    identity: {
      hook:
        "Peer implements bounded request/response and SSE or its paired native HTTP transport; endpoint identity is key-pinned.",
      retainedIds: ["session_id", "request_id"],
      providerKeyIsIdentity: false,
    },
    approval: {
      enforcementPoint:
        "Signed registration and tokens required before any routed traffic",
      resumeBinding: "producer slot",
      fixtureApprovalIsHypothetical: true,
    },
    resume: {
      transport: "paired-native-http",
      rule: "Event retries preserve the producer slot; without the native binding, routing is CAP_ADAPTER_UNAVAILABLE.",
      never: [
        "fetch an endpoint URL carried inside a product event",
        "guess a mesh HTTP endpoint",
      ],
    },
    vectors: ["TV-GW-61"],
  },
  "custom-wss": {
    family: "custom-wss",
    identity: {
      hook:
        "TLS hostname/key pins and native PolyMesh WSS framing; Gateway control auth remains scoped and key-bound.",
      retainedIds: ["session_id", "connection_id"],
      providerKeyIsIdentity: false,
    },
    approval: {
      enforcementPoint: "Native transport close/dispatch boundary",
      resumeBinding: "native WSS connection state",
      fixtureApprovalIsHypothetical: true,
    },
    resume: {
      transport: "paired-native-wss",
      rule: "Close codes follow native transport; unsent telemetry buffers locally, approvals stop.",
      never: [
        "replay an already dispatched operation on resume",
        "route after grant revocation",
      ],
    },
    vectors: ["TV-GW-62"],
  },
};

// ── Vector-check descriptors ─────────────────────────────────────────────

/** One named check a TV-GW-57..62 transcript vector must satisfy. */
export interface FamilyAssertion {
  readonly id: string;
  readonly vector: string;
  readonly description: string;
}

const COMMON_TRANSCRIPT_CHECKS = [
  {
    id: "ten-exchanges",
    description: "Exactly ten expanded RPC exchanges follow the header line.",
  },
  {
    id: "exchange-order",
    description:
      "Method order: challenge, pair.propose, pair.approve, register, " +
      "events.publish, objects.put, events.subscribe, approval.request, " +
      "lineage.query, agent.disconnect.",
  },
  {
    id: "native-boundary",
    description:
      "Header marks the native boundary: pinned owner artifact required, " +
      "fixture_routes=0, interoperability_claim=false.",
  },
  {
    id: "adapter-required",
    description:
      "agent.register reports mesh ADAPTER_REQUIRED without a pinned " +
      "native artifact; no CONNECTED claim without native ACK.",
  },
  {
    id: "peer-proofs",
    description:
      "Peer-authenticated exchanges carry the six §4.3 headers with a " +
      "REQUEST/1 proof under the enrolled key.",
  },
] as const;

/**
 * Per-family vector-check descriptors (TV-GW-57..62). The five common
 * transcript checks come first, then the family-specific rules from the
 * §4.4 table row.
 */
export function familyAssertions(family: ConnectorFamilyName): FamilyAssertion[] {
  const f = CONNECTOR_FAMILIES[family];
  if (f === undefined) {
    throw new RpcError("SCHEMA_INVALID", `unknown connector family ${family}`, {
      field: "family",
    });
  }
  const vector = f.vectors[0] ?? "";
  const specific: Record<ConnectorFamilyName, FamilyAssertion[]> = {
    "openai-completions": [
      {
        id: "completion-id-retained",
        vector,
        description:
          "Connector keeps the completion id; no respawn and no repeated provider call.",
      },
      {
        id: "no-mesh-claim",
        vector,
        description: "No native-mesh claim without the adapter.",
      },
    ],
    "openai-agents": [
      {
        id: "native-ids-retained",
        vector,
        description: "Native run/handoff ids retained as text.",
      },
      {
        id: "no-tool-reexecution",
        vector,
        description: "Transport reconnect does not reexecute tools.",
      },
    ],
    hermes: [
      {
        id: "no-cli-spawn",
        vector,
        description: "Transcript validates without CLI spawning Hermes.",
      },
      {
        id: "interceptor-required",
        vector,
        description:
          "A missing real interceptor prevents enforcement-capability advertisement.",
      },
    ],
    langgraph: [
      {
        id: "checkpoint-conflict",
        vector,
        description:
          "A moved checkpoint before approval resume yields REVISION_CONFLICT; resume/dispatch count 0.",
      },
    ],
    "custom-http": [
      {
        id: "control-without-mesh",
        vector,
        description:
          "Control enrollment succeeds within scopes while routing is CAP_ADAPTER_UNAVAILABLE; no guessed HTTP mesh endpoint.",
      },
    ],
    "custom-wss": [
      {
        id: "revoked-reconnect",
        vector,
        description:
          "Grant revocation during reconnect yields TOKEN_REVOKED; no WSS route or queued approval replay.",
      },
    ],
  };
  return [
    ...COMMON_TRANSCRIPT_CHECKS.map((c) => ({ ...c, vector })),
    ...specific[family],
  ];
}

// ── Transcript validation ────────────────────────────────────────────────

export interface TranscriptCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface TranscriptValidation {
  ok: boolean;
  family: ConnectorFamilyName;
  exchanges: number;
  checks: TranscriptCheck[];
}

const TRANSCRIPT_METHODS = [
  "agent.challenge",
  "agent.pair.propose",
  "agent.pair.approve",
  "agent.register",
  "events.publish",
  "objects.put",
  "events.subscribe",
  "approval.request",
  "lineage.query",
  "agent.disconnect",
] as const;

const PEER_HEADER_NAMES = [
  "Authorization",
  "X-LatticeAG-Nonce",
  "X-LatticeAG-Epoch",
  "X-LatticeAG-Issued-Ms",
  "X-LatticeAG-Expires-Ms",
  "X-LatticeAG-Key-Proof",
] as const;

/**
 * Validate a captured `peerTranscript(family, transport, session)` output
 * (the §4.4 J-lines: one header line then ten exchange lines) against the
 * family rules. When `verifyKey` (canonical base64url raw Ed25519 public
 * key) is supplied, each peer exchange's X-LatticeAG-Key-Proof signature
 * is verified under REQUEST/1 over the proof body reconstructed from the
 * headers and request envelope.
 */
export function peerTranscriptValidation(
  family: ConnectorFamilyName,
  lines: readonly string[],
  opts?: { verifyKey?: string; gateway?: string },
): TranscriptValidation {
  const checks: TranscriptCheck[] = [];
  const check = (name: string, ok: boolean, detail?: string): void => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
  };
  const fam = CONNECTOR_FAMILIES[family];
  if (fam === undefined) {
    check("family-known", false, family);
    return { ok: false, family, exchanges: 0, checks };
  }
  check("family-known", true);

  const parsed: unknown[] = [];
  for (const line of lines) {
    try {
      parsed.push(JSON.parse(line));
    } catch {
      parsed.push(null);
    }
  }
  check("lines-parse", parsed.every((p) => p !== null), `${parsed.length} lines`);

  // Header line.
  const header = parsed[0];
  const connector =
    typeof header === "object" && header !== null
      ? (header as Record<string, Json>).connector
      : undefined;
  const boundary =
    typeof header === "object" && header !== null
      ? (header as Record<string, Json>).native_boundary
      : undefined;
  check(
    "header-family",
    typeof connector === "object" &&
      connector !== null &&
      (connector as Record<string, Json>).family === family,
  );
  check(
    "header-transport",
    typeof connector === "object" &&
      connector !== null &&
      (connector as Record<string, Json>).transport === fam.resume.transport,
  );
  check(
    "native-boundary",
    typeof boundary === "object" &&
      boundary !== null &&
      (boundary as Record<string, Json>).fixture_routes === 0 &&
      (boundary as Record<string, Json>).interoperability_claim === false,
  );

  // Exchange lines.
  const exchanges = parsed.slice(1).filter((e): e is Record<string, Json> =>
    typeof e === "object" && e !== null,
  );
  check("ten-exchanges", exchanges.length === 10, `${exchanges.length}`);
  const methods = exchanges.map((e) =>
    typeof e.request === "object" && e.request !== null
      ? (e.request as Record<string, Json>).method
      : undefined,
  );
  check(
    "exchange-order",
    methods.every((m, i) => m === TRANSCRIPT_METHODS[i]),
    JSON.stringify(methods),
  );

  const register = exchanges[3];
  check(
    "adapter-required",
    typeof register?.response === "object" &&
      register.response !== null &&
      (register.response as Record<string, Json>).result !== undefined &&
      (register.response as Record<string, Json>).result !== null &&
      ((register.response as Record<string, Json>).result as Record<string, Json>).mesh ===
        "ADAPTER_REQUIRED",
  );

  // Peer exchanges (indices 4..9) carry §4.3 headers; optionally verify.
  let peerHeadersOk = true;
  let proofsOk = true;
  for (const e of exchanges.slice(4)) {
    const h = e.headers;
    if (typeof h !== "object" || h === null) {
      peerHeadersOk = false;
      continue;
    }
    const headers = h as Record<string, string>;
    for (const name of PEER_HEADER_NAMES) {
      if (typeof headers[name] !== "string") peerHeadersOk = false;
    }
    if (opts?.verifyKey !== undefined && peerHeadersOk) {
      const request = e.request as Record<string, Json>;
      const token = headers.Authorization?.startsWith("Bearer ")
        ? headers.Authorization.slice(7)
        : "";
      const body = {
        v: 1,
        kind: "request",
        gateway: opts.gateway ?? "gw1",
        workspace: request.workspace,
        epoch: headers["X-LatticeAG-Epoch"],
        token_hash: sha256Hex(token),
        id: request.id,
        method: request.method,
        params_sha256: sha256Hex(canonicalJson(request.params)),
        nonce: headers["X-LatticeAG-Nonce"],
        issued_ms: Number(headers["X-LatticeAG-Issued-Ms"]),
        expires_ms: Number(headers["X-LatticeAG-Expires-Ms"]),
      };
      if (!verifyRequest(body, headers["X-LatticeAG-Key-Proof"] ?? "", opts.verifyKey)) {
        proofsOk = false;
      }
    }
  }
  check("peer-headers", peerHeadersOk);
  if (opts?.verifyKey !== undefined) {
    check("peer-proofs-verify", proofsOk);
  }

  // Disconnect must be the last exchange with state DISCONNECTED.
  const last = exchanges[9];
  const lastResult =
    typeof last?.response === "object" && last.response !== null
      ? ((last.response as Record<string, Json>).result as Record<string, Json>)
      : undefined;
  check("disconnect-terminal", lastResult?.state === "DISCONNECTED");

  return {
    ok: checks.every((c) => c.ok),
    family,
    exchanges: exchanges.length,
    checks,
  };
}

