/**
 * Capturing harness for the Gateway v2 fixture program.
 *
 * `createExchangeCollector` and `collectPeerTranscript` reproduce the spec's
 * `exchange(...)` / `peerTranscript(...)` semantics exactly (same request id
 * sequence q1..qn, plan-hash injection, review rewrite, audit receipts, peer
 * headers) but record the printed objects/lines instead of console.log.
 *
 * `EXCHANGE_SPECS` transcribes the 58 §3.3 `exchange(...)` calls verbatim as
 * data; `PEER_TRANSCRIPT_SPECS` transcribes the six §4.4 invocations.
 */
import {F,H,J,auditor,blob,history,now,planFor,ref,scrub,signed,token} from "./prelude.mts";

/** One printed exchange: {request,response} plus the peer headers block when peer=true. */
export interface ExchangeEntry {
  request: any;
  response: any;
  headers?: Record<string, string>;
}

export interface ExchangeCollector {
  exchange: (method: string, params: any, result: any, peer?: boolean) => ExchangeEntry;
  entries: ExchangeEntry[];
}

/**
 * Spec `exchange(...)` with console.log replaced by recording: each call
 * pushes the exact {request,response,headers?} object the spec builds.
 */
export function createExchangeCollector(): ExchangeCollector {
  let exchangeNumber = 0;
  const entries: ExchangeEntry[] = [];
  const exchange = (method: string, params: any, result: any, peer = false): ExchangeEntry => {
    const p = structuredClone(params), r = structuredClone(result), id = "q" + String(++exchangeNumber);
    if (["product.install", "product.uninstall", "product.update", "product.rollback"].includes(method)) p.plan = H(J(planFor(method.split(".")[1]!)));
    if (Object.hasOwn(p, "review")) { delete p.review; p.review = H(J({ method, params: p, operator: "operator1", expires_ms: now + 300000 })); }
    const request = { v: 2, id, workspace: "ws1", method, params: p };
    const action = blob(J({ v: 1, method, principal: peer ? "peer1" : "operator1", request: id, operation: p.operation ?? null, redacted_params_sha256: H(J(scrub(p))), result_sha256: H(J(scrub(r))), outcome: "SUCCEEDED", code: "OK", previous_action: null }));
    const audit = history("op_" + id, blob(J({ method, params: scrub(p) })), action, "audit1", "gateway1", auditor, id);
    const exempt = ["daemon.hello", "run.heartbeat", "events.ack", "agent.challenge", "agent.renew", "ui.session.exchange"].includes(method);
    const response = { v: 2, id, ok: true, result: r, receipt: exempt ? null : { workspace: "audit1", event: ref(audit[3]) } };
    const output: ExchangeEntry = { request, response };
    if (peer) { const nonce = token(20 + exchangeNumber % 200); const proof = { v: 1, kind: "request", gateway: "gw1", workspace: "ws1", epoch: "1", token_hash: H(F.access), id, method, params_sha256: H(J(p)), nonce, issued_ms: now, expires_ms: now + 60000 }; output.headers = { Authorization: "Bearer " + F.access, "X-LatticeAG-Nonce": nonce, "X-LatticeAG-Epoch": "1", "X-LatticeAG-Issued-Ms": String(now), "X-LatticeAG-Expires-Ms": String(now + 60000), "X-LatticeAG-Key-Proof": signed("LATTICEAG-GATEWAY-REQUEST/1", proof) }; }
    entries.push(output);
    return output;
  };
  return { exchange, entries };
}

/**
 * Spec `peerTranscript(family,transport,session)` captured as the array of
 * J-lines it would print: one header line followed by the 10 exchange lines.
 * When `collector` is given, the exchanges are recorded through it (continuing
 * its q-id sequence, as in the concatenated spec program); otherwise a fresh
 * collector is used so the transcript is self-contained.
 */
export function collectPeerTranscript(family: string, transport: string, session: string, collector: ExchangeCollector = createExchangeCollector()): string[] {
  const lines: string[] = [];
  const emit = (method: string, params: any, result: any, peer = false) => lines.push(J(collector.exchange(method, params, result, peer)));
  lines.push(J({ connector: { family, transport, provider_session: session }, native_boundary: { required: "pinned PolyMesh owner artifact", fixture_routes: 0, interoperability_claim: false } }));
  emit("agent.challenge", { key: F.key.public, nonce: F.clientNonce }, { challenge: "challenge1", nonce: F.serverNonce, audience: "gw1", epoch: "1", expires_ms: now + 60000 });
  emit("agent.pair.propose", F.registration, { pair: "pair1", state: "AWAITING_OPERATOR", proposal: F.proposal, key: F.key.id, scopes: F.scopes });
  emit("agent.pair.approve", { pair: "pair1", proposal: F.proposal, key: F.key.id, scopes: F.scopes }, { pair: "pair1", state: "APPROVED" });
  emit("agent.register", F.registration, { peer: "peer1", source: "src1", role: "agent", scopes: F.scopes, access: F.access, refresh: F.refresh, expires_ms: now + 900000, mesh: "ADAPTER_REQUIRED" });
  const ownAction = { workspace: "ws1", event: ref(F.events[0]) };
  emit("events.publish", { profile: "proof-evidence/1", topic: "telemetry", producer: "src1", seq: "1", record: F.eventBlob }, { cursor: F.cursor, durable: true, duplicate: false }, true);
  emit("objects.put", { action: ownAction, blob: F.intent }, { ref: F.intent.ref }, true);
  emit("events.subscribe", { topics: ["approval.decision"], after: null }, { subscription: "sub1", cursor: F.cursor, expires_ms: now + 60000 }, true);
  emit("approval.request", { action: F.nativeRef, target: "product1", expires_ms: now + 60000, native: F.intent.ref }, { approval: "approval1", revision: "1", state: "PENDING", authority: "NONE" }, true);
  emit("lineage.query", { action: ownAction, max_nodes: 64, max_depth: 16 }, { nodes: [ownAction], edges: [], gaps: ["CAP_ADAPTER_UNAVAILABLE"], native_assessment: "NOT_EVALUATED" }, true);
  emit("agent.disconnect", { peer: "peer1" }, { peer: "peer1", state: "DISCONNECTED" }, true);
  return lines;
}

// ---------------------------------------------------------------------------
// §3.3 — the 58 exchange(...) calls, transcribed verbatim as data.
// ---------------------------------------------------------------------------
export interface ExchangeSpec { method: string; params: any; result: any; peer?: boolean; }

export const EXCHANGE_SPECS: ExchangeSpec[] = [
  { method: "daemon.hello", params: { profiles: ["@latticeag/events@0.1.0", "proof-evidence/1"], interfaces: "interfaces/1" }, result: { protocol: "gateway-control/2", profiles: ["@latticeag/events@0.1.0", "proof-evidence/1"], interfaces: "interfaces/1", mesh: { available: false, code: "CAP_ADAPTER_UNAVAILABLE" } } },
  { method: "daemon.status", params: {}, result: { instance: "gw1", state: "READY", config_revision: "1", products: 0, peers: 0, ui: "http://127.0.0.1:9848" } },
  { method: "daemon.stop", params: { grace_ms: 10000 }, result: { state: "DRAINING" } },
  { method: "config.get", params: {}, result: { revision: "1", document: F.config2 } },
  { method: "config.validate", params: { document: F.config2 }, result: { valid: true, errors: [] } },
  { method: "config.apply", params: { expected_revision: "1", document: F.config2, review: F.review }, result: { revision: "2", restart_required: false } },
  { method: "run.register", params: { run_id: F.ulid, kit: "openai-completions", owner: "cli1", resume: false }, result: { run_id: F.ulid, owner: "cli1", mode: "gateway" } },
  { method: "run.heartbeat", params: { run_id: F.ulid, owner: "cli1", spool_seq: "7" }, result: { accepted: true } },
  { method: "run.finish", params: { run_id: F.ulid, owner: "cli1", exit_code: 0, signal: null, spool_seq: "7" }, result: { state: "FINISHED", pending_sync: 0 } },
  { method: "events.publish", params: { profile: "proof-evidence/1", topic: "telemetry", producer: "src1", seq: "1", record: F.eventBlob }, result: { cursor: F.cursor, durable: true, duplicate: false } },
  { method: "events.query", params: { topics: ["telemetry"], after: null, limit: 100 }, result: { items: [], next: null } },
  { method: "events.subscribe", params: { topics: ["telemetry"], after: null }, result: { subscription: "sub1", cursor: F.cursor, expires_ms: F.now + 60000 } },
  { method: "events.ack", params: { subscription: "sub1", cursor: F.cursor }, result: { cursor: F.cursor } },
  { method: "objects.put", params: { action: F.pointer, blob: F.intent }, result: { ref: F.intent.ref } },
  { method: "objects.get", params: { action: F.pointer, ref: F.intent.ref }, result: { blob: F.intent } },
  { method: "receipt.get", params: { action: F.pointer, disclosure: "HASHES_ONLY" }, result: { action: F.pointer, inventory: F.inventory, outer: "SIGNED_UNANCHORED", inner: "NOT_EVALUATED", bundle: null } },
  { method: "lineage.query", params: { action: F.pointer, max_nodes: 64, max_depth: 16 }, result: { nodes: [F.pointer], edges: [], gaps: ["CAP_ADAPTER_UNAVAILABLE"], native_assessment: "NOT_EVALUATED" } },
  { method: "operation.get", params: { operation: "op1" }, result: { operation: "op1", kind: "install", state: "READY", slug: "lexverdict", from: null, to: "0.1.0", cursor: F.cursor, error: null } },
  { method: "operation.cancel", params: { operation: "op1" }, result: { operation: "op1", state: "CANCELLED" } },
  { method: "product.plan", params: { kind: "install", source: "lexverdict", version: "0.1.0", cascade: false, keep_data: true }, result: { plan: F.plan, summary: F.planSummary } },
  { method: "product.install", params: { plan: F.plan, review: F.review }, result: { operation: "op1", state: "QUEUED" } },
  { method: "product.uninstall", params: { plan: F.plan, review: F.review }, result: { operation: "op1", state: "QUEUED" } },
  { method: "product.update", params: { plan: F.plan, review: F.review }, result: { operation: "op1", state: "QUEUED" } },
  { method: "product.rollback", params: { plan: F.plan, review: F.review }, result: { operation: "op1", state: "QUEUED" } },
  { method: "product.list", params: { after: null, limit: 100 }, result: { items: [], next: null } },
  { method: "product.health", params: { slug: "lexverdict" }, result: { slug: "lexverdict", state: "READY", liveness: true, readiness: true, sandbox: "enforced", native: { status: "ok" } } },
  { method: "agent.pair.create", params: { role: "agent", scopes: F.scopes, key: F.key.id }, result: { pair: "pair1", code: F.code, expires_ms: F.now + 300000 } },
  { method: "agent.pair.propose", params: F.registration, result: { pair: "pair1", state: "AWAITING_OPERATOR", proposal: F.proposal, key: F.key.id, scopes: F.scopes } },
  { method: "agent.pair.get", params: { pair: "pair1", code: F.code }, result: { pair: "pair1", state: "AWAITING_OPERATOR", proposal: F.proposal, key: F.key.id, scopes: F.scopes } },
  { method: "agent.pair.approve", params: { pair: "pair1", proposal: F.proposal, key: F.key.id, scopes: F.scopes }, result: { pair: "pair1", state: "APPROVED" } },
  { method: "agent.pair.cancel", params: { pair: "pair1" }, result: { pair: "pair1", state: "CANCELLED" } },
  { method: "agent.challenge", params: { key: F.key.public, nonce: F.clientNonce }, result: { challenge: "challenge1", nonce: F.serverNonce, audience: "gw1", epoch: "1", expires_ms: F.now + 60000 } },
  { method: "agent.register", params: F.registration, result: { peer: "peer1", source: "src1", role: "agent", scopes: F.scopes, access: F.access, refresh: F.refresh, expires_ms: F.now + 900000, mesh: "ADAPTER_REQUIRED" } },
  { method: "agent.renew", params: { peer: "peer1", refresh: F.refresh, challenge: "challenge1", server_nonce: F.serverNonce, epoch: "1", proof: F.renewProof }, result: { access: F.access2, refresh: F.refresh2, expires_ms: F.now + 900000 } },
  { method: "agent.list", params: { after: null, limit: 100 }, result: { items: [], next: null } },
  { method: "agent.revoke", params: { peer: "peer1", reason: "operator_requested" }, result: { peer: "peer1", state: "REVOKED", grant_revision: "2" } },
  { method: "agent.disconnect", params: { peer: "peer1" }, result: { peer: "peer1", state: "DISCONNECTED" } },
  { method: "approval.request", params: { action: F.nativeRef, target: "product1", expires_ms: F.now + 60000, native: F.intent.ref }, result: { approval: "approval1", revision: "1", state: "PENDING", authority: "NONE" } },
  { method: "approval.list", params: { state: "PENDING", after: null, limit: 100 }, result: { items: [], next: null } },
  { method: "approval.get", params: { approval: "approval1" }, result: { approval: "approval1", revision: "1", state: "PENDING", action: F.nativeRef, expires_ms: F.now + 60000, native_status: "NOT_DISPATCHED" } },
  { method: "approval.decide", params: { approval: "approval1", expected_revision: "1", action: F.nativeRef, decision: "deny", reason: "scope_not_approved" }, result: { approval: "approval1", revision: "2", state: "DENIED", native_status: "NOT_DISPATCHED" } },
  { method: "approval.cancel", params: { approval: "approval1", expected_revision: "1" }, result: { approval: "approval1", revision: "2", state: "CANCELLED" } },
  { method: "ui.session.create", params: { role: "viewer" }, result: { bootstrap: F.bootstrap, expires_ms: F.now + 60000, url: "http://127.0.0.1:9848/#bootstrap=" + F.bootstrap } },
  { method: "ui.session.exchange", params: { bootstrap: F.bootstrap }, result: { session: "session1", role: "viewer", csrf: F.csrf, expires_ms: F.now + 28800000 } },
  { method: "ui.session.revoke", params: { session: "session1" }, result: { session: "session1", state: "REVOKED" } },
  { method: "sync.status", params: {}, result: { paused: false, streams: F.syncCounts, cloud: null } },
  { method: "sync.pause", params: { streams: ["runs", "receipts", "lineage", "approvals", "watch", "mesh"] }, result: { paused: ["runs", "receipts", "lineage", "approvals", "watch", "mesh"] } },
  { method: "sync.resume", params: { streams: ["receipts"] }, result: { resumed: ["receipts"] } },
  { method: "sync.configure", params: { expected_revision: "1", sync: F.config2.sync, review: F.review }, result: { revision: "2" } },
  { method: "sync.flush", params: { streams: ["receipts"], timeout_ms: 30000 }, result: { through: { receipts: "0" }, pending: 0, blocked: 0 } },
  { method: "cloud.pair.begin", params: { provider: "hosted", streams: ["receipts"], remote_ui: false }, result: { enrollment: "enroll1", state: "AWAITING_PROVIDER", user_code: F.code } },
  { method: "cloud.pair.complete", params: { enrollment: "enroll1", binding: F.nativeRef, review: F.review }, result: { cloud: "cloud1", state: "PAIRED", remote_ui: false } },
  { method: "cloud.pair.revoke", params: { cloud: "cloud1" }, result: { cloud: "cloud1", state: "REVOKED", remote_notice: "QUEUED" } },
  { method: "catalog.refresh", params: { source: "configured", offline: true }, result: { revision: "1", entries: 1, freshness: "OFFLINE_PINNED" } },
  { method: "catalog.search", params: { q: "lexverdict", series: "lex", after: null, limit: 20 }, result: { items: [F.catalogEntry], next: null } },
  { method: "catalog.show", params: { slug: "lexverdict", version: "0.1.0" }, result: { entry: F.catalogEntry } },
  { method: "catalog.pin", params: { slug: "lexverdict", version: "0.1.0", digest: F.archiveDigest, expected_revision: "1" }, result: { revision: "2", pin: F.pin } },
  { method: "catalog.unpin", params: { slug: "lexverdict", expected_revision: "2" }, result: { revision: "3" } },
];

// ---------------------------------------------------------------------------
// §4.4 — the six peerTranscript(...) invocations, transcribed verbatim.
// ---------------------------------------------------------------------------
export interface PeerTranscriptSpec { family: string; transport: string; session: string; }

export const PEER_TRANSCRIPT_SPECS: PeerTranscriptSpec[] = [
  { family: "openai-completions", transport: "loopback-http-sse", session: "completion1" },
  { family: "openai-agents", transport: "loopback-http-sse", session: "agent-run1" },
  { family: "hermes", transport: "loopback-http-sse", session: "hermes-session1" },
  { family: "langgraph", transport: "loopback-http-sse", session: "thread1" },
  { family: "custom-http", transport: "paired-native-http", session: "custom-session1" },
  { family: "custom-wss", transport: "paired-native-wss", session: "custom-session2" },
];
