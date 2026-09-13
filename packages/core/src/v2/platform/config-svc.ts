/**
 * ConfigService — config.get / config.validate / config.apply (spec §3.2,
 * §8.1–§8.2).
 *
 *  - get returns the *stored* document verbatim minus credential material —
 *    `*_env` fields carry env-var NAMES (never resolved values or token
 *    material), and the wire result never fabricates either.
 *  - validate runs the bundled v2 schema plus §8.1 semantic checks.
 *  - apply is a CAS on the decimal revision: the `review` param must equal
 *    `H(J({method:"config.apply", params:{expected_revision,document},
 *    operator, expires_ms}))` — the §3.3 rewrite binding recomputed over
 *    params-without-review — and protected changes (identity, endpoints,
 *    network/FS grants, trust roots, package digests, sync egress,
 *    products.instances add/remove/retarget) are POLICY_DENIED here because
 *    they require a reviewed product plan, which config.apply cannot carry.
 */
import { join } from "node:path";
import { existsSync } from "node:fs";
import { loadConfigV2, validateConfigV2Semantics } from "@latticeag/config";
import type {
  Count,
  Json,
  JsonObject,
  NativeRef,
} from "../protocol/refs.js";
import { RpcError } from "../protocol/errors.js";
import type { ConfigService } from "../protocol/services.js";
import { canonicalJson } from "../crypto/canonical.js";
import { sha256Hex } from "../crypto/hash.js";
import type { PlatformPorts, ServiceContext } from "./ports.js";
import { LOCAL_OPERATOR_CONTEXT } from "./ports.js";
import { KV_CONFIG_REVISION } from "./daemon.js";

const KV_CONFIG_DOCUMENT = "config:document";

/** Review binding window: H(J({... , expires_ms: now + 300000})) (§13.1). */
export const REVIEW_WINDOW_MS = 300_000;

// ── credential redaction ─────────────────────────────────────────────────

/**
 * Keys that would carry inline credential material if a document smuggled
 * them in. `*_env` fields are env-var NAMES — not values — and stay. The
 * `redaction.keys` list names event-payload keys and is itself config data,
 * not a credential (it is an array of strings, so key-based redaction
 * cannot reach it anyway).
 */
const SENSITIVE_KEY =
  /(?:^|_)(token|api_?key|secret|password|credentials?|private_?key|access_?token|refresh_?token|bearer|cookie|session_?token|client_?secret|signing_?key)(?:_|$)/i;

/**
 * Deep-redact a config document for config.get. Any object member whose
 * key matches SENSITIVE_KEY (and does not end in `_env`) is replaced with
 * `"[redacted]"` regardless of its value shape. For the stock v2 schema
 * this is a no-op — all credential references are env-var names — but the
 * wire contract ("credential values never returned") is enforced, not
 * assumed.
 */
export function redactConfigDocument(value: Json): Json {
  if (Array.isArray(value)) {
    return value.map(redactConfigDocument);
  }
  if (value !== null && typeof value === "object") {
    const out: JsonObject = {};
    for (const [key, child] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(key) && !key.toLowerCase().endsWith("_env")) {
        out[key] = "[redacted]";
      } else {
        out[key] = redactConfigDocument(child);
      }
    }
    return out;
  }
  return value;
}

// ── document diffing ─────────────────────────────────────────────────────

interface ChangedPath {
  /** Path segments from the document root. */
  path: string[];
  /** "change" for leaf/value edits; "add"/"remove" for key presence. */
  kind: "add" | "remove" | "change";
}

function isObj(v: unknown): v is Record<string, unknown> {
  return (
    typeof v === "object" &&
    v !== null &&
    !Array.isArray(v) &&
    (Object.getPrototypeOf(v) === Object.prototype ||
      Object.getPrototypeOf(v) === null)
  );
}

function diffDocs(
  oldDoc: unknown,
  newDoc: unknown,
  path: string[],
  out: ChangedPath[],
): void {
  if (isObj(oldDoc) && isObj(newDoc)) {
    for (const key of Object.keys(oldDoc)) {
      if (!Object.hasOwn(newDoc, key)) {
        out.push({ path: [...path, key], kind: "remove" });
        continue;
      }
      diffDocs(oldDoc[key], newDoc[key], [...path, key], out);
    }
    for (const key of Object.keys(newDoc)) {
      if (!Object.hasOwn(oldDoc, key)) {
        out.push({ path: [...path, key], kind: "add" });
      }
    }
    return;
  }
  if (Array.isArray(oldDoc) && Array.isArray(newDoc)) {
    // Arrays are atomic for review purposes (pin lists are protected as a
    // whole; nothing else needs per-index diffs).
    if (canonicalJson(oldDoc) !== canonicalJson(newDoc)) {
      out.push({ path, kind: "change" });
    }
    return;
  }
  if (oldDoc !== newDoc) {
    out.push({ path, kind: "change" });
  }
}

/** Adapter leaves that bind endpoints, filesystem paths, or credentials. */
const ADAPTER_PROTECTED_LEAF =
  /(^|_)(base_?url|url|endpoint|path|dir|bin|baseline|webhook_path|capability)(_|$)/i;

/**
 * §8.1/§3.2 protected changes: identity (workspace/instance), control
 * endpoints (ingest, gateway.ui/mesh), network origins and filesystem
 * grants (adapter endpoints/paths, storage.root), trust roots and package
 * digests (catalog.source/pins/allowlist/strict), cloud egress (sync.*),
 * operator-elevation policy (agents.allow_operator), and any
 * products.instances add/remove/manifest retarget.
 */
function isProtectedChange(change: ChangedPath): boolean {
  const [top, a, b, c] = change.path;
  switch (top) {
    case "gateway":
      // identity, ui endpoint, mesh binding — autostart stays editable.
      return a === "workspace_id" || a === "instance_id" || a === "ui" || a === "mesh";
    case "ingest":
      return true;
    case "storage":
      return a === "root";
    case "sync":
      return true; // egress consent lives behind sync.configure's own review
    case "catalog":
      return a === "source" || a === "pins" || a === "allowlist" || a === "strict";
    case "agents":
      return a === "allow_operator";
    case "products":
      if (a !== "instances") return false;
      if (change.kind !== "change") return true; // instance add/remove
      return c === "manifest"; // retarget = new package digest
    case "adapters":
      if (change.kind !== "change") return true; // adapter entry add/remove
      return b !== undefined && ADAPTER_PROTECTED_LEAF.test(b);
    default:
      return false;
  }
}

/** Sections whose edits require a daemon restart to take effect. */
const RESTART_SECTIONS = new Set([
  "bus",
  "ingest",
  "adapters",
  "gateway",
  "agents",
  "storage",
]);

async function readStoredConfig(
  ports: PlatformPorts,
): Promise<{ revision: string; document: JsonObject } | null> {
  const [doc, revision] = await Promise.all([
    ports.store.registry.kvGet(KV_CONFIG_DOCUMENT),
    ports.store.registry.kvGet(KV_CONFIG_REVISION),
  ]);
  if (doc !== null) {
    return {
      revision: revision ?? "1",
      document: JSON.parse(doc) as JsonObject,
    };
  }
  if (ports.configDir === "" || !existsSync(join(ports.configDir, "latticeag.json"))) {
    return null;
  }
  const loaded = loadConfigV2(ports.configDir); // throws on v1/invalid
  return { revision: "1", document: loaded.raw as JsonObject };
}

export function createConfigService(
  ports: PlatformPorts,
  ctx: ServiceContext = LOCAL_OPERATOR_CONTEXT,
): ConfigService {
  return {
    async get() {
      const stored = await readStoredConfig(ports);
      if (stored === null) {
        throw new RpcError("NOT_FOUND", "no v2 config document", {
          field: null,
        });
      }
      return {
        revision: stored.revision,
        document: redactConfigDocument(stored.document) as JsonObject,
      };
    },

    async validate(params: { document: JsonObject }) {
      const result = validateConfigV2Semantics(params.document);
      return {
        valid: result.valid,
        errors: result.errors as unknown as Json[],
      };
    },

    /**
     * The wire `review` is the 64-hex review-binding hash (typed NativeRef
     * in the shared interface); it must equal
     * H(J({method, params:{expected_revision,document}, operator,
     * expires_ms})) recomputed over the params *without* review — the
     * §3.3 rewrite semantics the testkit harness reproduces.
     */
    async apply(params: {
      expected_revision: Count;
      document: JsonObject;
      review: NativeRef;
    }) {
      // Param/schema stage: the incoming document must validate fully.
      const check = validateConfigV2Semantics(params.document);
      if (!check.valid) {
        const first = check.errors[0];
        throw new RpcError(
          "SCHEMA_INVALID",
          `config document invalid: ${first?.path ?? "(root)"}: ${first?.message ?? ""}`,
          { field: "document" },
        );
      }
      const stored = await readStoredConfig(ports);
      if (stored === null) {
        throw new RpcError("NOT_FOUND", "no v2 config document");
      }

      // CAS stage.
      if (params.expected_revision !== stored.revision) {
        throw new RpcError(
          "REVISION_CONFLICT",
          `config revision is ${stored.revision}, not ${params.expected_revision}`,
          { field: "expected_revision" },
        );
      }

      // Review binding: recompute over params-without-review (§3.3 rewrite).
      const { review, ...rest } = params;
      const expectedReview = sha256Hex(
        canonicalJson({
          method: "config.apply",
          params: rest,
          operator: ctx.principal.id,
          expires_ms: ports.clock() + REVIEW_WINDOW_MS,
        }),
      );
      if ((review as unknown) !== expectedReview) {
        throw new RpcError(
          "POLICY_DENIED",
          "review does not bind this method/document/revision",
          { field: "review" },
        );
      }

      // Protected changes need a reviewed product plan → denied here.
      const changes: ChangedPath[] = [];
      diffDocs(stored.document, params.document, [], changes);
      const blocked = changes.find(isProtectedChange);
      if (blocked !== undefined) {
        throw new RpcError(
          "POLICY_DENIED",
          `protected config change ${blocked.path.join(".")} requires a reviewed plan`,
          { field: blocked.path.join(".") },
        );
      }

      const nextRevision = String(BigInt(stored.revision) + 1n);
      const result = {
        revision: nextRevision,
        restart_required: changes.some((c) =>
          c.path[0] !== undefined && RESTART_SECTIONS.has(c.path[0]),
        ),
      };
      await ports.store.commit({
        mutation: {
          v: 1,
          kind: "kv",
          entries: [
            { key: KV_CONFIG_DOCUMENT, value: JSON.stringify(params.document) },
            { key: KV_CONFIG_REVISION, value: nextRevision },
          ],
        } as unknown as Json,
        result_sha256: sha256Hex(canonicalJson(result)),
      });
      return result;
    },
  };
}
