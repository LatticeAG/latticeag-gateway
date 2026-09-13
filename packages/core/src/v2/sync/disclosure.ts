/**
 * Gateway v2 sync — disclosure/redaction profiles (spec §9.1).
 *
 * Profiles:
 *  - `metadata` omits content objects and retains required visible
 *    envelope/inventory fields; every referenced object is marked
 *    WITHHELD.
 *  - `masked` creates a newly labeled sanitized projection object linked
 *    to the withheld original through an authorized NativeRef. Signed
 *    bytes are never edited in place — the projection is a new producer
 *    statement, not a "verifiable redacted original".
 *  - `full` includes only explicitly allowed referenced objects. A signed
 *    native envelope that itself carries confidential inline data is
 *    denied rather than exported to the cohort.
 *
 * Redaction keys apply case-insensitively at every structured depth, and
 * authorization/cookie/key patterns are scrubbed inside string values.
 * Even hashes, names, IDs, and object-existence markers require consent.
 * CIS/personal receipts are denied by default until both the personal-data
 * consent flag and a deletion-capable destination retention contract
 * satisfy INTERFACES E48 — the denial is raised before any object or
 * digest export (TV-GW-64).
 */

import { redactDeep } from "@latticeag/bus";
import { DEFAULT_REDACT_KEYS } from "@latticeag/events";
import type { Hash, NativeRef } from "../protocol/refs.js";
import type { StreamName, StreamProfile } from "../protocol/sync.js";

/** Marker replacing any withheld content object or unconsented digest. */
export const WITHHELD = "WITHHELD";
/** Schema label of every disclosure projection object. */
export const DISCLOSURE_SCHEMA = "gateway.disclosure/1";

/**
 * Key names redacted at every depth beyond the configured
 * `redaction.keys` — cookie/key material names called out by §9.1.
 * Matching is always case-insensitive.
 */
export const DISCLOSURE_REDACT_KEYS: readonly string[] = [
  ...DEFAULT_REDACT_KEYS,
  "cookie",
  "set-cookie",
  "x-api-key",
  "apikey",
  "api-secret",
  "access-key",
  "secret-key",
  "private-key",
  "client-secret",
  "access-token",
  "refresh-token",
  "id-token",
  "session-token",
  "credentials",
  "auth",
];

/**
 * Confidential patterns scrubbed inside string *values* (§9.1
 * "authorization/cookie/key patterns in strings"). Each match is replaced
 * by "[REDACTED]".
 */
export const SECRET_VALUE_PATTERNS: readonly RegExp[] = [
  /\bbearer\s+[A-Za-z0-9._~+/=-]{4,}/i,
  /\b(?:authorization|proxy-authorization)\s*:\s*[^\s;,}{]{4,}/i,
  /\b(?:cookie|set-cookie)\s*:\s*[^\s;]{4,}/i,
  /\b(?:api[-_]?key|api[-_]?secret|access[-_]?key|secret[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|access[-_]?token|refresh[-_]?token|session[-_]?token|id[-_]?token)\s*[:=]\s*["']?[^\s"',;}]{4,}/i,
];

/**
 * Disclosure consent flags (§9.1): even hashes, names, IDs, and
 * object-existence information require consent — all default to deny.
 */
export interface DisclosureConsent {
  /** include_objects stream flag — allows object bodies under "full". */
  readonly includeObjects?: boolean;
  /** May disclose hashes/digests. */
  readonly hashes?: boolean;
  /** May disclose names/IDs (source NativeRef identity). */
  readonly ids?: boolean;
  /** May disclose object-existence inventory markers. */
  readonly existence?: boolean;
  /** E48: explicit personal-data export consent. */
  readonly personalData?: boolean;
  /** E48: destination retention/deletion contract is deletion-capable. */
  readonly deletionContract?: boolean;
  /** Explicitly allowed object digests for the "full" profile. */
  readonly allowedObjects?: readonly string[];
  /** Extra redaction keys merged over the default set. */
  readonly redactKeys?: readonly string[];
  /** include_raw_text — false excludes raw prompt/completion/tool text. */
  readonly includeRawText?: boolean;
}

/** What may be projected for a stream. */
export interface DisclosureInput {
  /** Authorized reference to the (possibly withheld) original. */
  readonly source: NativeRef;
  /** Decoded source event/object — never mutated by projection. */
  readonly envelope: unknown;
  /** True when `envelope` is a signed native envelope. */
  readonly signed?: boolean;
  /** Content objects available for export, keyed by digest. */
  readonly objects?: Readonly<Record<string, unknown>>;
  /** CIS/personal receipt marker (INTERFACES E48). */
  readonly personal?: boolean;
  /** Consent snapshot bound to this disclosure (§9.1 consent revision). */
  readonly consent: DisclosureConsent;
}

/** One withheld object marker in a projection inventory. */
export interface WithheldEntry {
  readonly digest?: Hash;
  readonly availability: typeof WITHHELD;
}

/** Exported projection object (immutable payload source). */
export interface DisclosureProjection {
  readonly schema: typeof DISCLOSURE_SCHEMA;
  readonly profile: StreamProfile;
  readonly stream: StreamName;
  /** Link to the withheld original (masked) or the disclosed source. */
  readonly source: NativeRef | null;
  /** Sanitized visible envelope/inventory fields. */
  readonly body: unknown;
  /** Exported objects keyed by digest ("full" allowlist / masked copies). */
  readonly objects: Record<string, unknown>;
  /** Object-existence inventory, subject to the existence/hashes flags. */
  readonly withheld: WithheldEntry[];
}

export type DisclosureResult =
  | { readonly ok: true; readonly export: DisclosureProjection }
  | { readonly ok: false; readonly code: "POLICY_DENIED"; readonly reason: string };

/** Lowercase policy key set: defaults + consent-provided keys. */
function policyKeys(consent: DisclosureConsent): ReadonlySet<string> {
  const set = new Set<string>();
  for (const key of DISCLOSURE_REDACT_KEYS) set.add(key.toLowerCase());
  for (const key of consent.redactKeys ?? []) set.add(key.toLowerCase());
  return set;
}

/** Collect every object key occurring anywhere in the tree. */
function collectKeys(value: unknown, out: Set<string>): void {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, out);
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    out.add(key);
    collectKeys(nested, out);
  }
}

/**
 * Case-insensitive key redaction at every depth, built on `redactDeep`:
 * the exact-case key set handed to it is the subset of tree keys whose
 * lowercase form is in the policy set — equivalent to a case-insensitive
 * match without forking the bus redactor.
 */
function redactValue(
  value: unknown,
  lowerPolicy: ReadonlySet<string>,
  includeRawText: boolean,
): unknown {
  const encountered = new Set<string>();
  collectKeys(value, encountered);
  const exact = new Set<string>();
  for (const key of encountered) {
    if (lowerPolicy.has(key.toLowerCase())) exact.add(key);
  }
  const { value: redacted } = redactDeep(value, exact, includeRawText);
  return scrubStrings(redacted);
}

/** Replace secret patterns inside every string value, recursively. */
function scrubStrings(value: unknown): unknown {
  if (typeof value === "string") {
    let out = value;
    for (const pattern of SECRET_VALUE_PATTERNS) {
      out = out.replace(pattern, "[REDACTED]");
    }
    return out;
  }
  if (Array.isArray(value)) return value.map(scrubStrings);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      out[key] = scrubStrings(nested);
    }
    return out;
  }
  return value;
}

/**
 * True when the tree contains confidential inline data: a key matching
 * the redaction policy at any depth, or a string matching a secret
 * pattern. Used to deny export of signed envelopes we may not edit.
 */
export function containsSensitive(
  value: unknown,
  consent: Pick<DisclosureConsent, "redactKeys">,
): boolean {
  const lower = policyKeys(consent);
  const walk = (v: unknown): boolean => {
    if (typeof v === "string") {
      return SECRET_VALUE_PATTERNS.some((p) => p.test(v));
    }
    if (Array.isArray(v)) return v.some(walk);
    if (v !== null && typeof v === "object") {
      return Object.entries(v).some(
        ([key, nested]) => lower.has(key.toLowerCase()) || walk(nested),
      );
    }
    return false;
  };
  return walk(value);
}

function denied(reason: string): DisclosureResult {
  return { ok: false, code: "POLICY_DENIED", reason };
}

function inventory(
  digests: readonly string[],
  consent: DisclosureConsent,
): WithheldEntry[] {
  if (consent.existence !== true) return [];
  return digests.map((digest) => ({
    ...(consent.hashes === true ? { digest } : {}),
    availability: WITHHELD,
  }));
}

/**
 * Project one source event/object for a stream under its consent record
 * and profile. Pure: never mutates the input, never performs IO.
 *
 * Denials (all POLICY_DENIED, raised before any object/digest export):
 *  - personal/CIS content without both E48 consent flags;
 *  - a signed envelope carrying confidential inline data under "full"
 *    (the envelope may not be edited in place and may not leak).
 */
export function projectForStream(
  stream: StreamName,
  item: DisclosureInput,
  profile: StreamProfile,
): DisclosureResult {
  const consent = item.consent;
  // E48: personal receipts are denied by default — before any
  // object/digest export, and before hashes/names/existence are emitted.
  if (item.personal === true) {
    if (consent.personalData !== true || consent.deletionContract !== true) {
      return denied(
        "personal receipt export requires explicit consent and a " +
          "deletion-capable destination retention contract (E48)",
      );
    }
  }
  // A signed native envelope containing confidential inline data may not
  // be exported to this cohort under "full" — no claim of a fully
  // verifiable redacted original is permitted.
  if (
    profile === "full" &&
    item.signed === true &&
    containsSensitive(item.envelope, consent)
  ) {
    return denied(
      "signed envelope contains confidential inline data; export denied",
    );
  }

  const objects = item.objects ?? {};
  const digests = Object.keys(objects).sort();
  const includeRawText = consent.includeRawText === true;
  const lower = policyKeys(consent);
  const source = consent.ids === false ? null : item.source;

  if (profile === "full") {
    const allowed = new Set(consent.allowedObjects ?? []);
    const exported: Record<string, unknown> = {};
    const held: string[] = [];
    for (const digest of digests) {
      if (consent.includeObjects === true && allowed.has(digest)) {
        exported[digest] = objects[digest];
      } else {
        held.push(digest);
      }
    }
    // A signed envelope with no confidential inline data is exported
    // verbatim; unsigned content is string-scrubbed defensively.
    const body =
      item.signed === true
        ? item.envelope
        : redactValue(item.envelope, lower, includeRawText);
    return {
      ok: true,
      export: {
        schema: DISCLOSURE_SCHEMA,
        profile,
        stream,
        source,
        body,
        objects: exported,
        withheld: inventory(held, consent),
      },
    };
  }

  if (profile === "masked") {
    // New sanitized projection object linked to the withheld original via
    // an authorized NativeRef — never an edit of signed bytes.
    const maskedObjects: Record<string, unknown> = {};
    for (const digest of digests) {
      maskedObjects[digest] = {
        schema: DISCLOSURE_SCHEMA,
        projection_of: consent.hashes === true ? digest : WITHHELD,
        body: redactValue(objects[digest], lower, includeRawText),
      };
    }
    return {
      ok: true,
      export: {
        schema: DISCLOSURE_SCHEMA,
        profile,
        stream,
        source: item.source,
        body: redactValue(item.envelope, lower, includeRawText),
        objects: maskedObjects,
        withheld: inventory(digests, consent),
      },
    };
  }

  // metadata: content objects omitted; visible envelope/inventory fields
  // retained with redaction applied.
  return {
    ok: true,
    export: {
      schema: DISCLOSURE_SCHEMA,
      profile: "metadata",
      stream,
      source,
      body: redactValue(item.envelope, lower, includeRawText),
      objects: {},
      withheld: inventory(digests, consent),
    },
  };
}
