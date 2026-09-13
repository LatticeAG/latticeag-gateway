/**
 * Bounded SemVer machinery for the product lifecycle engine (spec §5.1,
 * §5.3). Dependency ranges are validated by `validateRange` in
 * ../protocol/product.js; this module adds the comparator/hyphen/caret
 * *satisfaction* check plus the looser partial-version comparator grammar
 * used for `runtime.node` ranges (e.g. `">=22.13 <25"`).
 *
 * No wildcards, no `latest`, no floating refs — those are rejected upstream
 * by validateRange before satisfaction is ever computed.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  /** Prerelease identifiers; empty array = release. */
  pre: string[];
  /** Build metadata (ignored by precedence). */
  build: string[];
}

const NUMERIC_RE = /^\d+$/;

const FULL_VERSION_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/** Parse an exact SemVer string; null when not strict `x.y.z[-pre][+build]`. */
export function parseSemver(input: string): SemVer | null {
  const m = FULL_VERSION_RE.exec(input);
  if (!m) return null;
  const [, major, minor, patch, pre, build] = m;
  const v: SemVer = {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
    pre: pre ? pre.split(".") : [],
    build: build ? build.split(".") : [],
  };
  if (!Number.isSafeInteger(v.major) || !Number.isSafeInteger(v.minor) || !Number.isSafeInteger(v.patch)) {
    return null;
  }
  return v;
}

/** Partial `x[.y[.z]][-pre][+build]` used only inside node comparators. */
const PARTIAL_RE =
  /^(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

interface PartialVer {
  parts: number[]; // 1–3 numeric components present
  pre: string[];
}

function parsePartial(input: string): PartialVer | null {
  const m = PARTIAL_RE.exec(input);
  if (!m) return null;
  const parts = [m[1], m[2], m[3]]
    .filter((p): p is string => p !== undefined)
    .map(Number);
  if (parts.some((p) => !Number.isSafeInteger(p))) return null;
  return { parts, pre: m[4] ? m[4].split(".") : [] };
}

function pad(v: PartialVer): SemVer {
  return {
    major: v.parts[0] ?? 0,
    minor: v.parts[1] ?? 0,
    patch: v.parts[2] ?? 0,
    pre: v.pre,
    build: [],
  };
}

/**
 * SemVer precedence (build metadata ignored): numeric core, then prerelease
 * — a release outranks its prereleases; numeric identifiers compare
 * numerically and sort below alphanumeric; a shorter identifier list that
 * is a prefix sorts lower.
 */
export function compareSemver(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1; // release > prerelease
  if (b.pre.length === 0) return -1;
  const n = Math.min(a.pre.length, b.pre.length);
  for (let i = 0; i < n; i += 1) {
    const x = a.pre[i]!;
    const y = b.pre[i]!;
    if (x === y) continue;
    const xn = NUMERIC_RE.test(x);
    const yn = NUMERIC_RE.test(y);
    if (xn && yn) {
      const xi = Number(x);
      const yi = Number(y);
      return xi < yi ? -1 : 1;
    }
    if (xn) return -1; // numeric < alphanumeric
    if (yn) return 1;
    return x < y ? -1 : 1;
  }
  if (a.pre.length === b.pre.length) return 0;
  return a.pre.length < b.pre.length ? -1 : 1;
}

type Bound = { v: SemVer; inclusive: boolean };

function satisfyBound(v: SemVer, bound: Bound, upper: boolean): boolean {
  const c = compareSemver(v, bound.v);
  if (upper) return bound.inclusive ? c <= 0 : c < 0;
  return bound.inclusive ? c >= 0 : c > 0;
}

/**
 * Translate one comparator (`op` + possibly-partial version) into
 * lower/upper bounds using npm partial-version semantics:
 *  - `>1.2`  means >1.2.x  → `>=1.3.0`
 *  - `<=1.2` means <=1.2.x → `<1.3.0`
 *  - `=1.2` / bare `1.2`   → `>=1.2.0 <1.3.0`
 *  - `<1.2`  means `<1.2.0`
 * Missing components in the version are wildcards, never `*`-tokens.
 */
function comparatorBounds(
  op: string,
  pv: PartialVer,
): { lower: Bound | null; upper: Bound | null } {
  const p = pv.parts;
  const bumped = (parts: number[]): SemVer => ({
    major: parts[0] ?? 0,
    minor: parts[1] ?? 0,
    patch: parts[2] ?? 0,
    pre: [],
    build: [],
  });
  // Next version at the first missing component boundary.
  const nextAfter = (): SemVer => {
    if (p.length >= 3) return bumped([p[0]!, p[1]!, p[2]! + 1]);
    if (p.length === 2) return bumped([p[0]!, p[1]! + 1, 0]);
    return bumped([p[0]! + 1, 0, 0]);
  };
  switch (op) {
    case ">":
      if (p.length < 3) return { lower: { v: nextAfter(), inclusive: true }, upper: null };
      return { lower: { v: pad(pv), inclusive: false }, upper: null };
    case ">=":
      return { lower: { v: pad(pv), inclusive: true }, upper: null };
    case "<":
      return { lower: null, upper: { v: pad({ ...pv, pre: [] }), inclusive: false } };
    case "<=":
      if (p.length < 3) return { lower: null, upper: { v: nextAfter(), inclusive: false } };
      return { lower: null, upper: { v: pad(pv), inclusive: true } };
    case "=":
    case "":
      if (p.length < 3 || pv.pre.length > 0) {
        return {
          lower: { v: pad(pv), inclusive: true },
          upper: { v: nextAfter(), inclusive: false },
        };
      }
      return {
        lower: { v: pad(pv), inclusive: true },
        upper: { v: pad(pv), inclusive: true },
      };
    default:
      return { lower: null, upper: null };
  }
}

/** `^x[.y[.z]]` — compatible-within-major (0.x rules tighten the bound). */
function caretBounds(pv: PartialVer): { lower: Bound; upper: Bound } {
  const p = pv.parts;
  const lower: Bound = { v: pad(pv), inclusive: true };
  const mk = (major: number, minor: number, patch: number): SemVer => ({
    major,
    minor,
    patch,
    pre: [],
    build: [],
  });
  if ((p[0] ?? 0) > 0 || p.length === 1) {
    return { lower, upper: { v: mk((p[0] ?? 0) + 1, 0, 0), inclusive: false } };
  }
  if ((p[1] ?? 0) > 0 || p.length === 2) {
    return { lower, upper: { v: mk(0, (p[1] ?? 0) + 1, 0), inclusive: false } };
  }
  return { lower, upper: { v: mk(0, 0, (p[2] ?? 0) + 1), inclusive: false } };
}

/** `~x[.y[.z]]` — within the minor (or major when only x given). */
function tildeBounds(pv: PartialVer): { lower: Bound; upper: Bound } {
  const p = pv.parts;
  const lower: Bound = { v: pad(pv), inclusive: true };
  const upper: Bound = {
    v:
      p.length <= 1
        ? { major: (p[0] ?? 0) + 1, minor: 0, patch: 0, pre: [], build: [] }
        : { major: p[0] ?? 0, minor: (p[1] ?? 0) + 1, patch: 0, pre: [], build: [] },
    inclusive: false,
  };
  return { lower, upper };
}

const COMPARATOR_TOKEN_RE = /^(>=|>|<=|<|=)?(.+)$/;

/**
 * Test whether `version` satisfies `range`. Supported grammar (the same
 * forms `validateRange` admits for dependencies, plus partial versions
 * when `allowPartial` is set — used for `runtime.node`):
 *  - exact version (partial only with allowPartial)
 *  - hyphen range `a.b.c - d.e.f`
 *  - `^` / `~` ranges
 *  - space/comma-separated comparator sets (`>=22.13 <25`)
 */
export function satisfiesSemver(
  version: string | SemVer,
  range: string,
  opts?: { allowPartial?: boolean },
): boolean {
  const v = typeof version === "string" ? parseSemver(stripV(version)) : version;
  if (v === null) return false;
  const allowPartial = opts?.allowPartial === true;
  const r = range.trim();
  if (r.length === 0) return false;

  // Hyphen range — both ends must be exact versions.
  const hy = r.split(" - ");
  if (hy.length === 2) {
    const lo = parseSemver(hy[0]!.trim());
    const hi = parseSemver(hy[1]!.trim());
    if (lo === null || hi === null) return false;
    return compareSemver(v, lo) >= 0 && compareSemver(v, hi) <= 0;
  }

  // Caret / tilde.
  if (r.startsWith("^") || r.startsWith("~")) {
    const pv = allowPartial ? parsePartial(r.slice(1)) : strictPartial(r.slice(1));
    if (pv === null) return false;
    const { lower, upper } = r.startsWith("^") ? caretBounds(pv) : tildeBounds(pv);
    return satisfyBound(v, lower, false) && satisfyBound(v, upper, true);
  }

  // Comparator set (or single comparator / bare version).
  const tokens = r.split(/[\s,]+/).filter((t) => t.length > 0);
  if (tokens.length === 0) return false;
  for (const token of tokens) {
    const m = COMPARATOR_TOKEN_RE.exec(token);
    if (!m) return false;
    const op = m[1] ?? "";
    const pv = allowPartial ? parsePartial(m[2]!) : strictPartial(m[2]!);
    if (pv === null) return false;
    const { lower, upper } = comparatorBounds(op, pv);
    if (lower !== null && !satisfyBound(v, lower, false)) return false;
    if (upper !== null && !satisfyBound(v, upper, true)) return false;
  }
  return true;
}

/** Partial parse that requires all three components (dependency domain). */
function strictPartial(input: string): PartialVer | null {
  const pv = parsePartial(input);
  return pv !== null && pv.parts.length === 3 ? pv : null;
}

/** Strip a leading `v` (Node `process.version`) before range checks. */
export function stripV(version: string): string {
  return version.startsWith("v") ? version.slice(1) : version;
}

const NODE_RANGE_MAX = 256;

/**
 * Validate a `runtime.node` range: the comparator-set grammar with partial
 * versions allowed (fixture uses `">=22.13 <25"`). Returns a reason when
 * the range is not a bounded node selector.
 */
export function validateNodeRange(range: unknown): { ok: true } | { ok: false; reason: string } {
  if (typeof range !== "string") return { ok: false, reason: "node range must be a string" };
  const r = range.trim();
  if (r.length === 0) return { ok: false, reason: "node range must be nonempty" };
  if (r.length > NODE_RANGE_MAX) return { ok: false, reason: "node range exceeds 256 characters" };
  if (/[x*]/.test(r) || /latest/i.test(r) || r.includes("://") || r.includes("#")) {
    return { ok: false, reason: "node range must be bounded (no wildcards/latest/URLs)" };
  }
  if (r.includes(" - ")) {
    const parts = r.split(" - ");
    if (parts.length !== 2 || parts.some((p) => parseSemver(p.trim()) === null)) {
      return { ok: false, reason: "hyphen range needs exact versions on both ends" };
    }
    return { ok: true };
  }
  const tokens = r.split(/[\s,]+/).filter((t) => t.length > 0);
  if (tokens.length === 0) return { ok: false, reason: "node range must be nonempty" };
  for (const token of tokens) {
    if (token.startsWith("^") || token.startsWith("~")) {
      if (parsePartial(token.slice(1)) === null) {
        return { ok: false, reason: `malformed node comparator "${token}"` };
      }
      continue;
    }
    const m = COMPARATOR_TOKEN_RE.exec(token);
    if (!m || parsePartial(m[2]!) === null) {
      return { ok: false, reason: `malformed node comparator "${token}"` };
    }
  }
  return { ok: true };
}

/** Satisfied `runtime.node` check (partial comparators allowed). */
export function satisfiesNode(nodeVersion: string, range: string): boolean {
  return satisfiesSemver(stripV(nodeVersion), range, { allowPartial: true });
}
