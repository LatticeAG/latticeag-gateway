/**
 * Egress guard (spec §9.4 / TV-GW-43).
 *
 * Every URL the daemon would connect to outbound — catalog index fetches,
 * sync destinations, redirect hops — must pass `assertEgressUrlAllowed`
 * *before* connect: HTTPS only, no userinfo, and never a loopback /
 * private / link-local / CGNAT / documentation / multicast / reserved
 * address or a localhost-style name. A denied URL throws
 * `NETWORK_DENIED` synchronously: no connection is opened and no DNS
 * lookup is performed (the guard runs before the transport is invoked).
 *
 * `egressFetch` follows redirects itself (bounded by
 * `EGRESS_MAX_REDIRECTS`), re-validating every hop: a redirect to a
 * private/metadata address never reaches the transport, and credentials
 * (`Authorization`, `Cookie`, `Proxy-Authorization`, `X-API-Key`) are
 * sent only to the origin of the initial request — never across origins.
 */
import { RpcError } from "../core-v2.js";

/** Maximum redirect hops followed per request (spec §9.4 bound). */
export const EGRESS_MAX_REDIRECTS = 2;

/** Headers that must never cross an origin boundary. */
const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "x-api-key",
]);

/** Hostname suffixes that must never be connected to. */
const DENIED_HOST_SUFFIXES = [
  "localhost",
  "localhost.localdomain",
  "local",
  "internal",
  "home.arpa",
  "corp",
  "lan",
  "intranet",
];

/**
 * Denied IPv4 ranges as `[octet0, octet1Min, octet1Max]` triples. Covers
 * unspecified, loopback, RFC-1918, link-local/metadata, CGNAT,
 * documentation, benchmarking, and reserved space; octet0 ≥ 224
 * (multicast + reserved + broadcast) is denied separately.
 */
const DENIED_V4: ReadonlyArray<readonly [number, number, number]> = [
  [0, 0, 255], // 0.0.0.0/8 "this network" / unspecified
  [10, 0, 255], // 10.0.0.0/8
  [100, 64, 127], // 100.64.0.0/10 CGNAT
  [127, 0, 255], // 127.0.0.0/8 loopback
  [169, 254, 254], // 169.254.0.0/16 link-local incl. .169.254 metadata
  [172, 16, 31], // 172.16.0.0/12
  [192, 0, 0], // 192.0.0.0/24 IETF protocol assignments
  [192, 0, 2], // 192.0.2.0/24 documentation
  [192, 168, 168], // 192.168.0.0/16
  [198, 18, 19], // 198.18.0.0/15 benchmarking
  [198, 51, 51], // 198.51.100.0/24 documentation
  [203, 0, 0], // 203.0.113.0/24 documentation
];

function parseIPv4(host: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (m === null) return null;
  const parts = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  return parts.every((p) => p <= 255) ? (parts as [number, number, number, number]) : null;
}

function ipv4Denied(ip: [number, number, number, number]): boolean {
  if (ip[0] >= 224) return true; // multicast 224/4 + reserved 240/4 + broadcast
  return DENIED_V4.some(([a, lo, hi]) => ip[0] === a && ip[1] >= lo && ip[1] <= hi);
}

/**
 * Parse an IPv6 literal (without brackets) to eight 16-bit groups.
 * Handles `::` compression and an embedded dotted IPv4 tail.
 */
function parseIPv6(host: string): number[] | null {
  let h = host.toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(h)) return null;
  // Embedded IPv4 tail: ::ffff:1.2.3.4 → groups + 2 v4-derived groups.
  const v4tail = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(h);
  let v4groups: number[] = [];
  if (v4tail !== null) {
    const ip = parseIPv4(v4tail[1] ?? "");
    if (ip === null) return null;
    v4groups = [(ip[0] << 8) | ip[1], (ip[2] << 8) | ip[3]];
    h = h.slice(0, h.length - (v4tail[1] ?? "").length);
    if (h.endsWith(":") && !h.endsWith("::")) h = h.slice(0, -1);
  }
  const halves = h.split("::");
  if (halves.length > 2) return null;
  const head = (halves[0] ?? "").split(":").filter((s) => s !== "");
  const tail = halves.length === 2 ? (halves[1] ?? "").split(":").filter((s) => s !== "") : [];
  const groups: number[] = [];
  for (const part of [...head, ...tail]) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    groups.push(parseInt(part, 16));
  }
  const total = groups.length + v4groups.length;
  if (halves.length === 2) {
    const zeros = 8 - total;
    if (zeros < 0) return null;
    return [...groups.slice(0, head.length), ...Array(zeros).fill(0), ...groups.slice(head.length), ...v4groups];
  }
  if (total !== 8) return null;
  return [...groups, ...v4groups];
}

function ipv6Denied(groups: number[]): boolean {
  const g0 = groups[0] ?? 0;
  const g1 = groups[1] ?? 0;
  const g5 = groups[5] ?? 0;
  const g6 = groups[6] ?? 0;
  const g7 = groups[7] ?? 0;
  // ::/128 unspecified and ::1/128 loopback
  if (groups.slice(0, 7).every((g) => g === 0) && (g7 === 0 || g7 === 1)) return true;
  // IPv4-mapped ::ffff:a.b.c.d — policy of the embedded v4 applies.
  if (groups.slice(0, 5).every((g) => g === 0) && g5 === 0xffff) {
    return ipv4Denied([
      (g6 >> 8) & 0xff,
      g6 & 0xff,
      (g7 >> 8) & 0xff,
      g7 & 0xff,
    ]);
  }
  if (g0 === 0x2001 && (g1 === 0x0db8 || g1 === 0x0000)) return true; // doc + Teredo
  if (g0 === 0x2002) return true; // 6to4 embeds a v4
  if (g0 === 0x0064 && g1 === 0xff9b) return true; // NAT64 WKP embeds a v4
  if ((g0 & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((g0 & 0xfe00) === 0xfc00) return true; // ULA fc00::/7
  if ((g0 & 0xff00) === 0xff00) return true; // multicast ff00::/8
  return false;
}

function hostDenied(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  if (h === "") return true;
  const v4 = parseIPv4(h);
  if (v4 !== null) return ipv4Denied(v4);
  if (h.startsWith("[") && h.endsWith("]")) {
    const v6 = parseIPv6(h.slice(1, -1));
    return v6 === null ? true : ipv6Denied(v6);
  }
  if (h.includes(":")) {
    const v6 = parseIPv6(h);
    return v6 === null ? true : ipv6Denied(v6);
  }
  for (const suffix of DENIED_HOST_SUFFIXES) {
    if (h === suffix || h.endsWith(`.${suffix}`)) return true;
  }
  return false;
}

/**
 * Validate an outbound URL against egress policy. Returns the normalized
 * `URL` when allowed; throws `RpcError NETWORK_DENIED` otherwise — before
 * any connection or DNS lookup can happen.
 */
export function assertEgressUrlAllowed(raw: string | URL): URL {
  let url: URL;
  try {
    url = raw instanceof URL ? raw : new URL(raw);
  } catch {
    throw new RpcError("NETWORK_DENIED", "egress url is not parseable", { field: "url" });
  }
  if (url.protocol !== "https:") {
    throw new RpcError("NETWORK_DENIED", "egress requires https", { field: "url" });
  }
  if (url.username !== "" || url.password !== "") {
    throw new RpcError("NETWORK_DENIED", "egress url must not carry userinfo", { field: "url" });
  }
  if (hostDenied(url.hostname)) {
    throw new RpcError("NETWORK_DENIED", "egress destination is not permitted", { field: "url" });
  }
  return url;
}

export interface EgressRequest {
  headers?: Record<string, string>;
}

export interface EgressResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Uint8Array;
}

/** One HTTP(S) round trip; must NOT follow redirects itself. */
export type EgressTransport = (url: URL, req: EgressRequest) => Promise<EgressResponse>;

/**
 * Hostname → resolved IP literals (DNS seam for tests and for the daemon's
 * pinned resolver). Called only AFTER the URL's literal checks pass; any
 * denied resolved address fails the whole request before connect — a
 * rebinding hostname never reaches the transport.
 */
export type EgressResolver = (hostname: string) => Promise<readonly string[]>;

function isAddressLiteral(host: string): boolean {
  return (
    parseIPv4(host) !== null ||
    (host.startsWith("[") && host.endsWith("]")) ||
    host.includes(":")
  );
}

/**
 * When `resolve` is bound, apply the address policy to every A/AAAA the
 * hostname yields. Literal hosts are already checked by
 * `assertEgressUrlAllowed` and are never resolved here.
 */
async function checkResolvedAddresses(
  url: URL,
  resolve?: EgressResolver,
): Promise<void> {
  if (resolve === undefined) return;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (host === "" || isAddressLiteral(host)) return;
  for (const addr of await resolve(host)) {
    const literal = addr.replace(/^\[|\]$/g, "");
    const v4 = parseIPv4(literal);
    const denied =
      v4 !== null
        ? ipv4Denied(v4)
        : (() => {
            const v6 = parseIPv6(literal);
            return v6 === null ? true : ipv6Denied(v6);
          })();
    if (denied) {
      throw new RpcError(
        "NETWORK_DENIED",
        `egress host ${host} resolves to a denied address`,
        { field: "url" },
      );
    }
  }
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/** Default transport: one manual-redirect fetch (no auto-follow). */
async function defaultTransport(url: URL, req: EgressRequest): Promise<EgressResponse> {
  const res = await fetch(url, { redirect: "manual", headers: req.headers });
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    headers[k] = v;
  });
  return { status: res.status, headers, body: new Uint8Array(await res.arrayBuffer()) };
}

/**
 * Fetch `start` through the egress guard: every URL — initial and each
 * redirect hop (≤ `EGRESS_MAX_REDIRECTS`) — is validated before the
 * transport sees it, and sensitive headers are dropped the moment a hop
 * crosses origins. A denied hop throws `NETWORK_DENIED` without touching
 * the network.
 */
export async function egressFetch(
  start: string | URL,
  transport: EgressTransport = defaultTransport,
  opts: {
    headers?: Record<string, string>;
    maxRedirects?: number;
    /** DNS seam: resolved addresses are policy-checked before connect. */
    resolve?: EgressResolver;
  } = {},
): Promise<EgressResponse> {
  const maxRedirects = opts.maxRedirects ?? EGRESS_MAX_REDIRECTS;
  let url = assertEgressUrlAllowed(start);
  const initialOrigin = url.origin;
  let redirects = 0;
  for (;;) {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(opts.headers ?? {})) {
      if (url.origin !== initialOrigin && SENSITIVE_HEADERS.has(k.toLowerCase())) continue;
      headers[k] = v;
    }
    await checkResolvedAddresses(url, opts.resolve);
    const res = await transport(url, { headers });
    if (!REDIRECT_STATUS.has(res.status)) return res;
    redirects += 1;
    if (redirects > maxRedirects) {
      throw new RpcError("NETWORK_DENIED", "egress redirect limit exceeded", { field: "redirect" });
    }
    const location = res.headers.location;
    const target = Array.isArray(location) ? location[0] : location;
    if (target === undefined || target === "") {
      throw new RpcError("NETWORK_DENIED", "egress redirect has no location", { field: "redirect" });
    }
    url = assertEgressUrlAllowed(new URL(target, url));
  }
}
