/** Display formatting — all plain text, no HTML. */

export function fmtTime(ms: number | string | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  const n = typeof ms === "string" ? Number(ms) : ms;
  if (!Number.isFinite(n)) return "—";
  return new Date(n).toLocaleTimeString([], { hour12: false });
}

export function fmtDateTime(ms: number | string | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  const n = typeof ms === "string" ? Number(ms) : ms;
  if (!Number.isFinite(n)) return "—";
  const d = new Date(n);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour12: false })}`;
}

export function fmtAge(ms: number | null | undefined, now = Date.now()): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "—";
  const s = Math.max(0, Math.floor((now - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function fmtCount(v: number | null | undefined): string {
  return v === null || v === undefined ? "—" : String(v);
}

/** Middle-ellipsize a long id/hash for table cells. */
export function shortId(id: string | null | undefined, head = 12, tail = 6): string {
  if (id === null || id === undefined) return "—";
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}

/** Hex fingerprint display grouped in 4s, e.g. `ab12 cd34 …`. */
export function fingerprint(hex: string | null | undefined): string {
  if (!hex) return "—";
  const clean = hex.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  const groups = clean.match(/.{1,4}/g) ?? [];
  return groups.join(" ");
}

export function fmtBytes(n: unknown): string {
  if (n === null || n === undefined) return "—";
  const v = typeof n === "string" ? Number(n) : typeof n === "number" ? n : NaN;
  if (!Number.isFinite(v)) return "—";
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KiB`;
  return `${(v / (1024 * 1024)).toFixed(1)} MiB`;
}

/** Coerce an unknown JSON value to a short printable string. */
export function show(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
