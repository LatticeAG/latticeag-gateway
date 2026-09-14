/**
 * DisclosureBadge — egress/disclosure level pill: HASHES_ONLY, REDACTED,
 * FULL, WITHHELD. Text+glyph, never color alone.
 */
import { pill } from "../lib/dom.js";

const TONE: Readonly<Record<string, "ok" | "warn" | "err" | "accent" | "muted">> = {
  HASHES_ONLY: "ok",
  REDACTED: "warn",
  FULL: "accent",
  WITHHELD: "warn",
  METADATA: "muted",
};

const GLYPH: Readonly<Record<string, string>> = {
  HASHES_ONLY: "#",
  REDACTED: "▒",
  FULL: "◆",
  WITHHELD: "◌",
  METADATA: "≡",
};

export function DisclosureBadge(props: { level: string }): HTMLElement {
  const level = props.level.toUpperCase();
  return pill(`disclosure ${level}`, TONE[level] ?? "muted", GLYPH[level] ?? "○");
}
