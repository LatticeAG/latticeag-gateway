/**
 * ConnectionBanner — §7.1 "disconnected banner" + §7.2 "a stale/
 * disconnected UI disables mutations immediately". Announce via a
 * throttled polite live region; hidden while the daemon is reachable.
 */
import { h, clear, append } from "../lib/dom.js";
import type { ConnectionPhase } from "../lib/state.js";
import { fmtTime } from "../lib/format.js";

export interface BannerState {
  phase: ConnectionPhase;
  daemonState: string | null;
  detail: string;
  lastOkMs: number;
  streamStale?: boolean;
}

export class ConnectionBanner {
  readonly el: HTMLElement;
  private lastAnnounced = "";
  private lastAnnounceMs = 0;

  constructor(private readonly now: () => number = Date.now) {
    this.el = h("div", {
      class: "conn-banner",
      role: "status",
      aria: { live: "polite" },
      hidden: true,
    });
  }

  update(s: BannerState): void {
    const stale = s.streamStale === true;
    let tone: "err" | "warn" | "ok" = "ok";
    let text = "";
    let visible = true;
    switch (s.phase) {
      case "offline":
        tone = "err";
        text = `Disconnected — ${s.detail || "daemon unreachable"}. Mutations are disabled; nothing will be retried or approved automatically on reconnect.`;
        break;
      case "degraded":
        tone = "warn";
        text = `Daemon ${s.daemonState ?? "DEGRADED"}${s.detail ? ` — ${s.detail}` : ""}`;
        break;
      case "connecting":
        tone = "warn";
        text = "Connecting…";
        break;
      case "online":
        if (stale) {
          tone = "warn";
          text = "Live stream is stale — no heartbeat for 45s. Data shown may lag; check the stream.";
        } else if (s.daemonState !== null && s.daemonState !== "READY") {
          tone = "warn";
          text = `Daemon state: ${s.daemonState}`;
        } else {
          visible = false;
        }
        break;
    }
    if (s.phase === "online" && s.lastOkMs > 0 && visible) {
      text += ` (last ok ${fmtTime(s.lastOkMs)})`;
    }
    // Throttle announcements: identical text re-announces at most 1/5 s.
    if (visible && text === this.lastAnnounced && this.now() - this.lastAnnounceMs < 5_000) {
      return;
    }
    if (visible) {
      this.lastAnnounced = text;
      this.lastAnnounceMs = this.now();
    }
    clear(this.el);
    if (!visible) {
      this.el.setAttribute("hidden", "");
      return;
    }
    this.el.removeAttribute("hidden");
    this.el.dataset.tone = tone;
    append(this.el, h("span", { text }));
  }
}
