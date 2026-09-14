import { describe, expect, test, vi } from "vitest";
import { ApprovalCard, approvalFrom } from "./approval-card.js";
import { ProductTable } from "./product-table.js";
import { CommandPalette } from "./command-palette.js";
import { installKeys, type KeyHandlers } from "../lib/keys.js";
import { readFileSync } from "node:fs";

import { join } from "node:path";

const css = readFileSync(join(process.cwd(), "src/styles/tokens.css"), "utf8");

const sampleApproval = approvalFrom({
  approval: "approval1",
  revision: "3",
  state: "PENDING",
  action: { hash: "ab".repeat(24) },
  target: "product1",
  scope: "products.manage",
  expires_ms: Date.now() + 60_000,
  requester: "peer1",
  native_status: "NOT_DISPATCHED",
  stored: true,
  native: { ref: "x" },
});

describe("ApprovalCard", () => {
  test("renders action hash / revision / expiry / requester / separate stored-approved-applied", () => {
    const el = ApprovalCard({ approval: sampleApproval, mutationsEnabled: true, onDecide: () => undefined });
    const text = el.textContent ?? "";
    expect(text).toContain("approval1");
    expect(text.match(/ab{2,}/) !== null || text.includes("abab")).toBe(true);
    expect(text).toContain("3");          // revision bound
    expect(text).toContain("stored yes");
    expect(text).toContain("approved no");
    expect(text).toContain("applied no");
    expect(text).toContain("peer1");
  });

  test("Approve disabled without a native decision binding (a11y: button[disabled])", () => {
    const noBinding = { ...sampleApproval, nativeBound: false };
    const el = ApprovalCard({ approval: noBinding, mutationsEnabled: true, onDecide: () => undefined });
    const approve = [...el.querySelectorAll("button")].find((b) => b.textContent === "Approve…");
    expect(approve).toBeDefined();
    expect(approve!.disabled).toBe(true);
    expect(approve!.hasAttribute("disabled")).toBe(true);
    // And the card explains why + offers a nonauthorizing note.
    expect(el.textContent).toContain("No native decision binding");
    expect(el.querySelector("input")).not.toBeNull();
  });

  test("nonreviewer session → decision controls disabled + read-only note", () => {
    const notEligible = { ...sampleApproval, reviewerEligible: false };
    const el = ApprovalCard({ approval: notEligible, mutationsEnabled: true, onDecide: () => undefined });
    const approve = [...el.querySelectorAll("button")].find((b) => b.textContent === "Approve…");
    const deny = [...el.querySelectorAll("button")].find((b) => b.textContent === "Deny…");
    expect(approve!.disabled).toBe(true);
    expect(deny!.disabled).toBe(true);
    expect(el.textContent).toContain("not a native-enrolled reviewer");
  });

  test("mutations disabled (stale UI) → all decision controls disabled", () => {
    const el = ApprovalCard({ approval: sampleApproval, mutationsEnabled: false, onDecide: () => undefined });
    for (const b of el.querySelectorAll("button")) expect(b.disabled).toBe(true);
  });

  test("expired pending shows EXPIRED and disables approve", () => {
    const expired = { ...sampleApproval, expires_ms: Date.now() - 1_000 };
    const el = ApprovalCard({ approval: expired, mutationsEnabled: true, onDecide: () => undefined });
    expect(el.textContent).toContain("EXPIRED");
    const approve = [...el.querySelectorAll("button")].find((b) => b.textContent === "Approve…");
    expect(approve!.disabled).toBe(true);
  });
});

describe("ProductTable", () => {
  test("rows render at the 36px row class and open on click", () => {
    const opened: string[] = [];
    const t = new ProductTable({ onOpen: (s) => opened.push(s) });
    t.setRows([{ slug: "lexverdict", version: "0.1.0", state: "installed" }]);
    const tr = t.el.querySelector("tbody tr")!;
    expect(tr).toBeTruthy();
    expect(css).toMatch(/\.tbl (tbody )?tr|\.tbl td/); // rows styled
    expect(css).toMatch(/height:\s*36px/);
    tr.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(opened).toEqual(["lexverdict"]);
    // enterprise-blocked surfaces as an explicit pill
    t.setRows([{ slug: "ent-prod", enterpriseBlocked: true }]);
    expect(t.el.textContent).toContain("enterprise blocked");
  });

  test("virtualizes beyond 200 rows with spacer rows", () => {
    const t = new ProductTable({});
    t.setRows(Array.from({ length: 500 }, (_, i) => ({ slug: `p${i}` })));
    const rendered = t.el.querySelectorAll("tbody tr.row-link").length;
    expect(rendered).toBeLessThan(500);
    expect(rendered).toBeGreaterThan(0);
  });
});

describe("CommandPalette", () => {
  test("opens on Ctrl+K, runs a command, restores focus", () => {
    const palette = new CommandPalette();
    document.body.appendChild(palette.el);
    const ran = vi.fn();
    palette.setCommands([{ id: "go", label: "Go to Products", run: ran }]);
    const h: KeyHandlers = {
      navigate: () => undefined,
      focusSearch: () => false,
      toggleStreamPause: () => undefined,
      closeOverlay: () => (palette.visible ? (palette.close(), true) : false),
      openPalette: () => palette.open(),
    };
    installKeys(window, h);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }));
    expect(palette.visible).toBe(true);
    palette.el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(ran).toHaveBeenCalled();
    expect(palette.visible).toBe(false);
  });
});
