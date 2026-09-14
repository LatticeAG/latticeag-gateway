import { describe, expect, test } from "vitest";
import { readFileSync } from "node:fs";

import { join } from "node:path";

const css = readFileSync(join(process.cwd(), "src/styles/tokens.css"), "utf8");

/** §7.8 verbatim — each custom property regex-checked against the spec. */
describe("tokens.css contains the §7.8 token block verbatim", () => {
  test.each([
    [/color-scheme:\s*dark/, "color-scheme dark"],
    [/--bg:\s*oklch\(0\.120 0 0\)/, "--bg"],
    [/--surface:\s*oklch\(0\.180 0 0\)/, "--surface"],
    [/--raised:\s*oklch\(0\.240 0 0\)/, "--raised"],
    [/--ink:\s*oklch\(0\.960 0 0\)/, "--ink"],
    [/--muted:\s*oklch\(0\.740 0 0\)/, "--muted"],
    [/--border:\s*oklch\(0\.540 0 0\)/, "--border"],
    [/--primary:\s*oklch\(0\.480 0\.100 140\)/, "--primary"],
    [/--on-primary:\s*oklch\(0\.980 0 0\)/, "--on-primary"],
    [/--focus:\s*oklch\(0\.880 0\.070 240\)/, "--focus"],
    [/--on-focus:\s*oklch\(0\.120 0 0\)/, "--on-focus"],
    [/--success:\s*oklch\(0\.790 0\.120 145\)/, "--success"],
    [/--warning:\s*oklch\(0\.850 0\.120 85\)/, "--warning"],
    [/--danger:\s*oklch\(0\.760 0\.150 25\)/, "--danger"],
    [/--font-ui:\s*system-ui, sans-serif/, "--font-ui"],
    [/--font-code:\s*ui-monospace, monospace/, "--font-code"],
    [/--text-small:\s*0\.8125rem/, "--text-small"],
    [/--text-body:\s*0\.875rem/, "--text-body"],
    [/--text-title:\s*1\.375rem/, "--text-title"],
    [/--space-1:\s*4px/, "--space-1"],
    [/--space-2:\s*8px/, "--space-2"],
    [/--space-3:\s*12px/, "--space-3"],
    [/--space-4:\s*16px/, "--space-4"],
    [/--space-6:\s*24px/, "--space-6"],
    [/--z-sticky:\s*10/, "--z-sticky"],
    [/--z-menu:\s*20/, "--z-menu"],
    [/--z-backdrop:\s*30/, "--z-backdrop"],
    [/--z-dialog:\s*40/, "--z-dialog"],
    [/--z-toast:\s*50/, "--z-toast"],
    [/--z-tooltip:\s*60/, "--z-tooltip"],
    [/--ease-out:\s*cubic-bezier\(0\.23,1,0\.32,1\)/, "--ease-out"],
    [/--motion-fast:\s*160ms/, "--motion-fast"],
  ])("%s", (re) => {
    expect(css).toMatch(re);
  });

  test("layout metrics: 216px nav, 360px inspector, 36px rows, 40px controls, 8px radii, 1px borders", () => {
    expect(css).toMatch(/216px/);
    expect(css).toMatch(/360px/);
    expect(css).toMatch(/height:\s*36px/);
    expect(css).toMatch(/min-height:\s*40px/);
    expect(css).toMatch(/border-radius:\s*8px/);
    expect(css).toMatch(/border:\s*1px solid var\(--border\)/);
  });

  test("reduced-motion removes movement; breakpoints at 1000/720 px", () => {
    expect(css).toMatch(/prefers-reduced-motion:\s*reduce/);
    expect(css).toMatch(/@media \(max-width:\s*1000px\)/);
    expect(css).toMatch(/@media \(max-width:\s*720px\)/);
  });

  test("no external font/resource refs", () => {
    expect(css).not.toMatch(/@import/);
    expect(css).not.toMatch(/url\(/);
    expect(css).not.toMatch(/@font-face/);
  });
});
