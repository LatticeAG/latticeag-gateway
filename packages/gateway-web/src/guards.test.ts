/**
 * Repo-wide guards (spec §7.2 + build rules), enforced statically:
 *  - no innerHTML / outerHTML / insertAdjacentHTML anywhere in src
 *  - no localStorage / sessionStorage / indexedDB persistence
 *  - no eval / new Function
 *  - no http(s):// URLs in shipped source (loopback fetch is relative)
 *  - no external fonts/analytics/CDN markers
 *  - no banned path tokens in file names (SPEC/PROMPT/REVIEW/INTERFACES/
 *    STATUS/DRAFT/inspect)
 */
import { describe, expect, test } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const SRC = join(process.cwd(), "src");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const files = walk(SRC).filter((f) => /\.(ts|css|html)$/.test(f));
const sources = files.filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));

describe("source guards", () => {
  test("no innerHTML / outerHTML / insertAdjacentHTML for any content", () => {
    for (const f of sources) {
      const text = readFileSync(f, "utf8");
      expect(text, f).not.toMatch(/innerHTML/);
      expect(text, f).not.toMatch(/outerHTML/);
      expect(text, f).not.toMatch(/insertAdjacentHTML/);
    }
  });

  test("no persistent storage APIs", () => {
    for (const f of sources) {
      const text = readFileSync(f, "utf8");
      expect(text, f).not.toMatch(/localStorage/);
      expect(text, f).not.toMatch(/sessionStorage/);
      expect(text, f).not.toMatch(/indexedDB/);
      expect(text, f).not.toMatch(/document\.cookie\s*=/);
    }
  });

  test("no eval / Function constructor / remote URLs", () => {
    for (const f of sources) {
      const text = readFileSync(f, "utf8");
      expect(text, f).not.toMatch(/\beval\s*\(/);
      expect(text, f).not.toMatch(/new Function\s*\(/);
      expect(text, f).not.toMatch(/https?:\/\//); // all traffic is same-origin relative
    }
  });

  test("no banned path tokens in shipped file names", () => {
    const banned = /spec|prompt|review|interfaces|status|draft|inspect/i;
    for (const f of files) {
      const base = f.slice(SRC.length);
      // *.test.ts files may exercise the tokens/routes textually; the ban
      // applies to shipped paths. Test files are excluded from the bundle.
      if (f.endsWith(".test.ts")) continue;
      expect(banned.test(base), base).toBe(false);
    }
  });
});
