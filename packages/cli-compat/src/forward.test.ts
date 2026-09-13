import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runCli } from "@latticeag/gateway/cli";

const here = path.dirname(fileURLToPath(import.meta.url));

describe("@latticeag/cli compat shim", () => {
  it("declares the latticeag bin entry", () => {
    const pkg = JSON.parse(
      readFileSync(path.join(here, "..", "package.json"), "utf8"),
    ) as { name: string; version: string; bin: Record<string, string> };
    expect(pkg.name).toBe("@latticeag/cli");
    expect(pkg.version).toBe("2.0.0");
    expect(pkg.bin.latticeag).toBe("dist/bin.js");
  });

  it("exposes runCli(argv): Promise<number> from @latticeag/gateway/cli", () => {
    const fn: (argv?: string[]) => Promise<number> = runCli;
    expect(typeof fn).toBe("function");
  });
});
