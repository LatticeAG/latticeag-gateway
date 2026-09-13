import { describe, expect, test } from "vitest";

import { F, auditor, H, J, now, origin } from "@latticeag/testkit";

import type { ProductManifest } from "../protocol/product.js";
import { manifestDigestOf } from "./manifest.js";
import {
  DependencyConflictError,
  dependentsPresent,
  EDGE_DISPOSITIONS,
  edgeDisposition,
  resolvePlan,
} from "./resolve.js";
import type { InstalledProduct, ResolveInput } from "./resolve.js";
import {
  dep,
  fixtureTrust,
  INDEX2,
  manifestOf,
  manifestPatched,
} from "./testbed.js";

const manifest1 = manifestOf(F.release1);
const digest1 = manifestDigestOf(
  Buffer.from(F.release1.wire.manifest.content, "base64url"),
);

const trustMaterials = [origin.material, auditor.material];
const revisions = { config: "1", catalog: "1", registry: "1" } as const;

function installInput(patch: Partial<ResolveInput> = {}): ResolveInput {
  return {
    kind: "install",
    source: "lexverdict",
    version: "0.1.0",
    target: { manifest: manifest1, manifestDigest: digest1 as ResolveInput extends never ? never : import("../protocol/refs.js").Hash },
    manifests: new Map([["lexverdict", [manifest1]]]),
    index: F.index as ResolveInput["index"],
    installed: [],
    opts: { now, revisions, trustMaterials },
    ...patch,
  };
}

describe("resolvePlan (§5.1)", () => {
  test("install plan matches the §13.1 planFor fixture exactly", () => {
    const r = resolvePlan(installInput());
    expect(r.summary).toEqual({
      kind: "install",
      slug: "lexverdict",
      from: null,
      to: "0.1.0",
      manifest: F.release1.wire.manifest.ref.digest,
      archive: F.release1.manifest.package.archive.digest,
      dependencies: [],
      grants: F.release1.manifest.capabilities,
      revisions: { config: "1", catalog: "1", registry: "1" },
      trust: expect.any(String),
      keep_data: true,
      cascade: false,
    });
    // The fixture's exact trust hash: H(J([origin.material, auditor.material])).
    expect(r.summary.trust).toBe(H(J(trustMaterials)));
    expect(r.plan).toHaveLength(64);
  });

  test("TV-GW-09: required-dependency cycle reports the exact path", () => {
    const mA = manifestPatched(F.release1, {
      slug: "a",
      version: "1.0.0",
      dependencies: [dep("b", "1.0.0")],
    });
    const mB = manifestPatched(F.release1, {
      slug: "b",
      version: "1.0.0",
      dependencies: [dep("a", "1.0.0")],
    });
    let caught: unknown;
    try {
      resolvePlan({
        kind: "install",
        source: "a@1.0.0",
        target: { manifest: mA, manifestDigest: "0".repeat(64) as import("../protocol/refs.js").Hash },
        manifests: new Map<string, ProductManifest[]>([
          ["a", [mA]],
          ["b", [mB]],
        ]),
        installed: [],
        opts: { revisions },
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(DependencyConflictError);
    expect((caught as { code: string }).code).toBe("DEPENDENCY_CONFLICT");
    expect((caught as DependencyConflictError).cycle).toEqual(["a", "b", "a"]);
  });

  test("TV-GW-10: E28 required edge → CAP_ADAPTER_UNAVAILABLE pre-allocation", () => {
    const m = manifestPatched(F.release1, {
      dependencies: [dep("trellis-thing", "1.0.0", "required", "E28")],
    });
    expect(() =>
      resolvePlan(installInput({ target: { manifest: m, manifestDigest: digest1 as import("../protocol/refs.js").Hash } })),
    ).toThrowError(expect.objectContaining({ code: "CAP_ADAPTER_UNAVAILABLE" }));
  });

  test("blocking edges E17/E21/E49/E38 carry their mapped codes", () => {
    const cases: [string, string][] = [
      ["E17", "UNSUPPORTED_COMPOSITION"],
      ["E21", "UNSUPPORTED_COMPOSITION"],
      ["E38", "MINT_EXCLUSIVE_HOLD_UNAVAILABLE"],
      ["E49", "UNSUPPORTED_COMPOSITION"],
    ];
    for (const [edge, code] of cases) {
      const m = manifestPatched(F.release1, {
        dependencies: [dep("x-target", "1.0.0", "required", edge)],
      });
      expect(
        () =>
          resolvePlan(
            installInput({ target: { manifest: m, manifestDigest: digest1 as import("../protocol/refs.js").Hash } }),
          ),
        edge,
      ).toThrowError(expect.objectContaining({ code }));
    }
  });

  test("E35 disposition maps to PROVENANCE_INVALID", () => {
    expect(edgeDisposition("E35")?.code).toBe("PROVENANCE_INVALID");
  });

  test("edge table is exactly E01–E53 in order", () => {
    expect(EDGE_DISPOSITIONS).toHaveLength(53);
    EDGE_DISPOSITIONS.forEach((d, i) => {
      expect(d.edge).toBe(`E${String(i + 1).padStart(2, "0")}`);
      expect(d.rule.length).toBeGreaterThan(0);
    });
  });

  test("evidence edges never trigger installs", () => {
    const m = manifestPatched(F.release1, {
      dependencies: [dep("ghostdep", "1.0.0", "evidence", "E18")],
    });
    const r = resolvePlan(
      installInput({ target: { manifest: m, manifestDigest: digest1 as import("../protocol/refs.js").Hash } }),
    );
    expect(r.dependencies.find((d) => d.slug === "ghostdep")?.kind).toBe("evidence");
  });

  test("strict catalog + empty allowlist authorizes zero installs", () => {
    expect(() =>
      resolvePlan(installInput({ opts: { strict: true, allowlist: [] } })),
    ).toThrowError(expect.objectContaining({ code: "POLICY_DENIED" }));
    // allowlisted slug proceeds
    const r = resolvePlan(
      installInput({ opts: { strict: true, allowlist: ["lexverdict"], revisions, trustMaterials } }),
    );
    expect(r.summary.slug).toBe("lexverdict");
  });

  test("update plan binds from=active version", () => {
    const installed: InstalledProduct[] = [
      {
        slug: "lexverdict",
        version: "0.1.0",
        state: "READY",
        active: true,
        dependencies: [],
      },
    ];
    const m2 = manifestOf(F.release2);
    const r = resolvePlan({
      kind: "update",
      source: "lexverdict@0.1.1",
      target: {
        manifest: m2,
        manifestDigest: manifestDigestOf(
          Buffer.from(F.release2.wire.manifest.content, "base64url"),
        ) as import("../protocol/refs.js").Hash,
      },
      manifests: new Map([["lexverdict", [manifest1, m2]]]),
      index: INDEX2,
      installed,
      opts: { now, revisions, trustMaterials },
    });
    expect(r.summary.kind).toBe("update");
    expect(r.summary.from).toBe("0.1.0");
    expect(r.summary.to).toBe("0.1.1");
  });

  test("dependentsPresent finds live required dependents only", () => {
    const installed: InstalledProduct[] = [
      { slug: "lexverdict", version: "0.1.0", state: "READY", active: true, dependencies: [] },
      {
        slug: "dep1",
        version: "1.0.0",
        state: "READY",
        active: true,
        dependencies: [dep("lexverdict", ">=0.1.0 <0.2.0")],
      },
      {
        slug: "dep2",
        version: "1.0.0",
        state: "REMOVED",
        active: false,
        dependencies: [dep("lexverdict", ">=0.1.0 <0.2.0")],
      },
    ];
    expect(dependentsPresent(installed, "lexverdict")).toEqual(["dep1"]);
    expect(dependentsPresent(installed, "dep1")).toEqual([]);
  });
});
