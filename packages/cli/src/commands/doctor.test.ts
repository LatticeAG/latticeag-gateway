import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  DOCTOR_CHECK_IDS,
  LATTICEAG_DOCTOR_ALLOW_MISSING_ADAPTERS,
  nodeSatisfies,
} from "./doctor.js";
import { runCli } from "../test-spawn.js";

function tempDir(): string {
  return mkdtempSync(path.join(tmpdir(), "latticeag-doctor-"));
}

const doctorEnv = {
  [LATTICEAG_DOCTOR_ALLOW_MISSING_ADAPTERS]: "1",
  AXION_WEBHOOK_ALLOW_UNSIGNED: "true",
  LATTICEAG_CONFIG: "",
};

describe("latticeag doctor", () => {
  it("loads cwd .env without overriding exported values", async () => {
    const dir = tempDir();
    const init = await runCli(
      ["init", dir, "--template", "blank", "--adapters", "lexverdict", "--schema", "1"],
      { env: doctorEnv },
    );
    expect(init.status).toBe(0);
    writeFileSync(path.join(dir, ".env"), 'LEXVERDICT_URL="http://127.0.0.1:8789"\nOPENAI_API_KEY=file-key\n');
    const result = await runCli(["--cwd", dir, "doctor", "--offline", "--json"], {
      env: { ...doctorEnv, LEXVERDICT_URL: undefined, OPENAI_API_KEY: "exported" },
    });
    const checks = JSON.parse(result.stdout).data.checks as Array<{ id: string; status: string; chars?: number }>;
    expect(checks.find((c) => c.id === "env_LEXVERDICT_URL")?.status).toBe("pass");
    expect(checks.find((c) => c.id === "env_OPENAI_API_KEY")?.chars).toBe(8);
  });

  it("offline checks emit every check id after init", async () => {
    const dir = tempDir();
    const init = await runCli(
      ["init", dir, "--template", "blank", "--adapters", "axion", "--schema", "1"],
      { env: doctorEnv },
    );
    expect(init.status).toBe(0);

    const result = await runCli(["--cwd", dir, "doctor", "--offline"], {
      env: doctorEnv,
    });
    const lines = result.stdout.trim().split("\n").filter(Boolean);
    const ids = lines.map((line) => line.trim().split(/\s+/)[1]);
    for (const id of DOCTOR_CHECK_IDS) {
      expect(ids, `missing check ${id}`).toContain(id);
    }
    expect(result.stdout).toMatch(/skip\s+axion_health/);
    expect(result.stdout).toMatch(/skip\s+lexverdict_health/);
    expect(result.stdout).toMatch(/skip\s+vekinbox_health/);
    expect(result.stdout).toMatch(/skip\s+repo_freshness/);
    expect(result.stdout).toMatch(/pass\s+config_valid/);
    expect(result.stdout).toMatch(/pass\s+secrets_not_in_config/);
    expect(result.stdout).not.toMatch(/sk-[a-zA-Z0-9]{10,}/);
    expect(readFileSync(path.join(dir, "latticeag.json"), "utf8")).not.toMatch(
      /sk-/,
    );
  });

  it("after init, doctor --offline exits 0 when adapters may be missing (node 20)", async () => {
    const dir = tempDir();
    const init = await runCli(
      ["init", dir, "--template", "blank", "--adapters", "axion", "--schema", "1"],
      { env: doctorEnv },
    );
    expect(init.status).toBe(0);

    const result = await runCli(["--cwd", dir, "doctor", "--offline", "--json"], {
      env: doctorEnv,
    });
    const envelope = JSON.parse(result.stdout) as {
      ok: boolean;
      command: string;
      data: { checks: Array<{ id: string; status: string; detail: string }> };
    };
    expect(envelope.command).toBe("doctor");
    const nodeCheck = envelope.data.checks.find((c) => c.id === "node_version");
    expect(nodeCheck).toBeTruthy();

    if (!nodeSatisfies(process.versions.node)) {
      expect(result.status).toBe(1);
      expect(nodeCheck?.status).toBe("fail");
      const otherFails = envelope.data.checks.filter(
        (c) => c.status === "fail" && c.id !== "node_version",
      );
      expect(otherFails).toEqual([]);
      return;
    }

    expect(result.status).toBe(0);
    expect(envelope.ok).toBe(true);
    expect(envelope.data.checks.some((c) => c.status === "fail")).toBe(false);
  });
});
