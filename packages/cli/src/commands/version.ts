import type { Command } from "commander";
import { addGlobalOptions, readGlobalOpts } from "../globals.js";
import { writeJson } from "../json-envelope.js";
import { CLI_VERSION } from "../cli-version.js";
import {
  resolveAdapterVersions,
  resolvePackageVersion,
} from "../package-version.js";

export interface VersionResult {
  latticeag: string;
  packages: Record<string, string>;
  /** §6.2 version axes, exposed separately under --json. */
  cli: string;
  package: string;
  events: string;
  config: number;
  control: number;
  interfaces: string;
  native_adapter: string | null;
}

export function collectVersions(): VersionResult {
  const packages: Record<string, string> = {};
  const events = resolvePackageVersion("@latticeag/events");
  if (events) {
    packages["@latticeag/events"] = events;
  }
  const bus = resolvePackageVersion("@latticeag/bus");
  if (bus) {
    packages["@latticeag/bus"] = bus;
  }
  Object.assign(packages, resolveAdapterVersions());
  return {
    latticeag: CLI_VERSION,
    packages,
    cli: CLI_VERSION,
    package: CLI_VERSION,
    events: events ?? "0.1.0",
    config: 2,
    control: 2,
    interfaces: "interfaces/1",
    native_adapter: null,
  };
}

export function runVersion(json: boolean): void {
  const data = collectVersions();
  if (json) {
    writeJson("version", true, data);
    return;
  }
  const lines = [`latticeag ${data.latticeag}`];
  const events = data.packages["@latticeag/events"];
  if (events) {
    lines.push(`@latticeag/events ${events}`);
  }
  const bus = data.packages["@latticeag/bus"];
  if (bus) {
    lines.push(`@latticeag/bus ${bus}`);
  }
  process.stdout.write(`${lines.join("\n")}\n`);
}

export function registerVersion(program: Command): void {
  const cmd = program
    .command("version")
    .description("Print latticeag and workspace package versions.")
    .action((_opts: Record<string, unknown>, command: Command) => {
      const globals = readGlobalOpts(command);
      runVersion(globals.json === true);
    });
  addGlobalOptions(cmd);
}
