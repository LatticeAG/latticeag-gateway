/**
 * `latticeag gateway catalog search|show|refresh|pin|unpin` and the root
 * `catalog` alias (spec §6.2, §5.1). Search/show hit the signed cached
 * index by default — no network refresh unless `catalog refresh` says so.
 */
import { Command } from "commander";
import { v2 } from "@latticeag/core";
import { addGlobalOptions } from "../../globals.js";
import { writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  commandName,
  connectDaemon,
  failControl,
  gatewayIdentity,
  globalsOf,
  parseBoundedInt,
  requireConfirmation,
  usageFail,
} from "../../gateway/common.js";

const { SERIES } = v2.protocol;

function parseSeries(raw: string | undefined, ctx: { json: boolean; command: string }): v2.protocol.Series | null {
  if (raw === undefined || raw === "") {
    return null;
  }
  if (!(SERIES as readonly string[]).includes(raw)) {
    usageFail(`--series must be ${SERIES.join("|")}: ${raw}`, ctx);
  }
  return raw as v2.protocol.Series;
}

async function runSearch(
  query: string | undefined,
  opts: { series?: string; limit?: string; after?: string; offline?: boolean; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  const limit = parseBoundedInt(
    opts.limit,
    { flag: "--limit", min: 1, max: 200, fallback: 50 },
    ctx,
  );
  const series = parseSeries(opts.series, ctx);
  const q = query ?? "";
  if (Buffer.byteLength(q) > 128) {
    usageFail("query exceeds 128 bytes", ctx);
  }
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    // --offline is the default posture: the cached index is queried; the
    // flag documents that no refresh is implied.
    const page = await client.call("catalog.search", {
      q,
      series,
      after: opts.after ?? null,
      limit,
    });
    if (json) {
      writeJson(ctx.command, true, page);
      return;
    }
    const items = (page as { items: Array<Record<string, unknown>> }).items;
    for (const entry of items) {
      process.stdout.write(
        `${String(entry["slug"] ?? "-")}\t${String(entry["series"] ?? "-")}\t${String(entry["version"] ?? "-")}\n`,
      );
    }
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runShow(
  slug: string,
  opts: { version?: string; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    // Default: the pinned version, else the selected channel head. The
    // daemon resolves "selected" to its configured channel version.
    let version = opts.version;
    if (!version) {
      const identity = gatewayIdentity();
      const pin = identity.config?.catalog.pins.find((p) => p.slug === slug);
      version = pin?.version ?? "selected";
    }
    const result = await client.call("catalog.show", { slug, version });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runRefresh(
  opts: { offline?: boolean; bundle?: string; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const result = await client.call("catalog.refresh", {
      source: opts.bundle ?? "configured",
      offline: opts.offline === true,
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runPin(
  slug: string,
  opts: { version?: string; digest?: string; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  if (!opts.version) {
    usageFail("catalog pin requires --version <exact>", ctx);
  }
  if (!opts.digest) {
    usageFail("catalog pin requires --digest <sha256:hex>", ctx);
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(opts.digest)) {
    usageFail(`--digest must match sha256:<64 hex>: ${opts.digest}`, ctx);
  }
  try {
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const current = await client.call<{ revision: string }>("config.get", {});
    const result = await client.call("catalog.pin", {
      slug,
      version: opts.version,
      digest: opts.digest,
      expected_revision: current.revision,
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`pinned ${slug}@${opts.version}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

async function runUnpin(
  slug: string,
  opts: { yes?: boolean; socket?: string },
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };
  try {
    await requireConfirmation({
      yes: opts.yes,
      summary: `remove catalog pin for ${slug} (allowlist and signature policy stay enforced)`,
      json,
      command: ctx.command,
    });
    const { client } = await connectDaemon({ socket: opts.socket, json, command: ctx.command });
    const current = await client.call<{ revision: string }>("config.get", {});
    const result = await client.call("catalog.unpin", {
      slug,
      expected_revision: current.revision,
    });
    if (json) {
      writeJson(ctx.command, true, result);
      return;
    }
    process.stdout.write(`unpinned ${slug}\n`);
  } catch (err) {
    failControl(err, ctx);
  }
}

/** Register the catalog group under any parent (gateway or root alias). */
export function buildCatalogCommand(name = "catalog"): Command {
  const catalog = new Command(name).description("Signed product catalog.");

  const search = catalog
    .command("search")
    .description("Search the cached signed index.")
    .argument("[query]", "Search query (≤128 bytes)")
    .option("--series <series>", `Series filter: ${SERIES.join("|")}`)
    .option("--limit <n>", "1..200", "50")
    .option("--after <cursor>", "Opaque page cursor")
    .option("--offline", "Never refresh; cached index only")
    .action(async (query: string | undefined, opts, command: Command) => {
      await runSearch(query, opts, command);
    });
  addGlobalOptions(search);
  addSocketOption(search);

  const show = catalog
    .command("show")
    .description("Show exact slug/version metadata, gates, and tier.")
    .argument("<slug>", "Catalog slug")
    .option("--version <exact>", "Default: pinned/selected channel version")
    .action(async (slug: string, opts, command: Command) => {
      await runShow(slug, opts, command);
    });
  addGlobalOptions(show, false);
  addSocketOption(show);

  const refresh = catalog
    .command("refresh")
    .description("Verified atomic cache replacement only.")
    .option("--offline", "Stay on the cached index")
    .option("--bundle <path>", "Import a local index bundle")
    .action(async (opts, command: Command) => {
      await runRefresh(opts, command);
    });
  addGlobalOptions(refresh);
  addSocketOption(refresh);

  const pin = catalog
    .command("pin")
    .description("Pin slug/version/archive digest and index commitment.")
    .argument("<slug>", "Catalog slug")
    .option("--version <exact>", "Exact version (required)")
    .option("--digest <sha256:hex>", "Archive digest (required)")
    .action(async (slug: string, opts, command: Command) => {
      await runPin(slug, opts, command);
    });
  addGlobalOptions(pin, false);
  addSocketOption(pin);

  const unpin = catalog
    .command("unpin")
    .description("CAS-remove one pin; policy stays enforced.")
    .argument("<slug>", "Catalog slug")
    .option("--yes", "Confirm unpin")
    .action(async (slug: string, opts, command: Command) => {
      await runUnpin(slug, opts, command);
    });
  addGlobalOptions(unpin);
  addSocketOption(unpin);

  return catalog;
}
