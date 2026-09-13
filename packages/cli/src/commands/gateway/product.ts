/**
 * `latticeag gateway install|uninstall|update|rollback` (spec §6.2, §5).
 *
 * Every product mutation is plan-gated: product.plan resolves the exact
 * reviewed plan (deps, grants, licenses, disk), the CLI displays it, and
 * the commit RPC runs only after `--yes --review-digest <plan>` matches the
 * displayed plan hash — or an interactive TTY confirmation. Accepted means
 * durable job admission; unless --detach, the CLI polls operation.get to a
 * terminal state.
 */
import { Command, Option } from "commander";
import { v2 } from "@latticeag/core";
import { addGlobalOptions } from "../../globals.js";
import { fail, writeJson } from "../../json-envelope.js";
import {
  addSocketOption,
  cliReviewDigestRef,
  commandName,
  connectDaemon,
  failControl,
  globalsOf,
  requireReviewedPlan,
  usageFail,
  EXIT,
} from "../../gateway/common.js";
import type { ControlClient } from "../../gateway/client.js";

type OpKind = "install" | "uninstall" | "update" | "rollback";

/** Operation states that mean "still working" while polling. */
const NON_TERMINAL = new Set([
  "QUEUED",
  "PLANNING",
  "RESOLVING",
  "DOWNLOADING",
  "VERIFYING",
  "STAGING",
  "ACTIVATING",
  "RUNNING",
  "DRAINING",
]);

const POLL_CAP_MS = 300_000;
const POLL_MS = 500;

interface ProductOpOpts {
  version?: string;
  to?: string;
  localSign?: boolean;
  cascade?: boolean;
  keepData?: boolean;
  purgeData?: boolean;
  dryRun?: boolean;
  detach?: boolean;
  yes?: boolean;
  reviewDigest?: string;
  socket?: string;
}

async function waitForOperation(
  client: ControlClient,
  operation: string,
  ctx: { json: boolean; command: string },
): Promise<void> {
  const deadline = Date.now() + POLL_CAP_MS;
  for (;;) {
    let op: {
      state: string;
      kind?: string;
      slug?: string;
      error?: { code: string } | null;
    };
    try {
      op = await client.call("operation.get", { operation });
    } catch (err) {
      failControl(err, ctx);
    }
    if (!NON_TERMINAL.has(op.state)) {
      if (op.error) {
        fail(
          `operation ${operation} ${op.state}: ${op.error.code}`,
          {
            json: ctx.json,
            command: ctx.command,
            code: op.error.code,
            exitCode: EXIT.GENERAL,
          },
        );
      }
      if (op.state === "FAILED") {
        fail(`operation ${operation} FAILED`, {
          json: ctx.json,
          command: ctx.command,
          code: "HEALTH_FAILED",
          exitCode: EXIT.GENERAL,
        });
      }
      if (ctx.json) {
        writeJson(ctx.command, true, op);
      } else {
        process.stdout.write(`operation ${operation} ${op.state}\n`);
      }
      return;
    }
    if (Date.now() > deadline) {
      fail(`operation ${operation} still ${op.state} after ${POLL_CAP_MS} ms`, {
        json: ctx.json,
        command: ctx.command,
        code: "BUSY",
        exitCode: EXIT.BUSY,
      });
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}

async function runProductOp(
  kind: OpKind,
  source: string,
  opts: ProductOpOpts,
  command: Command,
): Promise<void> {
  const globals = globalsOf(command);
  const json = globals.json === true;
  const ctx = { json, command: commandName(command) };

  const planParams: Record<string, unknown> = { kind, source };
  if (kind === "install" || kind === "update" || kind === "rollback") {
    const version = kind === "install" ? opts.version : opts.to;
    if (version !== undefined) {
      planParams["version"] = version;
    }
  }
  if (kind === "rollback" && (opts.to === undefined || opts.to === "")) {
    usageFail("gateway rollback requires --to <retained-exact>", ctx);
  }
  if (kind === "uninstall") {
    planParams["cascade"] = opts.cascade === true;
    planParams["keep_data"] = opts.purgeData === true ? false : opts.keepData !== false;
  }
  if (opts.localSign === true) {
    planParams["local_sign"] = true;
  }

  try {
    const { client } = await connectDaemon({
      socket: opts.socket,
      json,
      command: ctx.command,
    });
    const planned = await client.call<{ plan: string; summary: unknown }>(
      "product.plan",
      planParams,
    );
    const digest = `sha256:${planned.plan}`;
    if (json) {
      writeJson(ctx.command, true, {
        plan: planned.plan,
        summary: planned.summary,
        review_digest: digest,
        dry_run: opts.dryRun === true,
      });
    } else {
      process.stdout.write(`${JSON.stringify(planned.summary, null, 2)}\n`);
      process.stdout.write(`plan ${planned.plan}\nreview_digest ${digest}\n`);
    }
    if (opts.dryRun === true) {
      return;
    }
    await requireReviewedPlan({
      yes: opts.yes,
      reviewDigest: opts.reviewDigest,
      digest,
      summary: `${kind} ${source}`,
      json,
      command: ctx.command,
    });
    const accepted = await client.call<{ operation: string; state: string }>(
      `product.${kind}`,
      { plan: planned.plan, review: cliReviewDigestRef(digest) },
    );
    if (opts.detach === true) {
      // Detached admission succeeded → exit 0 (§6.1).
      if (json) {
        writeJson(ctx.command, true, accepted);
      } else {
        process.stdout.write(`operation ${accepted.operation} ${accepted.state}\n`);
      }
      return;
    }
    await waitForOperation(client, accepted.operation, ctx);
  } catch (err) {
    failControl(err, ctx);
  }
}

export function registerProductCommands(gateway: Command): void {
  const install = gateway
    .command("install")
    .description("Plan, review, and install a product.")
    .argument("<source>", "Catalog slug, npm selector, or local path")
    .option("--version <exact>", "Exact version")
    .option("--local-sign", "Permit a locally signed snapshot")
    .option("--dry-run", "Print the plan; commit nothing")
    .option("--detach", "Exit after durable admission")
    .option("--yes", "Approve the displayed plan")
    .option("--review-digest <hash>", "Digest of the displayed plan")
    .action(async (source: string, opts: ProductOpOpts, command: Command) => {
      await runProductOp("install", source, opts, command);
    });
  // --version is this command's own flag; skip the -V global on this leaf.
  addGlobalOptions(install, false);
  addSocketOption(install);

  const uninstall = gateway
    .command("uninstall")
    .description("Plan, review, and uninstall a product.")
    .argument("<slug>", "Installed product slug")
    .option("--cascade", "Include the full reverse dependency closure")
    .addOption(
      new Option("--keep-data", "Retain product data").default(true),
    )
    .option("--purge-data", "Destroy retained product data (destructive)")
    .option("--dry-run", "Print the plan; commit nothing")
    .option("--detach", "Exit after durable admission")
    .option("--yes", "Approve the displayed plan")
    .option("--review-digest <hash>", "Digest of the displayed plan")
    .action(async (slug: string, opts: ProductOpOpts, command: Command) => {
      // --purge-data overrides --keep-data; the destructive choice is
      // always visible in the displayed plan before review.
      await runProductOp("uninstall", slug, opts, command);
    });
  addGlobalOptions(uninstall);
  addSocketOption(uninstall);

  const update = gateway
    .command("update")
    .description("Plan, review, and update a product to an exact version.")
    .argument("<slug>", "Installed product slug")
    .option("--to <exact>", "Exact target version (no range widening)")
    .option("--dry-run", "Print the plan; commit nothing")
    .option("--detach", "Exit after durable admission")
    .option("--yes", "Approve the displayed plan")
    .option("--review-digest <hash>", "Digest of the displayed plan")
    .action(async (slug: string, opts: ProductOpOpts, command: Command) => {
      await runProductOp("update", slug, opts, command);
    });
  addGlobalOptions(update);
  addSocketOption(update);

  const rollback = gateway
    .command("rollback")
    .description("Plan, review, and roll back to a retained version.")
    .argument("<slug>", "Installed product slug")
    .requiredOption("--to <retained-exact>", "Retained exact version (required)")
    .option("--dry-run", "Print the plan; commit nothing")
    .option("--detach", "Exit after durable admission")
    .option("--yes", "Approve the displayed plan")
    .option("--review-digest <hash>", "Digest of the displayed plan")
    .action(async (slug: string, opts: ProductOpOpts, command: Command) => {
      await runProductOp("rollback", slug, opts, command);
    });
  addGlobalOptions(rollback);
  addSocketOption(rollback);
}
