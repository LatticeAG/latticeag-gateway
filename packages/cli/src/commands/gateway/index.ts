/**
 * Register the `latticeag gateway` command tree plus the documented root
 * convenience aliases `agent`, `ui`, `sync`, `catalog` (spec §6.2). The
 * aliases are the same commander builders — they forward to identical
 * handlers, with no separate privileged code path.
 */
import type { Command } from "commander";
import { addGlobalOptions } from "../../globals.js";
import { registerDaemonCommands } from "./daemon.js";
import { registerServiceCommands } from "./service.js";
import { registerProductCommands } from "./product.js";
import { buildAgentCommand } from "./agent.js";
import { buildUiCommand } from "./ui.js";
import { buildSyncCommand } from "./sync.js";
import { registerCloudCommands } from "./cloud.js";
import { buildCatalogCommand } from "./catalog.js";
import { registerConfigCommands } from "./config-cmd.js";
import { registerApprovalCommands } from "./approvals.js";
import { registerReceiptCommands } from "./receipts.js";

export function registerGateway(program: Command): void {
  const gateway = program
    .command("gateway")
    .description("Gateway v2 daemon, products, and control surface.")
    .enablePositionalOptions();
  addGlobalOptions(gateway);

  registerDaemonCommands(gateway);
  registerServiceCommands(gateway);
  registerProductCommands(gateway);
  gateway.addCommand(buildAgentCommand());
  gateway.addCommand(buildUiCommand());
  gateway.addCommand(buildSyncCommand());
  registerCloudCommands(gateway);
  gateway.addCommand(buildCatalogCommand());
  registerConfigCommands(gateway);
  registerApprovalCommands(gateway);
  registerReceiptCommands(gateway);

  // Root aliases (§6.2): same builders → identical routing/behavior.
  for (const build of [
    buildAgentCommand,
    buildUiCommand,
    buildSyncCommand,
    buildCatalogCommand,
  ]) {
    const alias = build();
    alias.description(`${alias.description()} (alias for gateway ${alias.name()})`);
    program.addCommand(alias);
  }
}
