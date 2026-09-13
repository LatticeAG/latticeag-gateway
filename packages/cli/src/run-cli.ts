import { buildProgram } from "./program.js";

/**
 * Build the latticeag commander program and parse `argv`
 * (defaults to `process.argv`, i.e. node + script + args).
 *
 * Returns the numeric exit code and never calls `process.exit` itself.
 * Note: some command actions and the global-opts hook still call
 * `process.exit` inline (globals.ts, json-envelope.ts, commands/{doctor,
 * events,dev,run}.ts); commander also exits directly for --help/--version
 * and usage errors.
 */
export async function runCli(argv?: string[]): Promise<number> {
  const program = buildProgram();
  await program.parseAsync(argv ?? process.argv);
  const code = process.exitCode;
  return typeof code === "number" ? code : 0;
}
