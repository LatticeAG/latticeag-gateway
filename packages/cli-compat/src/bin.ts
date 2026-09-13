#!/usr/bin/env node
// @latticeag/cli 2.x compatibility shim: forwards argv/stdin/stdout/signals
// and the exit code to @latticeag/gateway. The latticeag command is unchanged.
import { runCli } from "@latticeag/gateway/cli";

process.exitCode = await runCli(process.argv);
