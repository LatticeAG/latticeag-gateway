#!/usr/bin/env node
import { runCli } from "./run-cli.js";

runCli().then((code) => {
  process.exitCode = code;
});
