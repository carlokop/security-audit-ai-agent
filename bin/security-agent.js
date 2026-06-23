#!/usr/bin/env node

/**
 * CLI entry point for the security-agent audit orchestrator.
 */

import { runCli } from "../src/cli.js";

runCli(process.argv.slice(2)).catch((error) => {
  console.error(`security-agent failed: ${error.message}`);
  process.exit(2);
});
