/**
 * CLI argument parsing and command dispatch.
 */

import { existsSync } from "node:fs";
import path from "node:path";
import { runAudit } from "./engine.js";
import { loadConfig } from "./config.js";
import { severityMeetsThreshold } from "./utils.js";
import { logStep } from "./log.js";

const usage = `
Usage:
  security-agent audit --path <repo> [options]

Options:
  --mode full|diff                  Scan the full project or current Git diff. Default: full
  --base <branch>                   Base branch for diff mode. Default: main
  --output <dir>                    Output directory. Default: ./security-audits
  --scanners <list>                 Comma list: semgrep,gitleaks,trufflehog,trivy,grype,npm-audit,composer-audit,built-in,ai-review
  --ai-mode off|targeted|full-context
  --ai-token-budget <number>        Max AI input token budget. Default: 300000
  --api-key <key>                   Cursor API key. Defaults to CURSOR_API_KEY
  --severity-threshold <severity>   low|medium|high|critical. Default: medium
  --jira                            Create Jira tasks for findings above threshold
  --schedule daily                  Run now and report how to register the same command for daily execution
  --json-summary                    Print compact JSON summary to stdout
  --fail-on-findings                Accepted for CI compatibility; findings above threshold already exit 1
  --help                            Show help
`;

/**
 * Parses CLI arguments and runs the requested command.
 * @param {string[]} argv Raw CLI arguments excluding node and script path.
 */
export async function runCli(argv) {
  const [command, ...rest] = argv;
  if (!command || command === "--help" || command === "-h") {
    console.log(usage.trim());
    return;
  }

  if (command !== "audit") {
    throw new Error(`Unknown command "${command}".\n${usage.trim()}`);
  }

  const args = parseArgs(rest);
  if (args.help) {
    console.log(usage.trim());
    return;
  }

  const targetPath = path.resolve(args.path ?? ".");
  if (!existsSync(targetPath)) {
    throw new Error(`Target path does not exist: ${targetPath}`);
  }

  const config = loadConfig(targetPath, args);
  logStep(`Configuration loaded for ${targetPath}`);
  const result = await runAudit(config);

  if (args.jsonSummary) {
    console.log(JSON.stringify(result.summary, null, 2));
  } else {
    console.log(`Audit complete: ${result.reportPaths.markdown}`);
    if (result.reportPaths.json) {
      console.log(`JSON report: ${result.reportPaths.json}`);
    }
    console.log(`${result.summary.findingCount} findings, ${result.summary.limitations.length} limitations`);
  }

  const hasThresholdFindings = result.findings.some((finding) =>
    severityMeetsThreshold(finding.severity, config.severityThreshold),
  );

  if (result.fatalError) {
    process.exitCode = 2;
  } else if (hasThresholdFindings) {
    process.exitCode = 1;
  } else {
    process.exitCode = 0;
  }
}

/**
 * @param {string[]} argv
 */
function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      throw new Error(`Unexpected argument: ${token}`);
    }

    const key = toCamelCase(token.slice(2));
    if (["jira", "jsonSummary", "failOnFindings", "help"].includes(key)) {
      args[key] = true;
      continue;
    }

    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for ${token}`);
    }
    args[key] = value;
    index += 1;
  }
  return args;
}

/**
 * @param {string} value
 */
function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}
