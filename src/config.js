/**
 * Configuration loader for CLI flags, `.env`, and optional project config files.
 */

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import "./env.js";

/** @typedef {import("./utils.js").SecurityFinding} SecurityFinding */

/**
 * @typedef {object} AuditConfig
 * @property {string} targetPath Absolute path to the repository under audit.
 * @property {"full"|"diff"} mode Scan mode.
 * @property {string} baseBranch Base branch used for diff scans.
 * @property {string} outputDir Directory where reports are written.
 * @property {string[]} scanners Enabled scanner identifiers.
 * @property {{ provider: string, model: string, mode: string, apiKey?: string, maxInputTokens: number }} ai AI settings.
 * @property {{ enabled: boolean, baseUrl?: string, email?: string, apiToken?: string, projectKey?: string, issueType: string, status: string }} jira Jira settings.
 * @property {string} [schedule] Optional schedule hint from CLI.
 * @property {string} severityThreshold Minimum severity used for exit codes and Jira publishing.
 * @property {string[]} reportFormats Report output formats.
 * @property {boolean} failOnFindings Whether CI should fail on threshold findings.
 * @property {boolean} jsonSummary Whether stdout should contain JSON summary only.
 * @property {string[]} exclude Paths excluded from file collection.
 */

const defaultScanners = [
  "semgrep",
  "gitleaks",
  "trufflehog",
  "trivy",
  "grype",
  "npm-audit",
  "composer-audit",
  "built-in",
  "ai-review",
];

/**
 * Loads merged configuration from CLI args, environment, and optional project config.
 * @param {string} targetPath Repository path passed to `--path`.
 * @param {Record<string, string|boolean>} args Parsed CLI arguments.
 * @returns {AuditConfig}
 */
export function loadConfig(targetPath, args) {
  const fileConfig = loadConfigFile(targetPath);

  const outputDir = path.resolve(
    args.output
      ?? process.env.SECURITY_AGENT_OUTPUT_DIR
      ?? fileConfig.outputDir
      ?? path.join(process.cwd(), "security-audits"),
  );

  const scannerList = args.scanners ?? process.env.SECURITY_AGENT_SCANNERS ?? fileConfig.scanners;

  return {
    targetPath,
    mode: args.mode ?? fileConfig.mode ?? "full",
    baseBranch: args.base ?? fileConfig.baseBranch ?? "main",
    outputDir,
    scanners: normalizeScanners(scannerList),
    ai: {
      provider: "cursor",
      model: process.env.AI_MODEL ?? fileConfig.ai?.model ?? "auto",
      mode: args.aiMode ?? process.env.AI_MODE ?? fileConfig.ai?.mode ?? "targeted",
      apiKey: args.apiKey ?? process.env.CURSOR_API_KEY ?? fileConfig.ai?.apiKey,
      maxInputTokens: Number(
        args.aiTokenBudget ?? process.env.AI_MAX_INPUT_TOKENS ?? fileConfig.ai?.maxInputTokens ?? 300000,
      ),
    },
    jira: {
      enabled: Boolean(args.jira ?? fileConfig.jira?.enabled),
      baseUrl: process.env.JIRA_BASE_URL ?? fileConfig.jira?.baseUrl,
      email: process.env.JIRA_EMAIL ?? fileConfig.jira?.email,
      apiToken: process.env.JIRA_API_TOKEN ?? fileConfig.jira?.apiToken,
      projectKey: process.env.JIRA_PROJECT_KEY ?? fileConfig.jira?.projectKey,
      issueType: fileConfig.jira?.issueType ?? "Task",
      status: fileConfig.jira?.status ?? "In Progress",
    },
    schedule: args.schedule ?? fileConfig.schedule,
    severityThreshold: args.severityThreshold ?? fileConfig.severityThreshold ?? "medium",
    reportFormats: fileConfig.reportFormats ?? ["markdown", "json"],
    failOnFindings: Boolean(args.failOnFindings),
    jsonSummary: Boolean(args.jsonSummary),
    exclude: fileConfig.exclude ?? ["node_modules", "vendor", "dist", "build", ".git", ".next", "coverage"],
  };
}

/**
 * @param {string|string[]|Record<string, boolean>|undefined} value
 * @returns {string[]}
 */
function normalizeScanners(value) {
  if (!value) {
    return defaultScanners;
  }

  if (Array.isArray(value)) {
    return value;
  }

  if (typeof value === "object") {
    return Object.entries(value)
      .filter(([, enabled]) => Boolean(enabled))
      .map(([name]) => name);
  }

  return String(value)
    .split(",")
    .map((scanner) => scanner.trim())
    .filter(Boolean);
}

/**
 * @param {string} targetPath
 */
function loadConfigFile(targetPath) {
  const configPath = path.join(targetPath, "security-agent.config.json");
  if (!existsSync(configPath)) {
    return {};
  }

  return JSON.parse(readFileSync(configPath, "utf8"));
}
