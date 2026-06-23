/**
 * Core audit orchestration pipeline.
 */

import path from "node:path";
import { getGitContext } from "./git.js";
import { runScannerAdapters } from "./scanners/index.js";
import { runAiReview, formatAiUsageLog } from "./ai-reviewer.js";
import { buildReportPaths, writeReports } from "./report-writer.js";
import { publishJiraTasks } from "./jira-publisher.js";
import { listFiles } from "./utils.js";
import { logStep, logWarn } from "./log.js";

/**
 * @typedef {object} AuditContext
 * @property {import("./config.js").AuditConfig} config
 * @property {string} projectName
 * @property {Date} startedAt
 * @property {ReturnType<import("./git.js").getGitContext>} git
 * @property {string[]} files
 * @property {string[]} positiveChecks
 * @property {string[]} limitations
 */

/**
 * Runs a full security audit pipeline for the configured target repository.
 * @param {import("./config.js").AuditConfig} config Resolved audit configuration.
 * @returns {Promise<{
 *   findings: import("./utils.js").SecurityFinding[],
 *   report: object,
 *   reportPaths: { markdown?: string, json?: string },
 *   summary: object,
 *   fatalError: boolean
 * }>}
 */
export async function runAudit(config) {
  validateConfig(config);

  const startedAt = new Date();
  const projectName = path.basename(config.targetPath);
  logStep(`Audit started for ${projectName} (${config.mode})`);
  logStep(`Target path: ${config.targetPath}`);
  logStep(`Scanners: ${config.scanners.join(", ")}`);
  logStep(`AI mode: ${config.ai.mode}${config.ai.apiKey ? `, model: ${config.ai.model}` : ", no CURSOR_API_KEY"}`);

  logStep("Collecting Git context...");
  const git = getGitContext(config);
  if (git.isGitRepo) {
    logStep(`Git branch: ${git.branch}, base: ${git.baseBranch}`);
  } else {
    logWarn("Target is not a Git repository; diff information is limited.");
  }
  for (const limitation of git.limitations) {
    logWarn(limitation);
  }

  const files = config.mode === "diff" && git.changedFiles.length > 0
    ? git.changedFiles
    : listFiles(config.targetPath, config.exclude);
  logStep(`${files.length} file(s) selected for analysis.`);

  const context = {
    config,
    projectName,
    startedAt,
    git,
    files,
    positiveChecks: [],
    limitations: [...git.limitations],
  };

  if (config.schedule) {
    context.limitations.push(
      `Schedule option "${config.schedule}" was requested. This CLI run performs the audit now; register daily execution with cron/systemd or Cursor automation using the same command.`,
    );
    logWarn(context.limitations.at(-1));
  }

  logStep("Starting local scanners...");
  const scannerResult = await runScannerAdapters(context);
  let findings = scannerResult.findings;
  context.positiveChecks.push(...scannerResult.positiveChecks);
  context.limitations.push(...scannerResult.limitations);
  logStep(`Local scanners finished: ${findings.length} finding(s), ${scannerResult.limitations.length} limitation(s).`);

  logStep("Starting AI security review...");
  const aiResult = await runAiReview(context, findings);
  const aiFindingCount = aiResult.findings.length;
  findings = deduplicateFindings([...findings, ...aiResult.findings]);
  context.positiveChecks.push(...aiResult.positiveChecks);
  context.limitations.push(...aiResult.limitations);
  if (aiResult.metadata.enabled) {
    logStep(`AI review finished: ${aiFindingCount} additional finding(s), ${findings.length} total after deduplication.`);
    logStep(formatAiUsageLog(aiResult.metadata.usage));
  } else if (["missing-api-config", "api-error", "token-budget"].includes(aiResult.metadata.reason)) {
    logWarn(`AI review skipped: ${aiResult.limitations[0] ?? aiResult.metadata.reason}`);
  }

  const finishedAt = new Date();
  const reportDraft = {
    projectName,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    mode: config.mode,
    targetPath: config.targetPath,
    git,
    scanners: scannerResult.scanners,
    ai: aiResult.metadata,
    findings,
    positiveChecks: context.positiveChecks,
    limitations: context.limitations,
  };

  const reportPaths = buildReportPaths(config, reportDraft);
  if (config.jira.enabled) {
    logStep(`Creating Jira tasks (threshold: ${config.severityThreshold})...`);
  }
  const jiraResult = await publishJiraTasks(config, findings, reportPaths);
  context.limitations.push(...jiraResult.limitations);
  if (config.jira.enabled) {
    logStep(`Jira finished: ${jiraResult.tasks.length} task(s) created.`);
    for (const limitation of jiraResult.limitations) {
      logWarn(limitation);
    }
  }

  const report = {
    ...reportDraft,
    limitations: context.limitations,
    jira: jiraResult,
  };

  logStep("Writing report files...");
  writeReports(config, report);
  logStep(`Markdown report: ${reportPaths.markdown ?? "n/a"}`);
  if (reportPaths.json) {
    logStep(`JSON report: ${reportPaths.json}`);
  }

  const summary = {
    projectName,
    mode: config.mode,
    findingCount: findings.length,
    findingsBySeverity: countBy(findings, "severity"),
    limitations: context.limitations,
    reportPaths,
    aiUsage: aiResult.metadata.usage ?? null,
  };

  logStep(`Audit finished in ${Math.round((finishedAt - startedAt) / 1000)}s.`);

  return {
    findings,
    report,
    reportPaths,
    summary,
    fatalError: false,
  };
}

/**
 * @param {import("./config.js").AuditConfig} config
 */
function validateConfig(config) {
  if (!["full", "diff"].includes(config.mode)) {
    throw new Error(`Unsupported mode "${config.mode}". Use full or diff.`);
  }
  if (!["off", "targeted", "full-context"].includes(config.ai.mode)) {
    throw new Error(`Unsupported AI mode "${config.ai.mode}". Use off, targeted or full-context.`);
  }
}

/**
 * @param {import("./utils.js").SecurityFinding[]} findings
 */
function deduplicateFindings(findings) {
  const seen = new Set();
  const unique = [];
  for (const finding of findings) {
    const key = [finding.source, finding.title, finding.filePath, finding.line].join("|");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(finding);
  }
  return unique;
}

/**
 * @param {Array<Record<string, unknown>>} items
 * @param {string} key
 */
function countBy(items, key) {
  return items.reduce((counts, item) => {
    const value = item[key] ?? "unknown";
    counts[value] = (counts[value] ?? 0) + 1;
    return counts;
  }, {});
}
