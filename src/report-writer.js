/**
 * Markdown and JSON audit report generation.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { maskSecrets, severityRank } from "./utils.js";

/**
 * Builds deterministic report file paths without writing files yet.
 * @param {import("./config.js").AuditConfig} config
 * @param {{ startedAt: string, projectName: string, mode: string }} report
 */
export function buildReportPaths(config, report) {
  const stamp = report.startedAt.replace(/[:.]/g, "-");
  const safeProject = report.projectName.replace(/[^a-z0-9_-]/gi, "-").toLowerCase();
  const baseName = `${stamp}_${safeProject}-${report.mode}`;
  const reportPaths = {};

  if (config.reportFormats.includes("markdown")) {
    reportPaths.markdown = path.join(config.outputDir, `${baseName}.md`);
  }

  if (config.reportFormats.includes("json")) {
    reportPaths.json = path.join(config.outputDir, `${baseName}.json`);
  }

  return reportPaths;
}

/**
 * Writes Markdown and JSON audit reports to disk.
 * @param {import("./config.js").AuditConfig} config
 * @param {object} report
 */
export function writeReports(config, report) {
  mkdirSync(config.outputDir, { recursive: true });

  const reportPaths = buildReportPaths(config, report);

  if (reportPaths.markdown) {
    writeFileSync(reportPaths.markdown, renderMarkdown(report), "utf8");
  }

  if (reportPaths.json) {
    writeFileSync(reportPaths.json, JSON.stringify(report, null, 2), "utf8");
  }

  return reportPaths;
}

/**
 * @param {object} report
 */
function renderMarkdown(report) {
  const findingsBySeverity = groupFindings(report.findings);
  const severities = ["critical", "high", "medium", "low", "info"];

  return maskSecrets(`# Security Audit Report

## Summary
- Project: \`${report.projectName}\`
- Mode: \`${report.mode}\`
- Started: \`${report.startedAt}\`
- Finished: \`${report.finishedAt}\`
- Branch: \`${report.git.branch ?? "unknown"}\`
- Base branch: \`${report.git.baseBranch ?? "n/a"}\`
- Findings: \`${report.findings.length}\`

## Scope
- Target path: \`${report.targetPath}\`
- Git repository: \`${report.git.isGitRepo ? "yes" : "no"}\`
- Changed files considered: \`${report.git.changedFiles?.length ?? 0}\`
- AI mode: \`${report.ai?.mode ?? "off"}\`
- Requested model: \`${report.ai?.model ?? "n/a"}\`
- Resolved model: \`${report.ai?.usage?.resolvedModel ?? report.ai?.model ?? "n/a"}\`

## AI Usage
${renderAiUsage(report.ai)}

## What Went Well
${renderList(report.positiveChecks, "No positive checks were recorded.")}

## Scanner Status
${renderScannerStatus(report.scanners)}

## Findings
${severities.map((severity) => renderSeveritySection(severity, findingsBySeverity[severity] ?? [])).join("\n\n")}

## Scan Limitations And Errors
${renderList(report.limitations, "No scan limitations were recorded.")}

## Jira
${renderJira(report.jira)}

## Recommended Security Improvements
${renderRecommendations(report.findings)}
`);
}

/**
 * @param {import("./utils.js").SecurityFinding[]} findings
 */
function groupFindings(findings) {
  return findings.reduce((groups, finding) => {
    groups[finding.severity] = groups[finding.severity] ?? [];
    groups[finding.severity].push(finding);
    return groups;
  }, {});
}

/**
 * @param {string} severity
 * @param {import("./utils.js").SecurityFinding[]} findings
 */
function renderSeveritySection(severity, findings) {
  if (findings.length === 0) {
    return `### ${titleCase(severity)}\nNo findings.`;
  }

  return `### ${titleCase(severity)}\n${findings
    .sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0))
    .map((finding, index) => renderFinding(finding, index + 1))
    .join("\n\n")}`;
}

/**
 * @param {import("./utils.js").SecurityFinding} finding
 * @param {number} index
 */
function renderFinding(finding, index) {
  return `#### ${index}. ${finding.title}
- Source: \`${finding.source}\`
- File: \`${finding.filePath ?? "n/a"}${finding.line ? `:${finding.line}` : ""}\`
- Confidence: \`${finding.confidence}\`
- Risk: ${finding.risk ?? "n/a"}
- Impact: ${finding.impact ?? "n/a"}
- Recommendation: ${finding.recommendation ?? "n/a"}
${finding.codeContext ? `\n\`\`\`text\n${finding.codeContext}\n\`\`\`` : ""}`;
}

/**
 * @param {Array<{ name: string, status: string, findingCount?: number }>} scanners
 */
function renderScannerStatus(scanners) {
  if (!scanners.length) {
    return "No scanners were executed.";
  }
  return scanners
    .map((scanner) => `- \`${scanner.name}\`: ${scanner.status}${scanner.findingCount !== undefined ? `, findings: ${scanner.findingCount}` : ""}`)
    .join("\n");
}

/**
 * @param {{ enabled?: boolean, mode?: string, model?: string, usage?: import("./ai-reviewer.js").AiUsageSummary }} ai
 */
function renderAiUsage(ai) {
  if (!ai?.enabled || !ai.usage) {
    return "AI review was not executed.";
  }

  const duration = ai.usage.durationMs == null ? "unknown" : `${ai.usage.durationMs} ms`;
  return [
    `- Requested model: \`${ai.usage.requestedModel}\``,
    `- Resolved model: \`${ai.usage.resolvedModel}\``,
    `- Duration: \`${duration}\``,
    `- Estimated input tokens: \`${ai.usage.estimatedInputTokens}\``,
    `- Estimated output tokens: \`${ai.usage.estimatedOutputTokens}\``,
    `- Estimated total tokens: \`${ai.usage.estimatedTotalTokens}\``,
    `- Billing source: \`${ai.usage.billingSource}\` (Cursor SDK does not expose exact billed token counts)`,
    ai.usage.runId ? `- Run ID: \`${ai.usage.runId}\`` : null,
  ].filter(Boolean).join("\n");
}

/**
 * @param {{ enabled?: boolean, tasks?: Array<{ key?: string, title: string }>, limitations?: string[] }} jira
 */
function renderJira(jira) {
  if (!jira?.enabled) {
    return "Jira publishing was not requested.";
  }
  const tasks = jira.tasks?.length
    ? jira.tasks.map((task) => `- ${task.key ?? "unknown"}: ${task.title}`).join("\n")
    : "No Jira tasks were created.";
  const limitations = jira.limitations?.length ? `\n\nJira limitations:\n${renderList(jira.limitations)}` : "";
  return `${tasks}${limitations}`;
}

/**
 * @param {import("./utils.js").SecurityFinding[]} findings
 */
function renderRecommendations(findings) {
  if (findings.length === 0) {
    return "- Continue running full audits periodically and diff audits before merging sensitive changes.";
  }

  const themes = new Set(findings.map((finding) => finding.recommendation).filter(Boolean));
  return [...themes].slice(0, 12).map((item) => `- ${item}`).join("\n");
}

/**
 * @param {string[]} items
 * @param {string} [fallback]
 */
function renderList(items, fallback = "None.") {
  if (!items?.length) {
    return fallback;
  }
  return items.map((item) => `- ${item}`).join("\n");
}

/**
 * @param {string} value
 */
function titleCase(value) {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}
