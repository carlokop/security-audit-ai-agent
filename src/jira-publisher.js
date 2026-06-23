/**
 * Publishes eligible audit findings as Jira tasks.
 */

import { createSecurityIssue, resolveJiraConfig, transitionIssueToStatus } from "./jira.js";
import { severityMeetsThreshold } from "./utils.js";
import { logStep, logWarn } from "./log.js";

/**
 * Creates Jira tasks for findings above the configured severity threshold.
 * @param {import("./config.js").AuditConfig} config
 * @param {import("./utils.js").SecurityFinding[]} findings
 * @param {{ markdown?: string, json?: string }} reportPaths
 */
export async function publishJiraTasks(config, findings, reportPaths) {
  if (!config.jira.enabled) {
    return { enabled: false, tasks: [], limitations: [] };
  }

  const jiraConfig = resolveJiraConfig(config.jira);
  if (!jiraConfig) {
    logWarn("Jira credentials are incomplete; no tasks were created.");
    return {
      enabled: true,
      tasks: [],
      limitations: [
        "Jira publishing requested, but JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, or JIRA_PROJECT_KEY is not configured.",
      ],
    };
  }

  const eligible = findings.filter((finding) =>
    severityMeetsThreshold(finding.severity, config.severityThreshold),
  );
  if (eligible.length === 0) {
    logStep("No findings above threshold; no Jira tasks created.");
    return { enabled: true, tasks: [], limitations: ["Jira requested, but no findings met the severity threshold."] };
  }

  logStep(`${eligible.length} finding(s) eligible for Jira (project ${jiraConfig.projectKey}).`);

  const tasks = [];
  const limitations = [];

  for (const finding of eligible) {
    try {
      const payload = buildJiraTaskPayload(config, finding, reportPaths);
      logStep(`Creating Jira issue: ${payload.summary}`);
      const issue = await createSecurityIssue(jiraConfig, payload);
      logStep(`Transitioning Jira ${issue.key} to ${jiraConfig.inProgressStatus}...`);
      const transition = await transitionIssueToStatus(jiraConfig, issue.key, jiraConfig.inProgressStatus);
      tasks.push({
        key: issue.key,
        title: payload.summary,
        status: transition,
      });
      logStep(`Created Jira task: ${issue.key}`);
    } catch (error) {
      logWarn(`Failed to create Jira task for "${finding.title}": ${error.message}`);
      limitations.push(`Failed to create Jira task for "${finding.title}": ${error.message}`);
    }
  }

  return { enabled: true, tasks, limitations };
}

/**
 * Builds the Jira issue payload for a normalized finding.
 * @param {import("./config.js").AuditConfig} config
 * @param {import("./utils.js").SecurityFinding} finding
 * @param {{ markdown?: string, json?: string }} reportPaths
 */
export function buildJiraTaskPayload(config, finding, reportPaths) {
  const reportReference = reportPaths?.markdown ?? reportPaths?.json ?? "local audit report";
  return {
    summary: `[${finding.severity.toUpperCase()}] ${finding.title}`,
    description: [
      `Severity: ${finding.severity}`,
      `Confidence: ${finding.confidence}`,
      `Source: ${finding.source}`,
      `File: ${finding.filePath ?? "n/a"}${finding.line ? `:${finding.line}` : ""}`,
      "",
      `Risk: ${finding.risk}`,
      "",
      `Impact: ${finding.impact}`,
      "",
      `Recommended action: ${finding.recommendation}`,
      "",
      `Audit report: ${reportReference}`,
    ].join("\n"),
  };
}
