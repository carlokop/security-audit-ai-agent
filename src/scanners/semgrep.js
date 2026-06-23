/**
 * Semgrep adapter for static application security testing.
 */

import path from "node:path";
import { commandExists, makeFinding, readJson, runCommand } from "../utils.js";

/**
 * @param {import("../engine.js").AuditContext} context
 */
export async function runSemgrep(context) {
  if (!context.config.scanners.includes("semgrep")) {
    return empty();
  }
  if (!commandExists("semgrep")) {
    return {
      ...empty(),
      scanners: [{ name: "semgrep", status: "missing" }],
      limitations: ["Semgrep is not installed; static security rules were skipped."],
    };
  }

  const args = ["--config", "auto", "--json", "--no-git-ignore"];
  if (context.config.mode === "diff" && context.git.changedFiles.length > 0) {
    args.push(...context.git.changedFiles.map((file) => path.relative(context.config.targetPath, file)));
  } else {
    args.push(".");
  }

  const result = runCommand("semgrep", args, {
    cwd: context.config.targetPath,
    timeout: 180000,
    maxBuffer: 50 * 1024 * 1024,
  });
  const payload = readJson(result.stdout);
  if (!payload) {
    return {
      ...empty(),
      scanners: [{ name: "semgrep", status: result.error ? "error" : "completed", exitCode: result.exitCode }],
      limitations: [`Semgrep output could not be parsed. ${result.stderr}`.trim()],
    };
  }

  const findings = (payload.results ?? []).map((item) =>
    makeFinding({
      title: item.extra?.message ?? item.check_id ?? "Semgrep finding",
      severity: mapSeverity(item.extra?.severity),
      filePath: item.path,
      line: item.start?.line,
      risk: item.extra?.message,
      impact: "Semgrep detected a pattern that may introduce an application security risk.",
      recommendation: item.extra?.metadata?.fix ?? "Review the rule details and apply the secure framework-specific pattern.",
      confidence: item.extra?.metadata?.confidence ?? "medium",
      source: "semgrep",
      scanType: context.config.mode,
      cwe: item.extra?.metadata?.cwe,
      raw: { checkId: item.check_id },
    }),
  );

  return {
    findings,
    limitations: [],
    positiveChecks: findings.length === 0 ? ["Semgrep completed without findings."] : [],
    scanners: [{ name: "semgrep", status: "completed", exitCode: result.exitCode, findingCount: findings.length }],
  };
}

function empty() {
  return { findings: [], limitations: [], positiveChecks: [], scanners: [] };
}

function mapSeverity(severity) {
  const normalized = String(severity ?? "info").toLowerCase();
  if (normalized === "error") {
    return "high";
  }
  if (normalized === "warning") {
    return "medium";
  }
  return normalized;
}
