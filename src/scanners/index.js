/**
 * Scanner adapter registry and execution loop.
 */

import { runSemgrep } from "./semgrep.js";
import { runSecretsScanner } from "./secrets.js";
import { runTrivyOrGrype } from "./trivy-grype.js";
import { runPackageAudits } from "./package-audit.js";
import { runBuiltInChecks } from "./built-in.js";
import { logStep, logWarn } from "../log.js";

/** @type {Record<string, string>} */
const adapterLabels = {
  runSemgrep: "semgrep",
  runSecretsScanner: "secrets",
  runTrivyOrGrype: "trivy/grype",
  runPackageAudits: "package audit",
  runBuiltInChecks: "built-in",
};

/**
 * Executes enabled scanner adapters and aggregates normalized findings.
 * @param {import("../engine.js").AuditContext} context Audit execution context.
 */
export async function runScannerAdapters(context) {
  const adapters = [
    ["semgrep", runSemgrep],
    ["gitleaks", runSecretsScanner],
    ["trufflehog", runSecretsScanner],
    ["trivy", runTrivyOrGrype],
    ["grype", runTrivyOrGrype],
    ["npm-audit", runPackageAudits],
    ["composer-audit", runPackageAudits],
    ["built-in", runBuiltInChecks],
  ];

  const findings = [];
  const limitations = [];
  const positiveChecks = [];
  const scanners = [];
  const executedGroups = new Set();

  for (const [name, adapter] of adapters) {
    if (!context.config.scanners.includes(name)) {
      continue;
    }

    const groupKey = adapter.name;
    if (executedGroups.has(groupKey)) {
      continue;
    }
    executedGroups.add(groupKey);

    const label = adapterLabels[groupKey] ?? name;
    logStep(`Starting scanner: ${label}...`);
    const result = await adapter(context);
    findings.push(...result.findings);
    limitations.push(...result.limitations);
    positiveChecks.push(...result.positiveChecks);
    scanners.push(...result.scanners);

    for (const scanner of result.scanners) {
      if (scanner.status === "missing") {
        logWarn(`${label}: not installed, skipped.`);
      } else if (scanner.status === "error") {
        logWarn(`${label}: finished with error (exit ${scanner.exitCode ?? "unknown"}).`);
      } else {
        logStep(`${label}: finished with ${scanner.findingCount ?? 0} finding(s).`);
      }
    }

    for (const limitation of result.limitations) {
      logWarn(limitation);
    }
  }

  return { findings, limitations, positiveChecks, scanners };
}
