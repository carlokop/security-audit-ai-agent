/**
 * Secret scanning adapter for Gitleaks and TruffleHog.
 */

import { commandExists, makeFinding, readJson, runCommand } from "../utils.js";

/**
 * @param {import("../engine.js").AuditContext} context
 */
export async function runSecretsScanner(context) {
  if (context.config.scanners.includes("gitleaks") && commandExists("gitleaks")) {
    return runGitleaks(context);
  }

  if (context.config.scanners.includes("trufflehog") && commandExists("trufflehog")) {
    return runTrufflehog(context);
  }

  return {
    findings: [],
    positiveChecks: [],
    scanners: [{ name: "secrets", status: "missing" }],
    limitations: ["Neither Gitleaks nor TruffleHog is installed; secret scanning was skipped."],
  };
}

function runGitleaks(context) {
  const result = runCommand("gitleaks", ["detect", "--source", context.config.targetPath, "--report-format", "json", "--no-banner", "--redact"], {
    cwd: context.config.targetPath,
    timeout: 180000,
    maxBuffer: 30 * 1024 * 1024,
  });
  const payload = readJson(result.stdout) ?? [];
  const findings = Array.isArray(payload)
    ? payload.map((item) =>
        makeFinding({
          title: `Potential secret: ${item.RuleID ?? item.Description ?? "secret"}`,
          severity: "critical",
          filePath: item.File,
          line: item.StartLine,
          codeContext: item.Secret ? "[REDACTED]" : item.Match,
          risk: "A credential or secret-like value may be present in source control.",
          impact: "Leaked credentials can allow unauthorized access to systems or data.",
          recommendation: "Revoke the secret if real, move it to a secret manager, and rotate any affected credentials.",
          confidence: "high",
          source: "gitleaks",
          scanType: "secret scan",
        }),
      )
    : [];

  return {
    findings,
    limitations: [],
    positiveChecks: findings.length === 0 ? ["Gitleaks completed without secret findings."] : [],
    scanners: [{ name: "gitleaks", status: "completed", exitCode: result.exitCode, findingCount: findings.length }],
  };
}

function runTrufflehog(context) {
  const result = runCommand("trufflehog", ["filesystem", "--json", "--no-update", context.config.targetPath], {
    cwd: context.config.targetPath,
    timeout: 180000,
    maxBuffer: 30 * 1024 * 1024,
  });
  const findings = result.stdout
    .split(/\r?\n/)
    .map((line) => readJson(line))
    .filter(Boolean)
    .map((item) =>
      makeFinding({
        title: `Potential secret: ${item.DetectorName ?? "secret"}`,
        severity: item.Verified ? "critical" : "high",
        filePath: item.SourceMetadata?.Data?.Filesystem?.file,
        line: item.SourceMetadata?.Data?.Filesystem?.line,
        codeContext: "[REDACTED]",
        risk: "A credential or secret-like value may be present in the repository.",
        impact: "Leaked credentials can allow unauthorized access to systems or data.",
        recommendation: "Validate whether the secret is real, rotate it if needed, and move secrets to managed storage.",
        confidence: item.Verified ? "high" : "medium",
        source: "trufflehog",
        scanType: "secret scan",
      }),
    );

  return {
    findings,
    limitations: [],
    positiveChecks: findings.length === 0 ? ["TruffleHog completed without secret findings."] : [],
    scanners: [{ name: "trufflehog", status: "completed", exitCode: result.exitCode, findingCount: findings.length }],
  };
}
