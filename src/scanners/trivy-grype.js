/**
 * Trivy and Grype adapter for dependency, container, and IaC scanning.
 */

import { commandExists, makeFinding, readJson, runCommand } from "../utils.js";

/**
 * @param {import("../engine.js").AuditContext} context
 */
export async function runTrivyOrGrype(context) {
  if (context.config.scanners.includes("trivy") && commandExists("trivy")) {
    return runTrivy(context);
  }

  if (context.config.scanners.includes("grype") && commandExists("grype")) {
    return runGrype(context);
  }

  return {
    findings: [],
    positiveChecks: [],
    scanners: [{ name: "trivy-grype", status: "missing" }],
    limitations: ["Neither Trivy nor Grype is installed; broad dependency/container/IaC scanning was skipped."],
  };
}

function runTrivy(context) {
  const result = runCommand("trivy", ["fs", "--format", "json", "--scanners", "vuln,secret,misconfig", context.config.targetPath], {
    cwd: context.config.targetPath,
    timeout: 240000,
    maxBuffer: 80 * 1024 * 1024,
  });
  const payload = readJson(result.stdout);
  if (!payload) {
    return {
      findings: [],
      positiveChecks: [],
      scanners: [{ name: "trivy", status: "error", exitCode: result.exitCode }],
      limitations: [`Trivy output could not be parsed. ${result.stderr}`.trim()],
    };
  }

  const findings = [];
  for (const target of payload.Results ?? []) {
    for (const vulnerability of target.Vulnerabilities ?? []) {
      findings.push(makeFinding({
        title: `${vulnerability.VulnerabilityID}: ${vulnerability.PkgName}`,
        severity: vulnerability.Severity,
        filePath: target.Target,
        risk: vulnerability.Title ?? vulnerability.Description,
        impact: "A vulnerable dependency may be reachable by the application.",
        recommendation: vulnerability.FixedVersion
          ? `Upgrade ${vulnerability.PkgName} to ${vulnerability.FixedVersion} or later.`
          : "Review vendor guidance and upgrade or mitigate the affected package.",
        confidence: "high",
        source: "trivy",
        scanType: "dependency scan",
        raw: { id: vulnerability.VulnerabilityID, installedVersion: vulnerability.InstalledVersion },
      }));
    }
    for (const misconfiguration of target.Misconfigurations ?? []) {
      findings.push(makeFinding({
        title: misconfiguration.Title ?? misconfiguration.ID,
        severity: misconfiguration.Severity,
        filePath: target.Target,
        risk: misconfiguration.Description,
        impact: "Infrastructure or container configuration may weaken the runtime security posture.",
        recommendation: misconfiguration.Resolution ?? "Review the misconfiguration and apply least-privilege hardening.",
        confidence: "medium",
        source: "trivy",
        scanType: "configuration scan",
      }));
    }
  }

  return {
    findings,
    limitations: [],
    positiveChecks: findings.length === 0 ? ["Trivy completed without vulnerability or misconfiguration findings."] : [],
    scanners: [{ name: "trivy", status: "completed", exitCode: result.exitCode, findingCount: findings.length }],
  };
}

function runGrype(context) {
  const result = runCommand("grype", [`dir:${context.config.targetPath}`, "-o", "json"], {
    cwd: context.config.targetPath,
    timeout: 240000,
    maxBuffer: 80 * 1024 * 1024,
  });
  const payload = readJson(result.stdout);
  if (!payload) {
    return {
      findings: [],
      positiveChecks: [],
      scanners: [{ name: "grype", status: "error", exitCode: result.exitCode }],
      limitations: [`Grype output could not be parsed. ${result.stderr}`.trim()],
    };
  }

  const findings = (payload.matches ?? []).map((match) =>
    makeFinding({
      title: `${match.vulnerability?.id ?? "Vulnerability"}: ${match.artifact?.name ?? "dependency"}`,
      severity: match.vulnerability?.severity,
      filePath: match.artifact?.locations?.[0]?.path,
      risk: match.vulnerability?.description,
      impact: "A vulnerable dependency may be reachable by the application.",
      recommendation: match.vulnerability?.fix?.versions?.length
        ? `Upgrade to ${match.vulnerability.fix.versions.join(", ")}.`
        : "Review vendor guidance and upgrade or mitigate the affected package.",
      confidence: "high",
      source: "grype",
      scanType: "dependency scan",
      raw: { id: match.vulnerability?.id, version: match.artifact?.version },
    }),
  );

  return {
    findings,
    limitations: [],
    positiveChecks: findings.length === 0 ? ["Grype completed without vulnerability findings."] : [],
    scanners: [{ name: "grype", status: "completed", exitCode: result.exitCode, findingCount: findings.length }],
  };
}
