/**
 * Package manager audit adapter for Node.js and PHP Composer projects.
 */

import { existsSync } from "node:fs";
import path from "node:path";
import { commandExists, makeFinding, readJson, runCommand } from "../utils.js";

/**
 * @param {import("../engine.js").AuditContext} context
 */
export async function runPackageAudits(context) {
  const findings = [];
  const limitations = [];
  const positiveChecks = [];
  const scanners = [];

  const nodeResult = runNodeAudit(context);
  findings.push(...nodeResult.findings);
  limitations.push(...nodeResult.limitations);
  positiveChecks.push(...nodeResult.positiveChecks);
  scanners.push(...nodeResult.scanners);

  const composerResult = runComposerAudit(context);
  findings.push(...composerResult.findings);
  limitations.push(...composerResult.limitations);
  positiveChecks.push(...composerResult.positiveChecks);
  scanners.push(...composerResult.scanners);

  return { findings, limitations, positiveChecks, scanners };
}

function runNodeAudit(context) {
  if (!context.config.scanners.includes("npm-audit")) {
    return empty();
  }
  const packageJson = path.join(context.config.targetPath, "package.json");
  if (!existsSync(packageJson)) {
    return empty();
  }

  const command = selectNodePackageManager(context.config.targetPath);
  if (!command || !commandExists(command.name)) {
    return {
      ...empty(),
      scanners: [{ name: "node-package-audit", status: "missing" }],
      limitations: ["No supported Node package manager audit command is available."],
    };
  }

  const result = runCommand(command.name, command.args, {
    cwd: context.config.targetPath,
    timeout: 180000,
    maxBuffer: 50 * 1024 * 1024,
  });
  const payload = readJson(result.stdout);
  const findings = normalizeNodeAudit(payload, command.name);

  return {
    findings,
    limitations: payload ? [] : [`${command.name} audit output could not be parsed. ${result.stderr}`.trim()],
    positiveChecks: payload && findings.length === 0 ? [`${command.name} audit completed without findings.`] : [],
    scanners: [{ name: `${command.name}-audit`, status: payload ? "completed" : "error", exitCode: result.exitCode, findingCount: findings.length }],
  };
}

function runComposerAudit(context) {
  if (!context.config.scanners.includes("composer-audit")) {
    return empty();
  }
  const composerJson = path.join(context.config.targetPath, "composer.json");
  if (!existsSync(composerJson)) {
    return empty();
  }
  if (!commandExists("composer")) {
    return {
      ...empty(),
      scanners: [{ name: "composer-audit", status: "missing" }],
      limitations: ["Composer is not installed; PHP dependency audit was skipped."],
    };
  }

  const result = runCommand("composer", ["audit", "--format=json", "--no-interaction"], {
    cwd: context.config.targetPath,
    timeout: 180000,
    maxBuffer: 50 * 1024 * 1024,
  });
  const payload = readJson(result.stdout);
  const advisories = payload?.advisories ?? {};
  const findings = Object.entries(advisories).flatMap(([packageName, items]) =>
    items.map((item) =>
      makeFinding({
        title: `${item.cve ?? item.advisoryId ?? "Composer advisory"}: ${packageName}`,
        severity: mapComposerSeverity(item.severity),
        filePath: "composer.lock",
        risk: item.title,
        impact: "A vulnerable PHP dependency may affect the application.",
        recommendation: item.affectedVersions
          ? `Upgrade ${packageName} outside affected versions ${item.affectedVersions}.`
          : `Upgrade ${packageName} to a patched version.`,
        confidence: "high",
        source: "composer audit",
        scanType: "dependency scan",
        raw: { cve: item.cve, link: item.link },
      }),
    ),
  );

  return {
    findings,
    limitations: payload ? [] : [`Composer audit output could not be parsed. ${result.stderr}`.trim()],
    positiveChecks: payload && findings.length === 0 ? ["Composer audit completed without findings."] : [],
    scanners: [{ name: "composer-audit", status: payload ? "completed" : "error", exitCode: result.exitCode, findingCount: findings.length }],
  };
}

function normalizeNodeAudit(payload, source) {
  if (!payload) {
    return [];
  }

  if (payload.vulnerabilities && typeof payload.vulnerabilities === "object") {
    return Object.entries(payload.vulnerabilities).map(([packageName, vulnerability]) =>
      makeFinding({
        title: `${packageName}: ${vulnerability.name ?? "dependency vulnerability"}`,
        severity: vulnerability.severity,
        filePath: "package-lock.json",
        risk: vulnerability.title ?? `${packageName} has known vulnerability advisories.`,
        impact: "A vulnerable TypeScript/JavaScript dependency may affect the application.",
        recommendation: vulnerability.fixAvailable
          ? `Upgrade ${packageName} using the package manager audit fix guidance.`
          : `Review advisories for ${packageName} and upgrade or mitigate manually.`,
        confidence: "high",
        source: `${source} audit`,
        scanType: "dependency scan",
        raw: { via: vulnerability.via, range: vulnerability.range },
      }),
    );
  }

  if (payload.advisories && typeof payload.advisories === "object") {
    return Object.values(payload.advisories).map((advisory) =>
      makeFinding({
        title: `${advisory.module_name}: ${advisory.title}`,
        severity: advisory.severity,
        filePath: "package-lock.json",
        risk: advisory.overview,
        impact: "A vulnerable TypeScript/JavaScript dependency may affect the application.",
        recommendation: advisory.recommendation ?? `Upgrade ${advisory.module_name}.`,
        confidence: "high",
        source: `${source} audit`,
        scanType: "dependency scan",
        raw: { cves: advisory.cves, url: advisory.url },
      }),
    );
  }

  return [];
}

function selectNodePackageManager(targetPath) {
  if (existsSync(path.join(targetPath, "pnpm-lock.yaml"))) {
    return { name: "pnpm", args: ["audit", "--json"] };
  }
  if (existsSync(path.join(targetPath, "yarn.lock"))) {
    return { name: "yarn", args: ["npm", "audit", "--json"] };
  }
  if (existsSync(path.join(targetPath, "package-lock.json"))) {
    return { name: "npm", args: ["audit", "--json"] };
  }
  return { name: "npm", args: ["audit", "--json"] };
}

function mapComposerSeverity(severity) {
  const value = String(severity ?? "medium").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(value)) {
    return value;
  }
  return "medium";
}

function empty() {
  return { findings: [], limitations: [], positiveChecks: [], scanners: [] };
}
