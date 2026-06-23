/**
 * Shared helpers for command execution, file collection, and finding normalization.
 */

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

/** @typedef {object} SecurityFinding Finding normalized across all scanners. */

/** @type {Record<string, number>} */
export const severityRank = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * @param {string} severity
 * @param {string} threshold
 */
export function severityMeetsThreshold(severity, threshold) {
  return (severityRank[normalizeSeverity(severity)] ?? 0) >= (severityRank[normalizeSeverity(threshold)] ?? 2);
}

/**
 * @param {string|undefined} severity
 */
export function normalizeSeverity(severity) {
  const value = String(severity ?? "info").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(value)) {
    return value;
  }
  if (["error", "warning"].includes(value)) {
    return value === "error" ? "high" : "medium";
  }
  return "info";
}

/**
 * Executes a read-only shell command synchronously.
 * @param {string} command Executable name.
 * @param {string[]} args Command arguments.
 * @param {{ cwd?: string, maxBuffer?: number, timeout?: number }} [options]
 */
export function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? 20 * 1024 * 1024,
    timeout: options.timeout ?? 120000,
  });

  return {
    command: [command, ...args].join(" "),
    exitCode: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error,
  };
}

/**
 * @param {string} command
 */
export function commandExists(command) {
  const result = spawnSync("sh", ["-c", `command -v ${shellQuote(command)}`], {
    encoding: "utf8",
  });
  return result.status === 0;
}

/**
 * @param {string|undefined} value
 */
export function readJson(value) {
  if (!value?.trim()) {
    return null;
  }
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

/**
 * Recursively lists files under a root directory while honoring exclude rules.
 * @param {string} root Repository root.
 * @param {string[]} exclude Relative path segments to skip.
 * @param {number} [maxFiles]
 */
export function listFiles(root, exclude, maxFiles = 5000) {
  const files = [];
  walk(root);
  return files;

  function walk(current) {
    if (files.length >= maxFiles) {
      return;
    }
    const entries = safeReadDir(current);
    for (const entry of entries) {
      const fullPath = path.join(current, entry);
      const relativePath = path.relative(root, fullPath);
      if (isExcluded(relativePath, exclude)) {
        continue;
      }
      const stats = safeStat(fullPath);
      if (!stats) {
        continue;
      }
      if (stats.isDirectory()) {
        walk(fullPath);
      } else if (stats.isFile()) {
        files.push(fullPath);
      }
    }
  }
}

/**
 * @param {string} filePath
 * @param {number} [maxBytes]
 */
export function readTextFile(filePath, maxBytes = 1024 * 1024) {
  const stats = safeStat(filePath);
  if (!stats || stats.size > maxBytes) {
    return null;
  }
  const buffer = readFileSync(filePath);
  if (buffer.includes(0)) {
    return null;
  }
  return buffer.toString("utf8");
}

/**
 * Redacts likely secret values before reports or AI prompts are emitted.
 * @param {string} value
 */
export function maskSecrets(value) {
  return String(value)
    .replace(/([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY)[A-Z0-9_]*\s*[:=]\s*)['"]?[^'"\s]+/gi, "$1[REDACTED]")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]")
    .replace(/-----BEGIN [^-]+PRIVATE KEY-----[\s\S]*?-----END [^-]+PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]");
}

/**
 * Creates a normalized security finding object.
 * @param {Partial<SecurityFinding> & { title?: string, severity?: string }} fields
 */
export function makeFinding(fields) {
  return {
    title: fields.title ?? "Security finding",
    severity: normalizeSeverity(fields.severity),
    filePath: fields.filePath ?? null,
    line: fields.line ?? null,
    codeContext: fields.codeContext ? maskSecrets(fields.codeContext) : null,
    risk: fields.risk ?? "Potential security risk.",
    impact: fields.impact ?? "Requires review.",
    recommendation: fields.recommendation ?? "Review and apply the appropriate secure coding pattern.",
    confidence: fields.confidence ?? "medium",
    source: fields.source ?? "unknown",
    scanType: fields.scanType ?? "full",
    cwe: fields.cwe ?? null,
    raw: fields.raw ?? undefined,
  };
}

/**
 * @param {string} directory
 */
function safeReadDir(directory) {
  try {
    return readdirSync(directory);
  } catch {
    return [];
  }
}

/**
 * @param {string} filePath
 */
function safeStat(filePath) {
  try {
    return statSync(filePath);
  } catch {
    return null;
  }
}

/**
 * @param {string} relativePath
 * @param {string[]} exclude
 */
function isExcluded(relativePath, exclude) {
  const normalized = relativePath.split(path.sep).join("/");
  return exclude.some((entry) => normalized === entry || normalized.startsWith(`${entry}/`) || normalized.includes(`/${entry}/`));
}

/**
 * @param {string} value
 */
function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}
