/**
 * Built-in regex checks used when external scanners are unavailable.
 */

import path from "node:path";
import { makeFinding, readTextFile } from "../utils.js";

const checks = [
  {
    id: "unsafe-eval",
    pattern: /\beval\s*\(|new Function\s*\(/,
    severity: "high",
    title: "Unsafe dynamic code execution",
    risk: "Dynamic code execution can allow attacker-controlled input to execute as code.",
    recommendation: "Remove dynamic evaluation and replace it with explicit parsing or a safe dispatch table.",
  },
  {
    id: "shell-execution",
    pattern: /\b(exec|shell_exec|passthru|system|proc_open|popen|child_process\.(exec|spawn|execFile)|execSync|spawnSync)\s*\(/,
    severity: "high",
    title: "Shell command execution requires review",
    risk: "Shell execution can lead to command injection when user-controlled input reaches the command string.",
    recommendation: "Avoid shell execution or pass validated arguments to non-shell APIs.",
  },
  {
    id: "permissive-cors",
    pattern: /(Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|origin\s*:\s*["']\*)/,
    severity: "medium",
    title: "Permissive CORS configuration",
    risk: "Wildcard origins can expose browser-accessible APIs to untrusted websites.",
    recommendation: "Restrict CORS origins to trusted domains and validate credentials settings.",
  },
  {
    id: "weak-crypto",
    pattern: /\b(md5|sha1)\s*\(|createHash\s*\(\s*["'](md5|sha1)["']\s*\)/i,
    severity: "medium",
    title: "Weak cryptographic hash usage",
    risk: "MD5 and SHA-1 are weak for security-sensitive hashing.",
    recommendation: "Use modern algorithms such as SHA-256 for integrity or password hashing functions such as Argon2id/bcrypt.",
  },
  {
    id: "php-deserialize",
    pattern: /\bunserialize\s*\(/,
    severity: "high",
    title: "PHP unsafe deserialization requires review",
    risk: "Deserializing attacker-controlled PHP objects can lead to object injection.",
    recommendation: "Avoid `unserialize` for untrusted data; use JSON or restrict allowed classes.",
  },
  {
    id: "sql-concat",
    pattern: /(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,120}(\+|\.\s*\$|\$\{)/i,
    severity: "medium",
    title: "Possible SQL query construction from dynamic input",
    risk: "String-built SQL can become SQL injection if user-controlled input is included.",
    recommendation: "Use parameterized queries, prepared statements, or safe ORM query builders.",
  },
  {
    id: "hardcoded-secret",
    pattern: /(api[_-]?key|secret|password|token)\s*[:=]\s*["'][^"']{12,}["']/i,
    severity: "critical",
    title: "Possible hardcoded secret",
    risk: "Secrets committed to source control can be leaked and abused.",
    recommendation: "Move secrets to environment variables or a secret manager and rotate any exposed value.",
  },
];

const supportedExtensions = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".php",
  ".json",
  ".yml",
  ".yaml",
  ".env",
  ".example",
]);

/**
 * @param {import("../engine.js").AuditContext} context
 */
export async function runBuiltInChecks(context) {
  if (!context.config.scanners.includes("built-in")) {
    return { findings: [], limitations: [], positiveChecks: [], scanners: [] };
  }

  const findings = [];
  let scannedFiles = 0;

  for (const filePath of context.files) {
    if (!shouldScan(filePath)) {
      continue;
    }
    const text = readTextFile(filePath);
    if (!text) {
      continue;
    }
    scannedFiles += 1;
    const lines = text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      for (const check of checks) {
        if (!check.pattern.test(line)) {
          continue;
        }
        findings.push(makeFinding({
          title: check.title,
          severity: check.severity,
          filePath: path.relative(context.config.targetPath, filePath),
          line: index + 1,
          codeContext: line.trim(),
          risk: check.risk,
          impact: "This pattern may be exploitable depending on input sources and framework context.",
          recommendation: check.recommendation,
          confidence: "medium",
          source: "built-in",
          scanType: context.config.mode,
          raw: { checkId: check.id },
        }));
      }
    }
  }

  return {
    findings,
    limitations: [],
    positiveChecks: scannedFiles > 0 ? [`Built-in checks scanned ${scannedFiles} text files.`] : [],
    scanners: [{ name: "built-in", status: "completed", findingCount: findings.length }],
  };
}

function shouldScan(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath).toLowerCase();
  return supportedExtensions.has(extension) || basename.startsWith(".env");
}
