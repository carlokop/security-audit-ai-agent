/**
 * Git metadata collection for full and diff audit modes.
 */

import path from "node:path";
import { runCommand } from "./utils.js";

/**
 * Collects branch, changed files, and diff content for the target repository.
 * @param {import("./config.js").AuditConfig} config
 */
export function getGitContext(config) {
  const isRepo = runCommand("git", ["rev-parse", "--is-inside-work-tree"], { cwd: config.targetPath });
  if (isRepo.exitCode !== 0) {
    return {
      isGitRepo: false,
      branch: null,
      baseBranch: config.baseBranch,
      changedFiles: [],
      diff: "",
      limitations: ["Target path is not a Git repository; diff mode will scan available files as a full scan."],
    };
  }

  const branchResult = runCommand("git", ["branch", "--show-current"], { cwd: config.targetPath });
  const changedFiles = config.mode === "diff" ? getChangedFiles(config) : [];
  const diff = config.mode === "diff" ? getDiff(config) : "";

  return {
    isGitRepo: true,
    branch: branchResult.stdout.trim() || "detached-head",
    baseBranch: config.baseBranch,
    changedFiles,
    diff,
    limitations: [],
  };
}

/**
 * @param {import("./config.js").AuditConfig} config
 */
function getChangedFiles(config) {
  const result = runCommand("git", ["diff", "--name-only", `${config.baseBranch}...HEAD`], { cwd: config.targetPath });
  const fallback = result.exitCode === 0 ? result : runCommand("git", ["diff", "--name-only", config.baseBranch], { cwd: config.targetPath });
  if (fallback.exitCode !== 0) {
    return [];
  }
  return fallback.stdout
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean)
    .map((file) => path.join(config.targetPath, file));
}

/**
 * @param {import("./config.js").AuditConfig} config
 */
function getDiff(config) {
  const result = runCommand("git", ["diff", "--unified=80", `${config.baseBranch}...HEAD`], {
    cwd: config.targetPath,
    maxBuffer: 30 * 1024 * 1024,
  });
  const fallback = result.exitCode === 0 ? result : runCommand("git", ["diff", "--unified=80", config.baseBranch], {
    cwd: config.targetPath,
    maxBuffer: 30 * 1024 * 1024,
  });
  return fallback.exitCode === 0 ? fallback.stdout : "";
}
