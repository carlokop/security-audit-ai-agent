/**
 * Cursor-powered AI review layer for triaging scanner findings.
 */

import path from "node:path";
import { makeFinding, maskSecrets, readTextFile } from "./utils.js";
import { logStep, logWarn, logProgress, startProgressHeartbeat } from "./log.js";

/**
 * Runs optional AI review on top of normalized scanner findings.
 * @param {import("./engine.js").AuditContext} context
 * @param {import("./utils.js").SecurityFinding[]} scannerFindings
 */
export async function runAiReview(context, scannerFindings) {
  if (context.config.ai.mode === "off" || !context.config.scanners.includes("ai-review")) {
    logStep("AI review disabled.");
    return {
      findings: [],
      positiveChecks: ["AI review disabled; local scanner results only."],
      limitations: [],
      metadata: { enabled: false, mode: context.config.ai.mode },
    };
  }

  if (!context.config.ai.apiKey) {
    logWarn("CURSOR_API_KEY is missing; AI review skipped.");
    return {
      findings: [],
      positiveChecks: [],
      limitations: ["AI review skipped because CURSOR_API_KEY is not configured. Local scan results are still valid."],
      metadata: {
        enabled: false,
        mode: context.config.ai.mode,
        model: context.config.ai.model,
        reason: "missing-api-config",
      },
    };
  }

  const riskyFiles = selectRiskyFiles(context, scannerFindings);
  const prompt = buildPrompt(context, scannerFindings, riskyFiles);
  const estimatedTokens = Math.ceil(prompt.length / 4);
  logStep(`Prepared AI prompt (~${estimatedTokens} tokens, budget ${context.config.ai.maxInputTokens}).`);
  logReviewScope(context, scannerFindings, riskyFiles);
  if (estimatedTokens > context.config.ai.maxInputTokens) {
    logWarn(`AI review skipped: token budget exceeded (${estimatedTokens}).`);
    return {
      findings: [],
      positiveChecks: [],
      limitations: [`AI review skipped because estimated input (${estimatedTokens} tokens) exceeds budget (${context.config.ai.maxInputTokens}).`],
      metadata: { enabled: false, mode: context.config.ai.mode, estimatedTokens, reason: "token-budget" },
    };
  }

  try {
    logStep(`Starting Cursor agent (model: ${context.config.ai.model})...`);
    logProgress("This step can take several minutes while the agent reads code and analyzes findings.");
    const agentResult = await callCursorAgent(context.config.ai, context.config.targetPath, prompt, estimatedTokens);
    logStep("Cursor agent finished; parsing findings...");
    const parsed = parseAiFindings(agentResult.text);
    return {
      findings: parsed.map((finding) => makeFinding({ ...finding, source: "ai-review", scanType: context.config.mode })),
      positiveChecks: ["AI review completed with Cursor for scanner findings and selected context."],
      limitations: [],
      metadata: {
        enabled: true,
        mode: context.config.ai.mode,
        model: context.config.ai.model,
        estimatedInputTokens: estimatedTokens,
        usage: agentResult.usage,
      },
    };
  } catch (error) {
    logWarn(`AI review failed: ${error.message}`);
    return {
      findings: [],
      positiveChecks: [],
      limitations: [`AI review failed: ${error.message}`],
      metadata: { enabled: false, mode: context.config.ai.mode, model: context.config.ai.model, reason: "api-error" },
    };
  }
}

/**
 * @param {import("./engine.js").AuditContext} context
 * @param {import("./utils.js").SecurityFinding[]} scannerFindings
 */
function buildPrompt(context, scannerFindings, riskyFiles) {
  const snippets = riskyFiles.map((filePath) => {
    const text = readTextFile(filePath, 80 * 1024);
    return text ? `FILE: ${path.relative(context.config.targetPath, filePath)}\n${maskSecrets(text.slice(0, 12000))}` : null;
  }).filter(Boolean);

  const findings = scannerFindings.slice(0, 120).map((finding) => ({
    title: finding.title,
    severity: finding.severity,
    filePath: finding.filePath,
    line: finding.line,
    risk: finding.risk,
    source: finding.source,
  }));

  return `
You are a lead security advisor and ethical hacker. Review the supplied scanner results and code context for PHP and TypeScript applications.

Rules:
- Do not propose code changes as patches.
- Do not reveal secrets; treat secret values as redacted.
- Return JSON only, shaped as: {"findings":[{"title":"","severity":"critical|high|medium|low|info","filePath":"","line":1,"risk":"","impact":"","recommendation":"","confidence":"high|medium|low"}]}.
- Focus on exploitable risks, authorization/authentication flaws, injection risks, unsafe file uploads, insecure deserialization, weak crypto, secrets, vulnerable dependencies, unsafe framework configuration, and risky PR diffs.
- If scanner findings appear duplicated or false positive, do not repeat them unless you add meaningful context.

Audit metadata:
Project: ${context.projectName}
Mode: ${context.config.mode}
Branch: ${context.git.branch ?? "unknown"}
Base branch: ${context.git.baseBranch}

Scanner findings:
${JSON.stringify(findings, null, 2)}

Git diff:
${context.config.mode === "diff" ? maskSecrets(context.git.diff.slice(0, 60000)) : "[not a diff scan]"}

Selected code context:
${snippets.join("\n\n---\n\n")}
`.trim();
}

/**
 * @param {import("./engine.js").AuditContext} context
 * @param {import("./utils.js").SecurityFinding[]} scannerFindings
 */
function selectRiskyFiles(context, scannerFindings) {
  const fromFindings = scannerFindings
    .map((finding) => finding.filePath)
    .filter(Boolean)
    .map((filePath) => path.resolve(context.config.targetPath, filePath));

  const securityNames = /(auth|login|session|permission|policy|guard|middleware|upload|file|route|controller|api|db|database|sql|payment|webhook)/i;
  const fromNames = context.files.filter((filePath) => securityNames.test(filePath));
  const candidates = context.config.ai.mode === "full-context"
    ? [...fromFindings, ...fromNames, ...context.files]
    : [...fromFindings, ...fromNames];

  return [...new Set(candidates)].slice(0, 25);
}

/**
 * @param {import("./engine.js").AuditContext} context
 * @param {import("./utils.js").SecurityFinding[]} scannerFindings
 * @param {string[]} riskyFiles
 */
function logReviewScope(context, scannerFindings, riskyFiles) {
  const relativeFiles = riskyFiles.map((filePath) => path.relative(context.config.targetPath, filePath));
  const filePreview = relativeFiles.slice(0, 6).join(", ");
  const fileSuffix = relativeFiles.length > 6 ? ` (+${relativeFiles.length - 6} more)` : "";
  const topFindings = scannerFindings.slice(0, 4).map((finding) =>
    `[${finding.severity}] ${finding.title}${finding.filePath ? ` @ ${finding.filePath}` : ""}`,
  );

  logProgress(`Review scope: ${scannerFindings.length} scanner finding(s), ${relativeFiles.length} code file(s) in prompt.`);
  if (relativeFiles.length > 0) {
    logProgress(`Code context includes: ${filePreview}${fileSuffix}`);
  }
  if (topFindings.length > 0) {
    logProgress(`Prioritizing scanner input: ${topFindings.join("; ")}`);
  }
}

/**
 * @param {{ apiKey: string, model: string }} ai
 * @param {string} cwd
 * @param {string} prompt
 * @param {number} estimatedInputTokens
 * @returns {Promise<{ text: string, usage: AiUsageSummary }>}
 */
async function callCursorAgent(ai, cwd, prompt, estimatedInputTokens) {
  logProgress("Loading Cursor SDK (Node may print a harmless SQLite ExperimentalWarning)...");
  const { Agent, CursorAgentError } = await import("@cursor/sdk");
  logProgress("Cursor SDK loaded; creating local agent...");

  const agent = await Agent.create({
    apiKey: ai.apiKey,
    model: { id: ai.model },
    local: { cwd },
  });

  const stopHeartbeat = startProgressHeartbeat("Cursor agent reviewing code", 20);
  const activity = createAgentActivityTracker();

  try {
    const run = await agent.send(prompt, {
      onStep: ({ step }) => {
        activity.onStep(step);
      },
      onDelta: ({ update }) => {
        activity.onDelta(update);
      },
    });
    logProgress(`Run started (${run.id}); streaming agent activity...`);

    if (run.supports("stream")) {
      for await (const event of run.stream()) {
        logAgentStreamEvent(event, activity);
      }
    } else {
      logProgress("Live streaming unavailable; waiting for agent completion...");
    }

    activity.complete();

    const result = await run.wait();
    if (result.status === "error") {
      throw new Error(result.result ?? "Cursor agent returned an error status.");
    }

    const text = String(result.result ?? run.result ?? "").trim();
    const estimatedOutputTokens = Math.ceil(text.length / 4);

    return {
      text,
      usage: buildAiUsageSummary({
        requestedModel: ai.model,
        resolvedModel: result.model?.id ?? run.model?.id ?? ai.model,
        durationMs: result.durationMs ?? run.durationMs ?? null,
        runId: result.id ?? run.id ?? null,
        estimatedInputTokens,
        estimatedOutputTokens,
      }),
    };
  } catch (error) {
    if (error instanceof CursorAgentError) {
      throw new Error(`Cursor agent startup failed: ${error.message}`);
    }
    throw error;
  } finally {
    stopHeartbeat();
    agent.close();
  }
}

/**
 * Logs fallback stream events that are not always surfaced through onStep.
 * @param {import("@cursor/sdk").SDKMessage} event
 * @param {ReturnType<typeof createAgentActivityTracker>} activity
 */
function logAgentStreamEvent(event, activity) {
  switch (event.type) {
    case "status":
      if (event.status === "ERROR") {
        logWarn(`Agent status: ${event.status}${event.message ? ` (${event.message})` : ""}`);
      }
      break;
    case "thinking":
      activity.onThinkingText(event.text, event.thinking_duration_ms);
      break;
    case "task":
      if (event.text) {
        logProgress(event.text);
      } else if (event.status) {
        logProgress(`Task: ${event.status}`);
      }
      break;
    default:
      break;
  }
}

/**
 * Tracks agent steps and logs human-readable progress instead of raw tokens.
 */
function createAgentActivityTracker() {
  const thinkingLogger = createThinkingProgressLogger();
  let toolStepCount = 0;
  let responseStarted = false;
  let responseBuffer = "";

  return {
    onStep(step) {
      switch (step.type) {
        case "thinkingMessage":
          thinkingLogger.logComplete(step.message.text, step.message.thinkingDurationMs);
          break;
        case "toolCall":
          toolStepCount += 1;
          logConversationToolStep(step.message);
          break;
        case "assistantMessage":
          appendStreamText(responseBuffer, step.message.text, (nextBuffer) => {
            responseBuffer = nextBuffer;
            noteResponseStarted(toolStepCount > 0);
          });
          break;
        default:
          break;
      }
    },
    onDelta(update) {
      if (update.type === "thinking-delta" && update.text) {
        thinkingLogger.append(update.text);
      }
      if (update.type === "thinking-completed") {
        thinkingLogger.complete(update.thinkingDurationMs);
      }
      if (update.type === "text-delta" && update.text) {
        appendStreamText(responseBuffer, update.text, (nextBuffer) => {
          responseBuffer = nextBuffer;
          noteResponseStarted(toolStepCount > 0);
        });
      }
    },
    onThinkingText(text, durationMs) {
      thinkingLogger.append(text);
      if (durationMs != null) {
        thinkingLogger.complete(durationMs);
      }
    },
    complete() {
      thinkingLogger.complete();
      if (toolStepCount === 0 && !thinkingLogger.hasContent()) {
        logProgress("Agent answered from the supplied audit prompt without extra file reads or visible reasoning steps.");
      }
      noteResponseStarted(toolStepCount > 0);
      logDraftedFindingsSummary(responseBuffer);
    },
  };

  function noteResponseStarted(usedTools) {
    if (responseStarted) {
      return;
    }
    responseStarted = true;
    if (usedTools) {
      logProgress("Composing final findings report from code exploration...");
    } else {
      logProgress("Composing findings from supplied scanner data and code snippets...");
    }
  }
}

/**
 * @param {string} current
 * @param {string} chunk
 * @param {(next: string) => void} assign
 */
function appendStreamText(current, chunk, assign) {
  if (!chunk) {
    return;
  }

  if (chunk.length >= current.length && chunk.startsWith(current)) {
    assign(chunk);
    return;
  }

  if (!current.endsWith(chunk)) {
    assign(current + chunk);
  }
}

/**
 * @param {unknown} message
 */
function logConversationToolStep(message) {
  if (!message || typeof message !== "object") {
    return;
  }

  const step = /** @type {{ type?: string, args?: Record<string, unknown> }} */ (message);
  switch (step.type) {
    case "read":
      logProgress(`Reading file: ${pickString(step.args ?? {}, ["path"]) ?? "unknown path"}`);
      break;
    case "grep":
      logProgress(formatSearchProgress("Searching code", step.args));
      break;
    case "glob":
      logProgress(`Finding files: ${pickString(step.args ?? {}, ["globPattern", "pattern", "glob"]) ?? "project"}`);
      break;
    case "shell":
      logProgress(`Running command: ${truncateText(maskSecrets(String(step.args?.command ?? "")), 100) || "unknown command"}`);
      break;
    case "semSearch":
      logProgress(`Semantic search: ${pickString(step.args ?? {}, ["query", "searchTerm"]) ?? "project code"}`);
      break;
    case "ls":
      logProgress(`Listing directory: ${pickString(step.args ?? {}, ["path", "targetDirectory"]) ?? "project"}`);
      break;
    default:
      logProgress(`Tool: ${step.type ?? "unknown"}`);
      break;
  }
}

/**
 * @param {string} prefix
 * @param {Record<string, unknown>|undefined} args
 */
function formatSearchProgress(prefix, args) {
  const pattern = pickString(args ?? {}, ["pattern", "query"]);
  const scope = pickString(args ?? {}, ["path", "glob", "targetDirectory"]);
  if (pattern && scope) {
    return `${prefix}: "${pattern}" in ${scope}`;
  }
  return `${prefix}: ${pattern ?? scope ?? "project"}`;
}

/**
 * @param {string} text
 */
function logDraftedFindingsSummary(text) {
  const summary = summarizeDraftedFindings(text);
  if (summary) {
    logProgress(`Findings drafted: ${summary}`);
    return;
  }

  if (text.trim()) {
    logProgress("Findings report composed.");
  }
}

/**
 * @param {string} text
 */
function summarizeDraftedFindings(text) {
  try {
    const jsonText = text.replace(/^```json\s*/i, "").replace(/```$/i, "").trim();
    const payload = JSON.parse(jsonText);
    if (!Array.isArray(payload.findings) || payload.findings.length === 0) {
      return null;
    }

    return payload.findings
      .slice(0, 6)
      .map((finding) => `${finding.title} (${finding.severity ?? "unknown"})`)
      .join("; ");
  } catch {
    return null;
  }
}

/**
 * Tracks streamed thinking text and logs readable excerpts.
 */
function createThinkingProgressLogger() {
  let buffer = "";
  let loggedBufferLength = 0;
  let lastLoggedExcerpt = "";
  let durationLogged = false;
  /** @type {ReturnType<typeof setTimeout>|null} */
  let pendingTimer = null;

  return {
    append(text) {
      if (!text) {
        return;
      }

      if (text.length >= buffer.length && text.startsWith(buffer)) {
        buffer = text;
      } else if (!buffer.endsWith(text)) {
        buffer += text;
      }

      scheduleLog();
    },
    logComplete(text, durationMs) {
      if (text) {
        buffer = text;
      }
      flush(true);
      if (durationMs != null && !durationLogged) {
        logProgress(`Reasoning finished (${durationMs}ms).`);
        durationLogged = true;
      }
    },
    hasContent() {
      return buffer.trim().length > 0;
    },
    complete(durationMs) {
      if (pendingTimer) {
        clearTimeout(pendingTimer);
        pendingTimer = null;
      }
      flush(true);
      if (durationMs != null && !durationLogged) {
        logProgress(`Reasoning finished (${durationMs}ms).`);
        durationLogged = true;
      }
    },
  };

  function scheduleLog() {
    if (pendingTimer) {
      return;
    }

    pendingTimer = setTimeout(() => {
      pendingTimer = null;
      flush(false);
    }, 2500);
    pendingTimer.unref?.();
  }

  function flush(force) {
    if (!buffer.trim()) {
      return;
    }

    const excerpt = formatThinkingExcerpt(buffer);
    if (!excerpt) {
      return;
    }

    const newChars = buffer.length - loggedBufferLength;
    if (!force && excerpt === lastLoggedExcerpt && newChars < 40) {
      return;
    }

    logProgress(`Reasoning: ${excerpt}`);
    lastLoggedExcerpt = excerpt;
    loggedBufferLength = buffer.length;
  }
}

/**
 * @param {Record<string, unknown>} record
 * @param {string[]} keys
 */
function pickString(record, keys) {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

/**
 * @param {string} text
 */
function formatThinkingExcerpt(text) {
  const cleaned = maskSecrets(text.replace(/\s+/g, " ").trim());
  if (!cleaned) {
    return "";
  }

  const sentences = cleaned.match(/[^.!?]+[.!?]+/g);
  if (sentences?.length) {
    return truncateText(sentences.slice(-2).join(" ").trim(), 220);
  }

  return truncateText(cleaned.slice(-220), 220);
}

/**
 * @param {string} text
 * @param {number} max
 */
function truncateText(text, max) {
  if (text.length <= max) {
    return text;
  }
  return `${text.slice(0, max - 1)}…`;
}

/**
 * @typedef {object} AiUsageSummary
 * @property {string} requestedModel Model requested in config or CLI.
 * @property {string} resolvedModel Model reported by Cursor after the run.
 * @property {number|null} durationMs Agent runtime in milliseconds when available.
 * @property {string|null} runId Cursor run identifier when available.
 * @property {number} estimatedInputTokens Estimated prompt tokens from prompt size.
 * @property {number} estimatedOutputTokens Estimated completion tokens from response size.
 * @property {number} estimatedTotalTokens Sum of estimated input and output tokens.
 * @property {"estimated"} billingSource Indicates exact billing usage is not exposed by the SDK.
 */

/**
 * Builds a normalized AI usage summary for logs and reports.
 * Cursor SDK does not currently expose exact billed token counts on RunResult.
 * @param {{
 *   requestedModel: string,
 *   resolvedModel: string,
 *   durationMs: number|null,
 *   runId: string|null,
 *   estimatedInputTokens: number,
 *   estimatedOutputTokens: number
 * }} input
 * @returns {AiUsageSummary}
 */
export function buildAiUsageSummary(input) {
  return {
    requestedModel: input.requestedModel,
    resolvedModel: input.resolvedModel,
    durationMs: input.durationMs,
    runId: input.runId,
    estimatedInputTokens: input.estimatedInputTokens,
    estimatedOutputTokens: input.estimatedOutputTokens,
    estimatedTotalTokens: input.estimatedInputTokens + input.estimatedOutputTokens,
    billingSource: "estimated",
  };
}

/**
 * Formats AI usage for console logging.
 * @param {AiUsageSummary|null|undefined} usage
 */
export function formatAiUsageLog(usage) {
  if (!usage) {
    return "AI usage: not available.";
  }

  const duration = usage.durationMs == null ? "unknown" : `${usage.durationMs}ms`;
  return [
    `AI usage: requested model=${usage.requestedModel}, resolved model=${usage.resolvedModel}, duration=${duration}`,
    `Estimated tokens: input=${usage.estimatedInputTokens}, output=${usage.estimatedOutputTokens}, total=${usage.estimatedTotalTokens} (${usage.billingSource})`,
    usage.runId ? `Run ID: ${usage.runId}` : null,
  ].filter(Boolean).join(" | ");
}

/**
 * @param {string} content
 */
function parseAiFindings(content) {
  const jsonText = content.replace(/^```json\s*/i, "").replace(/```$/i, "").trim();
  const payload = JSON.parse(jsonText);
  return Array.isArray(payload.findings) ? payload.findings : [];
}
