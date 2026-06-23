# Cursor Agent Usage

This document tells Cursor agents how to call the local `security-agent` CLI from another project. Do not reimplement scanning in chat. Run the CLI, read the generated report, and summarize the results.

## Decision Rules

Use a full audit when the user asks for:

- "security audit"
- "scan the project"
- "check this codebase"
- "run a full security audit"

Command:

```bash
security-agent audit --path . --mode full --ai-mode targeted
```

Use a diff audit when the user asks for:

- "review this PR"
- "check this branch"
- "review the latest changes"
- "review recent changes"

Command:

```bash
security-agent audit --path . --mode diff --base main --ai-mode targeted
```

Use local-only scanning when the user asks for no AI or when AI configuration is missing:

```bash
security-agent audit --path . --mode full --ai-mode off
```

Create Jira tasks only when the user explicitly asks for Jira tasks or project config allows it:

```bash
security-agent audit --path . --mode diff --base main --jira --severity-threshold high
```

## Required Agent Behavior

1. Run the relevant `security-agent audit` command.
2. Read the generated Markdown or JSON report path printed by the CLI.
3. Summarize the highest-risk findings first.
4. Mention scan limitations, especially missing scanners.
5. Do not edit source files unless the user later explicitly asks for fixes.
6. Do not paste secrets or full `.env` values into chat, reports, or Jira tasks.

## Recommended Defaults

- Default mode: `--mode full`.
- Default AI mode: `--ai-mode targeted`.
- Default Cursor model: `auto` via `AI_MODEL`.
- Default base branch for PR/diff review: `main`.
- Default Jira threshold: `high`.
- Default token budget: `--ai-token-budget 300000`.
- Cursor API key: `CURSOR_API_KEY` in `.env`.
- Jira credentials: `JIRA_BASE_URL`, `JIRA_PROJECT_KEY`, `JIRA_EMAIL`, `JIRA_API_TOKEN`.

## Exit Code Handling

- `0`: Scan completed. Summarize the result and report path.
- `1`: Scan completed and findings met the failure threshold. Summarize high-risk items and report path.
- `2`: Scan failed. Report the error and suggest checking path, config, or scanner installation.

## Natural Language Mapping

- "Run a security audit" -> `security-agent audit --path . --mode full --ai-mode targeted`
- "Review this PR" -> `security-agent audit --path . --mode diff --base main --ai-mode targeted`
- "Local only, no AI" -> `security-agent audit --path . --mode full --ai-mode off`
- "Create Jira tickets" -> add `--jira --severity-threshold high`

## What AI Reviews

AI reviews scanner findings and selected context only by default. It should focus on:

- PHP: Laravel/Symfony routes, controllers, middleware, policies, file uploads, sessions, cookies, `unserialize`, raw SQL, command execution.
- TypeScript: Next.js/NestJS/Express routes, API handlers, middleware, auth guards, CORS, server actions, SSRF, unsafe redirects, child process usage.
- Cross-stack: secrets, weak crypto, vulnerable dependencies, missing authorization, insecure configuration, risky diffs.

Local scanners remain the source of deterministic findings.
