# AI Vulnerability Checker

Local Node.js CLI orchestrator for read-only security audits of Git codebases. The tool runs local scanners first, then optionally asks an AI model to triage scanner findings and selected risky code context.

## What It Does

- Full project audits and Git diff audits.
- PHP and TypeScript focused MVP support.
- Local scanner adapters for Semgrep, Gitleaks or TruffleHog, Trivy or Grype, npm/pnpm/yarn audit, and Composer audit.
- Built-in fallback checks for risky patterns such as shell execution, `eval`, weak crypto, permissive CORS, SQL string construction, PHP deserialization, and hardcoded secrets.
- Markdown and JSON reports per scan.
- Optional AI review using Cursor via `CURSOR_API_KEY`.
- Optional Jira task creation via the Jira REST API.

The tool does not fix code. It reports risks and recommended improvements only.

## Usage

```bash
node ./bin/security-agent.js audit --path /path/to/project --mode full
```

```bash
node ./bin/security-agent.js audit --path /path/to/project --mode diff --base main
```

```bash
node ./bin/security-agent.js audit --path . --mode full --ai-mode off
```

```bash
node ./bin/security-agent.js audit --path . --mode diff --base main --jira --severity-threshold high
```

## AI Usage

AI is not the primary scanner. Local tools produce deterministic signals first. AI is used for:

- exploitability and context review,
- priority and false-positive triage,
- extra review of authorization, authentication, file upload, routing, middleware, and business-logic risks,
- report and Jira task wording.

Set `--ai-mode off` for local-only scanning.

## Environment Variables

Use the same `.env` format as `tester-agent`:

```env
CURSOR_API_KEY="cursor_..."
JIRA_BASE_URL="https://websitediewerkt.atlassian.net"
JIRA_PROJECT_KEY="CLOCKIT"
JIRA_EMAIL="you@example.com"
JIRA_API_TOKEN="your_atlassian_api_token"
```

Optional:

```env
AI_MODEL=auto
AI_MODE=targeted
AI_MAX_INPUT_TOKENS=300000
SECURITY_AGENT_OUTPUT_DIR=./security-audits
```

Install dependencies once:

```bash
npm install
```

## Exit Codes

- `0`: scan completed without findings above the configured threshold.
- `1`: scan completed with findings above the configured threshold.
- `2`: configuration or runtime failure.

## Recommended Local Tools

Install whichever scanners fit your environment:

```bash
semgrep --version
gitleaks version
trivy --version
composer --version
npm --version
```

Missing tools are reported as scan limitations; the audit continues.
