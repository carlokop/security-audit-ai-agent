# Acceptance Criteria

- The CLI can scan a full local codebase and create Markdown and JSON reports.
- The CLI can review current Git branch changes against a base branch.
- The CLI detects available scanners and records missing scanners as limitations.
- Scanner outputs are normalized to one finding format.
- Reports include summary, scope, scanner status, positive checks, findings, limitations, Jira status, and recommended improvements.
- Source files in the target repository are not modified.
- Secrets are masked before report output and AI context.
- Node/TypeScript dependency audit and PHP Composer audit are supported when package managers are available.
- Cursor agents can use `AI_USAGE.md` to choose full audits, diff reviews, local-only scans, and Jira task creation.
- `--ai-mode off|targeted|full-context` and `--ai-token-budget` are supported.
- `CURSOR_API_KEY`, `JIRA_BASE_URL`, `JIRA_PROJECT_KEY`, `JIRA_EMAIL`, and `JIRA_API_TOKEN` are supported via `.env`.
- Exit code `1` indicates a successful scan with findings above threshold; exit code `2` indicates a runtime or configuration failure.
