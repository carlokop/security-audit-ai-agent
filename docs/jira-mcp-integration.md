# Jira Integration

Jira publishing is optional. The audit must always produce local reports even when Jira task creation fails.

## Required Environment Variables

```env
JIRA_BASE_URL="https://websitediewerkt.atlassian.net"
JIRA_PROJECT_KEY="CLOCKIT"
JIRA_EMAIL="you@example.com"
JIRA_API_TOKEN="your_atlassian_api_token"
```

These match the same `.env` format used by `tester-agent`.

## Flow

1. Run the audit and normalize findings.
2. Filter findings by `--severity-threshold`.
3. Create one Jira issue per eligible finding through the Jira REST API.
4. Move each issue to `In Progress` when the workflow allows it.
5. Record created issue keys or publishing limitations in the audit report.

## Task Content

Each Jira task contains:

- vulnerability title,
- severity and confidence,
- source scanner,
- affected file and line,
- risk and impact,
- recommended remediation steps,
- reference to the local audit report.

Secrets and full `.env` values are never included.

## Example

```bash
security-agent audit --path . --mode diff --base main --jira --severity-threshold high
```

If Jira credentials are missing or a transition fails, the scan still succeeds and the report records the limitation.
