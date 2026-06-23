/**
 * Jira REST API helpers for creating and transitioning security issues.
 */

/**
 * @typedef {object} ResolvedJiraConfig
 * @property {string} baseUrl
 * @property {string} email
 * @property {string} apiToken
 * @property {string} projectKey
 * @property {string} issueType
 * @property {string} inProgressStatus
 */

/**
 * Resolves Jira credentials from config values and environment variables.
 * @param {Record<string, string|boolean|undefined>} [fileConfig]
 * @returns {ResolvedJiraConfig|null}
 */
export function resolveJiraConfig(fileConfig = {}) {
  const baseUrl = fileConfig.baseUrl ?? process.env.JIRA_BASE_URL;
  const email = fileConfig.email ?? process.env.JIRA_EMAIL;
  const apiToken = fileConfig.apiToken ?? process.env.JIRA_API_TOKEN;
  const projectKey = fileConfig.projectKey ?? process.env.JIRA_PROJECT_KEY;

  if (!baseUrl || !email || !apiToken || !projectKey) {
    return null;
  }

  return {
    baseUrl: baseUrl.replace(/\/$/, ""),
    email,
    apiToken,
    projectKey,
    issueType: fileConfig.issueType ?? "Task",
    inProgressStatus: fileConfig.status ?? fileConfig.inProgressStatus ?? "In Progress",
  };
}

/**
 * Creates a Jira issue for a security finding.
 * @param {ResolvedJiraConfig} config
 * @param {{ summary: string, description: string }} input
 */
export async function createSecurityIssue(config, input) {
  const issue = await jiraRequest(config, "/rest/api/3/issue", {
    method: "POST",
    body: JSON.stringify({
      fields: {
        project: { key: config.projectKey },
        summary: input.summary,
        description: textToAdf(input.description),
        issuetype: { name: config.issueType },
      },
    }),
  });

  return issue;
}

/**
 * Transitions a Jira issue to the requested workflow status.
 * @param {ResolvedJiraConfig} config
 * @param {string} issueKey
 * @param {string} statusName
 */
export async function transitionIssueToStatus(config, issueKey, statusName) {
  const transitions = await jiraRequest(
    config,
    `/rest/api/3/issue/${encodeURIComponent(issueKey)}/transitions`,
    { method: "GET" },
  );

  const transition = (transitions.transitions ?? []).find(
    (item) => item.to?.name?.trim().toLowerCase() === statusName.trim().toLowerCase()
      || item.name?.trim().toLowerCase() === statusName.trim().toLowerCase(),
  );

  if (!transition) {
    throw new Error(`No Jira transition to "${statusName}" for ${issueKey}.`);
  }

  await jiraRequest(
    config,
    `/rest/api/3/issue/${encodeURIComponent(issueKey)}/transitions`,
    {
      method: "POST",
      body: JSON.stringify({
        transition: { id: transition.id },
      }),
    },
  );

  return transition.name ?? statusName;
}

/**
 * @param {ResolvedJiraConfig} config
 * @param {string} path
 * @param {RequestInit} init
 */
async function jiraRequest(config, path, init) {
  const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString("base64");
  const response = await fetch(`${config.baseUrl}${path}`, {
    ...init,
    headers: {
      Authorization: `Basic ${auth}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Jira API ${response.status} for ${path}: ${body}`);
  }

  if (response.status === 204) {
    return {};
  }

  return response.json();
}

/**
 * @param {string} text
 */
function textToAdf(text) {
  const blocks = text
    .split(/\n{2,}/)
    .map((block) => block.trim())
    .filter(Boolean);

  return {
    type: "doc",
    version: 1,
    content: blocks.map((block) => ({
      type: "paragraph",
      content: block.split("\n").flatMap((line, index, lines) => {
        const nodes = [{ type: "text", text: line }];
        if (index < lines.length - 1) {
          nodes.push({ type: "hardBreak" });
        }
        return nodes;
      }),
    })),
  };
}
