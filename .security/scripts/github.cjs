// Runs only from default-branch policy. Never eval, execute, or interpolate report data.
const fs = require('node:fs');
const SCAN_PATH = '.github/workflows/security-scan.yml';
const MARKER = '<!-- security-pipeline-summary-v1 -->';

async function current({github, context}) {
  const repo = context.repo;
  const {data: run} = await github.rest.actions.getWorkflowRun({
    ...repo, run_id: context.payload.workflow_run.id,
  });
  if (run.event !== 'pull_request' || run.path !== SCAN_PATH || run.status !== 'completed'
      || !/^[a-f0-9]{40}$/.test(run.head_sha) || run.conclusion === 'cancelled') return null;
  const {data: workflow} = await github.rest.actions.getWorkflow({...repo, workflow_id: 'security-scan.yml'});
  if (workflow.id !== run.workflow_id) return null;
  // GitHub's run-to-PR association is sometimes empty for forks. Use the commit API,
  // never a PR number, repository name, or SHA supplied by a report artifact.
  let candidates = run.pull_requests || [];
  if (!candidates.length) {
    candidates = await github.paginate(github.rest.repos.listPullRequestsAssociatedWithCommit,
      {...repo, commit_sha: run.head_sha, per_page: 100});
  }
  const matches = [];
  for (const candidate of candidates.slice(0, 100)) {
    const {data: pr} = await github.rest.pulls.get({...repo, pull_number: candidate.number});
    if (pr.state === 'open' && pr.base.repo.full_name === `${repo.owner}/${repo.repo}`
        && pr.head.sha === run.head_sha
        && pr.head.repo?.full_name === run.head_repository?.full_name) matches.push(pr);
  }
  if (matches.length !== 1) return null;
  const {data: latest} = await github.rest.actions.listWorkflowRuns({
    ...repo, workflow_id: workflow.id, event: 'pull_request', head_sha: run.head_sha, per_page: 1,
  });
  const newest = latest.workflow_runs[0];
  if (!newest || newest.id !== run.id || newest.run_attempt !== run.run_attempt
      || context.payload.workflow_run.run_attempt !== run.run_attempt) return null;
  return {run, pr: matches[0]};
}

async function validate(api) {
  const match = await current(api);
  if (!match) {
    api.core.notice('Ignoring stale, ambiguous, cancelled, or unrelated scan.');
    return;
  }
  api.core.setOutput('pr', String(match.pr.number));
  api.core.setOutput('head', match.pr.head.sha);
  api.core.setOutput('base', match.pr.base.sha);
  api.core.setOutput('same_repo', String(match.pr.head.repo.full_name === match.pr.base.repo.full_name));
  api.core.setOutput('attempt', String(match.run.run_attempt));
}

async function publish(api) {
  const {github, context, core} = api;
  const match = await current(api); // Recheck after the potentially long AI job.
  if (!match) { core.notice('PR advanced or scan superseded; report is artifact-only.'); return; }
  const data = JSON.parse(fs.readFileSync('aggregate.json', 'utf8'));
  const repo = context.repo;
  const reportUrl = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${context.runId}`;
  const scanUrl = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${match.run.id}`;
  // No scanner free text or Markdown is inserted into the PR comment.
  const body = `${MARKER}\n${data.summary}\n\nCommit: \`${match.pr.head.sha}\`\n\n` +
    `[Scanner artifacts](${scanUrl}) · [Combined report and AI artifacts](${reportUrl})`;
  const annotations = data.findings.slice(0, 50).map(f => ({
    path: f.path, start_line: f.line, end_line: f.line,
    annotation_level: f.category === 'secret' || (['CRITICAL', 'HIGH'].includes(f.severity)
      && f.confidence === 'high' && f.category === 'vulnerability') ? 'failure' : 'warning',
    // All strings below come from validated enums; full text stays in artifacts.
    message: `${f.engine}: ${f.category}; severity ${f.severity}; confidence ${f.confidence}. See normalized report artifact.`,
    title: 'Security finding',
  }));
  const output = {title: 'Security scan results', summary: data.summary,
                  text: 'At most 50 annotations are shown. All findings are in the report artifacts.'};
  const check = await github.rest.checks.create({...repo, name: 'Security / summary',
    head_sha: match.pr.head.sha, status: 'completed', conclusion: data.conclusion,
    details_url: reportUrl, external_id: `${match.run.id}:${match.run.run_attempt}`, output});
  // Invalid/outdated annotation lines must not prevent the summary comment.
  if (annotations.length) {
    try {
      await github.rest.checks.update({...repo, check_run_id: check.data.id, output: {...output, annotations}});
    } catch {
      core.warning('GitHub rejected some annotations; complete findings remain in artifacts.');
    }
  }
  const comments = await github.paginate(github.rest.issues.listComments,
    {...repo, issue_number: match.pr.number, per_page: 100});
  const previous = comments.find(c => c.user?.login === 'github-actions[bot]'
    && c.user?.type === 'Bot' && c.body?.startsWith(MARKER));
  if (previous) await github.rest.issues.updateComment({...repo, comment_id: previous.id, body});
  else await github.rest.issues.createComment({...repo, issue_number: match.pr.number, body});
}

module.exports = {validate, publish, current};
