// Runs only from default-branch policy. Never eval, execute, or interpolate report data.
const fs = require('node:fs');
const SCAN_PATH = '.github/workflows/security-scan.yml';
const MARKER = '<!-- security-pipeline-summary-v1 -->';

async function current({github, context}, starting = false) {
  const repo = context.repo;
  const {data: run} = await github.rest.actions.getWorkflowRun({
    ...repo, run_id: context.payload.workflow_run.id,
  });
  if (run.event !== 'pull_request' || run.path !== SCAN_PATH || (!starting && run.status !== 'completed')
      || !/^[a-f0-9]{40}$/.test(run.head_sha) || ['cancelled', 'skipped'].includes(run.conclusion)) return null;
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
    if (pr.state === 'open' && pr.draft === false && pr.base.repo.full_name === `${repo.owner}/${repo.repo}`
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

const NAMES = {gate: 'Security / gate', semgrep: 'Security / Semgrep',
  trivy: 'Security / Trivy', deepsec: 'Security / DeepSec'};

async function setCheck(api, match, kind, status, conclusion, summary, annotations, restart = false) {
  const {github, context} = api;
  const external = `${match.run.id}:${match.run.run_attempt}:${kind}`;
  const checks = await github.paginate(github.rest.checks.listForRef,
    {...context.repo, ref: match.pr.head.sha, check_name: NAMES[kind], per_page: 100});
  let existing = checks.filter(c => c.app?.slug === 'github-actions' && c.external_id === external)
    .sort((a, b) => b.id - a.id)[0];
  // Delayed start events must never overwrite a completed result.
  if (status === 'in_progress' && existing) {
    if (restart && existing.status === 'completed') existing = null;
    else return;
  }
  const output = {title: NAMES[kind], summary};
  const fields = {...context.repo, status, output,
    details_url: `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`};
  if (status === 'completed') fields.conclusion = conclusion;
  let response;
  if (existing) response = await github.rest.checks.update({...fields, check_run_id: existing.id});
  else response = await github.rest.checks.create({...fields, name: NAMES[kind],
    head_sha: match.pr.head.sha, external_id: external});
  if (annotations?.length) {
    try {
      await github.rest.checks.update({...context.repo, check_run_id: response.data.id,
        output: {...output, annotations}});
    } catch { api.core.warning('Some annotations were rejected; see the complete report artifact.'); }
  }
}

async function trustedWorkflow(api, match) {
  // A PR can otherwise replace its unprivileged workflow with fabricated clean artifacts.
  // Compare bytes with the protected policy checkout, never execute PR workflow content.
  const [owner, repo] = match.pr.head.repo.full_name.split('/');
  const {data} = await api.github.rest.repos.getContent({owner, repo, path: SCAN_PATH,
    ref: match.pr.head.sha});
  return data.type === 'file' && data.encoding === 'base64'
    && Buffer.from(data.content, 'base64').equals(fs.readFileSync(SCAN_PATH));
}

async function start(api) {
  const match = await current(api, true);
  if (!match || match.run.status === 'completed') return;
  for (const kind of Object.keys(NAMES)) {
    await setCheck(api, match, kind, 'in_progress', null,
      kind === 'deepsec' ? 'Waiting for static scans, then the protected AI review.'
        : 'Waiting for all required scanner reports for this commit.');
  }
}

async function validate(api) {
  const match = await current(api);
  if (!match) {
    api.core.notice('Ignoring draft, stale, ambiguous, cancelled, or unrelated scan.');
    return;
  }
  for (const kind of Object.keys(NAMES)) {
    await setCheck(api, match, kind, 'in_progress', null,
      kind === 'deepsec' ? 'Protected DeepSec review is running or awaiting environment approval.'
        : 'Collecting scanner findings; the gate remains pending until all reports are validated.', null, true);
  }
  if (!await trustedWorkflow(api, match)) {
    await setCheck(api, match, 'gate', 'completed', 'failure',
      'Scan workflow differs from protected default-branch policy. A maintainer must review the workflow change; artifacts cannot satisfy this gate.');
    return;
  }
  api.core.setOutput('pr', String(match.pr.number));
  api.core.setOutput('head', match.pr.head.sha);
  api.core.setOutput('base', match.pr.base.sha);
  api.core.setOutput('same_repo', String(match.pr.head.repo.full_name === match.pr.base.repo.full_name));
  api.core.setOutput('attempt', String(match.run.run_attempt));
}

async function writeContext(api) {
  const match = await current(api);
  if (!match || !await trustedWorkflow(api, match)) throw new Error('Scan is stale or workflow policy changed');
  const {context} = api;
  const metadata = {repository: `${context.repo.owner}/${context.repo.repo}`, pr: match.pr.number,
    head_sha: match.pr.head.sha, base_sha: process.env.REVIEW_BASE_SHA,
    scan_run_id: match.run.id, scan_attempt: match.run.run_attempt,
    scan_conclusion: match.run.conclusion,
    scan_base_sha: match.run.pull_requests?.find(p => p.number === match.pr.number)?.base?.sha || 'unknown',
    report_run_id: context.runId, report_attempt: Number(process.env.GITHUB_RUN_ATTEMPT),
    policy_sha: context.sha, model: process.env.SECURITY_MODEL || 'unconfigured',
    policy_scanner_versions: {...JSON.parse(fs.readFileSync('.security/versions.json', 'utf8')),
      deepsec: JSON.parse(fs.readFileSync('.security/deepsec/package.json', 'utf8')).dependencies.deepsec}};
  fs.writeFileSync('report-context.json', JSON.stringify(metadata));
}

function commentBody(markdown, links) {
  const prefix = `${MARKER}\n`;
  const budget = 55000 - Buffer.byteLength(prefix + links, 'utf8');
  let text = markdown;
  if (Buffer.byteLength(text, 'utf8') > budget) {
    // Cut only at complete finding boundaries; never split an escape or UTF-8 character.
    const parts = text.split('\n#### ');
    text = parts.shift();
    for (const part of parts) {
      if (Buffer.byteLength(text + '\n#### ' + part, 'utf8') > budget - 250) break;
      text += '\n#### ' + part;
    }
    text += '\n\nReport preview shortened. Download security-report.md or security-report.json for all findings.\n';
  }
  return prefix + text + links;
}

async function publish(api) {
  const {github, context, core} = api;
  const match = await current(api); // Recheck after the potentially long AI job.
  if (!match || !await trustedWorkflow(api, match)) {
    core.notice('PR or policy advanced; report is artifact-only.'); return;
  }
  const data = JSON.parse(fs.readFileSync('security-report.json', 'utf8'));
  if (data.schema_version !== 2 || data.context.head_sha !== match.pr.head.sha
      || data.context.scan_run_id !== match.run.id || data.context.scan_attempt !== match.run.run_attempt
      || data.context.repository !== `${context.repo.owner}/${context.repo.repo}`
      || data.context.pr !== match.pr.number) throw new Error('Report provenance mismatch');
  const repo = context.repo;
  const reportUrl = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${context.runId}`;
  const scanUrl = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${match.run.id}`;
  const body = commentBody(fs.readFileSync('security-report.md', 'utf8'),
    `\n\n[Scanner artifacts](${scanUrl}) · [Full Markdown and JSON report](${reportUrl})`);
  for (const scanner of data.scanners) {
    await setCheck(api, match, scanner.engine, 'completed', scanner.conclusion,
      `${scanner.status}: ${scanner.finding_count} observations, ${scanner.blocking_count} blocking. See Security / gate for details.`);
  }
  const annotations = data.findings.slice(0, 50).map(f => ({
    path: f.path, start_line: f.line, end_line: f.line,
    annotation_level: f.decision === 'blocking' ? 'failure' : 'warning',
    message: `${f.id}: ${f.engine}; ${f.category}; ${f.severity}; confidence ${f.confidence}. See the PR security report.`,
    title: 'Security finding',
  }));
  const comments = await github.paginate(github.rest.issues.listComments,
    {...repo, issue_number: match.pr.number, per_page: 100});
  const previous = comments.find(c => c.user?.login === 'github-actions[bot]'
    && c.user?.type === 'Bot' && c.body?.startsWith(MARKER));
  if (previous) await github.rest.issues.updateComment({...repo, comment_id: previous.id, body});
  else await github.rest.issues.createComment({...repo, issue_number: match.pr.number, body});
  // Complete the gate last: a failure to publish must not silently produce a passing gate.
  await setCheck(api, match, 'gate', 'completed', data.conclusion, data.summary, annotations);
}

module.exports = {validate, publish, current, start, writeContext, setCheck, commentBody, trustedWorkflow};
