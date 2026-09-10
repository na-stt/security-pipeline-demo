const test = require('node:test');
const assert = require('node:assert/strict');
const {current} = require('../scripts/github.cjs');

function fixture() {
  const sha = 'a'.repeat(40);
  const run = {id: 4, run_attempt: 1, event: 'pull_request', status: 'completed',
    conclusion: 'success', path: '.github/workflows/security-scan.yml', workflow_id: 2,
    head_sha: sha, head_repository: {full_name: 'fork/repo'}, pull_requests: []};
  const pr = {number: 3, state: 'open', draft: false, base: {repo: {full_name: 'org/repo'}},
    head: {sha, repo: {full_name: 'fork/repo'}}};
  const api = {context: {repo: {owner: 'org', repo: 'repo'}, payload: {workflow_run: {...run}}},
    github: {paginate: async () => [{number: 3}], rest: {
      actions: {getWorkflowRun: async () => ({data: run}),
        getWorkflow: async () => ({data: {id: 2}}),
        listWorkflowRuns: async () => ({data: {workflow_runs: [run]}})},
      repos: {listPullRequestsAssociatedWithCommit: () => {}},
      pulls: {get: async () => ({data: pr})}}}};
  return {api, run, pr};
}

test('finds a fork PR using GitHub commit provenance', async () => {
  const {api} = fixture();
  assert.equal((await current(api)).pr.number, 3);
});
test('refuses stale heads', async () => {
  const {api, pr} = fixture(); pr.head.sha = 'b'.repeat(40);
  assert.equal(await current(api), null);
});
test('refuses unrelated workflows and events', async () => {
  for (const [key, value] of [['path', '.github/workflows/evil.yml'], ['event', 'push']]) {
    const {api, run} = fixture(); run[key] = value;
    assert.equal(await current(api), null);
  }
});
test('refuses an older run attempt', async () => {
  const {api, run} = fixture(); run.run_attempt = 2;
  assert.equal(await current(api), null);
});
test('refuses source repository mismatch', async () => {
  const {api, pr} = fixture(); pr.head.repo.full_name = 'other/repo';
  assert.equal(await current(api), null);
});

test('refuses a PR returned to draft before reporting', async () => {
  const {api, pr} = fixture();
  assert.ok(await current(api));
  pr.draft = true;
  assert.equal(await current(api), null);
});
test('fails closed if draft status is missing', async () => {
  const {api, pr} = fixture(); delete pr.draft;
  assert.equal(await current(api), null);
});

test('refuses skipped scans even if the PR has since become ready', async () => {
  const {api, run} = fixture(); run.conclusion = 'skipped';
  assert.equal(await current(api), null);
});

const fs = require('node:fs');
const {start, setCheck, commentBody, trustedWorkflow} = require('../scripts/github.cjs');
function checkFixture() {
  const f = fixture();
  f.api.core = {notice() {}, warning() {}};
  f.api.context.serverUrl = 'https://github.com'; f.api.context.runId = 55;
  f.checks = []; f.writes = [];
  f.api.github.rest.checks = {
    listForRef: () => {},
    create: async fields => {
      const data = {...fields, id: f.checks.length + 1, app: {slug: 'github-actions'}};
      f.checks.push(data); f.writes.push(fields); return {data};
    },
    update: async fields => {
      const data = f.checks.find(c => c.id === fields.check_run_id);
      Object.assign(data, fields); f.writes.push(fields); return {data};
    },
  };
  f.api.github.paginate = async (fn, fields) => fn === f.api.github.rest.checks.listForRef
    ? f.checks.filter(c => c.name === fields.check_name) : [{number: 3}];
  return f;
}
test('creates four pending checks, including DeepSec, on the current PR head', async () => {
  const f = checkFixture(); f.run.status = 'in_progress'; f.run.conclusion = null;
  await start(f.api);
  assert.equal(f.checks.length, 4);
  assert.ok(f.checks.some(c => c.name === 'Security / DeepSec'));
  assert.ok(f.checks.every(c => c.status === 'in_progress' && c.head_sha === f.pr.head.sha));
  await start(f.api);
  assert.equal(f.checks.length, 4);
});
test('late start events do not reopen completed checks', async () => {
  const f = checkFixture();
  await start(f.api); assert.equal(f.writes.length, 0);
  const match = await current(f.api);
  await setCheck(f.api, match, 'gate', 'completed', 'failure', 'Blocked');
  await setCheck(f.api, match, 'gate', 'in_progress', null, 'Late start');
  assert.equal(f.writes.length, 1);
  assert.equal(f.checks[0].conclusion, 'failure');
});
test('a report rerun can create a fresh pending gate after a completed report', async () => {
  const f = checkFixture(); const match = await current(f.api);
  await setCheck(f.api, match, 'gate', 'completed', 'success', 'Passed');
  await setCheck(f.api, match, 'gate', 'in_progress', null, 'Rerunning', null, true);
  assert.equal(f.checks.length, 2);
  assert.equal(f.checks[1].status, 'in_progress');
});
test('never overwrites a check from another app or another scan attempt', async () => {
  const f = checkFixture(); const match = await current(f.api);
  f.checks.push({id: 88, name: 'Security / gate', external_id: '4:1:gate', app: {slug: 'other'}});
  await setCheck(f.api, match, 'gate', 'completed', 'failure', 'Blocked');
  assert.equal(f.checks.length, 2);
  assert.equal(f.checks[0].status, undefined);
});
test('rejects fabricated artifacts from a modified PR scan workflow', async () => {
  const f = fixture();
  f.api.github.rest.repos.getContent = async () => ({data: {type: 'file', encoding: 'base64',
    content: Buffer.from('malicious workflow').toString('base64')}});
  assert.equal(await trustedWorkflow(f.api, await current(f.api)), false);
  f.api.github.rest.repos.getContent = async () => ({data: {type: 'file', encoding: 'base64',
    content: fs.readFileSync('.github/workflows/security-scan.yml').toString('base64')}});
  assert.equal(await trustedWorkflow(f.api, await current(f.api)), true);
});
test('comment preview stays bounded and keeps complete finding boundaries', () => {
  const markdown = '## Report\n' + Array.from({length: 200}, (_, i) => `\n#### SEC-${i}\n${'é'.repeat(500)}\n`).join('');
  const body = commentBody(markdown, '\n[Artifacts](https://github.com/example)');
  assert.ok(Buffer.byteLength(body) < 55000);
  assert.ok(body.includes('Report preview shortened'));
  assert.ok(body.endsWith('[Artifacts](https://github.com/example)'));
});

test('publisher binds provenance, posts readable evidence, and completes gate last', async () => {
  const {publish} = require('../scripts/github.cjs');
  const f = checkFixture(); const writes = f.writes;
  f.api.github.rest.repos.getContent = async () => ({data: {type: 'file', encoding: 'base64',
    content: fs.readFileSync('.github/workflows/security-scan.yml').toString('base64')}});
  f.api.github.rest.issues = {listComments() {}, createComment: async fields => writes.push({comment: fields}),
    updateComment: async () => assert.fail('unexpected update')};
  const paginate = f.api.github.paginate;
  f.api.github.paginate = async (fn, fields) => fn === f.api.github.rest.issues.listComments ? [] : paginate(fn, fields);
  const originalRead = fs.readFileSync;
  let sha = f.pr.head.sha;
  fs.readFileSync = function(path, ...args) {
    if (path === 'security-report.json') return JSON.stringify({schema_version: 2,
      context: {head_sha: sha, scan_run_id: 4, scan_attempt: 1, repository: 'org/repo', pr: 3},
      summary: 'BLOCKED', conclusion: 'failure', findings: [],
      scanners: ['semgrep', 'trivy', 'deepsec'].map(engine => ({engine, status: 'complete',
        finding_count: 1, blocking_count: 1, conclusion: 'failure'}))});
    if (path === 'security-report.md') return '## BLOCKED\nReadable finding evidence';
    return originalRead.call(fs, path, ...args);
  };
  try {
    sha = 'b'.repeat(40);
    await assert.rejects(() => publish(f.api), /provenance/);
    assert.equal(writes.length, 0);
    sha = f.pr.head.sha;
    await publish(f.api);
    assert.ok(writes.at(-2).comment.body.includes('Readable finding evidence'));
    assert.equal(writes.at(-1).name, 'Security / gate');
    assert.equal(writes.at(-1).conclusion, 'failure');
  } finally { fs.readFileSync = originalRead; }
});
