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
