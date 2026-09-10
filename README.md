# Focused security scanner demo

This NodeGoat-derived training fork demonstrates two deliberately introduced bugs:

- Contribution evaluation: request fields reach server-side `eval`. Semgrep and
  DeepSec provide complementary evidence about code execution.
- Allocation ownership: a route selects the owner from the URL instead of the
  authenticated session. DeepSec reviews the missing authorization check.

This setup branch contains the corrected implementations. After it is reviewed
and merged, the default branch becomes the starting point for fresh demo PRs.
The saved scenarios introduce a small selection of issues and must stay unmerged. The GitHub App runs all three scanners and
publishes one `Security / gate` and one updated comment linking to its report in
GitHub. Regression tests are a separate required check. A medium/advisory ownership
finding does not alone fail the current security gate; its regression test fails.

## Run the focused application locally

Requires Node 24+ and Docker Compose for MongoDB:

```sh
npm ci --ignore-scripts
npm test
docker compose up -d mongo
# Optional, idempotent schema initialization (also performed on startup):
docker compose run --rm --build web npm run db:seed
docker compose up -d --build web
```

Open http://localhost:4000 and create a demo account. The web port binds only to
localhost. No accounts or known passwords are seeded; use no real data.
A random session key is generated at startup; optionally provide SESSION_SECRET
when starting Node directly. Do not publish this training application.

## Baseline cleanup

Runtime packages are pinned and the application lockfile regenerated. The old
development pipeline has been replaced. The existing `.security/` files are
preserved unchanged in this PR; the active scanner policy belongs to the installed
App's repository. The separate required regression check and App gate remain.

The focused runtime mounts login/signup, contributions, and allocations only.
Other original NodeGoat lessons remain as reference source, not active routes.
Nunjucks replaces Swig with automatic HTML escaping; CSRF validation and session
regeneration protect the active forms. Passwords use bounded asynchronous scrypt; authentication is rate limited. Sessions have TTL eviction and a hard capacity bound. Allocation thresholds
are validated and queried using MongoDB operators rather than JavaScript `$where`.
The obsolete checked-in training TLS private key is removed from the current tree;
its historical copies remain and must never be trusted as a real credential.

The full upstream lesson catalog and old Grunt/Cypress commands no longer describe
this focused runtime. This is a scanner demo, not a production security guarantee.

## Attribution

Derived from OWASP NodeGoat, licensed under Apache-2.0; see LICENSE.

## Create a fresh demo PR

First merge the reviewed setup PR through the existing required checks and review
process. Do not use the old demo branches or PRs as the starting point. Each demo
starts from the updated `origin/master` with a new branch and one focused commit.

The patches in `.demo/scenarios/` are inert preparation files, not active
application changes or installed dependencies. Choose either scenario, or apply
both to show all three selected issues in **one new PR**:

| Patch | Selected issue | Expected evidence |
|---|---|---|
| `contribution.patch` | Server-side evaluation of contribution input | Semgrep and DeepSec, related evidence grouped |
| `contribution.patch` | One vulnerable dependency fixture (minimist 1.2.5) | Trivy |
| `ownership.patch` | Allocation owner taken from the URL | DeepSec; advisory under current policy |

Scanner observations and grouping can vary. These are expected examples, not a
hard-coded report limit or suppressed findings. The dependency fixture is never
installed into or copied into the application image.

From a clean checkout, choose a **new, unused** branch name for each presentation:

```sh
gh api user --jq .login  # Must be na-stt; stop if it is another account.
git status --short     # Must be empty before continuing.
git fetch origin
git switch --no-track -c feature/contribution-and-allocation-demo-01 origin/master
git apply --check .demo/scenarios/contribution.patch .demo/scenarios/ownership.patch
git apply .demo/scenarios/contribution.patch .demo/scenarios/ownership.patch
npm ci --ignore-scripts
npm test  # Selected security regressions are expected to fail.
git diff --check
git diff --stat
git add .dockerignore app/routes/contributions.js app/routes/allocations.js demo-fixtures
git commit -m "Add contribution expressions and allocation owner selection"
git push -u origin HEAD
gh pr create --repo na-stt/security-pipeline-demo --base master --draft \
  --title "Add contribution expressions and allocation owner selection" \
  --body "Training demo: show code execution, dependency risk, and an ownership bypass. Intentionally vulnerable; do not merge."
```

To demonstrate only one scenario, apply only its patch and stage only its changed
paths. Keep the safety disclosure in the PR body even when using a realistic
feature title and a fresh, focused commit.

### Control paid scans

Keep preparation PRs **draft**. The App scans ready PRs when opened, updated, or
marked ready for review; pushing another commit to a ready PR can spend OpenRouter
balance again. Use previous reports to guide fixes and run local regression tests
while preparing. Previous reports describe their original commit, not proof that
a changed commit passed.

Only when the demo is finalized and the paid run is approved, run
`gh pr ready <new-pr-number> --repo na-stt/security-pipeline-demo` once. This starts
Semgrep, Trivy, and DeepSec (OpenRouter `openai/gpt-6-astra`, low reasoning).
Expect one `Security / gate`, one updated App comment, and a report view within
GitHub with scanner attribution. Regression tests remain a separate required check.
Do not repeatedly toggle draft/ready to refresh formatting or repeat a demo.
Close the demo without merging after the presentation; create a fresh branch and
PR for the next one.

The earlier baseline report for commit `9efff89` completed all three scanners with
zero observations: [baseline scan](https://github.com/na-stt/security-pipeline-demo/runs/102814541248).
That result predates these scenario patches and documentation; no new paid scan
was requested to add them.
