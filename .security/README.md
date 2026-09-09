# Security pipeline operations

## What runs

1. `security-scan.yml` runs on PR `opened`, `synchronize`, `reopened`, and
   `ready_for_review`, including drafts and forks subject to GitHub's runner approval
   policy. Semgrep and Trivy run independently with `contents: read`.
2. `security-report.yml` runs from the default branch after the scan completes.
   It verifies the originating workflow, event, run attempt, repository, open PR,
   and current head SHA through GitHub's API. Superseded/cancelled runs are ignored.
3. A separate job optionally runs DeepSec for same-repository PRs. Forks never
   receive the model key. AI-disabled or missing-key runs explicitly report a skip.
4. A publisher job validates report data, creates `Security / summary` on the exact
   PR head, and updates a single PR comment. It rechecks freshness before posting.
   Up to 50 individual findings get check annotations; all are retained as artifacts.

The scan and reporting workflows must already be on the default branch to bootstrap
this design. Do not expect a PR that first introduces them to exercise the whole flow.
The unprivileged scan loads policy from the target base commit. DeepSec and reporting
load policy from the default branch, independently of changes proposed in the PR.

## Scanner responsibilities and overlap

| Tool | This starter's scope | Execution |
| --- | --- | --- |
| Semgrep CE | Five checked-in Python and JS/TS rules for unsafe deserialization, shell calls, dynamic evaluation, and request-to-shell flow | Pinned Docker image, no network during analysis |
| Trivy OSS | Dependencies represented in tracked manifests/lockfiles; filesystem secrets; supported IaC and Dockerfile misconfigurations | Pinned Docker image, public database downloads |
| DeepSec | Contextual review of regular files changed since the PR merge base; surrounding snapshot available for reading | Locked Node CLI, restricted Pi agent on a separate runner |

The five Semgrep rules are deliberately a small baseline, not comprehensive SAST for
every language. Extend `.security/semgrep/rules.yml` after identifying each target
repository's framework. No Semgrep account, hosted rules fetch, Pro engine, or Trivy
commercial service is used. Telemetry is disabled.

Semgrep and DeepSec can report the same code vulnerability. Trivy can overlap with
both on configuration and secrets. Findings retain scanner provenance; counts are
**scanner observations, not a deduplicated count of vulnerabilities**. This first
version does not infer equivalence or raise confidence just because scanners agree.
Use pilot results to measure DeepSec's additional confirmed findings and cost.

### DeepSec's actual pattern

Verified against official upstream commit
`23a69227e3380e6b44a7ebd93c52e023c59f17c3` and npm `deepsec@2.3.9` on 2026-09-09:

- Full audit: `deepsec scan` runs local matchers and stores candidates; `deepsec process`
  uses an AI agent to investigate pending files. Pattern matches are leads, not findings.
- PR mode: `deepsec process --diff <base>` resolves changed files, runs scoped matching,
  and investigates those files even if no matcher fired. It reviews changed files,
  not exclusively added lines, and may identify a pre-existing bug in a touched file.
- This adapter computes a merge-base file list and uses the official equivalent
  `--files-from` with `--root`, avoiding a Git checkout or executable configuration
  inside the agent's readable snapshot. No initial `init` or full-repo paid scan is needed.
- `deepsec revalidate` is an optional later pass over findings, with true-positive,
  false-positive, fixed, or uncertain outcomes. It does not automatically fix code.
- Semgrep/Trivy reports are not inputs to DeepSec in this version.

See [PR mode](https://deepsec.sh/docs/reviewing-changes),
[architecture](https://deepsec.sh/docs/architecture), and
[configuration](https://deepsec.sh/docs/configuration). The official interactive
installation is `npx deepsec init`; CI instead installs the exact release through
the committed npm lockfile. No guessed `deepsec scan --diff` command is used.

## Activate in a repository

### 1. Check prerequisites

You need a target GitHub repository, permission to propose workflow changes, and an
administrator who can configure Actions, secrets, and repository rules. Identify its
default branch, visibility, owner (personal account or organization), existing CI,
languages/frameworks, dependency lockfiles, Dockerfiles, and IaC before rollout.

CI uses GitHub-hosted Ubuntu and pinned scanner images. You do not need a VPS or a
Docker daemon on your laptop to run GitHub Actions. For local verification, install
Git, Python 3.10+, Docker with its daemon running, and Node 22+ with npm for DeepSec
(CI pins Node 24.18.0). The scanner adapters install no application dependencies.

Choose one setup path:

- **Path A, full profile:** public repository on GitHub Free, or a private repository
  on Pro (personal), Team (organization), or Enterprise, with environment secrets and
  branch restrictions available. The AI model has separate usage costs.
- **Path B, static-only:** private GitHub Free, or a deployment deliberately excluding
  model access. Use the exact job replacement below to remove the environment dependency.

On private GitHub Free, displaying checks works within Actions quotas, but protected
branches/required-check enforcement and the environment-based model-key isolation
used here are unavailable. Review the current
[environment policy](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
and [branch protection availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

### 2. Copy and review the files

Inspect the target working tree first and create a normal change branch. If any target
files already exist, merge the policy changes manually instead of overwriting them.
For a target without an existing `.security/` or workflows of these names, set these
two paths and run:

```sh
starter_dir=/absolute/path/to/select-scan-deepsec
target_dir=/absolute/path/to/your-repository

git -C "$target_dir" status --short --branch
git -C "$target_dir" switch -c chore/security-pipeline
mkdir -p "$target_dir/.github/workflows" "$target_dir/.security"
cp "$starter_dir/.github/workflows/security-scan.yml" "$target_dir/.github/workflows/"
cp "$starter_dir/.github/workflows/security-report.yml" "$target_dir/.github/workflows/"
rsync -a --exclude=node_modules --exclude=__pycache__ \
  "$starter_dir/.security/" "$target_dir/.security/"
```

Keep the target application's README and ignore rules. Merge these entries into its
`.gitignore` if equivalent exclusions do not already exist:

```gitignore
.security/deepsec/node_modules/
.security/**/__pycache__/
.security-output/
.env*
!.env.example
```

Review the five Semgrep rules against the project's language/framework. Add reviewed
rules where coverage is missing. For DeepSec, customize the short `infoMarkdown` in
`.security/deepsec/deepsec.config.mjs` with the application's purpose, auth boundaries,
and key entry points; preserve the read-only security policy and trusted config location.
Do not run DeepSec's interactive bootstrap against untrusted PR code in CI.

### 3. Configure GitHub Actions

In the target repository, open **Settings → Actions → General**:

1. Enable GitHub Actions and allow the pinned `actions/checkout`, `actions/setup-node`,
   `actions/github-script`, `actions/upload-artifact`, and `actions/download-artifact`
   versions used in the workflows. An organization allowlist may need an admin update.
2. Set default workflow token permissions to **Read repository contents and packages**.
   Preserve the workflow's explicit per-job permissions. Only publishing requests
   `pull-requests: write` and `checks: write`; no job requests `contents: write`.
3. Keep fork-workflow approval requirements appropriate for untrusted contributions.
   Do not enable sending write tokens or repository secrets to fork PR workflows.
4. Leave `SECURITY_SCAN_RUNNER` and `SECURITY_AI_RUNNER` unset initially.
5. Review Actions usage and storage budgets under the owner's billing settings. The
   workflow retains reports for seven days. Runner minutes from parallel jobs add up;
   they are not the elapsed wall-clock duration of the PR scan.

### Path A: full setup with DeepSec

First configure the environment, even if you plan to leave AI disabled during the
initial static-scanner pilot. The shipped `deepsec` job references it unconditionally.

1. In **Settings → Environments**, create **`security-analysis`**.
2. Under deployment branches/tags, choose **Selected branches and tags** and add only
   a **branch** rule for the actual default branch, such as `main`. Do not add wildcard
   PR refs, tags with that name, or an unrestricted/all-protected-branches rule.
   `workflow_run` uses the default branch; PR merge refs must not access the credential.
3. Protect that default branch and require maintainer review for workflow/security
   changes. Add `.github/workflows/**` and `.security/**` to CODEOWNERS using the real
   maintainer team. Configure required code-owner reviews where supported; a CODEOWNERS
   file by itself does not enforce approval.
4. In your OpenRouter account, create a dedicated [API key](https://openrouter.ai/settings/keys)
   for security review with a credit limit. Choose a tool-capable model available to
   your account and the pinned Pi model catalog. No application deployment is required.
   See the [OpenRouter quickstart](https://openrouter.ai/docs/quickstart).
5. Add the key under **`security-analysis` → Environment secrets** with the exact name
   **`OPENROUTER_API_KEY`**. Do not also put it in repository/organization secrets or
   commit it to `.env` files. Configure a provider-side spending/usage limit, and approve
   the repository's source-code transfer to the model provider before enabling AI.
6. Under **Settings → Secrets and variables → Actions → Variables**, set the repository
   variables below. Their values are plain strings, without surrounding quotation marks.

| Repository variable | Value | Effect |
| --- | --- | --- |
| `SECURITY_DEEPSEC_ENABLED` | `false` for initial static pilot; then `true` | Enables the AI steps only when exactly `true` |
| `SECURITY_DEEPSEC_MODEL` | An OpenRouter model ID, e.g. `openai/gpt-5.5` (if available) | Model used by the Pi agent; verify with your account |
| `SECURITY_SCAN_RUNNER` | Leave unset | GitHub-hosted `ubuntu-24.04` for Semgrep/Trivy |
| `SECURITY_AI_RUNNER` | Leave unset | GitHub-hosted `ubuntu-24.04` for DeepSec |

Same-repository PRs run DeepSec only when both enable/model variables are configured.
Missing keys are explicitly reported as skipped; authentication/model errors are
reported as failed coverage. Fork PRs never run the AI steps. No key is needed for
Semgrep or Trivy; the reporting job uses GitHub's automatic job-scoped token.

Environment required-reviewer approval is optional where available. Enabling it pauses
this environment job for review, so do not expect fully unattended PR runs with that
approval rule active. Branch restrictions are the credential control required by this
design. See [environment behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

### Path B: static-only on private GitHub Free

**This is a documented adaptation, not an automatic profile switch in the shipped
workflow.** Setting `SECURITY_DEEPSEC_ENABLED=false` alone is insufficient because the
current job still references `security-analysis`.

In your target copy of `.github/workflows/security-report.yml`, replace the entire
`jobs.deepsec` block with the following job. Keep the `context` and `publish` jobs
unchanged. This preserves the expected artifact and dependency names, while removing
all environment, model-key, source-checkout, and AI-installation steps from this job:

```yaml
  deepsec:
    name: DeepSec disabled (static-only)
    needs: context
    if: needs.context.outputs.pr != ''
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions: {}
    steps:
      - name: Record explicit AI skip
        run: |
          mkdir -p reports
          python3 - <<'PY'
          import json
          from pathlib import Path
          Path('reports/deepsec.json').write_text(json.dumps({
            'schema': 1, 'engine': 'deepsec', 'status': 'skipped', 'findings': [],
            'reason': 'Static-only deployment; no model credential configured',
            'coverage': {}}))
          PY
      - name: Preserve skip report
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: security-deepsec-${{ github.run_attempt }}
          path: reports/deepsec.json
          if-no-files-found: error
          retention-days: 7
```

Create no model secret and no `security-analysis` environment for this profile. Leave
the AI variables unset. Semgrep, Trivy, and the PR publisher continue to run, and
DeepSec is honestly marked skipped. With no blocking findings/errors, the summary
check is neutral rather than claiming all three scanners completed.

To add AI later, restore the original `deepsec` job from reviewed starter policy and
complete Path A after obtaining the required environment protections. Changing runner
labels to a VPS does not by itself provide equivalent credential isolation.

### 4. Merge the policy and verify a pilot PR

Complete the chosen profile and local validation, then submit the policy changes for
maintainer review. Merge both workflows and `.security/` into the default branch first.
The scan workflow reads base-commit policy, and `workflow_run` reporting must exist on
the default branch. Port the policy to other supported PR target branches as needed.

Open a new pilot PR using a small harmless code change. Then verify:

1. **Actions → Security scan** shows separate Semgrep and Trivy jobs.
2. Each job uploads its `security-<scanner>-<attempt>` normalized JSON report.
3. **Actions → Security report** validates the PR, records AI findings or an explicit
   skip, and publishes a PR comment plus `Security / summary` on that exact commit.
4. Push another commit to the pilot PR. New scans should run; the comment should refer
   to the new head rather than an older report. Old artifacts may remain until expiry.
5. If your contribution model includes forks, open a controlled fork PR and approve
   the untrusted scan if GitHub requires it. Static reports should publish and AI should
   remain skipped. Keep secrets and write tokens unavailable to the fork workflow.
6. Use temporary synthetic vulnerability fixtures to verify a finding and its annotation,
   then remove them. Never use real credentials or execute an intentionally unsafe fixture.
7. For Path A, enable AI on a small same-repository PR and inspect `deepsec.json` for
   `status: complete`, findings, and coverage. A green static scan does not prove AI ran.

After the pilot, configure required checks under repository branch protection/rules
where your plan supports them. `Security / summary` applies the findings policy;
`semgrep` and `trivy` primarily indicate scanner execution. A neutral result permits
skipped AI in this initial policy, so requiring the summary alone does not require AI
coverage. Agree on fork and skip policy before enforcing AI on every PR.

The starter's PR workflow is not tamper-proof: a same-repository contributor can
propose workflow edits and forge reports in an unprivileged run. The trusted publisher
validates provenance and treats artifacts solely as data; it cannot prove the scan
was honest. Required workflow enforcement from a protected organization policy
repository is a later option if scan integrity must withstand malicious contributors.

If default-branch-only secret access cannot be enforced, use Path B. An external
credential broker or separate trusted scanning service is a future design option,
not part of this starter.

## Credentials and costs

| Credential | Where available | Purpose |
| --- | --- | --- |
| Automatic `GITHUB_TOKEN` | Per-job permissions only | Read checkouts; trusted publisher writes checks/comments |
| `OPENROUTER_API_KEY` | `security-analysis` environment, one trusted DeepSec step | Model calls; never production access |

This implementation uses only OpenRouter through DeepSec's Pi custom-provider route:
`https://openrouter.ai/api/v1`, with bearer authentication from `OPENROUTER_API_KEY`.
No Vercel account, Gateway key, project/team credentials, or Sandbox setup is required.
The adapter passes `openrouter/<model ID>` to Pi; set `SECURITY_DEEPSEC_MODEL` to the
OpenRouter ID alone, such as `openai/gpt-5.5`, without the additional `openrouter/` prefix.
Choose a tool-capable model in the pinned Pi catalog or our trusted additional catalog. Unknown models fail coverage;
this starter does not fall back to another model route. See
[DeepSec custom routes](https://deepsec.sh/docs/models#pi-for-alternate-harness-runs) and
[OpenRouter authentication](https://openrouter.ai/docs/quickstart).

The adapter also passes the provider, endpoint, and key variable name explicitly:
DeepSec 2.3.9's credential preflight does not honor the configured custom key name
without `--ai-api-key-env`. The key value stays in the process environment.

`deepsec/models.json` adds `openai/gpt-6-astra`, which is absent from the locked Pi
catalog. Its metadata was checked against [OpenRouter's model API](https://openrouter.ai/api/v1/models)
on 2026-09-09. The demo caps its context at 128,000 tokens and output at 8,192 tokens;
reasoning stays `low`. Listed prices are estimates, not a spending limit. This file
is copied from trusted policy into a fresh Pi directory on each run. Never load
model definitions or credential commands from the PR checkout.


DeepSec receives source code through model requests. Enable it only for repositories
approved for that provider. Set a dedicated provider-side usage/spend limit. The adapter
caps a review at 20 changed files/500 KB, concurrency 1, batch size 5, 12 turns per batch,
low reasoning effort, and 15 minutes. Exceeding the file budget is partial coverage,
not a clean result. These bounds are not a guaranteed dollar cap. No analysis cache
is reused across PRs; this avoids stale findings and cache poisoning at the cost of
rescanning on each update. GitHub runner minutes and artifact storage may also cost money.

## Trust boundaries

- There is no `pull_request_target` execution of PR code and no scan job with repository
  write permissions. All checkouts use `persist-credentials: false`.
- Snapshot creation reads regular tracked Git blobs directly. It ignores export-ignore
  attributes, never follows symlinks, removes `.semgrepignore`, and excludes submodules.
  It does not run filters, dependency installers, builds, tests, hooks, or Dockerfiles.
- Semgrep uses only trusted local rules, with `nosem` disabled. Trivy uses explicit
  trusted config/ignore/secret files. No PR-supplied config is imported as executable code.
- Static scanners get read-only source mounts, no token environment, no Docker socket,
  no Linux capabilities, a non-root user, and bounded CPU/memory/runtime. Docker runs
  the **scanner images**, not images built from the PR. Trivy needs network access for
  its public databases; dependency-identification API calls are disabled.
- DeepSec itself is not in Docker. Its published Pi backend disables skills, extensions,
  context files, and prompt templates, and guards read/grep/find/ls paths against root
  escapes and symlinks. Its only enabled tools are these readers. No shell, write tool,
  or repo plugin is enabled. The readable snapshot contains no Git credentials, agent
  auth, or model credential; those are outside the guarded root. The subprocess gets
  an allowlisted environment, a fresh home, trusted config, and separate temporary state.
- Prompt instructions reinforce these controls; they are not the security boundary.
  A malicious file can still influence an AI verdict. AI output never gets executed.
  Reader/SDK vulnerabilities remain a residual risk; this is not a VM sandbox.
- Reporting runs on a fresh GitHub-hosted runner. Only default-branch code executes;
  artifact strings are not shell commands, prompts, Markdown templates, or GitHub API
  identities. Sizes, field types, paths, and finding counts are bounded before display.
  PR comments contain fixed text/counts, not scanner prose or source excerpts.

## Findings and developer experience

The PR comment separates high-severity/high-confidence code vulnerabilities, other
code findings requiring confidence review, dependencies/CVEs, secrets, IaC/container
misconfigurations, and informational findings. Severity and confidence remain separate.
Unknown confidence is not upgraded to high.

`Security / summary` fails for potential exposed secrets, HIGH/CRITICAL code findings
with high confidence, and missing/failed/partial scanner coverage. Dependency findings,
other code findings, and misconfigurations are advisory initially. This avoids blocking
every PR on existing dependency debt. The scanner jobs themselves fail on execution
errors; the aggregate check applies the finding policy. Tune `reports.blocking` in a
reviewed policy change. A success means no findings meeting this policy, not proof of safety.

Artifacts are kept for seven days: `security-semgrep-<attempt>`,
`security-trivy-<attempt>`, `security-deepsec-<attempt>`, and
`security-summary-<scan-run-id>-<report-attempt>`. They contain normalized JSON with
location, rule ID, category, severity, confidence, and available remediation information.
Raw scanner output, source snippets, agent transcripts, and Trivy secret matches are
not uploaded. AI-generated descriptions can still reproduce source; artifact access
follows repository visibility. Do not place real secrets in test PRs.

Semgrep/Trivy scan the full tracked snapshot, so pre-existing findings can recur.
Git LFS content, submodule contents, symlink targets, and Git history are not scanned.
The snapshot fails rather than silently truncating beyond 20,000 files, 200 MB total,
or 5 MB per file. Scanner built-in binary/unsupported-file limits still apply.
Trivy cannot infer all dependencies without suitable manifests/lockfiles and may honor
inline IaC ignore directives; review suppressions as security policy changes.

No application or container image is built, so installed OS packages in a built image
are **not** assessed here. Dockerfiles are analyzed as configuration. Later add a
separate `trivy image <image@sha256:...>` job for a trusted build artifact, with no
registry push credentials in the scanner. SARIF upload into GitHub code scanning is
also deferred; check annotations and JSON artifacts work without purchasing a scanner
service or relying on private-repository code-scanning availability.

## Run locally

Use Python 3.10+, Git, Docker, and (for DeepSec) Node 22+; CI pins Node 24.18.0.
Run from a trusted policy checkout. Each command scans the source repository's committed
HEAD, not uncommitted working-tree changes. The adapters pull the pinned scanner images,
so you do not need separate native Semgrep/Trivy installations for these commands.

```sh
scan_source=/absolute/path/to/your-repository

# Check local prerequisites. Docker must report a running server.
git --version
python3 --version
docker info

python3 .security/scripts/scan.py --engine semgrep --source "$scan_source" --out .security-output
python3 .security/scripts/scan.py --engine trivy --source "$scan_source" --out .security-output
```

For DeepSec, install the locked scanner dependency, supply `OPENROUTER_API_KEY` through
your shell's secret manager, and use a locally available base commit. Never paste a real
key into tracked files or a command that will remain in shell history. Replace
`origin/main` below with the actual PR target ref and ensure the clone has enough
history to calculate the merge base.

```sh
node --version
npm ci --prefix .security/deepsec --ignore-scripts --no-audit --no-fund
git -C "$scan_source" fetch origin
scan_base=$(git -C "$scan_source" rev-parse origin/main)
scan_model=openai/gpt-5.5

python3 .security/scripts/deepsec.py --source "$scan_source" \
  --base "$scan_base" --model "$scan_model" --out .security-output

python3 .security/scripts/aggregate.py --reports .security-output --out .security-output/aggregate.json
```

Without the AI key, the DeepSec adapter writes an explicit skipped report without
model calls. For a local static-only report, run that adapter without the key before
aggregation; otherwise a missing `deepsec.json` is correctly treated as an error.
The aggregate command writes the check conclusion in JSON; its process exit code is
not the finding-policy result.

Run the pipeline's own verification from the trusted policy checkout:

```sh
python3 -m unittest discover -s .security/tests -v
node --test .security/tests/github.test.cjs
# Optional tools, if installed separately:
SEMGREP_BIN=/path/to/semgrep python3 -m unittest discover -s .security/tests -v
actionlint .github/workflows/security-scan.yml .github/workflows/security-report.yml
```

The integration test requires native Semgrep 1.176.1; the other tests use Python and
Node standard libraries. These verify the pipeline, not the target application's tests.
For scanner failures, run the verified CLI locally against synthetic or approved code
to diagnose; CI deliberately does not publish raw logs that may contain secrets/source.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| No scan starts | Ensure Actions is enabled, the PR targets a branch with the starter policy, and fork approval is not pending. The scan is PR-triggered, not manually dispatched. |
| Static scans run but no reporting workflow starts | Both workflow files must exist on the default branch; the report trigger expects the exact workflow name `Security scan`. |
| Validation ignores a run or no PR comment appears | Check whether the PR advanced, the run was cancelled/superseded, or GitHub could not establish one unambiguous current PR association. Also check the publisher's explicit permissions and organization policy. |
| Private GitHub Free fails at the environment job | Apply Path B's complete job replacement. Turning the AI variable off alone still leaves the original environment dependency. |
| Environment job waits or is rejected | Check branch rules against the default branch and any required-reviewer policy. Do not broaden access to PR refs to make it pass. |
| DeepSec shows `skipped` | Expected for forks or Path B. On Path A, verify the exact enable flag, a nonempty model variable, and the environment secret. |
| DeepSec shows `error` | Check key validity, OpenRouter credits, model availability, membership in the pinned/additional Pi catalog, timeout, refusals, and per-file completion. Exit code 1 alone cannot distinguish findings from an agent failure. |
| DeepSec shows `partial` | The PR exceeds the 20-file/500-KB changed-file budget. Arrange manual review or a reviewed policy change; this is not a clean scan. |
| Local Docker scanner fails | Start the Docker daemon and ensure the pinned image can be pulled. Trivy also needs access to its public database endpoints. |
| Semgrep scans few or no applicable files | Only five Python/JS/TS rules ship. Add rules for the actual languages/frameworks and inspect coverage before interpreting the result. |
| A report is missing or invalid | Preserve the failure signal; inspect job status and the exact run-attempt artifact names. Do not substitute an older successful report. |
| A check exists but has no line annotations | GitHub may reject a location or the 50-annotation display limit may apply. The complete retained findings are in normalized JSON artifacts. |
| Runs stop after usage grows | Inspect the repository owner's Actions/storage quotas and the separate model budget. Fork approvals and reruns also affect when work runs. |
| Adding `security-autofix` does nothing | Expected: remediation is design-only. No label-triggered code modification workflow is installed. |

## Maintenance and later runners

Actions are pinned to verified commit SHAs, scanner images to tags plus immutable
digests, and DeepSec's transitive npm dependencies to `package-lock.json` integrity
hashes. Updating a version is a reviewed change: resolve its official digest, read
release/security notes, re-run fixtures, and pilot on a PR. Trivy's vulnerability and
IaC databases intentionally update, so findings can change even for the same commit.

By default both scan and AI jobs use `ubuntu-24.04`. To move heavy work later, set:

```text
SECURITY_SCAN_RUNNER = ["self-hosted","linux","x64","security-ephemeral"]
SECURITY_AI_RUNNER = ["self-hosted","linux","x64","security-ai-ephemeral"]
```

The values are JSON arrays; leave them unset for GitHub-hosted runners. Keep validation
and publishing on GitHub-hosted runners. The replacement workers must be single-job,
ephemeral machines in an isolated runner group, destroyed after each job. Do not use a
persistent production runner: a PR can alter its unprivileged workflow and execute code
outside the scanner container. Give workers no production network routes, cloud metadata
credentials, shared writable caches, user logins, or access to other jobs' disks. Allow
only necessary GitHub/image/database/model endpoints and provision Git/Python/Docker/Node.
Do not mount the host Docker socket inside scanner containers. The workflow job shape
and report contract remain unchanged when runner labels change.

## Validation performed here

Thirteen tests passed, including the optional real Semgrep regression test covering
all five rules. GitHub Actions workflow lint and published DeepSec CLI flags/reader
controls were checked. A synthetic Trivy fixture produced five dependency findings,
one secret finding, and four Dockerfile misconfiguration findings; normalization
removed the synthetic secret value, and the aggregate correctly failed its check policy.
Docker was installed but its daemon was not running, so the actual Linux container
invocations have not been executed locally. Workflow events, environment protection,
PR commenting, and live paid DeepSec analysis remain deployment/pilot checks in the
target GitHub repository. See `AUTOFIX.md` for the separately authorized design.

## Draft pull requests

Draft PRs skip the security scan jobs. Mark a PR **Ready for review** to trigger
Semgrep, Trivy, and the eligible DeepSec review; further updates rerun them while
it remains ready. Returning a PR to draft cancels an active scan through its
concurrency group. GitHub may still show skipped workflow entries. The trusted
reporter rechecks draft state before starting AI and before publishing; an AI
request already in progress may finish, but its report is not published while
the PR remains draft. Existing comments and check results are retained as history.

Trivy uses a disposable runner-disk cache because its vulnerability database can
exceed the container's 1 GB `/tmp` limit. The cache is never reused between runs.

The scanner container uses the invoking non-root user's UID/GID (or `65534:65534`
when invoked by root). This allows the host to remove Trivy's private cache
directories after normalization. It does not add host mounts or credentials;
source/policy remain read-only, with capabilities dropped and privileges disabled.
