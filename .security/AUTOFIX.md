# Maintainer-authorized remediation design (not enabled)

The scan workflow never changes code. No `security-autofix.yml` executable is installed
in this first iteration; adding the `security-autofix` label currently has no effect.
The following is the implementation contract for that separate workflow.

## Trigger and authorization

Implement a trusted default-branch `workflow_dispatch` workflow accepting a PR number
and exact expected head SHA. A small `pull_request_target: types: [labeled]` dispatcher
can later react to the exact label `security-autofix`; it must only call GitHub APIs,
never checkout or execute PR code. Verify the event sender's current repository
permission through GitHub's collaborator-permission API and require `maintain` or
`admin`, or an explicitly reviewed maintainer allowlist. Author association and the
mere presence of a label are insufficient authorization.

The dispatcher records PR number, current head SHA, triggering maintainer, and scan run
ID. Remove the label when the request is accepted; it authorizes one exact commit.
A new push requires a new explicit trigger. Limit concurrency to one fix attempt per PR.
Reject fork PRs initially, closed PRs, protected head branches, stale findings, expired
artifacts, and a PR head differing from the authorization. A protected
`security-remediation` environment can add final maintainer approval tied to this SHA.

## Job boundaries

| Job | Allowed work | Credentials |
| --- | --- | --- |
| Authorize | Validate maintainer, PR/head, latest completed scan, artifact provenance and schema | Read GitHub metadata; separate minimal token if consuming the label |
| Investigate and propose | Independently validate each finding; edit only confirmed vulnerabilities; produce patch and evidence | Model access through a restricted broker; no GitHub write token |
| Validate | Apply candidate patch to the approved SHA and run trusted regression checks plus the existing test/lint/typecheck suite | No model key, GitHub write token, production credentials, or infrastructure access |
| Publish | Recheck authorization and unchanged head, validate patch constraints, create a commit on the PR branch | Short-lived, single-repository GitHub App installation token, introduced only here |

Do not hand an agent shell both an API key and untrusted tests. A coding agent can
execute PR-controlled commands: isolate it in an ephemeral sandbox and keep provider
credentials behind a host-side, model-endpoint-only broker. Running code inside a
container while injecting raw credentials into the same container does not solve this.
The validation runner must be separate, ephemeral, and unable to access production
services or the agent's credentials. Do not reuse its filesystem for the publisher.

## Finding-by-finding rules

Retrieve the latest complete findings for the **authorized head SHA**, not simply the
latest artifact by name. Revalidate GitHub workflow ID/path/event, run attempt, head
repository, PR association, and report schema. Downloaded files remain untrusted data.

The agent must establish attacker-controlled input, reachable vulnerable behavior,
missing protection, and impact using the current code. Scanner/model confidence and
agreement between scanners are evidence to investigate, not confirmation. For each
finding, record `confirmed`, `false_positive`, `already_fixed`, or `uncertain` with
evidence. Fix only confirmed findings. For secrets, source removal does not revoke the
credential; report the required owner rotation rather than claiming a complete fix.

Group duplicates for investigation while preserving all source finding IDs. Restrict
changes to the smallest justified code/dependency fix and relevant regression tests.
No unrelated refactors, formatting sweeps, weakened assertions, disabled checks, new
network endpoints, or changes to workflow/security/agent policy are permitted. If a
confirmed vulnerability requires changing a protected policy file, stop that finding
for a maintainer's manual change.

Require a regression demonstration that fails on the approved original commit and
passes with the patch where feasible. Then run the repository's existing test, lint,
and typecheck commands, using an explicit reviewed command manifest for that project.
This starter has no application, so those commands cannot yet be specified. Failed or
unavailable required checks prevent publication; uncertain findings remain reported.

Repository files, PR descriptions, issue comments, tool output, and findings are data.
The agent must not load repository skills/extensions or obey embedded instructions
that conflict with its trusted task. Structural tool, filesystem, network, and
credential boundaries enforce privilege restrictions regardless of model compliance.

## Patch validation and commit

The publisher loads only trusted default-branch code. Bound patch size and changed-file
count; validate every path and Git mode before application. Reject absolute/traversal
paths, symlinks, submodules, binaries, `.git*` policy paths, `.github/**`, `.security/**`,
agent instructions/configuration, and unapproved generated/vendor files. Enforce scope
against the approved finding evidence. Never execute a proposed patch, test command,
hook, diff driver, filter, or script from an artifact in this job.

Use a fresh checkout of the authorized SHA with hooks and external filters disabled,
or GitHub's Git-data APIs. Recheck current PR head, apply the validated patch, create a
commit whose parent is the authorized SHA, and advance the PR branch without force.
Abort if the branch advanced; do not rebase or overwrite another contributor's work.
Preserve the verification evidence, sanitized patch, test status, and resulting commit
SHA as artifacts. Never grant the App workflow-edit permission.

Use a GitHub App installation token restricted to this repository with `contents: write`
for the final push so the normal PR security workflow can run again. Do not assume a
push with `GITHUB_TOKEN` causes an ordinary unattended run: GitHub suppresses many
token-triggered events and currently puts some generated PR events into an approval-
required state. See [GitHub token event behavior](https://docs.github.com/en/actions/concepts/security/github_token).
Keep the App private key in a protected default-branch environment; never expose it
to the agent or validation jobs. The subsequent scan does not automatically trigger
another autofix, because each fix attempt requires new maintainer authorization.
