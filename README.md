# Focused security scanner demo

This NodeGoat-derived training fork demonstrates two deliberately introduced bugs:

- Contribution evaluation: request fields reach server-side `eval`. Semgrep and
  DeepSec provide complementary evidence about code execution.
- Allocation ownership: a route selects the owner from the URL instead of the
  authenticated session. DeepSec reviews the missing authorization check.

The default branch contains the corrected implementations. Demo PRs reintroduce
one bug each and must stay unmerged. The GitHub App runs all three scanners and
publishes one `Security / gate` and one updated comment linking to its report in
GitHub. Regression tests are a separate required check. A medium/advisory ownership
finding does not alone fail the current security gate; its regression test fails.

## Run the focused application locally

Requires Node 24+ and Docker Compose for MongoDB:

```sh
npm ci --ignore-scripts
npm test
docker compose up -d mongo
# To seed an empty local demo database (this explicitly resets demo data):
docker compose run --rm --build web npm run db:seed
docker compose up -d --build web
```

Open http://localhost:4000 and create a demo account. The web port binds only to
localhost. The seeded training users also remain available; use no real data.
A random session key is generated at startup; optionally provide SESSION_SECRET
when starting Node directly. Do not publish this training application.

## Baseline cleanup

Runtime packages are pinned and the lockfile regenerated. The old development
pipeline and duplicated scanner dependencies have been removed: scanner policy
now belongs to the installed App's repository. This preserves the separate
required regression check and does not replace or disable the App gate.

The focused runtime mounts login/signup, contributions, and allocations only.
Other original NodeGoat lessons remain as reference source, not active routes.
Nunjucks replaces Swig with automatic HTML escaping; CSRF validation and session
regeneration protect the active forms. Passwords are hashed. Allocation thresholds
are validated and queried using MongoDB operators rather than JavaScript `$where`.
The obsolete checked-in training TLS private key is removed from the current tree;
its historical copies remain and must never be trusted as a real credential.

The full upstream lesson catalog and old Grunt/Cypress commands no longer describe
this focused runtime. This is a scanner demo, not a production security guarantee.

## Attribution

Derived from OWASP NodeGoat, licensed under Apache-2.0; see LICENSE.
