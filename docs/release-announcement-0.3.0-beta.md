# Plumber v0.3.0-beta.6: GitHub Actions support

> Live: https://github.com/getplumber/plumber/releases/tag/v0.3.0-beta.6 (pre-release, opted out of the "latest" badge, so newcomers landing on the repo still get v0.2.22).


---

## TL;DR

Plumber now scans GitHub Actions workflows with the same engine, same `.plumber.yaml`, and same CLI you already use for GitLab. **Your existing GitLab usage is unchanged** — same flags, same output, same exit codes. The only thing you'll notice if you stay on GitLab is a one-line deprecation warning suggesting you upgrade the `.plumber.yaml` schema (optional).

If you want to scan a GitHub Actions project too, this release lets you.

### What changed since beta.5

- Four new GitHub controls ship default-on, taking the catalog from 11 to 14 (13 default-on + 1 opt-in `workflowMustIncludeRequiredActions`):
  - **`actionsMustNotBeArchived`** (ISSUE-108, High): flags `uses: owner/repo@ref` pointing at an archived GitHub repository. Driven by per-action GitHub API metadata, one cached call per unique ref. PBOM tags each affected include with `archived: true` / CycloneDX `plumber:archived`. Caught 13 real findings on `grafana/grafana` in matrix testing.
  - **`actionsMustNotCarryKnownCVEs`** (ISSUE-114, Critical): cross-references every action against the GitHub Advisory Database under the `actions` ecosystem. Same metadata path as the archived check. PBOM exposes `hasCve: true` plus `advisories: [GHSA-…]`; CycloneDX gets matching `plumber:has-cve` and `plumber:advisories` properties.
  - **`pipelineMustNotEnableDebugTrace`** on the GitHub side (ISSUE-203, Critical): the GitLab control's GitHub twin. Catches truthy `ACTIONS_STEP_DEBUG` / `ACTIONS_RUNNER_DEBUG` in any merged `env:` block (workflow, job, or step), in `${{ ... }}` expression-driven bindings (`actions_step_debug: ${{ vars.enable_debug }}`), and in runtime `echo "...=true" >> $GITHUB_ENV` script writes. All three paths emit Critical, so the obvious workarounds for the literal check are also covered. Case-insensitive; extend `forbiddenVariables` for other diagnostic toggles.
  - **`workflowMustNotGrantPermissionsWriteAll`** (ISSUE-509, High): flags `permissions: write-all` at workflow or job level. Pairs with `workflowsMustDeclarePermissions` (which catches the "no block at all" case) to close the least-privilege loop.
- `--skip-controls` now sets `skipped: true` in the JSON per-control blocks. Previously the flag only affected the terminal display, leaving downstream dashboards that read the JSON to mislabel a skipped control as "evaluated, passed". Findings, compliance, and `passed` were already correct. Affects every shipping control on both providers, not just the new ones.
- Workflow-top-level `env:` blocks now reach `Job.Variables`. The GitHub collector previously dropped them silently, leaving `pipelineMustNotEnableDebugTrace` and `workflowMustNotInjectUserInputInScripts` blind to toggles set at workflow root. Job and step env continue to merge on top, mirroring GitHub's `step > job > workflow` precedence.

### What changed since beta.2

- New GitHub control `workflowMustIncludeRequiredActions` (ISSUE-416): fail the scan when a workflow is missing a required action or reusable workflow. Same DNF shape as GitLab's `pipelineMustIncludeComponent` (outer list is OR, inner list is AND), and a single required entry resolves against both step-level `uses:` (actions) and job-level `uses:` (reusable workflow calls). Ref-agnostic with a slash-guard so `org/sast-scan` is not accidentally satisfied by `org/sast-scan-fork`. Opt-in, off by default.
- Restored the v0.2.22 `Total Includes` denominator. A bug in the v0.3 helper excluded origin types that should have counted, so a project with 8 real includes was reported as 1 (and "Using Authorized Versions" collapsed to 0 alongside it). Affects both `includesMustBeUpToDate` and `includesMustNotUseForbiddenVersions`. Findings and per-control compliance were already correct, only the totals were wrong.
- Branch-protection scan no longer goes silent on large repos. The progress bar reports per-page during the listing pagination and per-branch during the protection-detail loop, so a scan against something like `grafana/grafana` (774 branches across 8 listing pages) now cycles `Listing branches (page 8, 700 collected)` and `Resolving protection for <name>` live instead of pausing at 100% with no signal.
- Branch-protection scan also skips the slow detail calls for branches that do not match your configured `namePatterns`. On a typical config (`main`, `release/*`, etc.) plus a repo that has hundreds of unrelated protected branches (release tags, dependabot, version branches), the work drops from hundreds of API round-trips to just the ones you asked about. The findings are unchanged; only the wasted calls are gone.
- `branchMustBeProtected` (GitHub) reads Repository **and** Organization-level Rulesets alongside classic Branch Protection. Rules from any source are unioned, stricter wins. A code-owner rule defined only in a Ruleset is now seen.
- Fixed a duplicate-branch bug where GitHub's silent default-branch redirect on stale lookups (for example `/branches/master` returning main's payload after a master to main rename) caused main to land in the IR twice and falsely trigger the "skipped on N branches" postflight.
- Fixed issue [#158](https://github.com/getplumber/plumber/issues/158): a control omitted from `.plumber.yaml` is treated as skipped on the v0.3.0 path, matching v0.2.x. Its findings no longer leak into the score.
- `dockerInDockerResult.detail` reports both insecure conditions when present (TLS-empty + DOCKER_HOST on port 2375), matching v0.2.x wording.
- Binary self-reports the right version. beta.2 was stamped as `0.3.0-beta.1` due to a release-time ldflags issue.

---

## 1. Install

Beta is **not** on Homebrew, mise, or Docker Hub — those channels follow the latest stable (v0.2.22) and will resume with the v0.3.0 final. Three short steps: download, verify, install. Run them in a fresh empty directory so the checksum check has nothing else in scope:

```bash
mkdir -p ~/plumber-beta && cd ~/plumber-beta
```

### Step 1: Download your platform binary + the checksums file

Pick the one line that matches your platform; download `checksums.txt` either way.

```bash
# macOS (Apple Silicon)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta.6/plumber-darwin-arm64
# macOS (Intel)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta.6/plumber-darwin-amd64
# Linux (amd64)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta.6/plumber-linux-amd64
# Linux (arm64)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta.6/plumber-linux-arm64
# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/getplumber/plumber/releases/download/v0.3.0-beta.6/plumber-windows-amd64.exe -OutFile plumber-windows-amd64.exe

# Checksums (all platforms)
curl -LO https://github.com/getplumber/plumber/releases/download/v0.3.0-beta.6/checksums.txt
```

### Step 2: Verify integrity (recommended)

```bash
shasum -a 256 -c checksums.txt --ignore-missing
# Expected output: plumber-<your-platform>: OK
```

If the line you downloaded doesn't print `OK`, **stop and re-download** — don't install a binary whose hash doesn't match the release.

> **SLSA attestations are deliberately not produced for beta builds** — they're a CI-pipeline artifact, and the beta is built outside the release pipeline. `gh attestation verify` will fail against the beta binaries; that's expected. SLSA L3 provenance resumes with the v0.3.0 stable release. For the beta, the `checksums.txt` above is the integrity story.

### Step 3: Install and verify the version

```bash
# Replace plumber-darwin-arm64 with the binary you downloaded
chmod +x plumber-darwin-arm64 && sudo mv plumber-darwin-arm64 /usr/local/bin/plumber
plumber version                # expect: plumber version 0.3.0-beta.6
```

For Windows, just put `plumber-windows-amd64.exe` somewhere on your `PATH` and rename it to `plumber.exe`.

---

## 2. Pick your test track

Three independent scenarios. Run whichever apply to you — you don't have to do all three.

| Track | Who it's for | Time |
|---|---|---|
| **A. GitLab regression** | You already use Plumber for GitLab and want to confirm nothing broke | 5 min |
| **B. First GitHub scan** | You have a GitHub Actions project (clone or remote) | 10 min |
| **C. Upstream-fetch** | You want to scan a GitHub repo without cloning it (security-team workflow) | 5 min |

---

### Track A — GitLab regression

```bash
cd ~/path/to/your/gitlab/project
export GITLAB_TOKEN=glpat-…
plumber analyze
```

**Expected:** identical output to your previous Plumber run, with one new line:

```
WARN: legacy config schema detected; run 'plumber config migrate' to upgrade.
      v1 support will be removed in 1.0.0.
```

That warning is the only change. If anything else is different, please report it.

#### Optional: upgrade your `.plumber.yaml` schema

Plumber moved from a single root-level `controls:` block (v1) to per-provider sections (v2). Today your file looks like this:

```yaml
controls:
  containerImageMustNotUseForbiddenTags: { ... }
  branchMustBeProtected: { ... }
```

The new shape moves your controls one indent deeper under `gitlab:`, and reserves a parallel `github:` section for when you want it:

```yaml
version: "2.0"
gitlab:
  controls:
    containerImageMustNotUseForbiddenTags: { ... }
    branchMustBeProtected: { ... }
```

You don't have to upgrade — Plumber auto-converts v1 in memory on every run. But if you want to clean it up:

```bash
plumber config migrate              # writes .plumber.yaml.v2 alongside the original
# review, then either rename or:
plumber config migrate --in-place   # overwrites .plumber.yaml; backs up to .plumber.yaml.bak
```

Comments are preserved. The migration is idempotent (safe to re-run).

---

### Track B — First GitHub scan

You'll need:
1. A checked-out GitHub repo with workflows under `.github/workflows/`
2. A GitHub-aware `.plumber.yaml`
3. (Recommended) GitHub auth

#### Step 1: Get a GitHub-aware `.plumber.yaml`

Two ways. Pick the one that fits.

**Option 1 — generate the full commented template, then trim** (recommended; fastest path to a usable config):

```bash
cd ~/path/to/your/github/project
plumber config generate -o .plumber.yaml
```

This writes the official template with both `gitlab:` and `github:` sections fully populated and commented. Open it, glance at the comments, delete the section you don't need (or keep both for a shared config), tweak any value you care about. You're ready in under a minute.

**Option 2 — interactive wizard** (better if you want to be walked through each decision):

```bash
plumber config init -o .plumber.yaml
```

The wizard auto-detects GitHub from your git remote and pre-checks the right provider on the first question. It walks you through the GitHub-specific controls one by one: third-party action SHA pinning, dangerous triggers, workflow permissions, security-job patterns, branch protection, etc. Slower but you make a deliberate choice on each control.

#### Step 2: Authenticate (recommended)

```bash
gh auth login                        # uses your gh CLI credential
# OR
export GH_TOKEN=ghp_…                # PAT scopes — fine-grained: Contents:Read, Metadata:Read, Administration:Read · classic: repo
```

Local-clone analysis works without auth but the repo-level controls (branch protection) silently abstain — the postflight output flags that case clearly.

#### Step 3: Run

```bash
plumber analyze --output report.json --pbom pbom.json --pbom-cyclonedx sbom.json
```

**Expected:** per-control compliance percentages for the 14 GitHub controls (SHA pinning, archived-repo refs, known-CVE actions, dangerous triggers, write-all permission grants, debug-trace toggles, declared-permissions presence, template injection, reusable-workflow secrets, security-job weakening, container images, DinD, branch protection, required actions / reusable workflows). Three artifacts on disk: `report.json` (per-control results, with the new `archivedActionsResult`, `knownVulnerableActionsResult`, `excessivePermissionsResult`, and `debugTraceResult` blocks among them), `pbom.json` (container images + every `uses: owner/repo@<sha>` action reference, with `archived` / `hasCve` / `advisories` fields on affected entries), `sbom.json` (CycloneDX 1.5 — ingestible by Grype / Trivy / Dependency-Track, with `plumber:archived` / `plumber:has-cve` / `plumber:advisories` properties on affected components).

---

### Track C — Scan a GitHub repo without cloning it

Symmetric to GitLab's `--gitlab-url + --project` flow:

```bash
gh auth login        # auth is required in this mode
plumber analyze --github-url github.com --project getplumber/plumber --output report.json
```

Same per-control output as Track B, no local clone needed. Works on GitHub Enterprise Server too — pass the GHES host instead of `github.com`.

---

## 3. Token scope note (GitHub branch protection)

For `branchMustBeProtected` to evaluate the full rule set (force-push + code-owner-approval), the token needs **`Administration: Read`** (fine-grained PAT) or **`repo`** scope (classic PAT). Without it, the rule silently abstains and a `partialControls` block in the JSON output makes the abstention explicit — no false 100% claims. `gh auth login` with a user account that has admin on the repo works without any extra scope work.

Plumber reads **both** GitHub's Branch Protection mechanisms and merges them, stricter wins:

- **Classic Branch Protection** (the older *Settings → Branches → Branch protection rule* flow).
- **Repository Rulesets** and any **Organization-level Rulesets** the repo inherits (the newer *Settings → Rules → Rulesets* flow, GA 2023). Multiple rulesets covering the same branch are fine: the effective set is the union; disabled / evaluate-mode rulesets are skipped automatically.

So a code-owner-approval rule lives in either mechanism (or both) and Plumber finds it. `force-push allowed` only flips to "blocked" when at least one source disables it.

---

## 4. What I'm looking for

- **GitLab regression**: anything that worked before but doesn't now.
- **GitHub findings sanity**: do the 14 controls report things you'd expect for your repo? In particular for this beta, the four new ones: `actionsMustNotBeArchived` should be silent unless you depend on abandoned action repos; `actionsMustNotCarryKnownCVEs` should be silent unless you pin a version inside a published advisory window; `pipelineMustNotEnableDebugTrace` should only fire on `ACTIONS_STEP_DEBUG` / `ACTIONS_RUNNER_DEBUG`; `workflowMustNotGrantPermissionsWriteAll` should only fire when a workflow or job literally declares `permissions: write-all`. Anything noisy or obviously wrong?
- **Wizard UX**: was `plumber config init` clear? Anything confusing or missing?
- **CLI ergonomics**: any flag or message that felt unfamiliar coming from the GitLab-only flow?
- **Output artifacts**: `report.json` / `pbom.json` / `sbom.json` — does the shape match what you'd want to script against?

Reply with findings or open an issue at https://github.com/getplumber/plumber/issues. Screenshots welcome. Thanks for stress-testing! 🛠
