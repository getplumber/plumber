<p align="center">
  <img src="assets/plumber.svg" alt="Plumber">
</p>

<p align="center">
  <b>CI/CD security scanner for GitLab CI and GitHub Actions</b><br/>
  <sub>One CLI, one <code>.plumber.yaml</code>, one Rego policy engine.</sub>
</p>

<p align="center">
  <a href="https://score.getplumber.io/github.com/getplumber/plumber"><img src="https://score.getplumber.io/github.com/getplumber/plumber.svg" alt="Plumber Score"></a>
  &nbsp;&nbsp;
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/getplumber/plumber"><img src="https://img.shields.io/ossf-scorecard/github.com/getplumber/plumber?label=OpenSSF%20Scorecard&style=for-the-badge&labelColor=2b2d42&color=4a90d9" alt="OpenSSF Scorecard"></a>
  &nbsp;&nbsp;
  <a href="https://slsa.dev/spec/v1.0/levels#build-l3"><img src="https://img.shields.io/badge/SLSA-Level%203-4a90d9?style=for-the-badge&logo=slsa&logoColor=white&labelColor=2b2d42" alt="SLSA 3"></a>
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
  <a href="https://getplumber.io/docs/cli">Docs</a> •
  <a href="https://discord.gg/932xkSU24f">Discord</a> •
  <a href="https://github.com/getplumber/plumber/issues">Issues</a>
</p>

---

## What Is Plumber?

Plumber scans CI/CD pipelines for risky patterns and security gaps.

- **GitLab CI:** reads `.gitlab-ci.yml`, resolved includes, and repository settings.
- **GitHub Actions:** reads `.github/workflows/*.{yml,yaml}` locally or through the GitHub API.
- **One config:** `.plumber.yaml` contains provider-specific policy sections for GitLab and GitHub.

Plumber reports findings in the terminal, JSON, SARIF, GitLab SAST, CSV, OCSF, PBOM, and CycloneDX formats.

<p align="center">
  <img src="assets/component.gif" alt="Plumber GitLab CI component running" width="700">
</p>

## Start Here

Run your first scan before reading the full docs.

```bash
brew tap getplumber/plumber
brew install plumber

plumber config generate # generate the default configuration file
plumber analyze
```

See the generated default config in this repo: [`defaultConfig/.plumber.yaml`](./defaultConfig/.plumber.yaml).

Plumber auto-detects the provider from your git remote. Use explicit flags when scanning a repo that is not the current checkout.

## Choose Your Path

| I want to... | Use this | Start here |
|---|---|---|
| Try Plumber locally | CLI | [`plumber analyze`](#local-cli) |
| Add checks to GitLab CI | GitLab CI Component | [GitLab CI Component](#gitlab-ci-component) |
| Add checks to GitHub Actions | GitHub Action | [GitHub Action](#github-action) |
| Audit many repos from a script | CLI + JSON/SARIF | [Outputs](#outputs) |
| Tune policy rules | `.plumber.yaml` | [Configuration](#configuration) |

## Local CLI

### Install

```bash
brew tap getplumber/plumber
brew install plumber
```

Other options:

- `mise use -g github:getplumber/plumber`
- Download a binary from [GitHub Releases](https://github.com/getplumber/plumber/releases)
- Run the Docker image: `getplumber/plumber`

Full install docs:

- GitLab: [getplumber.io/docs/cli/gitlab#run-with-the-gitlab-ci-component](https://getplumber.io/docs/cli/gitlab#run-with-the-gitlab-ci-component)
- GitHub: [getplumber.io/docs/cli/github#run-with-github-actions](https://getplumber.io/docs/cli/github#run-with-github-actions)

### Authenticate

GitLab:

```bash
export GITLAB_TOKEN=glpat_xxxx
```

GitHub (preferred, uses the gh CLI's keyring):

```bash
gh auth login
```

Alternative (CI runners, automation):

```bash
export GH_TOKEN=ghp_xxxx
```

Local GitHub scans can run without a token for workflow-content checks. A token enables repo-level and action-metadata checks.

If a workflow uses an action hosted in an org with an IP allow list (which blocks the runner's `GITHUB_TOKEN`), set `PLUMBER_METADATA_TOKEN` to a token with public-repository read so Plumber can still resolve that action's version for the known-CVE check. Without it, Plumber falls back to an anonymous read and, if that is rate-limited too, skips the version check rather than guessing.

### Run

Current repo:

```bash
plumber analyze
```

Specific GitLab project:

```bash
plumber analyze \
  --provider gitlab \
  --gitlab-url https://gitlab.com \
  --project group/project
```

Specific GitHub repo without a local clone:

```bash
plumber analyze \
  --provider github \
  --github-url github.com \
  --project owner/repo
```

## GitHub Action

1. Add [the official Plumber action](https://github.com/marketplace/actions/plumber-score) to `.github/workflows/plumber.yml`:
    ```yaml
    name: Plumber

    on:
      pull_request:
      push:
        branches: [main]

    permissions:
      contents: read
      security-events: write
      # id-token: write   # uncomment to enable score-push below

    jobs:
      plumber:
        runs-on: ubuntu-24.04
        steps:
          - uses: actions/checkout@v6
          - uses: getplumber/plumber@<version>
            with:
              # Set to `true` to publish an official Plumber score badge
              # (it makes your score and repo name public, see Score Push section below)
              score-push: false
    ```


> To resolve action versions hosted in an org with an IP allow list, pass a
> public-repo-read token via the `metadata-token` input (kept in a secret):
>
> ```yaml
>         with:
>           metadata-token: ${{ secrets.PLUMBER_METADATA_TOKEN }}
> ```

**Full guide:** [getplumber.io/docs/cli/github#run-with-github-actions](https://getplumber.io/docs/cli/github#run-with-github-actions)

## GitLab CI Component

1. Add [the official Plumber component](https://gitlab.com/explore/catalog/getplumber/plumber) to `.gitlab-ci.yml`:
    ```yaml
    include:
      - component: gitlab.com/getplumber/plumber/plumber@<version>
        inputs:
          # Set to `true` to publish an official Plumber score badge
          # (it makes your score and repo name public, see Score Push section below)
          score_push: false
    ```
2. Add `GITLAB_TOKEN` in **Settings -> CI/CD -> Variables**.
    Use `read_api` + `read_repository` for scanning, or `api` if you want Plumber to post MR comments or badges.

**Full guide:** [getplumber.io/docs/cli/gitlab#run-with-the-gitlab-ci-component](https://getplumber.io/docs/cli/gitlab#run-with-the-gitlab-ci-component)

## Score Push

Enabling score push publishes a self-updating `A–E` badge to the hosted score
service. It's the only way to get an **official Plumber score**. It's only
available in CI, not when running the CLI locally.

Display it with a badge in your README (swap in your platform/owner/repo):
```md
[![Plumber Score](https://score.getplumber.io/github.com/OWNER/REPO.svg)](https://score.getplumber.io/github.com/OWNER/REPO)
```

> ⚠️ Opt-in and off by default. Enabling it makes your **score and repository
> name public**. Only the default branch's score is displayed. See [score
> docs](https://getplumber.io/docs/plumber-score).

## Common `analyze` flags

| Flag | Purpose |
|---|---|
| `--score-endpoint` | Score service base URL (default `https://score.getplumber.io`). Override only for a self-hosted score service. |
| `--platform` | Plumber platform base URL. Setting it turns on **platform mode** (see below) and pushes this run's full results there over CI OIDC, taking precedence over `--score-push`. Requires an id-token grant: `permissions: id-token: write` on GitHub, the component's `id_tokens:` block on GitLab. |

### Platform mode

Without `--platform` nothing changes: Plumber collects everything itself and
evaluates one policy, exactly as it always has.

With `--platform`, Plumber first reads the project's context from the
platform - the resolved policy set and a cached settings snapshot - and uses
it to decide what to collect and what to report:

- **One result per policy.** The platform's policy set decides how many
  results the run produces, each keyed to its own policy and carrying its own
  score. Policies that share a control configuration are evaluated once.
- **The CI configuration comes from the platform.** Resolving `include:`
  directives needs an API a CI job token cannot reach, so platform mode reads
  the resolved configuration from the platform instead of asking the git host
  itself.
- **So do the project settings.** Branch protections, merge-request approval
  rules and settings, and CI/CD variable metadata are read from the snapshot
  rather than collected per run. That is what stops a project scanned once
  per policy file from re-fetching the same settings once per policy file.
  Variable *values* are never served and never needed: the controls read the
  protected and masked flags, not the secrets.
- **A CI job needs no GitLab token.** Platform mode is built for CI, and a
  job already has what the rest would have been fetched for: its own
  identity in the predefined `CI_*` variables, its checkout, and its
  environment. Set `--platform` and Plumber runs without a `GITLAB_TOKEN`.
  A few checks still read the projects your pipeline *includes* from, and
  without a token those report `not_evaluable` rather than passing.
- **Your branch is evaluated against its own configuration.** Plumber hashes
  the CI config in the checkout - the root file plus every local include -
  and compares it to what the platform's snapshot was resolved from. A branch
  that does not touch CI config matches and reuses the snapshot at no extra
  cost; a branch that does changes gets its own resolution from the platform.
- **Controls whose data is unavailable report `not_evaluable`, never a
  pass.** If the platform cannot resolve a configuration, or reports a
  settings collection as failed, the controls that read it say so instead of
  reporting a clean result over data nobody collected. A lane the platform
  vouches for as genuinely empty is still a real verdict a control may fail
  on. A run prints which configuration it used and why, with no `--verbose`
  needed.

Platform mode reports *less* when data is missing, never something different:
a run that cannot evaluate a control says so.

The platform can gate the run: if it returns a blocking decision for this
push, the job exits `1` with a line naming every blocking policy. A platform
that is down, slow, or erroring **never blocks**: the gate only ever fails
open, and the two sentences below are exact so you can alert on them:

- `gate unavailable, letting through`: the platform itself is unreachable
  (timeout, connection error, 5xx). The run proceeds.
- `gate NOT RUN: authentication/configuration failed`: the request reached
  the platform but was rejected (expired/invalid token, misconfigured
  project). The run proceeds.

A third, informational line is deliberately distinct from both, so alerts on
the sentences above stay precise: `platform returned no gate verdict,
letting through` means the push was accepted (2xx) but the response carried
no usable gate decision - typically a platform version that predates the
gate. Routine during a platform rollout; the run proceeds.

## Configuration

Plumber reads `.plumber.yaml`.

Create a config interactively:

```bash
plumber config init
```

Generate the full commented [default template](./defaultConfig/.plumber.yaml):

```bash
plumber config generate
```

Example:

```yaml
version: "2.0"

gitlab:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true

github:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
      trustedOwners:
        - actions
        - github
```

Useful commands:

```bash
plumber config validate
plumber config view
plumber config diff
plumber explain ISSUE-411
```

Full config reference:

- Default config: [`defaultConfig/.plumber.yaml`](./defaultConfig/.plumber.yaml)
- CLI docs: [getplumber.io/docs/cli](https://getplumber.io/docs/cli)
- Issue reference: [getplumber.io/docs/use-plumber/issues](https://getplumber.io/docs/use-plumber/issues)

### Overlay configuration

Extend Plumber's baseline and list only what you change:

```yaml
extends: plumber:default
version: "2.0"
github:
  controls:
    githubActionMustComeFromAuthorizedSources:
      includePlumberDefaults: true # keep the curated trusted orgs, default
      trustedGithubActions:
        - myorg
```

Everything else is inherited, and new controls Plumber ships appear automatically. For allowlist
controls, `includePlumberDefaults: true` unions your entries with Plumber's list, `false` uses
only your own. Run `plumber config generate --overlay` for a starter, and `plumber config resolve`
to print the full effective config.

## Controls

Plumber ships controls for:

- container image pinning and authorized sources
- branch protection
- GitLab merge request approval rules (minimum approvals, coverage of all protected branches) and approval settings (author/committer approval, per-MR overrides, re-authentication, approval reset)
- GitLab CI/CD settings variables that must be protected and masked
- unverified script execution (`curl | bash`, `base64 -d | bash`, etc.)
- Docker-in-Docker
- weakened security jobs
- unsafe variable expansion
- GitHub action pinning, archived actions, ref confusion, impostor commits, and known CVEs
- dangerous GitHub triggers and overbroad permissions

Full catalogs:

- GitLab controls: [getplumber.io/docs/use-plumber/controls?p=gitlab](https://getplumber.io/docs/use-plumber/controls?p=gitlab)
- GitHub controls: [getplumber.io/docs/use-plumber/controls?p=github](https://getplumber.io/docs/use-plumber/controls?p=github)

## Outputs

| Output | Flag | Use it for |
|---|---|---|
| Terminal | default | Human review during local or CI runs |
| JSON | `--output results.json` | Automation and dashboards |
| SARIF | `--sarif results.sarif` | GitHub Code Scanning and SARIF-compatible tools |
| GitLab SAST | `--glsast gl-sast-report.json` | GitLab Security Dashboard / MR widget |
| CSV | `--csv results.csv` | Spreadsheet tools, ad-hoc analysis |
| OCSF | `--ocsf plumber.ocsf.json` | OCSF consumers and GRC platforms (Compliance Finding, schema 1.8.0) |
| PBOM | `--pbom pbom.json` | Pipeline inventory |
| CycloneDX | `--pbom-cyclonedx cdx.json` | SBOM tooling |

<p align="center">
  <img src="assets/plumber-output.png" alt="Plumber terminal output" width="700">
</p>

Example:

```bash
plumber analyze \
  --output results.json \
  --sarif results.sarif \
  --csv results.csv \
  --pbom pbom.json \
  --pbom-cyclonedx cdx.json
```

### Artifacts without a verdict

To produce an artifact (typically the PBOM) and nothing else, pass
`--no-controls`. No control is evaluated, no score is computed, and the run
exits `0` as long as data collection succeeded:

```bash
plumber analyze --pbom-cyclonedx cdx.json --no-controls --print=false
```

It overrides whatever `.plumber.yaml` enables, so the same config keeps working
for a normal `plumber analyze` in another job. Nothing the run produces claims a
verdict: the JSON, CSV and OCSF reports mark every control `skipped` rather than
`passed`, and the PBOM records the collected inventory (images, includes,
upstream versions) with no compliance flags on it, per-image or per-include.

The run still fails (exit 3) when data collection did not produce a usable
pipeline: a degraded collection, a `.gitlab-ci.yml` that was fetched but does
not parse, or (on GitLab) no CI configuration at all. In each case the
inventory would be empty, and an empty PBOM must not ship as a complete one.

Flags that read or publish a verdict are ignored, with a notice naming them:
`--min-points`, `--min-score`, `--threshold`, `--badge`, `--score-push`,
`--mr-comment`, `--platform`, and also `--sarif` / `--glsast`. Those last two
are security reports with no honest empty form: an empty SARIF is what makes
GitHub Code Scanning clear previously-reported alerts, and an empty GitLab SAST
report shows a clean Security Dashboard. Writing them from a run that evaluated
nothing would dismiss real alerts, so they are skipped rather than emitted
empty.

More details:

- PBOM docs: [`docs/PBOM.md`](./docs/PBOM.md)
- Scoring docs: [`docs/scoring.md`](./docs/scoring.md)
- Finding fingerprint (tracking a finding across runs): [`docs/FINGERPRINT.md`](./docs/FINGERPRINT.md)
- CLI reference: [getplumber.io/docs/cli](https://getplumber.io/docs/cli)

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | The Plumber Score meets the gate (`--min-points` / `--min-score`), or `--no-controls` was used and data collection succeeded |
| `1` | The Plumber Score is below the gate (or the deprecated `--threshold` is not met) |
| `2` | Invalid usage, configuration, or a runtime / provider / auth / network failure |
| `3` | A check could not be verified and `--fail-warnings` is set (e.g. an action version that could not be resolved) |

## Self-Hosted GitLab

If you run a self-hosted GitLab instance, host or mirror the Plumber component inside your instance, publish a release, and include that component URL from your pipelines.

Guide: [getplumber.io/docs/cli/gitlab#hosting-on-self-hosted-gitlab](https://getplumber.io/docs/cli/gitlab#hosting-on-self-hosted-gitlab)

## Troubleshooting

| Problem | What to check |
|---|---|
| `GITLAB_TOKEN environment variable is required` | Export `GITLAB_TOKEN` or add it as a CI/CD variable |
| GitHub upstream scan refuses to start | Set `GH_TOKEN`, `GITHUB_TOKEN`, or run `gh auth login` |
| No GitHub repo-level findings | Local GitHub scans soft-degrade without token/API scope |
| Config warnings | Run `plumber config validate` |
| Need to inspect a finding | Run `plumber explain ISSUE-XXX` |

More help:

- GitLab guide: [getplumber.io/docs/cli/gitlab](https://getplumber.io/docs/cli/gitlab)
- GitHub guide: [getplumber.io/docs/cli/github](https://getplumber.io/docs/cli/github)
- Discord: [discord.gg/932xkSU24f](https://discord.gg/932xkSU24f)
- Contact: [tech@getplumber.io](mailto:tech@getplumber.io)

## Development

Build locally:

```bash
make build
```

Run tests:

```bash
make test
```

Contributing guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)

## Resources

- Website: [getplumber.io](https://getplumber.io)
- Documentation: [getplumber.io/docs/cli](https://getplumber.io/docs/cli)
- GitHub Action listing: [Plumber Score](https://github.com/marketplace/actions/plumber-score)
- GitLab component docs: [`COMPONENT_README.md`](./COMPONENT_README.md)
- Security policy: [`SECURITY.md`](./SECURITY.md)

## License

Plumber is licensed under the [Mozilla Public License 2.0](LICENSE).
