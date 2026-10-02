<p align="center">
  <img src="assets/plumber-banner.png" alt="Plumber">
</p>

<p align="center">
  <a href="https://score.getplumber.io/github.com/getplumber/plumber"><img src="https://score.getplumber.io/github.com/getplumber/plumber.svg?style=flat" alt="Plumber Score"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/getplumber/plumber"><img src="https://img.shields.io/ossf-scorecard/github.com/getplumber/plumber?label=OpenSSF%20Scorecard" alt="OpenSSF Scorecard"></a>
  <a href="https://slsa.dev/spec/v1.0/levels#build-l3"><img src="https://img.shields.io/badge/SLSA-Level%203-4a90d9?logo=slsa&logoColor=white" alt="SLSA 3"></a>
  <a href="https://github.com/getplumber/plumber/releases"><img src="https://img.shields.io/github/v/release/getplumber/plumber?color=blue" alt="Latest Release"></a>
  <a href="https://hub.docker.com/r/getplumber/plumber"><img src="https://img.shields.io/docker/pulls/getplumber/plumber" alt="Docker Pulls"></a>
</p>

<p align="center">
  <b>CI/CD security scanner for GitHub Actions and GitLab CI</b>
</p>

<p align="center">Securing the workflows of:</p>
<table align="center">
  <tr>
    <td align="center"><a href="https://github.com/lightpanda-io/browser"><img src="https://avatars.githubusercontent.com/u/145980012?s=96" width="48" height="48" alt="Lightpanda"></a><br><sub><b>Lightpanda</b><br>&#9733; 35.6k</sub></td>
    <td align="center"><a href="https://github.com/go-delve/delve"><img src="https://avatars.githubusercontent.com/u/19232073?s=96" width="48" height="48" alt="Delve"></a><br><sub><b>Delve</b><br>&#9733; 24.9k</sub></td>
    <td align="center"><a href="https://github.com/go-resty/resty"><img src="assets/adopters/resty.png" width="48" height="48" alt="Resty"></a><br><sub><b>Resty</b><br>&#9733; 11.8k</sub></td>
    <td align="center"><a href="https://github.com/0xJacky/nginx-ui"><img src="assets/adopters/nginx-ui.png" width="48" height="48" alt="nginx-ui"></a><br><sub><b>nginx-ui</b><br>&#9733; 11.5k</sub></td>
    <td align="center"><a href="https://github.com/bunkerity/bunkerweb"><img src="https://avatars.githubusercontent.com/u/86405535?s=96" width="48" height="48" alt="Bunkerity"></a><br><sub><b>Bunkerity</b><br>&#9733; 11k</sub></td>
    <td align="center"><a href="https://github.com/intuitem/ciso-assistant-community"><img src="https://avatars.githubusercontent.com/u/71849524?s=96" width="48" height="48" alt="intuitem"></a><br><sub><b>intuitem</b><br>&#9733; 4.4k</sub></td>
  </tr>
</table>

<p align="center">
  📡 <a href="https://getplumber.io/radar"><b>Plumber Radar</b></a> ➡️ 20k public repos scanned
</p>

---

## What is Plumber?

Plumber scans CI/CD pipelines for risky patterns and security gaps.

- **GitHub Actions:** scans `.github/workflows/*.{yml,yaml}` and repository settings.
- **GitLab CI:** scans `.gitlab-ci.yml`, resolved includes, and repository settings.

Findings are reported in the terminal, JSON, SARIF, GitLab SAST, CSV, OCSF, PBOM, and CycloneDX.

<p align="center">
  <img src="assets/plumber-cli.gif" alt="plumber analyze scanning a repository" width="700">
</p>

## Where to run it

| | Use it for |
|---|---|
| 💻 **[Run locally](#quick-start)** | Trying Plumber, or auditing repos from a script |
| 🐙 **[Run in GitHub Actions](#github-action)** | Checks on every PR and push, findings in Code Scanning |
| 🦊 **[Run in GitLab CI](#gitlab-ci-component)** | Checks on every pipeline, findings in the MR widget |

## Quick start

```bash
brew tap getplumber/plumber
brew trust --formula getplumber/plumber/plumber
brew install plumber

plumber analyze
```

No config file is needed: `plumber analyze` runs with the built-in default configuration ([`defaultConfig/.plumber.yaml`](./defaultConfig/.plumber.yaml)) and auto-detects the provider from your git remote.

## Install

Other options besides Homebrew:

- `mise use -g github:getplumber/plumber`
- A binary from [GitHub Releases](https://github.com/getplumber/plumber/releases)
- The Docker image [`docker.io/getplumber/plumber`](https://hub.docker.com/r/getplumber/plumber) on Docker Hub

## Authenticate

```bash
# GitHub, using the gh CLI keyring
gh auth login
# or, for CI runners and automation
export GH_TOKEN=ghp_xxxx

# GitLab
export GITLAB_TOKEN=glpat_xxxx
```

## Run

```bash
# current repo
plumber analyze

# a GitHub repo without a local clone
plumber analyze github.com/owner/repo

# a GitLab project without a local clone (self-hosted instances work too)
plumber analyze gitlab.com/group/project
```

The target can also be a full URL pasted from the browser (`https://github.com/owner/repo/tree/main` selects the branch). Run `plumber analyze --help` for the full flag list.

## GitHub Action

Add [the official Plumber action](https://github.com/marketplace/actions/plumber-score) to `.github/workflows/plumber.yml`:

```yaml
name: Plumber

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  id-token: write # required by score-push

jobs:
  plumber:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
      - uses: getplumber/plumber@<version>
        with:
          # Publishes your Plumber Score and repository name publicly on
          # score.getplumber.io (see Score badge below). Set to false to keep them private.
          score-push: true
```

**Full guide:** [getplumber.io/docs/cli/github#run-with-github-actions](https://getplumber.io/docs/cli/github#run-with-github-actions)

## GitLab CI component

Add [the official Plumber component](https://gitlab.com/explore/catalog/getplumber/plumber) to `.gitlab-ci.yml`:

```yaml
include:
  - component: gitlab.com/getplumber/plumber/plumber@<version>
    inputs:
      # Publishes your Plumber Score and repository name publicly on
      # score.getplumber.io (see Score badge below). Set to false to keep them private.
      score_push: true
```

Add `GITLAB_TOKEN` in **Settings -> CI/CD -> Variables**: `read_api` + `read_repository` for scanning, or `api` if you want Plumber to post MR comments or badges.

**Full guide:** [getplumber.io/docs/cli/gitlab#run-with-the-gitlab-ci-component](https://getplumber.io/docs/cli/gitlab#run-with-the-gitlab-ci-component)

Self-hosted GitLab: host or mirror the component in your instance and include that URL. [Guide](https://getplumber.io/docs/cli/gitlab#hosting-on-self-hosted-gitlab).

## Score badge

The badge at the top of this README comes from the hosted score service. With score push on (`score-push: true` on the Action, `score_push: true` on the component, as in the snippets above), each run on the default branch keeps an `A-E` badge for your repo up to date:

```md
[![Plumber Score](https://score.getplumber.io/github.com/OWNER/REPO.svg)](https://score.getplumber.io/github.com/OWNER/REPO)
```

For a GitLab project, use `gitlab.com/GROUP/PROJECT` in place of `github.com/OWNER/REPO`.

Score push makes your score and repository name public, works in CI only, and is off by default when the input is omitted. See the [score docs](https://getplumber.io/docs/plumber-score).

## Configuration

Plumber reads `.plumber.yaml`; without one, the built-in default applies.

```bash
plumber config init       # create one interactively
plumber config generate   # write the full commented default template
plumber config validate
plumber explain ISSUE-411
```

Example:

```yaml
version: "2.0"

github:
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
      trustedOwners:
        - actions
        - github

gitlab:
  controls:
    containerImageMustNotUseForbiddenTags:
      enabled: true
```

Extend the baseline with `extends: plumber:default` and list only what you change; new controls Plumber ships then appear automatically. Full reference: [`defaultConfig/.plumber.yaml`](./defaultConfig/.plumber.yaml) and [getplumber.io/docs/cli](https://getplumber.io/docs/cli).

## Controls

A few of the checks Plumber runs:

- **Unpinned actions and images:** a third-party action or container image referenced by a tag that can be moved to other code.
- **Remote scripts piped into a shell:** `curl | bash` and similar, running code nobody reviewed.
- **Unprotected default branch:** anyone with push access can change what gets built and released.
- [See all controls](https://getplumber.io/docs/use-plumber/controls)

## Outputs

| Output | Flag | Use it for |
|---|---|---|
| Terminal | default | Human review during local or CI runs |
| JSON | `--output results.json` | Automation and dashboards |
| SARIF | `--sarif results.sarif` | GitHub Code Scanning and SARIF tools |
| GitLab SAST | `--glsast gl-sast-report.json` | GitLab Security Dashboard / MR widget |
| CSV | `--csv results.csv` | Spreadsheets, ad-hoc analysis |
| OCSF | `--ocsf plumber.ocsf.json` | OCSF consumers and GRC platforms |
| PBOM | `--pbom pbom.json` | Pipeline inventory |
| CycloneDX | `--pbom-cyclonedx cdx.json` | SBOM tooling |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Score meets the gate (`--min-points` / `--min-score`), or `--no-controls` was used and collection succeeded |
| `1` | Score is below the gate |
| `2` | Invalid usage or configuration, or a runtime / provider / auth / network failure |
| `3` | Data collection was incomplete, so the score is withheld; or a check could not be verified and `--fail-warnings` is set (e.g. an action version that could not be resolved) |

## Contributing

```bash
make build
make test
```

Contributing guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)

## Resources

- Website: [getplumber.io](https://getplumber.io)
- Documentation: [getplumber.io/docs/cli](https://getplumber.io/docs/cli), with troubleshooting in the [GitHub](https://getplumber.io/docs/cli/github#troubleshooting) and [GitLab](https://getplumber.io/docs/cli/gitlab#troubleshooting) guides
- Community: [Discord](https://discord.gg/932xkSU24f), or [tech@getplumber.io](mailto:tech@getplumber.io)
- GitHub Action listing: [Plumber Score](https://github.com/marketplace/actions/plumber-score)
- GitLab component listing: [CI/CD Catalog](https://gitlab.com/explore/catalog/getplumber/plumber)
- Security policy: [`SECURITY.md`](./SECURITY.md)

## License

Plumber is licensed under the [Mozilla Public License 2.0](LICENSE).
