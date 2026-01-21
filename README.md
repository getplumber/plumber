# 🔧 Plumber

Find compliance issues in your GitLab repositories and their CI/CD pipelines.

## 🎯 What it does

Plumber scans your GitLab CI/CD configuration and run following controls:

- 🏷️ **Mutable image tags** — Flags `latest`, `dev`, and other non-reproducible tags for container images used in CI/CD pipelines
- 🔒 **Untrusted image registries** — Ensures container images used in your CI/CD pipelines come from approved sources
- 🛡️ **Branch protection compliance** — Verifies that repository branches are properly protected
- Other controls will come

## 🚀 Quick Start (GitLab CI)

**1. Add your token**

Go to **Settings → CI/CD → Variables** and add:
- Name: `GITLAB_TOKEN`
- Scopes: `read_api`, `read_repository`

**2. Add to `.gitlab-ci.yml`**

```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@~latest
```

✅ That's it! Plumber runs on MRs, main branch, and tags.

> 💡 Everything is customizable — GitLab URL, branch, threshold, and more. See [Customize](#️-customize) below.

### ⚠️ Self-Hosted GitLab

If you're running a self-hosted GitLab instance, you'll need to create your own component since `gitlab.com` components can't be accessed from your instance.

**Option 1:** Fork our [GitLab component](https://gitlab.com/getplumber/plumber) to your instance

**Option 2:** Create a component using [`templates/analyze.yml`](templates/analyze.yml) as a base

See [GitLab's CI/CD component documentation](https://docs.gitlab.com/ee/ci/components/) for setup instructions.

## ⚙️ Customize

Override any input to fit your needs:

```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@~latest
    inputs:
      # Target (defaults to current project)
      server_url: https://gitlab.example.com  # Self-hosted GitLab
      project_path: other-group/other-project # Analyze a different project
      branch: develop                         # Analyze a specific branch

      # Compliance
      threshold: 80                           # Minimum % to pass (default: 100)
      config_file: $CI_PROJECT_DIR/.plumber.yaml  # Custom config from your repo

      # Output
      output_file: plumber-report.json        # Export JSON report
      print_output: true                      # Print to stdout (default: true)

      # Job behavior
      stage: test                             # Run in a different stage (default: .pre)
      allow_failure: true                     # Don't block pipeline on failure
      gitlab_token: $MY_CUSTOM_TOKEN          # Use a different token variable
```

### All Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `server_url` | `$CI_SERVER_URL` | GitLab instance URL |
| `project_path` | `$CI_PROJECT_PATH` | Project to analyze |
| `branch` | `$CI_COMMIT_REF_NAME` | Branch to analyze |
| `gitlab_token` | `$GITLAB_TOKEN` | CI/CD variable with the API token |
| `threshold` | `100` | Minimum compliance % to pass |
| `config_file` | `/.plumber.yaml` | Path to configuration file |
| `output_file` | `""` | Path to write JSON results |
| `print_output` | `true` | Print text output to stdout |
| `stage` | `.pre` | Pipeline stage for the job |
| `image` | `getplumber/plumber:0.1` | Docker image to use |
| `allow_failure` | `false` | Allow job to fail without blocking |

## 💻 Test Locally (CLI)

```bash
# Run analysis
docker run --rm \
  -e GITLAB_TOKEN=glpat-xxxx \
  getplumber/plumber:latest analyze \
  --gitlab-url https://gitlab.com \
  --project mygroup/myproject \
  --branch main \
  --config /.plumber.yaml \
  --threshold 100

# Save JSON output locally
docker run --rm \
  -e GITLAB_TOKEN=glpat-xxxx \
  -v $(pwd):/output \
  getplumber/plumber:latest analyze \
  --gitlab-url https://gitlab.com \
  --project mygroup/myproject \
  --branch main \
  --config /.plumber.yaml \
  --threshold 100 \
  --output /output/results.json
```

Or build from source:

```bash
git clone https://github.com/getplumber/plumber.git
cd plumber
go build -o plumber .

export GITLAB_TOKEN=glpat-xxxx
./plumber analyze \
  --gitlab-url https://gitlab.com \
  --project mygroup/myproject \
  --branch main \
  --config .plumber.yaml \
  --threshold 100
```

## 📋 Example Output

```
=== Pipeline Analysis Results ===

Project: mygroup/myproject

--- Mutable Image Tag Control ---
  Compliance: 50.0%
  Issues Found:
    - Job 'build' uses mutable tag 'latest' (image: docker.io/node:latest)

--- Untrusted Image Control ---
  Compliance: 100.0%
  Trusted: 8, Untrusted: 0

--- Branch Protection Control ---
  Compliance: 100.0%
  Protected: 2, Unprotected: 0

=== Summary ===
  Overall Compliance: 83.3%
  Threshold: 100.0%
  Status: FAILED ✗
```

## 📝 Configuration

Create a `.plumber.yaml` in your repo to customize controls:

```yaml
version: "1.0"

controls:
  imageMutable:
    enabled: true
    mutableTags:
      - latest
      - dev

  imageUntrusted:
    enabled: true
    trustDockerHubOfficialImages: true
    trustedUrls:
      - registry.gitlab.com/*
      - $CI_REGISTRY_IMAGE:*

  branchProtection:
    enabled: true
    defaultMustBeProtected: true
    namePatterns:
      - main
      - release/*
```

See [`.plumber.yaml`](.plumber.yaml) for the full reference with all options.

## 🔍 CLI Reference

```
plumber analyze [flags]

Flags:
  --gitlab-url    GitLab instance URL (required)
  --project       Project path, e.g., group/project (required)
  --config        Path to .plumber.yaml (required)
  --threshold     Minimum compliance % to pass (required)
  --branch        Branch to analyze (default: project default)
  --output        Write JSON results to file
  --print         Print text output (default: true)

Environment:
  GITLAB_TOKEN    GitLab API token (required)

Exit Codes:
  0  Passed (compliance ≥ threshold)
  1  Failed (compliance < threshold or error)
```

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `GITLAB_TOKEN environment variable is required` | Add `GITLAB_TOKEN` in CI/CD Variables |
| `401 Unauthorized` | Token should have `read_api` + `read_repository` scopes |
| `403 Forbidden` on MR settings | Expected on non-Premium GitLab; continues without that data |

## 📄 License

[Elastic License 2.0 (ELv2)](LICENSE) — Free to use. Cannot be offered as a managed service.

