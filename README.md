# Plumber - Trust Policy Manager for GitLab CI/CD

A command-line tool and GitLab CI/CD component for analyzing GitLab pipelines and enforcing trust policies on third-party components, images, and branch protections.

---

## CLI

### What This Service Does

Plumber analyzes GitLab projects to enforce security and compliance policies across your CI/CD pipelines. It performs the following checks:

| Control | Description |
|---------|-------------|
| **Mutable Image Tags** | Detects jobs using Docker images with mutable tags (e.g., `latest`, `dev`). Mutable tags make builds non-reproducible and can introduce security vulnerabilities when the underlying image changes unexpectedly. |
| **Untrusted Images** | Identifies jobs using Docker images from untrusted registries. Only images from explicitly approved sources should be used to prevent supply chain attacks. |
| **Branch Protection** | Verifies that critical branches (main, release/*, etc.) have proper protection settings including force push restrictions, code owner approvals, and access level requirements. |

The CLI outputs:
- **Text report** to stdout (human-readable)
- **JSON report** to file (machine-readable, for integrations)
- **Exit code** indicating pass/fail based on a configurable compliance threshold

### Requirements

#### GitLab Instance
- GitLab.com or self-hosted GitLab instance (CE/EE)
- API access enabled on the instance

#### GitLab Token
A GitLab Personal Access Token (PAT) or Project/Group Access Token with the following scopes:

| Scope | Required | Purpose |
|-------|----------|---------|
| `read_api` | **Yes** | Read project configuration, CI/CD variables, branches, and protection rules |
| `read_repository` | **Yes** | Read `.gitlab-ci.yml` and included files |

> **Note:** The CLI performs **read-only** operations. No write access is required.

**Creating a token:**
1. Navigate to **Settings → Access Tokens** (User/Project/Group)
2. Select scopes: `read_api`, `read_repository`
3. Set an appropriate expiration date
4. Copy the generated token

#### Configuration File
A `conf.r2.yaml` configuration file is **required**. This file defines:
- Which controls are enabled
- Control-specific settings (mutable tags list, trusted registries, branch patterns)

See [`conf.r2.yaml`](conf.r2.yaml) for a complete example with documentation.

The Docker image includes a default configuration at `/conf.r2.yaml`.

### Installation

#### From Source
```bash
git clone https://github.com/getplumber/plumber.git
cd plumber
go build -o plumber .
```

#### Using Docker
```bash
docker pull getplumber/plumber:latest
```

### Usage

#### Basic Usage

```bash
# Set the token via environment variable
export R2_GITLAB_TOKEN=glpat-xxxxxxxxxxxx

# Analyze a project
plumber analyze \
  --gitlab-url https://gitlab.com \
  --project mygroup/myproject \
  --config conf.r2.yaml \
  --threshold 100
```

#### Command Reference

```
plumber analyze [flags]

Required Flags:
  --gitlab-url    GitLab instance URL (e.g., https://gitlab.com)
  --project       Full path of the project to analyze (e.g., mygroup/myproject)
  --config        Path to conf.r2.yaml configuration file
  --threshold     Minimum compliance percentage to pass (0-100)

Optional Flags:
  --branch        Branch to analyze (defaults to project's default branch)
  --print         Print text output to stdout (default: true)
  --output, -o    Write JSON results to file
  --verbose, -v   Enable debug logging

Environment Variables:
  R2_GITLAB_TOKEN GitLab API token (required)
```

#### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Analysis passed (compliance ≥ threshold) |
| `1` | Analysis failed (compliance < threshold or error) |

### Use Cases

#### 1. Local Development Check
Run before pushing changes to verify your pipeline configuration:

```bash
export R2_GITLAB_TOKEN=glpat-xxxx

plumber analyze \
  --gitlab-url https://gitlab.com \
  --project mygroup/myproject \
  --branch feature/my-branch \
  --config conf.r2.yaml \
  --threshold 100
```

#### 2. CI/CD Gate (Pass/Fail)
Enforce 100% compliance in your pipeline:

```bash
plumber analyze \
  --gitlab-url $CI_SERVER_URL \
  --project $CI_PROJECT_PATH \
  --branch $CI_COMMIT_REF_NAME \
  --config /conf.r2.yaml \
  --threshold 100
```

#### 3. Compliance Audit with JSON Export
Generate a detailed report for auditing or processing:

```bash
plumber analyze \
  --gitlab-url https://gitlab.com \
  --project mygroup/myproject \
  --config conf.r2.yaml \
  --threshold 0 \
  --print=false \
  --output audit-report.json
```

#### 4. Gradual Compliance Adoption
Start with a lower threshold and increase over time:

```bash
# Week 1: 50% threshold
plumber analyze --threshold 50 ...

# Week 2: 75% threshold  
plumber analyze --threshold 75 ...

# Week 3+: 100% threshold
plumber analyze --threshold 100 ...
```

#### 5. Multi-Project Analysis (Script)
Analyze multiple projects in a loop:

```bash
#!/bin/bash
PROJECTS=("group/project1" "group/project2" "group/project3")

for project in "${PROJECTS[@]}"; do
  echo "Analyzing $project..."
  plumber analyze \
    --gitlab-url https://gitlab.com \
    --project "$project" \
    --config conf.r2.yaml \
    --threshold 100 \
    --output "reports/${project//\//_}.json"
done
```

### Example Output

```
=== Pipeline Analysis Results ===

Project: mygroup/myproject
CI Valid: true
CI Missing: false

--- Pipeline Origin Metrics ---
  Total Jobs: 12
  Hardcoded Jobs: 2
  Total Origins: 5
    - Components: 3
    - Local: 1
    - Template: 1
  GitLab Catalog Resources: 2

--- Pipeline Image Metrics ---
  Total Images: 8

--- Mutable Image Tag Control ---
  Version: 0.2.0
  Compliance: 0.0%
  Total Images: 8
  Using Mutable Tags: 2

  Issues Found:
    - Job 'build' uses mutable tag 'latest' (image: docker.io/node:latest)
    - Job 'test' uses mutable tag 'dev' (image: myregistry.com/app:dev)

--- Untrusted Image Control ---
  Version: 0.1.0
  Compliance: 100.0%
  Total Images: 8
  Trusted: 8
  Untrusted: 0

--- Branch Protection Control ---
  Version: 0.2.0
  Compliance: 100.0%
  Total Branches: 5
  Branches to Protect: 2
  Protected Branches: 2
  Unprotected: 0
  Non-Compliant: 0

=== Summary ===
  Overall Compliance: 66.7%
  Threshold: 100.0%
  Status: FAILED ✗
```

---

## GitLab Component

### Overview

Plumber is available as a GitLab CI/CD Component, enabling easy integration into any GitLab project with minimal configuration.

**Component Location:** `templates/analyze.yml`

### Prerequisites

1. **Set the GitLab Token as a CI/CD Variable:**
   - Navigate to **Settings → CI/CD → Variables**
   - Add a variable named `R2_GITLAB_TOKEN`
   - Value: Your GitLab API token with `read_api` and `read_repository` scopes
   - Options: Enable **Mask variable** (recommended), optionally **Protect variable**

### Basic Usage

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@1.0.0
```

This will:
- Run in the `test` stage
- Analyze the current project and default branch
- Use the default configuration at `/conf.r2.yaml` bundled in the Docker image
- Require 100% compliance (fail the job if not met)
- Print results to the job log

### With Custom Inputs

```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@1.0.0
    inputs:
      # Lower the threshold for gradual adoption
      threshold: 80
      
      # Export results to a JSON artifact
      output_file: compliance-report.json
      
      # Use a custom config file from your repository
      config_file: $CI_PROJECT_DIR/conf.r2.yaml
      
      # Allow the job to fail without failing the pipeline
      allow_failure: true
```

### Input Reference

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `gitlab_token` | string | `$R2_GITLAB_TOKEN` | CI/CD variable containing the GitLab API token |
| `project_path` | string | `$CI_PROJECT_PATH` | Project to analyze |
| `default_branch` | string | `$CI_DEFAULT_BRANCH` | Branch to analyze |
| `server_url` | string | `$CI_SERVER_URL` | GitLab instance URL |
| `config_file` | string | `/conf.r2.yaml` | Path to configuration file (in container) |
| `threshold` | number | `100` | Minimum compliance percentage (0-100) |
| `print_output` | boolean | `true` | Print text output to job log |
| `output_file` | string | `""` | Path to write JSON results (empty = skip) |
| `stage` | string | `test` | Pipeline stage for the job |
| `image` | string | `getplumber/plumber:latest` | Docker image to use |
| `allow_failure` | boolean | `false` | Allow job to fail without failing pipeline |

### Examples

#### Minimal Setup (Strictest)
```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@1.0.0
```

#### Custom Configuration from Repository
```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@1.0.0
    inputs:
      config_file: $CI_PROJECT_DIR/conf.r2.yaml
```

> **Note:** The path must be accessible in the container. Use `$CI_PROJECT_DIR/conf.r2.yaml` to reference a config file in your repository root.

#### Generate Artifact for Compliance Dashboard
```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@1.0.0
    inputs:
      threshold: 0  # Don't fail, just report
      output_file: plumber-results.json
      allow_failure: true
```

#### Different Thresholds per Branch
```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@1.0.0
    inputs:
      threshold: 100
    rules:
      - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

include:
  - component: gitlab.com/getplumber/plumber/analyze@1.0.0
    inputs:
      threshold: 75
      allow_failure: true
    rules:
      - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

#### Using a Custom Token Variable
```yaml
include:
  - component: gitlab.com/getplumber/plumber/analyze@1.0.0
    inputs:
      gitlab_token: $MY_ANALYSIS_TOKEN
```

### Pipeline Behavior

The component runs on:
- **Merge request pipelines** (`merge_request_event`)
- **Default branch commits** (when `CI_COMMIT_BRANCH == CI_DEFAULT_BRANCH`)

To customize when the job runs, override the rules in your pipeline or use `allow_failure` for non-blocking analysis.

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `R2_GITLAB_TOKEN environment variable is required` | Ensure the `R2_GITLAB_TOKEN` CI/CD variable is set in your project settings |
| `401 Unauthorized` | Verify the token has `read_api` and `read_repository` scopes and hasn't expired |
| `403 Forbidden` on MR approval settings | This is expected for non-Premium GitLab instances; the control continues without this data |
| Job fails but pipeline should continue | Set `allow_failure: true` in the inputs |
| Need to analyze a different project | Override `project_path` input with the target project's path |

---

## Configuration Reference

See [`conf.r2.yaml`](conf.r2.yaml) for the complete configuration file with inline documentation.

### Quick Reference

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
    allowForcePush: false
    codeOwnerApprovalRequired: false
    minMergeAccessLevel: 30
    minPushAccessLevel: 40
```

---

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
