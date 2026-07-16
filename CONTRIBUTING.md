# Contributing to Plumber

Thank you for your interest in contributing to Plumber! This guide will help you get started.

## Table of Contents

- [AI Usage Policy](#ai-usage-policy)
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
  - [Reporting Issues](#reporting-issues)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Setup](#development-setup)
  - [Prerequisites](#prerequisites)
  - [Building](#building)
  - [Make Targets](#make-targets)
  - [Running Locally](#running-locally)
  - [Running Tests](#running-tests)
  - [Project Structure](#project-structure)
- [Adding a New Control](#adding-a-new-control)
- [Adding a New Provider](#adding-a-new-provider)
- [Coding Conventions](#coding-conventions)
- [Commit Conventions](#commit-conventions)
- [Review Process](#review-process)

## AI Usage Policy

If you use AI tools (e.g. Cursor, Claude Code, Copilot) to contribute to Plumber, please read our [AI Usage Policy](AI_POLICY.md) first. All AI usage must be disclosed, and AI-assisted pull requests must reference an accepted issue and be fully verified by a human.

## Code of Conduct

Please be respectful and constructive in all interactions. We're building this together.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/plumber.git
   cd plumber
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/getplumber/plumber.git
   ```

## How to Contribute

### Reporting Issues

Before opening an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Use a clear, descriptive title**
3. **Provide as much context as possible**:
   - Plumber version (`plumber --version`)
   - GitLab version (if relevant)
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs (use `--verbose` flag)

#### Issue Types

- **Bug Report**: Something isn't working as expected
- **Feature Request**: Suggest a new feature or enhancement
- **Question**: Ask for help or clarification

### Submitting Pull Requests

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following our [coding conventions](#coding-conventions)

3. **Build and test your changes**:
   ```bash
   make build
   make test
   make lint
   ```

4. **Commit your changes** following our [commit conventions](#commit-conventions)

5. **Push**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request** against `main` with:
   - A clear title and description
   - Reference to related issues (e.g., "Fixes #123")
   - Screenshots/output examples if applicable
   - **"Allow edits from maintainers" enabled** (checked by default on GitHub). This lets maintainers push fixes or rebases directly to your branch, which speeds up the review process.

## Development Setup

### Prerequisites

- Go 1.25 or later
- Make
- Git
- A GitLab token with `read_api` + `read_repository` scopes (for testing against a real project)

### Building

Always use `make build` instead of `go build` directly. The Makefile embeds the default `.plumber.yaml` configuration into the binary (required for `plumber config generate` to work):

```bash
make build
```

This runs two steps:
1. Copies `.plumber.yaml` into `internal/defaultconfig/default.yaml` (with a build header)
2. Compiles the Go binary

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Embed config + build binary |
| `make build-all` | Cross-compile for Linux, macOS, and Windows |
| `make test` | Embed config + run all tests |
| `make lint` | Embed config + lint code |
| `make run` | Embed config + `go run .` (quick dev iteration) |
| `make install` | Build + install to `/usr/local/bin/` |
| `make clean` | Remove binary and generated `default.yaml` |

### Running Locally

**View configuration** (no GitLab token needed — useful for testing config changes):

```bash
# View the default config
./plumber config view

# View a custom config file
./plumber config view --config my-test.yaml

# Generate a default config file
./plumber config generate --output test-config.yaml
```

**Run analysis** (requires a GitLab token):

```bash
export GITLAB_TOKEN=glpat-xxxx

# Auto-detect from git remote
./plumber analyze

# Specify project explicitly
./plumber analyze --gitlab-url https://gitlab.com --project mygroup/myproject

# With debug output
./plumber analyze --verbose

# Lower threshold for testing
./plumber analyze --threshold 50

# Save JSON output
./plumber analyze --output results.json
```

### Running Tests

```bash
# Run all tests
make test

# Run tests for a specific package
go test ./configuration/ -v

# Run a specific test
go test ./configuration/ -run TestParseRequiredExpression -v
```

The expression parser (`configuration/expression_test.go`) has comprehensive test coverage for the `required` expression syntax. If you're working on expression parsing, run those tests frequently:

```bash
go test ./configuration/ -v -count=1
```

#### Fuzz Testing

The project includes Go fuzz tests for the expression parser and the git remote URL parser. These exercise the parsers with random inputs to catch panics, crashes, and unexpected behavior.

```bash
# Run fuzz tests (default 10s each)
go test -fuzz=FuzzParseRequiredExpression ./configuration/ -fuzztime=30s
go test -fuzz=FuzzParseGitRemoteURL ./utils/ -fuzztime=30s
```

If a fuzz test finds a crash, Go saves the failing input in `testdata/fuzz/` inside the package directory. These corpus entries are committed to the repo so the regression is covered by `go test` going forward.

### Project Structure

```
plumber/
├── main.go                    # Entry point
├── Makefile                   # Build, test, install targets
├── .plumber.yaml              # Source-of-truth default configuration
│
├── cmd/                       # CLI commands (Cobra)
│   ├── root.go                # Root command + global flags
│   ├── analyze_shared.go      # Provider-agnostic analyze core
│   ├── analyze_gitlab.go      # plumber analyze (GitLab entrypoint)
│   ├── analyze_github.go      # plumber analyze (GitHub entrypoint)
│   ├── config.go              # plumber config view / generate
│   └── version.go             # plumber version
│
├── configuration/             # Config loading, types, and validation
│   ├── configuration.go       # Runtime Configuration struct
│   ├── plumberconfig.go       # PlumberConfig YAML schema + loading
│   ├── expression.go          # Boolean expression parser (required field)
│   └── expression_test.go     # Expression parser tests
│
├── policies/                  # Rego rules (where detection logic lives)
│   ├── *.rego                 # One file per rule, emits findings for one or more ISSUE codes
│   └── rules_test.go          # In-process OPA evaluation against hand-built or fixture pipelines
│
├── internal/ir/               # The provider-agnostic IR every rego rule reads from
│   └── pipeline.go            # NormalizedPipeline, Job, Action, Dockerfile, ... types
│
├── control/                   # Bookkeeping (NOT detection — that lives in policies/)
│   ├── types.go               # AnalysisResult + result/metric types
│   ├── codes.go               # ISSUE code → severity / title / control name registry
│   ├── catalog.go             # Per-provider control catalog (display order, skip flags)
│   ├── task.go                # RunAnalysis() orchestrator (GitLab)
│   └── task_github.go         # RunGitHubAnalysis() orchestrator (GitHub)
│
├── provider/                  # Provider abstraction: the Provider interface + adapters
│   ├── provider.go            # Provider interface + registry
│   ├── gitlab.go              # GitLabProvider adapter (wires the gitlab/ package)
│   └── github.go              # GitHubProvider adapter (wires the github/ package)
│
├── gitlab/                    # GitLab: API client (REST + GraphQL) + data collection + IR
│   ├── client.go              # HTTP client with retry + token masking
│   ├── project.go             # Project details fetching
│   ├── models.go              # Data models
│   ├── dataCollectionGitlab*.go # Pipeline origin, image, protection collectors
│   ├── gitlab_ir.go           # Projection of collected data onto internal/ir
│   ├── utils.go               # Pattern matching, version comparison
│   └── utilsCI.go             # CI config parsing, variable resolution
│
├── github/                    # GitHub: workflow parsing, metadata/API enrichment + IR
│   ├── github_workflows.go    # Workflow YAML parsing → IR
│   ├── github_workflows_remote.go # Remote workflow fetch (GitHub API)
│   ├── github_metadata.go     # Repo metadata / Advisory DB enrichment (REST via go-gh)
│   ├── github_branch_protection.go # Branch protection rules fetch
│   └── github_repo_artifacts.go # Dockerfile bases, dependabot config scan
│
├── pbom/                      # Pipeline Bill of Materials generation
│   ├── types.go               # PBOM schema types (JSON + CycloneDX)
│   ├── generate.go            # GitLab PBOM builder
│   ├── generate_github.go     # GitHub PBOM builder
│   └── builders.go            # Shared compliance/override data builders
│
├── utils/                     # Shared utilities (no CLI or provider dependency)
│   ├── pipeline.go            # HasDigestPin, CleanOriginPath, FoldDockerHubAliasInName
│   ├── gitremote.go           # Auto-detect GitLab URL/project from git remote
│   └── hash.go                # FNV-1a hashing
│
├── internal/
│   ├── ir/                    # Provider-agnostic IR (already listed above)
│   ├── engine/opa/            # OPA/Rego rule engine wrapper
│   │   └── engine.go          # Loads policies, evaluates them, returns []Finding
│   └── defaultconfig/         # Embedded default config (generated by make build)
│       ├── embed.go           # go:embed directive
│       └── default.yaml       # Auto-generated — do not edit directly
│
└── templates/
    └── plumber.yml            # GitLab CI component template
```

#### Other key files

- **Expression parser:** `configuration/expression.go` handles the `required` field syntax (e.g., `component/a AND component/b OR component/c`). See `configuration/expression_test.go` for [examples](https://github.com/getplumber/plumber/blob/main/configuration/expression_test.go).
- **CLI output:** `cmd/render_details.go` + `cmd/legacy_json.go` for the GitLab path, `cmd/legacy_json_github.go` for the GitHub path.
- **GitLab API client:** all REST/GraphQL calls live in `gitlab/`. Collectors use these; rules never call the API directly.

## Adding a New Control

> **Architecture:** detection logic lives in Rego rules under `policies/*.rego`; the `control/` package is purely bookkeeping (codes registry, catalog, output wiring). The pre-Rego Go-function pattern (the historical `control/controlGitlab*.go` layer) has been fully phased out — every shipped control is now a Rego rule.

A new control is **detection in one Rego file + ~15 wires** through the Go layer to make sure the finding appears in every output (terminal, JSON, SARIF, GLSAST, PBOM where applicable), the control is configurable via `.plumber.yaml`, the `--controls` / `--skip-controls` flags work, the `config init` wizard knows about it, and the docs (in-repo + website) describe it.

The checklist below walks every wire. Skipping a step is how PRs end up with "tests pass but the terminal doesn't render the new stat block", "JSON looks right but `--skip-controls` silently doesn't work for this control", or "the website docs are wrong for one provider". Each step names:
- The **file path(s)** to edit
- A **reference example** from an existing control to model on
- A **code snippet** showing the shape of the change

You can hand this checklist to an LLM (Claude Code, Cursor, Copilot) and ask it to implement step by step, ticking each box as it goes. Mark a step **N/A** in your PR description if it genuinely doesn't apply (e.g. you did not need PBOM enrichment, or your control is GitLab-only).

### Files-touched cheatsheet

For a typical "new GitHub-side control with simple `enabled` config, no new IR field, no PBOM enrichment":

| Layer | Files |
|---|---|
| **Rule** | `policies/<rule>.rego`, `policies/rules_test.go`, `policies/testdata/ISSUE-XXX/{github,gitlab}/*.yml` |
| **Codes** | `control/codes.go` |
| **Config schema** | `configuration/plumberconfig.go`, `configuration/plumberconfig_test.go` |
| **Provider registry** | `configuration/registry.go` (controlsMeta, optional benchedControls) |
| **Catalog** | `control/catalog.go` (GitLabControls / GitHubControls, DisabledControlNames) |
| **Stats** (GitHub only) | `control/types.go`, `control/github_stats.go` |
| **Terminal** | `cmd/render_details.go` |
| **JSON** | `cmd/legacy_json.go` (GitLab) or `cmd/legacy_json_github.go` (GitHub) |
| **Default config** | `.plumber.yaml` (then `make embed`) |
| **Init wizard** | `cmd/init.go`, `cmd/init_test.go` |
| **Docs in-repo** | `README.md`, `docs/GITHUB_ISSUES.md` (GitHub side), `docs/PBOM.md` (if applicable), `docs/scoring.md` (if severity changes) |
| **Website** | `getplumber.io/src/data/issues.ts` (per-provider sub-blocks), the relevant `cli/<provider>/index.mdx` if the control needs a tutorial section |

For a control with **new IR data** also touch: `internal/ir/pipeline.go` plus the relevant collector under `gitlab/` (GitLab) or `github/` (GitHub). For **inventory-touching controls** (action/image attributes) also touch: `pbom/types.go`, `pbom/generate*.go`, `pbom/cyclonedx.go`, `cmd/analyze*.go::buildPBOMCompliance`.

### 1. Data layer (collector + IR)

Skip if your rule only reads fields the IR already exposes (jobs, scripts, triggers, permissions, action `uses`, image refs, …).

- [ ] **IR field** — `internal/ir/pipeline.go`. Add the field to the right struct (`NormalizedPipeline`, `Job`, `Action`, `Dockerfile`, …) with a JSON tag and a comment explaining what populates it. Every Rego rule reads from `input.pipeline.*`, so this is the contract.
  ```go
  // Job is the provider-agnostic view of a single CI/CD job.
  type Job struct {
      Name string `json:"name"`
      // ...
      // YourNewField is populated by gitlab/<collector>.go or
      // github/<collector>.go from <data source>; empty when <degraded condition>.
      YourNewField []YourType `json:"yourNewField,omitempty"`
  }
  ```
- [ ] **Collector enrichment** — where the data comes from determines which file:
  - **GitLab API** → extend `gitlab/dataCollectionGitlab*.go` or write a new collector file in `gitlab/`. All REST/GraphQL calls live in `gitlab/`; collectors USE that, never call the API directly.
  - **GitHub workflow YAML parsing** → extend `github/github_workflows.go`.
  - **GitHub repo metadata / Advisory DB / archived flag etc.** → extend `github/github_metadata.go` (REST via `go-gh`) — reference: `advisoriesForRepo`, `resolveCommitToTag`.
  - **Repo-artifact scan** (Dockerfile bases, dependabot config) → extend `github/github_repo_artifacts.go`.

  Plumber deliberately executes **no external binaries** during analysis (see #310) — collectors are API calls, YAML parsing, and on-disk file reads only.
- [ ] **Wiring** — call the collector from `control/task.go`'s `RunAnalysis` (GitLab) or `control/task_github.go`'s `RunGitHubAnalysis` (GitHub), after the pipeline is built and before the rego engine runs.

### 2. Rule layer (Rego)

- [ ] **Write the rule** — `policies/<rule_name>.rego`. Pattern:
  ```rego
  # <rule-name> — one-paragraph description of what is flagged and why.
  # Document any false-positive guards and trust mechanisms here.
  package <rule_name>

  import rego.v1

  deny contains finding if {
      some i, j
      job := input.pipeline.jobs[i]
      # ... read from input.pipeline.*, input.config.<controlName>.* ...
      finding := {
          "code":     "ISSUE-XXX",
          "severity": "critical|high|medium|low",
          "message":  sprintf("Job %q ...", [job.name]),
          "job":      job.name,
          # rule-specific fields surface in JSON / SARIF via the generic
          # Finding shape — anything you add here lands in result.Findings[*].Data
      }
  }
  ```
  **Reference rules** by complexity:
  - simplest (no parameters, single pattern): `policies/artipacked.rego`
  - parametrized (reads from `input.config.<controlName>.*`): `policies/excessive_permissions.rego`, `policies/dangerous_triggers.rego`
  - with helpers + FP guards (regex, quote-stripping, exemptions): `policies/unverified_scripts.rego`, `policies/template_injection.rego`
- [ ] **Engine input shape** — the OPA engine receives `{"pipeline": <NormalizedPipeline>, "config": <controlsCfg>}`. The `config` block is built by `control/task.go` / `control/task_github.go` from the user's `.plumber.yaml` — see the `cfg["<controlName>"] = map[string]any{...}` blocks. If your control needs parameters in Rego, add them to the corresponding `cfg[...]` builder.

### 3. Test fixtures + rego tests

- [ ] **Fixtures** — `policies/testdata/ISSUE-XXX/{github,gitlab}/*.yml`. Conventions:
  - GitLab fixtures: `<job-name>.gitlab-ci.yml` shape (raw GitLab CI YAML).
  - GitHub fixtures: GitHub Actions workflow YAML.
  - Naming: `violation_<descriptor>.yml` (positive cases) and `clean_<descriptor>.yml` (negative cases). One scenario per file keeps test names readable.
  - Add a top-of-file comment explaining what the fixture proves and the expected hit count.
- [ ] **Test function** — `policies/rules_test.go`. Use the existing helpers:
  ```go
  func TestIssueXXX_<Name>(t *testing.T) {
      // GitLab
      runGitLabPolicyCases(t, "ISSUE-XXX", []policyCase{
          {"violation_<X>.gitlab-ci.yml", []string{"<expected job name>"}},
          {"violation_<Y>.gitlab-ci.yml", []string{"<job1>", "<job2>"}},
          {"clean_<Z>.gitlab-ci.yml", nil},
      }, nil)
  }

  // GitHub-side, in a second function:
  func TestIssueXXX_<Name>_GitHub(t *testing.T) {
      runGitHubFixtureCases(t, "ISSUE-XXX", []struct {
          fixture      string
          expectedHits []string
      }{
          {"violation_<X>.yml", []string{"<workflow>/<job>"}},
          {"clean_<Z>.yml", nil},
      })
  }
  ```
  **Minimum cases:** positive (violation fires), negative (clean does not fire), abstain (control disabled / config empty — engine returns no findings).
- [ ] **Reference test patterns**:
  - hand-built IR fixtures (no filesystem): `TestIssue301_LeakedSecrets`
  - GitLab fixture-based: `TestIssue411_UnverifiedScripts`
  - GitHub fixture-based: `TestIssue411_UnverifiedScripts_GitHub`, `TestIssue207_TemplateInjection`
  - regression case for a specific bug fix: add a `clean_<bug>.yml` that the rule incorrectly flagged before the fix and lock it in.

### 4. Codes registry

- [ ] **ISSUE code constant** — `control/codes.go`, in the relevant const block. Number ranges:
  - `1xx` supply chain (image tags, action pinning, archived repos, CVEs)
  - `2xx` expressions & injections (template injection, env-injection, debug trace)
  - `3xx` secrets / credentials / permissions
  - `4xx` triggers & composition (unverified scripts, dangerous triggers, DinD)
  - `5xx` access & authorisation
  - `6xx` workflow hygiene (anonymous, concurrency, obfuscation, dependabot)
  - `7xx` reserved for GitHub-specific supply-chain
  - `8xx` reserved for GitHub-specific triggers
  - `9xx` reserved for repo / dependabot artefacts
  Pick the next free number; existing assignments live in the constants block at the top of `codes.go`.
- [ ] **Registry entry** — `errorCodeRegistry` map entry:
  ```go
  CodeYourThing: {
      Code:        CodeYourThing,
      Severity:    SeverityCritical, // or High / Medium / Low
      Title:       "Short title for terminal + reports",
      Description: "Longer one-paragraph description of what triggers this and why it matters.",
      Remediation: "How to fix it. Be specific.",
      DocURL:      docsBaseURL + string(CodeYourThing),
      ControlName: "<controlName>", // MUST match .plumber.yaml key + registry.go entry
  },
  ```

### 5. Config plumbing (`.plumber.yaml` schema + Go types)

- [ ] **`validControlSchema` entry** — `configuration/plumberconfig.go`. Lists the valid sub-keys; missing this entry makes `plumber config validate` emit "Unknown control".
  ```go
  var validControlSchema = map[string][]string{
      // ...
      "yourControlName": {"enabled", "yourParam1", "yourParam2"},
  }
  ```
- [ ] **`ControlsConfig` struct field** — same file. Use the shared `EnabledOnlyControlConfig` for config-free rules, or define a typed `<Name>ControlConfig` for parametrized ones:
  ```go
  // Inside ControlsConfig:
  YourControlName *YourControlConfig `yaml:"yourControlName,omitempty"`

  // Typed config struct (when you need parameters):
  type YourControlConfig struct {
      Enabled    *bool    `yaml:"enabled,omitempty"`
      ParamList  []string `yaml:"yourParam1,omitempty"`
  }

  func (c *YourControlConfig) IsEnabled() bool {
      return c == nil || c.Enabled == nil || *c.Enabled
  }
  ```
- [ ] **Optional getter** — `Get<Name>Config()` on `PlumberConfig` if downstream code benefits from ergonomic access (rare).
- [ ] **`TestValidControlNames` entry** — `configuration/plumberconfig_test.go`. Add your control name **alphabetically** to the `expected` slice. **This is the most-forgotten step.** The test fails loudly if you skip it but only on `make test`, not on `go build`.
- [ ] **`v1_to_v2.go`** (GitLab controls only) — add the field to both `controlsConfigIsZero` and `controlsConfigEqual`. Lets legacy v1 schema users auto-migrate without dropping your control during the upgrade. GitHub-only controls skip this step.

### 6. Provider registry + control catalog

- [ ] **`controlsMeta` entry** — `configuration/registry.go`. Declares which providers the control applies to:
  ```go
  var controlsMeta = map[string]ControlMeta{
      // ...
      "yourControlName": {Providers: []string{ProviderGitLab, ProviderGitHub}}, // or one of them
  }
  ```
- [ ] **`GitLabControls` and/or `GitHubControls` entry** — `control/catalog.go`. Each provider has its own catalog function returning `[]ControlEntry`:
  ```go
  // In GitHubControls:
  entries = append(entries, ControlEntry{
      DisplayName: "Your control (terminal-friendly title)",
      ControlName: "yourControlName",
      Skipped:     c.YourControlName == nil || !c.YourControlName.IsEnabled(),
  })
  ```
- [ ] **`DisabledControlNames` entry** — same file, contributes to the `--controls` / `--skip-controls` filter:
  ```go
  if cfg := c.YourControlName; cfg == nil || !cfg.IsEnabled() {
      out["yourControlName"] = true
  }
  ```

### 7. Bench gate (only if NOT ready to ship)

- [ ] If your rule is in early development (missing fixtures, uncertain false-positive rate, depends on collector work not yet landed) — add it to `configuration/registry.go::benchedControls` under the right provider, with a comment explaining why. Benched rules are loaded by the engine but their findings are dropped before reaching the user (see `control.FilterFindingsByEnabledControls` in `control/catalog.go`).
  ```go
  var benchedControls = map[string]map[string]struct{}{
      ProviderGitHub: {
          // ...
          "yourControlName": {}, // WIP — needs <X> before unbenching
      },
  }
  ```
- [ ] **Promotion criteria for unbenching:** substantive rule + ≥3 fixtures (positive, negative, edge case) + docs in-repo + website docs + parity with the other provider if cross-provider. Remove the bench entry, ship as default-on or default-off as `.plumber.yaml` specifies.

### 8. Stats aggregation (GitHub side only)

GitLab reads metrics directly off the IR / findings list at render time, no aggregator. GitHub uses an aggregator because the IR is normalised differently — stats fields are pre-computed and rendered from a struct.

- [ ] **`control/types.go`** — add the metric field(s) to `GitHubAnalysisStats`:
  ```go
  type GitHubAnalysisStats struct {
      // ...
      // Your new metric. Populated by AggregateGitHubStats (denominator)
      // and ApplyGitHubFindingCounts (numerator).
      YourMetricFound int
  }
  ```
- [ ] **`control/github_stats.go`** — `AggregateGitHubStats` populates the denominator (total jobs / lines / refs your control scanned). `ApplyGitHubFindingCounts` then walks `result.Findings` once after Rego evaluation and increments the per-control counters from each finding's `Code`. Both must be updated if your control surfaces a "X of Y" ratio in the terminal.

### 9. Output: terminal stat block

- [ ] **`cmd/render_details.go`** — add a `case "<controlName>":` in `buildGitLabControlStats` (GitLab) or `buildGitHubControlStats` (GitHub) that returns `[]statLine`:
  ```go
  case "yourControlName":
      return []statLine{
          {"Jobs Checked", fmt.Sprintf("%d", stats.JobsTotal)},
          {"Your Metric Found", fmt.Sprintf("%d", stats.YourMetricFound)},
      }
  ```
  Without this case, the control still appears in the bottom compliance table but has no `── header ── stats body ──` block in the scrolling output, which looks broken next to siblings that do.
- [ ] If your control's terminal section needs a custom rendering (e.g. grouped findings, a sub-table), extend `cmd/render_details.go` with a `buildYourControlBlock` helper called from the case above.

### 10. Output: JSON `*Result` block

- [ ] **`cmd/legacy_json.go`** (GitLab) or `cmd/legacy_json_github.go` (GitHub) — add a `case "<controlName>":` returning `("<resultKey>", build<Name>Block(common, result, findings))`:
  ```go
  case "yourControlName":
      return "yourControlResult", buildYourControlBlock(common, result, findings)
  ```
- [ ] **Builder function** — same file. Reference: `buildDebugTraceBlock`, `buildUnverifiedScriptsBlockGitHub`. Block shape (consistent across every control):
  ```go
  func buildYourControlBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
      s := statsOf(result)
      return map[string]any{
          "issues":     projectFindings(findings, c.URLEscape, "job"),
          "metrics":    map[string]any{ /* per-control metrics */ },
          "compliance": c.Compliance,
          "version":    c.Version,
          "ciValid":    c.CIValid,
          "ciMissing":  c.CIMissing,
          "skipped":    c.Skipped,
      }
  }
  ```
- [ ] **SARIF + GLSAST** — **no per-control wiring needed.** Both formats iterate `result.Findings` generically: `cmd/sarif.go` emits one `sarifResult` per finding with rule metadata from `control.LookupCode`, and `cmd/glsast.go` emits one `glsastVuln` per finding. The clickable URL (`properties.url` in SARIF, `links[]` in GLSAST) is populated automatically by the location linker (§13) — your control inherits it.

### 11. Output: PBOM + CycloneDX (ONLY if your control affects inventory)

Skip unless your control marks per-action or per-image attributes (`archived`, `hasCve`, `forbiddenTag`, …). Most behavioural controls do not touch inventory — explicitly mark this section N/A in the PR description if so.

- [ ] **PBOM Include enrichment** — `pbom/types.go`. Add the field to the relevant struct (typically `Include`):
  ```go
  type Include struct {
      // ...
      YourAttr bool `json:"yourAttr,omitempty"`
  }
  ```
- [ ] **`GitHubComplianceData` (or `ImageComplianceData`)** — add a lookup map field in `pbom/generate_github.go` / `pbom/generate.go`.
- [ ] **Harvest into the lookup** — `cmd/analyze_github.go::buildGitHubPBOMCompliance` (or the GitLab equivalent) — read the relevant finding code from `result.Findings`, populate the lookup map keyed by action ref or image ref.
- [ ] **Populate the field** — `pbom/generate_github.go::processGitHubIncludes` (or GitLab equivalent) — at include-build time, read the lookup map and set the field on each `Include`.
- [ ] **CycloneDX property** — `pbom/cyclonedx.go`. Add a `plumber:<your-field>` property entry on the relevant component.
- [ ] **Document the new fields** — `docs/PBOM.md`. Both the JSON field on `Include` and the CycloneDX property; readers consume the PBOM as a contract, so the doc IS the spec.

### 12. Default config (`.plumber.yaml`) + embed

- [ ] **`.plumber.yaml`** — add a `<controlName>:` block under the right provider section (`gitlab.controls.*` or `github.controls.*`):
  ```yaml
  # ===========================================
  # Your control display name
  # ===========================================
  # One-paragraph explanation of what this control flags and why.
  # Cover any non-obvious config knobs and the threat model.
  #
  # Best practice: <one-liner>
  yourControlName:
    # Set to false to disable this control
    enabled: true
    # Optional parameter — explain what it does
    yourParam: []
  ```
  Use the banner-comment style other blocks use (`# ===` header lines). Keep config keys and the explanation in sync with the rego rule's actual behaviour.
- [ ] **`make embed`** regenerates `internal/defaultconfig/default.yaml` from the source `.plumber.yaml`. **Don't edit the generated file directly** — it's overwritten on every build.

### 13. Source links (location linker — automatic)

No work to do, but worth knowing: every finding's `file` + `line` is decorated with a clickable URL by `cmd/location_link.go::Annotate(findings)` before any output writer runs. In CI it's a forge blob URL anchored to the analysed commit; locally it's an absolute `<path>:<line>` reference. The terminal, results.json `url` field, SARIF `properties.url`, and GLSAST `links[]` all inherit this for free as long as your rule emits `File` and `Line` on the finding.

If your rule emits a finding without `File` and `Line` (e.g. project-level controls like `branchMustBeProtected`), the URL stays empty — no broken links. Worth setting if you can pinpoint a location.

### 14. Init wizard (`plumber config init`)

The wizard is a **separate code path** from `.plumber.yaml`. It generates a curated minimal config based on user answers; it does NOT read `.plumber.yaml`. So every new control needs a parallel update here, or `config init` silently produces a config missing your control.

- [ ] **`cmd/init.go`** — add the relevant lines for your control:
  - If it belongs to a composition / category menu item (e.g. "Security scanning", "Variables"), update `compositionOptionsForProviders` to include your control in that group, and the corresponding emit block in `toPlumberConfig`.
  - If it has provider-specific defaults that differ from `.plumber.yaml`, add a dedicated field to `initWizardState`, a prompt with the right `Default:`, and the emit branch.
  - The starter config emitted on "minimal" answer is built by `starterPlumberConfig` — make sure it gets your default values for the provider(s) this control applies to.
- [ ] **`cmd/init_test.go`** — parity guards. `TestStarterGitHubControlsMatchEmbeddedDefault` and `TestDefaultTrustedURLsMatchEmbeddedDefault` are the existing ones; extend them or add a new one if your control has a default the test framework cannot infer.

### 15. CLI filter flags (`--controls` / `--skip-controls`)

- [ ] **No code needed** — once the catalog entry from §6 is in place, both flags work automatically through `control.MarkSkippedByFilter` + the JSON path's `legacyResultsByName(..., includeOnly, skip)` wiring.
- [ ] **Smoke check**:
  ```bash
  ./plumber analyze --controls yourControlName              # only this fires
  ./plumber analyze --skip-controls yourControlName         # all others fire
  ```
  Verify the JSON `yourControlResult.skipped: true` for skipped, the section is fully populated for included.

### 16. Config validation (`plumber config validate`)

- [ ] **Validate** with `./plumber config validate -c .plumber.yaml` — should pass cleanly with the new control present. If it emits "Unknown control" or "Unknown sub-key", you missed the `validControlSchema` entry from §5.
- [ ] If you added a typed config struct — `plumber config view` should display the new section correctly without crashing on nil values.

### 17. Compliance + score

- [ ] **Per-control compliance** is binary today: 100% when the control's findings list is empty, 0% when ≥1 finding. Computed automatically — the catalog entry from §6 hooks your control in.
- [ ] **Severity scoring** (`--score` / `--score-point`) — the severity from §4's `ErrorCodeInfo.Severity` automatically contributes. Critical findings can trigger the "critical malus" (cap at 30 points); see `docs/scoring.md`.
- [ ] **Threshold gating** (`--threshold`) — orchestrator-level, no per-control work. Smoke check: enable your control, introduce a violation, run `./plumber analyze --threshold 100` and verify non-zero exit.

### 18. Tests + lint

- [ ] **`make embed && make test && make lint`** — every gate must pass before commit.
- [ ] Rego tests in `policies/rules_test.go` (§3).
- [ ] Collector tests in `gitlab/*_test.go` / `github/*_test.go` (§1) if you added enrichment.
- [ ] Init wizard tests in `cmd/init_test.go` (§14).
- [ ] **Manual smoke** — write a fixture that triggers your rule, run `./plumber analyze`, eyeball:
  - **Terminal**: control's section appears with the stat block (§9).
  - **Terminal**: finding is listed under "Issues Found" with code, severity, doc URL, and a clickable `↳ at <url>` (§13).
  - **JSON `--output`**: `yourControlResult` block populated correctly (§10); each finding has a `url` field.
  - **SARIF `--sarif`**: one `sarifResult` per finding with `ruleId: ISSUE-XXX`, `properties.url`, repo-relative `artifactLocation.uri`.
  - **GLSAST `--glsast`**: one `vulnerability` per finding with `identifiers[].value: ISSUE-XXX` and a `links[].url`.
  - **Compliance table at the bottom**: row for the control with the right percentage and colour.
  - **PBOM `--pbom`** / **CDX `--pbom-cyclonedx`**: enrichment fields present (§11), if applicable.

### 19. Documentation

- [ ] **`README.md`** — update the count in the "Available Controls" intro (`X GitLab controls` / `Y GitHub controls`), add a `<details>` block describing the control with bad / good YAML examples, add a row in the "Valid control names" table at the bottom.
- [ ] **`docs/GITHUB_ISSUES.md`** (GitHub controls only) — add a TOC row under the right severity-category section (1xx/2xx/3xx/4xx/5xx/6xx), then a detailed `## ISSUE-XXX — <rule-name>` section with: severity + control name banner, threat model paragraph, bad/good YAML examples, FP guards if any, config snippet. Reference: the ISSUE-411 section we added during the Megalodon work.
- [ ] **`docs/PBOM.md`** — only if you added PBOM enrichment (§11). Document both the JSON field and the CycloneDX property.
- [ ] **`docs/scoring.md`** — only if your control's severity or contribution changes the score formula. Adding a new control at an existing severity does not require an update.
- [ ] **Website — `getplumber.io/src/data/issues.ts`**. Each `ISSUE-XXX` entry has up to two sub-blocks keyed by provider:
  ```typescript
  "ISSUE-XXX": {
      code: "ISSUE-XXX",
      gitlab: {  // only if the control applies to GitLab
          title: "...",
          category: "...",      // "Pipeline Composition", "CI/CD Variables", etc.
          severity: "high",
          fixDuration: "medium",
          controlName: "...",
          controlConfigKey: "yourControlName",
          productScope: "cli",
          description: "...",   // 1-3 sentences
          impact: "...",        // why it matters / blast radius
          remediation: "...",   // how to fix
          badExample: `...`,    // .gitlab-ci.yml YAML demonstrating the violation
          badExampleCaption: "...",
          goodExample: `...`,
          goodExampleCaption: "...",
          tips: ["...", "..."], // bullet points
          relatedCodes: ["ISSUE-YYY"],
      },
      github: { /* same shape, GitHub-flavored examples */ },
  }
  ```
  Add both `gitlab` and `github` blocks for cross-provider controls. Update tutorial sections in `src/docs/data/docs/en/cli/<provider>/index.mdx` if the control needs walk-through coverage (most don't).
- [ ] **Release announcement** — maintainers update `docs/release-announcement-*.md` and the corresponding `getplumber.io/src/data/blog/en/release-cli-*` post at release time; contributors don't need to.

## Adding a New Provider

> **Architecture:** every CI platform is modelled as a `provider.Provider`
> (interface in `provider/provider.go`). The analyze command resolves the
> active provider through a global registry (`provider.Get(name)`) and
> delegates all platform-specific work to it, so the shared pipeline
> (compliance, rendering, artifacts) stays provider-agnostic. There is no
> `if gitlab { … } else if github { … }` switch to extend — you register a
> new implementation and it plugs in.

Two layers are involved:

- **`<provider>/`** — the raw logic package (data collection, API client,
  IR projection). It knows nothing about the abstraction; it just produces
  data and projects it onto `internal/ir.NormalizedPipeline`. Mirror
  `gitlab/` or `github/`.
- **`provider/<provider>.go`** — the **adapter** that implements the
  `Provider` interface by orchestrating the raw package + `control/` +
  `pbom/`. This is the file that satisfies the contract.

### Checklist

- [ ] **Raw logic package** — create `<provider>/` (e.g. `bitbucket/`):
  collect the pipeline from the platform's API or checked-out files and
  project it onto `internal/ir.NormalizedPipeline` (add a `ToNormalizedPipeline`
  equivalent). Add a `Provider` constant in `internal/ir/pipeline.go` if the
  platform needs one. All HTTP/API calls live here, never in `provider/` or
  Rego.
- [ ] **Adapter** — create `provider/<provider>.go` with a
  `type <Name>Provider struct{}` implementing every method of the `Provider`
  interface (`provider/provider.go`): `Name`, `Controls`, `ComputeCompliance`,
  `Run`, `RunRemote` (return `ErrNoRemote` if unsupported), `WritePBOM`,
  `WritePBOMCycloneDX`, `PostAnalysisActions` (return `nil` if none),
  `BlobURLInfix`, `CIEnvVars`. Use `provider/gitlab.go` / `provider/github.go`
  as templates.
- [ ] **Register** — add an `init()` in the adapter that calls
  `Register(&<Name>Provider{})`. Registration is what makes `provider.Get("<name>")`
  resolve; the analyze command needs nothing else.
- [ ] **Orchestrator** — add a `Run<Name>Analysis(conf)` in `control/`
  (mirror `RunAnalysis` / `RunGitHubAnalysis`) that builds the IR, runs the
  Rego engine, and returns an `AnalysisResult`. The adapter's `Run` calls it.
- [ ] **Control catalog** — add a `<Name>Controls(pc)` in `control/catalog.go`
  (with a `<name>ControlSpecs` table) listing the controls the provider ships,
  in display order. The adapter's `Controls` returns it.
- [ ] **Control applicability** — declare each applicable control under the
  new provider in `configuration/registry.go` (`controlsMeta`, using a
  `provider<Name>` constant). Gate not-yet-ready controls via `benchedControls`.
- [ ] **Config schema** — add a `<Name> *ProviderConfig` field in
  `configuration/plumberconfig.go` and wire it into `ProviderConfig(name)` /
  `ControlsFor(name)` in `configuration/v1_to_v2.go` so `<name>.controls:`
  works in `.plumber.yaml`.
- [ ] **Stats builder (optional)** — if the provider needs per-control stats
  blocks in the terminal output, register one via
  `provider.RegisterStatsBuilder("<name>", …)` from `cmd/analyze_shared.go`
  (kept in `cmd/` to avoid an import cycle).
- [ ] **CLI entry** — add `cmd/analyze_<provider>.go` resolving the provider
  with `provider.Get("<name>")` and driving the shared analyze flow.
- [ ] **Tests** — `<provider>/*_test.go` for the raw logic (incl. IR
  projection) and `provider/<provider>_test.go` for `ComputeCompliance`
  edge cases (see `provider/compliance_test.go`).
- [ ] **Rego rules** — reuse cross-provider policies where the concept maps;
  add provider-specific `policies/*.rego` only where it genuinely differs.

## Coding Conventions

### Go Style

- Follow standard [Go conventions](https://go.dev/doc/effective_go)
- Use `gofmt` to format code
- Use meaningful variable and function names
- Add comments for exported functions and complex logic
- Handle errors explicitly - don't ignore them

### Logging

- Use `logrus` for structured logging
- Include relevant context fields:
  ```go
  l := logrus.WithFields(logrus.Fields{
      "action":      "FunctionName",
      "projectPath": projectPath,
  })
  l.Info("Descriptive message")
  ```
- Use appropriate log levels:
  - `Debug`: Detailed info for troubleshooting
  - `Info`: General operational messages
  - `Warn`: Recoverable issues
  - `Error`: Failures that need attention

### Error Handling

- Return errors with context:
  ```go
  if err != nil {
      return fmt.Errorf("failed to fetch project: %w", err)
  }
  ```
- Log errors at the point where they're handled, not where they're created

### Configuration

When adding new fields to `.plumber.yaml`:

1. Add the Go struct field in `configuration/plumberconfig.go`
2. Add the field with YAML comments in `.plumber.yaml`
3. Run `make build` to regenerate `internal/defaultconfig/default.yaml`
4. Update `cmd/config.go` if the field needs special display handling in `config view`
5. Update the README control documentation

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/) with scopes. This enables automated releases via semantic-release.

### Format

```
<type>(<scope>): <description>
```

### Types and Release Impact

| Type | Description | Triggers Release? |
|------|-------------|-------------------|
| `feat` | New feature | ✅ Patch |
| `fix` | Bug fix | ✅ Patch |
| `perf` | Performance improvement | ✅ Patch |
| `refactor` | Code refactoring | ✅ Patch |
| `docs` | Documentation only | ❌ No |
| `style` | Formatting, whitespace | ❌ No |
| `test` | Adding/updating tests | ❌ No |
| `chore` | Maintenance, deps | ❌ No |
| `ci` | CI/CD changes | ❌ No |

**Breaking changes** (add `!` after type, e.g., `feat(api)!: remove endpoint`) trigger a **minor** release.

### Scopes

Use a scope that describes the area of change:

- `analysis` - Core analysis logic
- `controls` - Compliance controls
- `component` - GitLab CI component
- `conf` - Configuration handling
- `expr` - Expression parser
- `output` - CLI output formatting
- `log` - Logging
- `docs` / `readme` - Documentation

### Examples

```
feat(controls): add support for MR approval rules

fix(analysis): resolve variable expansion in nested includes

feat(expr): add NOT operator to required expression syntax

docs(readme): update token requirements

refactor(collector): extract image parsing into separate function

feat(component)!: change default threshold to 100

chore(deps): update go-gitlab to v0.100.0
```

### Guidelines

- Use imperative mood ("add" not "added")
- Keep the commit message under 72 characters
- Scope is encouraged but optional
- Reference issues in the PR description (not in commit messages)

## Review Process

1. **Before submitting**, ensure your code:
   - Builds successfully (`make build`)
   - Passes tests (`make test`)
   - Lints correctly (`make lint`)
   - Is formatted (`gofmt -w .`)

2. **Code review** by maintainers:
   - We aim to review PRs within a few days
   - Be open to feedback and iterate
   - Keep discussions focused and constructive

3. **Merge requirements**:
   - At least one maintainer approval
   - No unresolved conversations
   - Up-to-date with `main`

4. **After merge**:
   - Delete your feature branch
   - Semantic-release will automatically create a new version if your commit type triggers a release (see [Commit Conventions](#commit-conventions))

## Questions?

If you have questions about contributing, feel free to:

- Open a GitHub Discussion
- Ask in an issue
- [Join our Discord](https://discord.gg/932xkSU24f)

Thank you for contributing to Plumber!
