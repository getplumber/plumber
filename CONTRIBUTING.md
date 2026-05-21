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
│   ├── analyze.go             # plumber analyze
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
├── collector/                 # Data collection + external enrichment
│   ├── dataCollection*.go     # Pipeline origin, image, protection data (GitLab API)
│   ├── github_*.go            # Workflow file parsing + GitHub API enrichment
│   └── gitleaks_scan.go       # Example external-binary enrichment (writes to pipeline.GitleaksHits)
│
├── internal/ir/               # The provider-agnostic IR every rego rule reads from
│   └── pipeline.go            # NormalizedPipeline, Job, Action, GitleaksHit, ... types
│
├── control/                   # Bookkeeping (NOT detection — that lives in policies/)
│   ├── types.go               # AnalysisResult + result/metric types
│   ├── codes.go               # ISSUE code → severity / title / control name registry
│   ├── catalog.go             # Per-provider control catalog (display order, skip flags)
│   ├── task.go                # RunAnalysis() orchestrator
│   └── controlGitlab*.go      # LEGACY Go controls (pre-Rego migration, being phased out)
│
├── gitlab/                    # GitLab API client (REST + GraphQL)
│   ├── client.go              # HTTP client with retry + token masking
│   ├── project.go             # Project details fetching
│   ├── models.go              # Data models
│   ├── utils.go               # Pattern matching, version comparison
│   └── utilsCI.go             # CI config parsing, variable resolution
│
├── utils/                     # Shared utilities
│   ├── gitremote.go           # Auto-detect GitLab URL/project from git remote
│   └── hash.go                # FNV-1a hashing
│
├── internal/
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

> **Heads-up:** legacy controls live in `control/controlGitlab*.go` as Go functions with `Run()` methods. **Do not add new controls that way.** Detection logic for every new control belongs in a Rego rule under `policies/*.rego`. The `control/` package is now purely bookkeeping (codes registry, catalog, output wiring). The legacy Go controls are being phased out as their Rego ports land.

The current pattern splits the work into three layers — **data** (collector + IR), **rule** (Rego), **wiring** (Go bookkeeping + output + docs). The checklist below walks every wire that needs to be hooked up for a new control to ship correctly: terminal output, JSON output, PBOM/CDX enrichment, compliance calculation, `--skip-controls` / `--controls` filters, `plumber config validate`, the bench gate, and docs. Skipping a step is how PRs end up with "tests pass but the terminal doesn't render the new stat block" or "JSON looks right but `--skip-controls` silently doesn't work for this control."

You can hand this checklist to an LLM (Claude Code, Cursor, Copilot) and ask it to implement step by step, ticking each box as it goes — every step names the specific file(s) and the concrete reference example to model on. Mark a step **N/A** in your PR description if it genuinely doesn't apply (e.g. you didn't need PBOM enrichment).

### 1. Data layer (collector + IR)

- [ ] **IR field** — if your rule needs data the IR doesn't already carry, add the field to `internal/ir/pipeline.go` on the right struct (`NormalizedPipeline`, `Job`, `Action`, …) with a JSON tag and a comment explaining what populates it.
- [ ] **Collector enrichment** — if the field needs external input (GitLab API, GitHub API, an external binary like gitleaks), add the collector code:
  - GitLab API → extend the appropriate `collector/dataCollectionGitlab*.go` or write a new collector file. All actual GitLab API calls live in `gitlab/`; collectors USE that, never call the API directly.
  - GitHub workflow YAML parsing → extend `collector/github_workflows.go`.
  - GitHub API enrichment → extend or add a sibling to `collector/github_metadata.go`.
  - External binary (gitleaks-style) → write `collector/<tool>_scan.go` modelled on `collector/gitleaks_scan.go`. Redact any sensitive payload BEFORE it reaches the IR (the raw secret value must never leave the collector).
- [ ] **Wiring** — call the collector from `control/task.go`'s `RunGitlabAnalysis` or the equivalent GitHub flow, after the pipeline is built and before the rego engine runs.

### 2. Rule layer (Rego)

- [ ] **Write the rule** — `policies/<rule_name>.rego`. Pattern:
  ```rego
  package <rule_name>
  import rego.v1
  deny contains finding if {
      input.config.<controlName>           # opt-in gate (use {} or check a specific field)
      # ... data read from input.pipeline.* ...
      finding := {
          "code":     "ISSUE-XXX",
          "severity": "critical|high|medium|low",
          "message":  sprintf("...", [...]),
          # rule-specific fields (job, uses, line, ...)
      }
  }
  ```
  Compact templates: `policies/leaked_secrets.rego`, `policies/excessive_permissions.rego`, `policies/action_archived_repo.rego`.
- [ ] **Test the rule** — `policies/rules_test.go` with at least 3 sub-tests per rule (positive, negative, abstain-when-config-absent). Mirror `TestIssue301_LeakedSecrets` or `TestIssue108_ActionArchivedRepo`. Hand-built `ir.NormalizedPipeline` fixtures are fine; no filesystem needed for most rules.

### 3. Codes registry

- [ ] **ISSUE code constant** — `control/codes.go`, in the relevant const block (1xx supply chain, 2xx variables, 3xx secrets, 4xx composition, 5xx access, 6xx hygiene). Pick the next free number in the right range.
- [ ] **Registry entry** — `errorCodeRegistry` map entry with `Code`, `Severity`, `Title`, `Description`, `Remediation`, `DocURL: docsBaseURL + string(...)`, and `ControlName` (must match the control name you'll use in `.plumber.yaml` and `configuration/registry.go`).

### 4. Config plumbing (`.plumber.yaml` schema + Go types)

- [ ] **`validControlSchema` entry** — `configuration/plumberconfig.go`, list the valid sub-keys (`enabled`, plus any rule-specific options like `forbiddenVariables`, `gitleaksPath`, …). Missing this entry makes `plumber config validate` emit "Unknown control".
- [ ] **`ControlsConfig` struct field** — same file, add a pointer field with the YAML tag matching your control name. Use the shared `EnabledOnlyControlConfig` for config-free rules, or define a typed `<Name>ControlConfig` struct for rules with parameters. Include an `IsEnabled()` method on any new struct.
- [ ] **Optional getter** — `Get<Name>Config()` helper on `PlumberConfig` if downstream code needs ergonomic access.
- [ ] **Alphabetised test list** — `configuration/plumberconfig_test.go`, add the control name to the `expected` slice in `TestValidControlNames`. **This is the most-forgotten step** — the test fails loudly if you skip it.
- [ ] **`v1_to_v2.go`** (GitLab controls only) — add the field to both `controlsConfigIsZero` and `controlsConfigEqual`. Lets legacy v1 schema users auto-migrate without dropping your control.

### 5. Control catalog + provider registry

- [ ] **`controlsMeta` entry** — `configuration/registry.go`, declare which providers (`ProviderGitLab` / `ProviderGitHub` / both) the control applies to.
- [ ] **`GitLabControls` or `GitHubControls` entry** — `control/catalog.go`, add a `ControlEntry` with `DisplayName`, `ControlName`, and `Skipped` (derived from the cfg's `IsEnabled()`).
- [ ] **`DisabledControlNames` entry** — same file, contributes to the `--controls` / `--skip-controls` filter logic.

### 6. Bench gate (only if NOT ready to ship)

- [ ] If your rule is in early development (missing fixtures, uncertain false-positive rate, depends on collector work not yet landed) — add it to `configuration/registry.go::benchedControls` under the right provider, with a comment explaining why. Benched rules are loaded by the engine but their findings are dropped before reaching the user (see `control/bench_filter.go`).
- [ ] **Promotion criteria for unbenching:** substantive rule + ≥3 fixtures + docs. Remove the bench entry, ship as default-on or default-off as the README's `<details>` block specifies.

### 7. Output: terminal stat block

- [ ] **`cmd/render_details.go`** — add a `case "<controlName>":` in `buildGitLabControlStats` (GitLab) or `buildGitHubControlStats` (GitHub) that returns `[]statLine` with the per-control metrics (jobs/lines/refs checked, findings counted, etc.). Without this, the control shows up in the compliance table at the bottom but has no `── header ── stats body ──` block during the terminal scroll.
- [ ] If your stats need a new `GitHubAnalysisStats` field (GitHub side) — add it in `control/types.go` and populate it in `control/github_stats.go::AggregateGitHubStats`. GitLab side reads directly off the IR / findings list, no aggregator.

### 8. Output: JSON `*Result` block

- [ ] **`cmd/legacy_json.go`** (GitLab) or `cmd/legacy_json_github.go` (GitHub) — add a `case "<controlName>":` returning `("<resultKey>", build<Name>Block(common, result, findings))`. Pattern for the builder: see `buildDebugTraceBlock`, `buildSecretsLeakBlock`.
- [ ] Block shape (consistent across every control): `issues`, `metrics`, `compliance`, `version`, `ciValid`, `ciMissing`, `skipped`.

### 9. Output: PBOM + CycloneDX (ONLY if your control affects inventory)

- [ ] **PBOM Include enrichment** — if your control marks per-action or per-image attributes (`archived: true`, `hasCve: true`, `forbiddenTag: true`, …):
  - Add the field to `pbom/types.go` on the relevant struct.
  - Populate in `pbom/generate_github.go::processGitHubIncludes` (or the GitLab equivalent) from the compliance lookup data.
  - Document the new field in `docs/PBOM.md`.
- [ ] **`GitHubComplianceData` (or `ImageComplianceData`)** — add a lookup map field in `pbom/generate_github.go` / `pbom/generate.go`.
- [ ] **Harvest into the lookup** — `cmd/analyze_github.go::buildGitHubPBOMCompliance` (or the GitLab equivalent) — read the relevant finding code from `result.Findings`, populate the lookup map.
- [ ] **CycloneDX property** — `pbom/cyclonedx.go`, add a `plumber:<your-field>` property entry on the relevant component. Document in `docs/PBOM.md`.
- [ ] If your control does NOT touch inventory (most don't — it's mostly relevant for action/image-specific controls), explicitly mark this step N/A in the PR description.

### 10. Default config (`.plumber.yaml`) + embed

- [ ] **`.plumber.yaml`** — add a `<controlName>:` block under the right provider section (`gitlab.controls.*` or `github.controls.*`) with `enabled: true|false` and any parameters, each with an inline comment explaining what it does. Use the banner-comment style other blocks use (`# ===` header lines).
- [ ] **`make embed`** regenerates `internal/defaultconfig/default.yaml` from the source `.plumber.yaml`. Don't edit the generated file directly; it'll be overwritten on the next build.

### 11. CLI filter flags (`--controls` / `--skip-controls`)

- [ ] **Test the filter** — once the catalog entry from §5 is in place, both flags work automatically through `control.MarkSkippedByFilter` + the JSON path's `legacyResultsByName(..., includeOnly, skip)` wiring. Smoke check: `./plumber analyze --skip-controls <yourControl>` then verify the JSON `<resultKey>.skipped: true`.

### 12. Config validation (`plumber config validate`)

- [ ] **Validate** with `./plumber config validate -c .plumber.yaml` — should pass cleanly with the new control present. If it emits "Unknown control" or "Unknown sub-key", you missed the `validControlSchema` entry from §4.
- [ ] If you added a typed config struct (§4) — `plumber config view` should display the new section correctly without crashing on nil values.

### 13. Compliance + score

- [ ] **Per-control compliance** is binary today: 100 when the control's findings list is empty, 0 when ≥1 finding. Computed in `cmd/analyze.go` (GitLab) / `cmd/analyze_github.go` (GitHub). No new code needed — the catalog entry from §5 hooks your control in automatically.
- [ ] **Severity scoring** (`--score` / `--score-point`) — the severity assigned in §3 (`ErrorCodeInfo.Severity`) automatically contributes to the score. Critical findings can trigger the "Critical malus" (cap at 30 points); see `docs/scoring.md`.
- [ ] **Threshold gating** (`--threshold`) — already covered by the orchestrator. Smoke check: enable your control, introduce a violation, run `./plumber analyze --threshold 100` and verify it exits non-zero.

### 14. Tests + lint

- [ ] **`make embed && make test && make lint`** — every gate must pass before commit.
- [ ] Rego tests in `policies/rules_test.go` (§2).
- [ ] Collector tests in `collector/*_test.go` (§1) if you added enrichment.
- [ ] **Manual smoke** — write a fixture that triggers your rule, run `./plumber analyze`, eyeball:
  - Terminal: control's section appears with the stat block (§7).
  - Terminal: finding is listed under "Issues Found" with code, severity, doc URL.
  - JSON `--output`: `<resultKey>` block populated correctly (§8).
  - Compliance table at the bottom: row for the control with the right percentage and colour.
  - PBOM `--pbom` / CDX `--pbom-cyclonedx`: enrichment fields present (§9), if applicable.

### 15. Documentation

- [ ] **`README.md`** — bump the control count (GitLab / GitHub total in the "Available Controls" intro), add a `<details>` block describing the control, add a row in the "Valid control names" table at the bottom.
- [ ] **`docs/PBOM.md`** — only if you added PBOM enrichment (§9).
- [ ] **`docs/scoring.md`** — only if your control's severity or contribution changes the score formula.
- [ ] **Release announcement** — maintainers update `docs/release-announcement-*.md` at release time; you don't need to.
- [ ] **Website** — if `getplumber.io` is in scope for this change, add the control to `src/data/issues.ts` (with the right `gitlab` / `github` sub-block(s)) and to `src/docs/data/docs/en/use-plumber/controls.mdx` in the right provider tab + section.

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
