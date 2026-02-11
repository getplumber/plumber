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
├── control/                   # Compliance controls (evaluation logic)
│   ├── types.go               # AnalysisResult + all result/metric types
│   ├── task.go                # RunAnalysis() orchestrator
│   └── control*.go            # Individual control implementations
│
├── collector/                 # Data collection from GitLab APIs
│   └── dataCollection*.go     # Pipeline origin, image, protection data
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

#### Key Files for Contributors

- **Adding/modifying a control**: Look at an existing `control/control*.go` file as a template. Each control has a conf struct, result struct, and `Run()` method.
- **Data collection**: If a control needs more data, the `collector/` package is responsible for gathering it from GitLab and passing it to controls. All actual GitLab API calls (REST and GraphQL) live in the `gitlab/` package — collectors use those, controls never call the API directly.
- **Configuration changes**: Update `configuration/plumberconfig.go` for the Go types, `.plumber.yaml` for the default config, and `internal/defaultconfig/default.yaml` will be regenerated by `make build`.
- **Expression parser**: `configuration/expression.go` handles the `required` field syntax (e.g., `component/a AND component/b OR component/c`). See `configuration/expression_test.go` for [examples](https://github.com/getplumber/plumber/blob/main/configuration/expression_test.go).
- **CLI output**: `cmd/analyze.go` contains the text output formatting (tables, colors).

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
