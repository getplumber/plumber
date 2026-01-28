# Contributing to Plumber

Thank you for your interest in contributing to Plumber! This guide will help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
  - [Reporting Issues](#reporting-issues)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Setup](#development-setup)
- [Coding Conventions](#coding-conventions)
- [Commit Conventions](#commit-conventions)
- [Review Process](#review-process)

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

3. **Test your changes**:
   ```bash
   go test ./...
   go build -o plumber .
   ```

4. **Commit your changes** following our [commit conventions](#commit-conventions)

5. **Push to your fork**:
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
- Git
- A GitLab token with `read_api` + `read_repository` scopes (for testing)

### Building

```bash
# Build the binary
go build -o plumber .

# Run tests
go test ./...

# Run with verbose output
./plumber analyze --verbose \
  --gitlab-url https://gitlab.com \
  --project your-group/your-project \
  --config .plumber.yaml \
  --threshold 100
```

### Project Structure

```
plumber/
├── cmd/              # CLI commands (cobra)
├── collector/        # Data collection from GitLab
├── configuration/    # Config loading and validation
├── control/          # Compliance controls logic
├── gitlab/           # GitLab API client (REST + GraphQL)
├── templates/        # GitLab CI component template
├── .plumber.yaml     # Default configuration
└── main.go           # Entry point
```

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
- `output` - CLI output formatting
- `log` - Logging
- `docs` / `readme` - Documentation

### Examples

```
feat(controls): add support for MR approval rules

fix(analysis): resolve variable expansion in nested includes

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
   - Builds successfully (`go build .`)
   - Passes tests (`go test ./...`)
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
- Reach out to maintainers

Thank you for contributing to Plumber!
