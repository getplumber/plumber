# Multi-Provider Refactor — Rego/OPA Rule Engine

> **Status:** Phases 0, 1, 2 and 4 complete (2026-04-23). Multi-provider plumbing validated: the same `image_mutable_tag` Rego policy runs unchanged against both the GitLab lab (solution/lab-12) and the GitHub lab (plumber-tests/lab-github-cicd). Next up: Phase 5 (more provider-specific rules).
> **Owner:** Stéphane Robert
> **Last updated:** 2026-04-23

This document is the working reference for the on-going refactor of Plumber
from a GitLab-only, Go-hardcoded rule engine toward a **multi-provider scanner
driven by Rego/OPA policies**. It is meant to be read by contributors (human
or AI) continuing the work across sessions.

---

## 1. Goals

1. **Support multiple CI/CD providers**: GitLab (current), GitHub Actions,
   and — later — Azure DevOps, Gitea, Bitbucket Pipelines.
2. **Replace the hardcoded Go control engine** with a Rego/OPA-based engine
   where each rule is a declarative policy file.
3. **Keep rules portable across providers** where the concept applies
   (mutable image tags, weakened security jobs, debug trace, DinD…).
4. **Let users add their own rules** without recompiling Plumber.
5. **Preserve the current UX**: same CLI, same JSON output shape (or a
   documented, versioned migration path).

## 2. Non-goals

- Replacing OPA with a home-grown DSL. OPA/Rego is a deliberate choice for
  ecosystem reasons (Conftest, Styra, tooling, learnability).
- Rewriting the GitLab API collector. It stays; only the rule-evaluation
  layer is rewritten.
- Scanning arbitrary YAML or Terraform. Scope stays on CI/CD pipelines.

## 3. Current architecture (as-is)

```text
cmd/analyze.go
    │
    ▼
collector/*              ← fetches & parses GitLab CI (API + local YAML)
    │
    ▼
control/controlGitlab*.go  ← ~15 hardcoded Go controls, each with typed result
    │
    ▼
AnalysisResult (control/types.go)
```

Pain points:

- Each rule = one Go file + its own result type + its own test suite.
- Every new rule requires a new release.
- No way for a user to contribute a rule without touching Go code.
- Multi-provider would currently mean duplicating all rules per provider.

## 4. Target architecture (to-be)

```text
                 ┌──────────────────────────────────────┐
 cmd/analyze →   │ Provider collectors (loaders)        │
                 │   - gitlab/   (existing, adapted)    │
                 │   - github/   (new)                  │
                 │   - azure/    (later)                │
                 └──────────────────┬───────────────────┘
                                    │  produces
                                    ▼
                 ┌──────────────────────────────────────┐
                 │ Normalized IR (internal/ir)          │
                 │   NormalizedPipeline {                │
                 │     Provider, Jobs[]{                 │
                 │       Image, Script[], Services[],    │
                 │       AllowFailure, When, Rules, …    │
                 │     },                                │
                 │     Includes[], Branches[], …         │
                 │   }                                   │
                 └──────────────────┬───────────────────┘
                                    │  evaluated by
                                    ▼
                 ┌──────────────────────────────────────┐
                 │ OPA engine (internal/engine/opa)     │
                 │   - embeds built-in policies          │
                 │   - loads user policies from path     │
                 │   - namespaces: data.plumber.{rule}  │
                 └──────────────────┬───────────────────┘
                                    │  emits
                                    ▼
                 ┌──────────────────────────────────────┐
                 │ Findings[] → existing reporter       │
                 │ (PBOM, JSON, terminal, MR comment)    │
                 └──────────────────────────────────────┘
```

Key properties:

- **Collectors** are provider-specific and do all I/O (API calls, YAML
  parsing, include resolution, version lookups). They emit the IR.
- **IR** is the single input format for all policies.
- **Policies** are `.rego` files grouped by concern, not by provider.
  A policy like `image_mutable_tag.rego` runs against any IR regardless of
  origin.
- **Engine** wraps OPA, handles policy discovery (embedded + user dir),
  catalog of rule metadata (severity, code, remediation link).

## 5. Normalized IR — first sketch

```go
// internal/ir/pipeline.go (to be created)

type Provider string

const (
    ProviderGitLab Provider = "gitlab"
    ProviderGitHub Provider = "github"
)

type NormalizedPipeline struct {
    Provider      Provider
    ProjectPath   string
    DefaultBranch string
    Jobs          []Job
    Includes      []Include
    Branches      []Branch
    Raw           map[string]any // provider-specific escape hatch
}

type Job struct {
    Name         string
    Image        *Image
    Services     []Image
    Scripts      []string
    AllowFailure bool
    When         string    // "on_success", "manual", "never", …
    Rules        []Rule
    Variables    map[string]string
    OriginFile   string    // file where the job is declared
    OriginKind   string    // "local", "remote", "component", "template"…
}

type Image struct {
    Name   string
    Tag    string
    Digest string // empty if not pinned
}

type Include struct {
    Kind    string // "local", "remote", "component", "template", "project"
    Ref     string // version/ref if applicable
    Source  string
    Current string // fetched "latest" ref for freshness checks (nullable)
}
```

The GitHub collector maps `jobs.<id>.runs-on`, `uses`, `with`, `container`
etc. to the same shape. The IR stays **lossy on purpose**: what doesn't fit
goes into `Raw` and can be used by provider-specific policies.

## 6. Policy layout — first sketch

```text
policies/
├── lib/
│   ├── image.rego         # helpers: parse_image(), is_mutable_tag()
│   └── job.rego           # helpers: is_security_scanner(), is_weakened()
├── image/
│   ├── mutable_tag.rego
│   ├── untrusted_registry.rego
│   └── pinned_by_digest.rego
├── pipeline/
│   ├── debug_trace.rego
│   ├── docker_in_docker.rego
│   ├── variable_injection.rego
│   ├── unverified_scripts.rego
│   └── hardcoded_jobs.rego
├── security/
│   └── weakened_scanners.rego
└── origin/
    ├── outdated_includes.rego
    └── forbidden_versions.rego
```

Every policy emits findings in a uniform shape:

```rego
package plumber.image.mutable_tag

import rego.v1

deny contains finding if {
    job := input.jobs[_]
    job.image.tag in {"latest", "dev", "master", "main"}
    finding := {
        "code":     "IMG-001",
        "severity": "high",
        "message":  sprintf("job %q uses mutable tag %q", [job.name, job.image.tag]),
        "job":      job.name,
        "file":     job.origin_file,
    }
}
```

A Go-side schema validates and enriches findings (severity catalog,
remediation URL, CWE references…) before they flow into the existing
reporter.

## 7. Design decisions (validated 2026-04-23)

<!-- markdownlint-disable MD060 -->
| #  | Decision                     | Chosen option |
| -- | ---------------------------- | ------------- |
| D1 | **IR scope**                 | **Minimal shared IR + `Raw` escape hatch per provider.** Extend as concrete rules demand it — not in advance. |
| D2 | **Policy packaging**         | **`//go:embed` built-in policies + optional user directory via `--policies`.** The binary is self-contained; users can extend or override without recompiling. |
| D3 | **Initial provider targets** | **GitLab (adapt existing collector) + GitHub Actions (new collector).** Gitea, Azure DevOps, Bitbucket Pipelines, and Dagger are explicitly out of scope for v1 and will be considered after the first stable release. |
| D4 | **Hybrid period**            | **Rule-by-rule port.** Each Go control is replaced by its Rego equivalent behind a feature flag, parity is verified against integration fixtures, then the Go path is removed. No big-bang cutover. |
| D5 | **Output compatibility**     | **Deprecate-in-place.** A new `findings[]` field is added to `AnalysisResult`. Legacy per-control fields are kept for 1–2 minor versions with a deprecation warning in the JSON output, then removed in a documented minor release. |
<!-- markdownlint-enable MD060 -->

## 8. Migration plan

### Phase 0 — preparation (no behavior change) — DONE

- [x] Validate open decisions §7 with maintainers.
- [x] Open a tracking issue (required by `AI_POLICY.md`). — [#148](https://github.com/getplumber/plumber/issues/148)
- [x] Add `github.com/open-policy-agent/opa` to `go.mod`.
- [x] Create `internal/ir/` and `internal/engine/opa/` skeletons.

### Phase 1 — IR + engine alongside existing controls — DONE

- [x] Define `NormalizedPipeline` and the minimal `Job`/`Image`/`Include` types.
- [x] Write a GitLab IR mapper from the existing `collector` output (`collector.ToNormalizedPipeline`).
- [x] Build the OPA engine: load embedded policies, evaluate, emit findings.
- [x] Unit-test the engine with a fake IR + one dummy policy.
- [x] Gate the engine behind `engine.enabled` (default off) with parity checks against `lab-gitlab-cicd` (branch `solution/lab-12`).

### Phase 2 — port one rule end-to-end

- [ ] Pick the simplest rule (proposal: `image/mutable_tag`).
- [ ] Write the Rego policy + fixtures.
- [ ] Wire a feature flag so the rule runs via Rego, not Go.
- [ ] Verify JSON output is identical to the Go version on the integration fixtures.

### Phase 3 — port remaining GitLab rules — DONE

- [x] Incrementally migrate each of the ~15 controls.
      ISSUE-{101,102,103,203,204,205,401,403,404,410,411,412,413,501,505}
      plus required components/templates ISSUE-{405,406,408,409}.
- [ ] Remove Go controls as each Rego equivalent reaches parity.
- [x] Keep tests green at every step.

### Phase 4 — GitHub Actions provider — DONE

- [x] New collector (`collector/github_workflows.go`, local-only MVP — no GitHub API needed).
- [x] GitHub → IR mapper (`ScanGitHubWorkflows` emits `ir.NormalizedPipeline`).
- [x] Run existing `image_mutable_tag` policy against `../lab-github-cicd` GitHub fixture with zero changes to the Rego.
- [x] CLI auto-dispatches on `github.com` remote; `runGitHubAnalyze` is Rego-only, no `GITLAB_TOKEN` required.
- [ ] Provider-specific policies (Phase 5+: `excessive-permissions`, `dangerous-triggers`, `template-injection`, … — see §11).

### Phase 5 — documentation & DX

- [ ] User docs for writing a custom policy.
- [ ] `plumber policy test` command (wrapper around `opa test`).
- [ ] Update `README`, `CONTRIBUTING`, website.

## 9. Risks & mitigations

<!-- markdownlint-disable MD060 -->
| Risk                                            | Mitigation |
| ----------------------------------------------- | ---------- |
| Rego can't fetch (API calls during evaluation)  | Collector enriches the IR *before* OPA runs (e.g. pre-fetch latest include refs). |
| Performance regression on large pipelines       | Benchmark before/after in Phase 2; keep Go path behind feature flag until benchmarks pass. |
| Breaking JSON output for existing users         | Keep legacy fields, add new ones; document migration. |
| Policy explosion / unmaintainable Rego          | Shared `lib/` helpers; `opa test` coverage; lint in CI. |
| Scope creep (Terraform, K8s…)                   | Explicit non-goal §2. Reject in reviews. |
<!-- markdownlint-enable MD060 -->

## 10. AI contribution notes

This refactor is expected to involve Claude Code (see `AI_POLICY.md`).
All AI-assisted PRs **must**:

- Reference the tracking issue for this refactor (to be opened in Phase 0).
- Be fully reviewed and verified by a human before merge.
- Disclose AI usage in the PR description.

## 11. Catalog of GitHub Actions security checks

The following rule catalog drives the Rego policies Plumber ships for
GitHub Actions workflows. Each check has a stable identifier used as
its Rego package name and Rego module file name (e.g. `excessive-permissions`
→ `policies/excessive_permissions.rego`). Fixture YAMLs live under
`policies/testdata/ISSUE-XXX/github/`.

Status legend: **done** — policy ported and tested; **planned** — to port.

### Supply chain & action references

<!-- markdownlint-disable MD060 -->
| Check                               | Detects                                                            | Status   |
| ----------------------------------- | ------------------------------------------------------------------ | -------- |
| `unpinned-uses` (ISSUE-104)         | `uses: owner/action@v4` instead of hash-pinned references          | **done** |
| `cache-poisoning` (ISSUE-106)       | Release/publish job restores a non-ref-scoped build cache          | **done** |
| `archived-uses` (ISSUE-108)         | Actions hosted in an archived repository                           | **done** |
| `impostor-commit` (ISSUE-109)       | Commit SHA that does not belong to the declared upstream repo      | **done** |
| `ref-version-mismatch` (ISSUE-110)  | Hash-pinned action with a misleading `# vX.Y.Z` comment            | **done** |
| `stale-action-refs` (ISSUE-111)     | Action pin is behind the latest upstream release                   | **done** |
| `ref-confusion` (ISSUE-113)         | Symbolic refs that are ambiguous (branch vs tag collision)         | **done** |
| `known-vulnerable-actions` (ISSUE-114) | Action versions with published GHSA advisories                  | **done** |
| `superfluous-actions` (ISSUE-115)   | Third-party actions duplicating runner built-ins                   | **done** |
<!-- markdownlint-enable MD060 -->

### Container images

<!-- markdownlint-disable MD060 -->
| Check                               | Detects                                                            | Status   |
| ----------------------------------- | ------------------------------------------------------------------ | -------- |
| `unpinned-images` (ISSUE-102)       | Mutable container tags (`:latest`, `:dev`, glob patterns)          | **done** |
| `image-pinned-by-digest` (ISSUE-103) | Container images must be pinned by immutable digest (@sha256:…)   | **done** |
| `hardcoded-container-credentials` (ISSUE-105) | Registry password literals in `container.credentials`              | **done** |
<!-- markdownlint-enable MD060 -->

### Triggers & inputs

<!-- markdownlint-disable MD060 -->
| Check                               | Detects                                                            | Status   |
| ----------------------------------- | ------------------------------------------------------------------ | -------- |
| `dangerous-triggers` (ISSUE-414)    | `pull_request_target`, `workflow_run` with unsafe code checkout    | **done** |
| `pull-request-target-with-head-checkout` (ISSUE-415) | Explicit PR-head checkout under `pull_request_target` (CVE-2025-30066 pattern) | **done** |
| `template-injection` (ISSUE-206)    | User input rendered into `run:` via `${{ github.event.* }}`        | **done** |
| `bot-conditions` (ISSUE-210)        | Spoofable `github.actor == 'dependabot[bot]'` checks               | **done** |
| `unsound-condition` (ISSUE-211)     | Logically unsound conditional expressions                          | **done** |
| `unsound-contains` (ISSUE-212)      | Misused `contains()` built-in                                      | **done** |
<!-- markdownlint-enable MD060 -->

### Permissions & secrets

<!-- markdownlint-disable MD060 -->
| Check                               | Detects                                                            | Status   |
| ----------------------------------- | ------------------------------------------------------------------ | -------- |
| `excessive-permissions` (ISSUE-509) | Blanket `permissions: write-all`                                   | **done** |
| `undocumented-permissions` (ISSUE-304) | Workflow runs with no explicit `permissions:` block              | **done** |
| `overprovisioned-secrets` (ISSUE-301) | Entire `secrets` context exported via `toJson(secrets)`            | **done** |
| `secrets-outside-env` (ISSUE-305)   | Deploy/publish job uses secrets without `environment:` gate        | **done** |
| `unredacted-secrets` (ISSUE-303)    | `fromJSON(secrets.X).y` bypasses automatic log redaction           | **done** |
| `secrets-inherit` (ISSUE-302)       | Reusable workflow called with `secrets: inherit`                   | **done** |
| `github-app` (ISSUE-306)            | GitHub App token issued with `skip-token-revoke: true`             | **done** |
| `github-env` (ISSUE-209)            | Untrusted writes to `GITHUB_ENV` / `GITHUB_PATH`                   | **done** |
| `artipacked` (ISSUE-307)            | `actions/checkout` without `persist-credentials: false`            | **done** |
<!-- markdownlint-enable MD060 -->

### Workflow hygiene

<!-- markdownlint-disable MD060 -->
| Check                               | Detects                                                            | Status   |
| ----------------------------------- | ------------------------------------------------------------------ | -------- |
| `anonymous-definition` (ISSUE-601)  | Workflow or action without a `name:` field                         | **done** |
| `concurrency-limits` (ISSUE-602)    | Missing `concurrency` block with `cancel-in-progress`              | **done** |
| `insecure-commands` (ISSUE-208)     | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true`                            | **done** |
| `cache-poisoning` (ISSUE-106)       | `actions/cache` used inside a release workflow                     | **done** |
| `use-trusted-publishing` (ISSUE-605) | PyPI/npm publish via static token instead of OIDC                  | **done** |
| `misfeature` (ISSUE-603)            | Upload-artifact of the checkout directory (leaks `.git/`)          | **done** |
| `obfuscation` (ISSUE-604)           | Zero-width / bidirectional Unicode in scripts and inputs           | **done** |
<!-- markdownlint-enable MD060 -->

### Dependabot

<!-- markdownlint-disable MD060 -->
| Check                               | Detects                                                            | Status   |
| ----------------------------------- | ------------------------------------------------------------------ | -------- |
| `dependabot-execution` (ISSUE-606)  | `insecure-external-code-execution: allow`                          | **done** |
| `dependabot-cooldown` (ISSUE-607)   | Missing `cooldown:` window in `.github/dependabot.yml`             | **done** |
<!-- markdownlint-enable MD060 -->

### Repository-hygiene checks

Rules that extend the audit surface from the workflow YAML to the
surrounding repository artefacts — Dockerfiles, SECURITY.md,
dependency-update configs, release-signing steps — and to
injection patterns not covered by the original template-injection
family.

<!-- markdownlint-disable MD060 -->
| Check                                   | Detects                                                                                                                | Status   |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------- |
| `unsafe-github-context-dump` (ISSUE-213) | `toJson(github)` / `toJson(github.event)` piped into a script / env / input                                        | **done** |
| `unpinned-package-install` (ISSUE-214)  | `pip install X` / `npm install X` without version pin or lockfile                                                      | **done** |
| `release-workflow-unsigned` (ISSUE-112) | Release / publish job produces artefacts without any signing step (cosign, sigstore, GPG)                              | **done** |
| `dockerfile-unpinned-base` (ISSUE-107)  | `FROM image:tag` in a repo Dockerfile without `@sha256:` digest                                                        | **done** |
| `dependency-update-tool-missing` (ISSUE-608) | Repository ships workflows but neither Dependabot nor Renovate is configured                                      | **done** |
| `sast-workflow-missing` (ISSUE-609)     | No workflow runs a recognised SAST scanner (CodeQL, Semgrep, SonarQube, Trivy, Snyk, …)                                | **done** |
| `security-policy-missing` (ISSUE-610)   | Repository ships workflows but no SECURITY.md disclosure policy                                                        | **done** |
<!-- markdownlint-enable MD060 -->

A matching fixture project lives in `../lab-github-cicd/` (outside the
Plumber repository) so every planned check has a real workflow to run
against during development.
