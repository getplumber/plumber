# Plumber Multi-Provider Implementation Plan

**Date:** 2026-05-06
**Branch:** `refacto-rego`
**Author note:** This plan is the canonical source of truth for the in-flight work. It is written to be picked up by future sessions (you, other Claude instances, other LLMs, human collaborators) without prior conversational context. Read top to bottom. Each Phase is self-contained.

---

## Background and current state (read this first)

Plumber is a Go CLI that scans CI/CD pipelines for compliance. Historically it targeted only GitLab (using the GitLab REST API + a mandatory `--token`). The `refacto-rego` branch added a second provider: **GitHub Actions**, evaluated via Rego policies (`policies/*.rego`) compiled into the binary and executed by OPA (`open-policy-agent/opa` in `go.mod`). The Go-controls-per-check pattern that GitLab used has been retired (Phase A in `docs/REFACTOR_MULTI_PROVIDER.md`); Rego is now the single evaluation engine for both providers.

### What works today

- **GitLab path**: `cmd/analyze.go` → `control/task.go` → collectors (token-required) → Rego engine → findings.
- **GitHub path**: `cmd/analyze_github.go` → `control/task_github.go` → `collector/github_workflows.go` (local YAML) + `collector/github_metadata.go` (uses `cli/go-gh` for API enrichment) + `collector/github_repo_artifacts.go` → Rego engine → findings.
- **Auth model — GitLab**: token mandatory; hard fail without it.
- **Auth model — GitHub**: `cli/go-gh`'s `api.DefaultRESTClient()` resolves credentials in this order automatically: `GH_TOKEN` env → `GITHUB_TOKEN` env → `gh auth token` from `gh auth login` config → degraded mode (empty results, no crash). Today this degradation is silent.
- **Rego policies**: 52 files in `policies/`; tested in `policies/rules_test.go` (~2934 lines).
- **Issue registry**: `control/codes.go` maps `ErrorCode` ↔ `ControlName`. Helper: `control.LookupCode(ErrorCode)`.

### Known problems this plan addresses

1. **Config schema is provider-flat.** All controls live under one `controls:` section in `.plumber.yaml`. Same control name needs different config per provider (e.g. trusted registries: `registry.gitlab.com/*` vs `ghcr.io/<org>/*`). Already partly migrated by the user — the current `.plumber.yaml` has `gitlab:` and `github:` roots with `controls:` under each, but the Go config layer still expects the flat shape, so **the YAML file is currently broken until Phase 0 ships**.
2. **GitHub auth state is invisible.** A user with no `gh` auth gets fewer findings than they should and doesn't know.
3. **GitHub controls have uneven test coverage.** Audit on 2026-05-06 found 8 fully tested, 7 lightly tested, 7 untested out of the 22 tier-1 controls.
4. **`branchMustBeProtected` is GitLab-only**: registered in codes but no GitHub collector populates the IR.
5. **Vestigial `engine.enabled` config block** in `.plumber.yaml` (currently commented out by the user with `#to remove`). The block contradicts itself ("off by default" in the header, "Default: true" in the field comment) and the only real behaviour of `enabled: false` is "skip rule evaluation entirely → empty findings", a footgun.

### Audit reference (2026-05-06)

For the 22 controls considered "tier-1" for GitHub:

**Fully tested (real rule body + ≥3 tests in `policies/rules_test.go`) — ship default-on:**
1. `actionsMustBePinnedByCommitSha` (ISSUE-104) — `policies/action_unpinned.rego`
2. `containerImageMustNotUseForbiddenTags` (ISSUE-102 + ISSUE-103) — `policies/image_mutable_tag.rego` + `policies/image_pinned_by_digest.rego`
3. `pipelineMustNotUseDockerInDocker` (ISSUE-412 + ISSUE-413) — `policies/docker_in_docker.rego` + `policies/docker_in_docker_insecure.rego`
4. `reusableWorkflowsMustNotInheritSecrets` (ISSUE-302) — `policies/secrets_inherit.rego`
5. `securityJobsMustNotBeWeakened` (ISSUE-410) — `policies/security_jobs_weakened.rego`
6. `workflowMustNotInjectUserInputInScripts` (ISSUE-206) — `policies/template_injection.rego`
7. `workflowMustNotUseDangerousTriggers` (ISSUE-414) — `policies/dangerous_triggers.rego`
8. `workflowsMustDeclarePermissions` (ISSUE-304) — `policies/undocumented_permissions.rego`

**Lightly tested (rule body present, 1–2 tests):**
- `containerImageMustComeFromAuthorizedSources` (ISSUE-101) — `policies/image_authorized_sources.rego`
- `pipelineMustNotEnableDebugTrace` (ISSUE-203) — `policies/debug_trace.rego`
- `pipelineMustNotExecuteUnverifiedScripts` (ISSUE-411) — `policies/unverified_scripts.rego`
- `pipelineMustNotIncludeHardcodedJobs` (ISSUE-401) — `policies/hardcoded_jobs.rego`
- `pipelineMustNotOverrideJobVariables` (ISSUE-205) — `policies/job_variable_override.rego`
- `pipelineMustNotUseUnsafeVariableExpansion` (ISSUE-204) — `policies/unsafe_variable_expansion.rego`
- `pullRequestTargetMustNotCheckoutHead` (ISSUE-415) — `policies/pull_request_target_head_checkout.rego`

**Untested (rule body present, 0 tests):**
- `actionsMustNotBeArchived` (ISSUE-108) — `policies/action_archived_repo.rego` (API-backed)
- `actionsMustNotCarryKnownCVEs` (ISSUE-114) — `policies/known_vulnerable_action.rego` (API-backed)
- `branchMustBeProtected` (ISSUE-501 + ISSUE-505) — `policies/branch_unprotected.rego` + `policies/branch_non_compliant.rego` (GitHub collector missing — Phase 5A)
- `includesMustBeUpToDate` (ISSUE-403) — `policies/includes_outdated.rego`
- `includesMustNotUseForbiddenVersions` (ISSUE-404) — `policies/includes_forbidden_version.rego`
- `pipelineMustIncludeComponent` (ISSUE-408 + ISSUE-409) — `policies/component_missing.rego` + `policies/component_overridden.rego`
- `pipelineMustIncludeTemplate` (ISSUE-405 + ISSUE-406) — `policies/template_missing.rego` + `policies/template_overridden.rego`

### Scope of impact per provider (READ THIS BEFORE PANICKING)

**GitLab is functionally untouched by this plan.** The 14 existing GitLab controls work today and stay working. Specifically for GitLab:

- **YAML**: every control config moves one indent level deeper, under `gitlab.controls:`. Field names, values, defaults are bit-identical. (The user has already done this part manually in the in-flight `.plumber.yaml`.)
- **Go code**: every site that reads `conf.PlumberConfig.Controls.X` becomes `conf.PlumberConfig.GitLab.Controls.X`. The per-control struct types are reused unchanged.
- **Rego**: zero changes. The engine receives the `gitlab.controls` subtree as its `input.config` for the GitLab path, the same way it receives `controls` today.
- **GitLab control behaviour tests**: unchanged.
- **User-visible**: an existing user runs `plumber config migrate`, gets a new YAML file, and analyze behaviour is bit-identical to before.

The only GitLab-side test work is in the **config loader** (v1/v2 detection + the `convertV1ToV2` path), not in any control logic.

**GitHub is where all the functional work happens.** Phases 1–5 are GitHub-only. Phase 0 touches both providers (because it's a schema change), but the GitHub touch in Phase 0 is just "now it has its own provider section to put things in."

### Architectural decisions already locked

- **YAML schema v2** = per-provider nesting (`gitlab.controls.X`, `github.controls.X`). Decision rationale: same control name can need divergent config per platform (registries, version patterns, required components). Flat shared config forces wrong choices. YAML anchors (`&` / `*`) handle the dedup case without inventing a Plumber-specific inheritance grammar.
- **Auth model — GitHub**: keep soft-degrade as the default (matches `gh` CLI ergonomics, makes "drop in a repo" UX work), but add `github.auth.requireAuth: true` for compliance-conscious orgs that want GitLab-style hard-fail.
- **Engine block**: delete entirely. Vestigial. The "shadow mode alongside legacy Go controls" narrative is stale — Go controls were retired in Phase A.
- **Per-provider control config types**: for controls that exist on both providers (e.g. `containerImageMustNotUseForbiddenTags`), the **Go struct type is shared**; only the YAML location and values differ. The provider section just contains a `Controls` map populated from its own YAML subtree.

### Tech stack

- Go 1.25
- OPA — `github.com/open-policy-agent/opa`
- GitHub API — `github.com/cli/go-gh/v2/pkg/api` (auto-resolves auth)
- GitLab API — `gitlab.com/gitlab-org/api/client-go`
- YAML — `gopkg.in/yaml.v2`
- CLI — `github.com/spf13/cobra`
- Logging — `github.com/sirupsen/logrus`

### Build invariants

- **Always run `make embed` (or `make test`) before raw `go test`** — the embedded default config under `internal/defaultconfig/default.yaml` is generated from `.plumber.yaml` and tests depend on it.
- `make lint` (golangci-lint v2) must pass before push.
- Conventional Commits (`feat(scope): ...`, `fix(scope): ...`, `chore(scope): ...`).

---

## Status tracking convention (READ AND FOLLOW)

This plan is a living document worked on by multiple sessions / LLMs / humans across time. To prevent re-doing finished work, every Phase has a **Status** line and every task has a `- [ ]` checkbox. **Update them as you go.**

### Per-task checkboxes

Use standard markdown checkboxes:

- `- [ ]` = not started.
- `- [x]` = complete (verified by you in this session).
- `- [~]` = in progress (you started it but did not finish before context ran out / handed off).
- `- [!]` = blocked (annotate inline why: `- [!] **0-4: Update loader …** — blocked: yaml.v2 doesn't expose top-level keys without re-parse, see comment below`).

### Per-Phase Status line

Each Phase header has a `**Status:**` line. Acceptable values:

- `not started` (default)
- `in progress — <ISO date> — <session/LLM identifier>` (e.g. `in progress — 2026-05-07 — Claude Opus 4.7 (session abc123)`)
- `complete — <ISO date> — commit <short-sha-or-PR>` (e.g. `complete — 2026-05-08 — commit a1b2c3d`)
- `blocked — <ISO date> — <one-line reason>`

**When you finish a Phase**, also append an "Outcome" subsection at the end of that Phase containing:
- Final commit SHA(s) or PR link.
- Any deviations from the written tasks and why.
- Anything the next Phase needs to know that wasn't anticipated.

### Phase status overview (keep current — edit when you start/finish a Phase)

| Phase | Title | Status |
|---|---|---|
| 0 | Config v2 schema migration | complete — 2026-05-06 — commit 7f05d81 |
| 1 | GitHub gating mechanism | complete — 2026-05-06 — commit f7a1c59 (load-time bench filter + provider-aware validation + GHES URL) |
| 2 | Add coverage to bring it to ≥3 tests | not started (blocked on Phase 1) |
| 3 | Sprint 1: lightly-tested → fully tested | not started (blocked on Phase 1) |
| 4 | Sprint 2: 4 untested → tested | not started (blocked on Phase 1) |
| 5A | Branch protection collector | not started (blocked on Phase 1) |
| 5B | Auth UX banner + requireAuth | not started (blocked on Phase 0) |
| 5C | Upstream fetch for GitHub (`--project` polymorphism) | implemented — uncommitted local changes (commit pending) |
| 6 | Cross-cutting docs | not started (blocked on 1–5) |

### Verification policy for downstream sessions

If a Phase is marked `complete`, you do NOT need to re-verify it before starting a downstream Phase. Trust the Outcome note. If you do choose to verify (recommended for the Phase immediately upstream of yours), spot-check the acceptance criteria — don't redo the work.

If something marked `complete` turns out to be wrong, flip its Status to `blocked — <reason>`, write what you found in the Outcome section, and stop. Do not silently fix and continue — the next session needs to know the plan diverged from reality.

---

## Phase ordering and dependency graph

```
Phase 0 (Config v2 schema) ──┬── must complete before all others
                             │
                             ├── Phase 1 (GitHub gating)
                             │     │
                             │     ├── Phase 2 (+1 control)
                             │     │
                             │     ├── Phase 3 (Sprint 1: 5 lightly-tested→fully tested)
                             │     │
                             │     ├── Phase 4 (Sprint 2: 4 untested→tested)
                             │     │
                             │     └── Phase 5 (Sprint 3: branch + auth UX)
                             │
                             └── Phase 6 (cross-cutting docs)
```

Phase 0 is the gate. Until it lands, the in-flight `.plumber.yaml` cannot be loaded by Go.

---

# Phase 0 — Config v2 schema migration

**Status:** complete — 2026-05-06 — Claude Opus 4.7 — commit `7f05d81` on `refacto-rego`

**Outcome:** Schema bumped to `version: "2.0"` (per-provider). Loader handles v1 and v2 transparently; legacy v1 files auto-convert in memory with a deprecation warning. `plumber config migrate` rewrites v1 → v2 on disk, preserving comments. `engine.enabled` setting deleted (was vestigial). All callers in `cmd/`, `control/` rewired through `pc.ControlsFor("gitlab")`. End-to-end verified: `./plumber analyze` runs against this repo (GitHub) and a real GitLab project. Bonus pre-existing rego bug fixed in `policies/security_jobs_weakened.rego` (function determinism conflict on multi-violation jobs) with regression test.

**Side-quest fixes that surfaced during validation:**
- `policies/security_jobs_weakened.rego` — split `_weakening_reason` into separate deny rules (multi-violation jobs were producing `eval_conflict_error`). Pre-existing bug; not from the v2 work.
- `control/catalog.go::GitLabControls` — was reading legacy `pc.Controls`; now uses `pc.ControlsFor("gitlab")`. Caused empty Controls/Compliance tables in analyze output.
- 14 legacy getter methods in `configuration/plumberconfig.go` — same problem; one (`GetBranchMustBeProtectedConfig`) gated the branch-protection collector and was making it skip silently. Fixed by `replace_all` to `c.ControlsFor("gitlab").X`.

**Goal:** Move from flat `.plumber.yaml` (`controls:` at root) to nested per-provider (`gitlab.controls:`, `github.controls:`). Add a `version:` discriminator. Delete the `engine` block. Provide a one-shot migration tool. Support both v1 and v2 in the loader during a deprecation window, then drop v1 in a future major release.

### v2 schema specification

```yaml
# Top-level discriminator. Required from this release onward.
# - "1.0" = first stable schema (per-provider nesting, this document).
# - Absent or "0.x" = legacy flat schema (auto-detected, deprecation warning emitted).
version: "1.0"

# Provider section: GitLab.
gitlab:
  # Provider-specific knobs (none today; reserved for future use, e.g.
  # GitLab Self-Managed base URL, default branch override, etc.).
  # auth: { ... }   # placeholder

  # Allowlist of control names enabled for the GitLab path.
  # Empty/missing → default set (all 14 historical GitLab controls).
  # ["*"] → bypass filter (all loaded rego policies fire).
  # enabledControls: []

  # Per-control configuration. Same struct types as the Go-side
  # ControlsConfig, but values are GitLab-specific.
  controls:
    containerImageMustNotUseForbiddenTags: { ... }
    branchMustBeProtected: { ... }
    # ... 14 GitLab controls total

# Provider section: GitHub.
github:
  # GitHub-specific knobs.
  auth:
    # Hard-fail when no gh-cli / GH_TOKEN / GITHUB_TOKEN credential is found.
    # Default: false (soft-degrade with visible banner; matches gh CLI norms).
    requireAuth: false

  # Allowlist of control names enabled for the GitHub path.
  # Empty/missing → eight shipping controls (defaultEnabledGitHubControls).
  # ["*"] → bypass.
  enabledControls: []

  # Per-control configuration. Values are GitHub-specific.
  controls:
    actionsMustBePinnedByCommitSha:
      enabled: true
      trustedOwners: [actions, github]
    # ... add more as Phases 2–5 ship them
```

### Schema rules

1. `version` is **required** from this release. Loader behaviour:
   - `"1.0"` → parse as v2.
   - Missing or `"0.x"` → parse as v1, emit `WARN: legacy config schema detected; run 'plumber config migrate' to upgrade. v1 support will be removed in 1.0.0`.
   - Unknown version → fatal error with list of supported versions.
2. The legacy `controls:` top-level key is rejected in v2 (would silently do nothing — better to fail loud).
3. The legacy `engine:` top-level key is rejected in v2 (deleted feature).
4. Unknown top-level keys → warning, not error (forward compatibility).
5. Unknown keys under `gitlab:` / `github:` → warning.
6. Unknown control names under `controls:` → warning (could be a bench control, could be a typo; user picks).
7. Same control name can appear in both `gitlab.controls` and `github.controls` with different values — that is the entire point of v2.

### YAML anchors as the deduplication escape hatch

Documented in README, not enforced by code. Example:

```yaml
gitlab:
  controls:
    pipelineMustNotEnableDebugTrace: &debug_trace
      enabled: true
      forbiddenVariables: [CI_DEBUG_TRACE, CI_DEBUG_SERVICES]

github:
  controls:
    pipelineMustNotEnableDebugTrace: *debug_trace
```

`gopkg.in/yaml.v2` resolves anchors before unmarshalling, so this Just Works™ with no Plumber-side support code.

### Files to touch (Phase 0)

**Modify:**
- `.plumber.yaml` — already in transitional state; finalise to v2; delete commented engine block; add `version: "1.0"`.
- `internal/defaultconfig/default.yaml` — auto-generated by `make embed`; do NOT hand-edit.
- `configuration/plumberconfig.go`:
  - Replace `PlumberConfig` struct shape: add `Version string`, `GitLab *ProviderConfig`, `GitHub *ProviderConfig`. Keep top-level `Controls` field (now optional, only populated when v1 detected, used by the v1→v2 internal converter).
  - Add `EngineConfig` removal (delete `Engine` field, `EngineConfig` type, `IsEngineEnabled` method).
  - Add `validV2TopLevelKeys` / `validProviderKeys` / per-provider `validControlKeys`.
  - Add `LoadPlumberConfig` v1/v2 detection + dispatch.
  - Add `convertV1ToV2(*PlumberConfig)` for the deprecation-window auto-upgrade in memory (separate from the file-on-disk migration tool).
- `configuration/types.go` (or wherever `ProviderConfig` will live) — define:
  ```go
  type ProviderConfig struct {
      Auth             *AuthConfig     `yaml:"auth,omitempty"`
      EnabledControls  []string        `yaml:"enabledControls,omitempty"`
      Controls         *ControlsConfig `yaml:"controls,omitempty"`
  }
  type AuthConfig struct {
      RequireAuth *bool `yaml:"requireAuth,omitempty"`  // GitHub-only today
  }
  ```
  `ControlsConfig` is the existing struct — reused unchanged. Each provider has its own instance.
- `control/task.go:461` — delete the `if conf.PlumberConfig.IsEngineEnabled()` guard; engine always runs. Read GitLab controls from `conf.PlumberConfig.GitLab.Controls`.
- `cmd/analyze_github.go` — read GitHub controls from `conf.PlumberConfig.GitHub.Controls`.
- All call sites that currently read `conf.PlumberConfig.Controls.X` — switch to `conf.PlumberConfig.GitLab.Controls.X` (for GitLab path) or `conf.PlumberConfig.GitHub.Controls.X` (for GitHub path). Find them with: `grep -rn "PlumberConfig.Controls" --include="*.go"`.
- `cmd/config.go` — add `migrate` subcommand.

**Create:**
- `cmd/config_migrate.go` — implements `plumber config migrate`. Reads a v1 file, writes v2, preserves comments where feasible (use `gopkg.in/yaml.v3`'s node API just for this command — yaml.v2 doesn't preserve comments; this is the one place the dependency split is worth it).
- `configuration/v1_to_v2.go` — pure conversion logic, unit-tested.
- `configuration/v1_to_v2_test.go` — table-driven cases.
- `configuration/plumberconfig_v2_test.go` — v2-specific load/validate tests.
- `docs/plumber-yaml-v2-migration.md` — user-facing migration guide; explains automatic in-memory upgrade, how to run `plumber config migrate`, deprecation timeline.

**Delete:**
- The `engine:` block in `.plumber.yaml` (currently commented with `#to remove`).
- `EngineConfig` type, `Engine` field, `IsEngineEnabled` method, `validEngineKeys` slice in `configuration/plumberconfig.go`.

### Tasks (Phase 0)

- [x] **0-1: Define v2 Go types** *(complete — additive only, no behavior change; build + config tests green)*
  - Added `ProviderConfig`, `AuthConfig`, `AuthConfig.IsRequireAuth()` in `configuration/plumberconfig.go`.
  - Added `GitLab *ProviderConfig` and `GitHub *ProviderConfig` fields on `PlumberConfig`. Kept legacy `Controls` and `Engine` fields for v1 compat.
  - `Version` tag changed from `yaml:"version"` to `yaml:"version,omitempty"` (was already required-named, now optional in YAML).

- [x] **0-2: Write v1→v2 converter with tests (RED)** *(complete — `configuration/v1_to_v2_test.go`)*
  - File: `configuration/v1_to_v2.go`. Function: `func convertV1ToV2(in *PlumberConfig) *PlumberConfig`. Maps `in.Controls` to `out.GitLab.Controls` (legacy was GitLab-only; GitHub gets nil controls map = use defaults).
  - File: `configuration/v1_to_v2_test.go`. At least 3 cases:
    - empty v1 → v2 with version="1.0", both providers nil.
    - v1 with one control → v2 with `gitlab.controls.X` populated, `github` nil.
    - v1 with engine block → v2 with engine ignored + warning returned.
  - Run: `go test ./configuration/ -run TestConvertV1ToV2 -v`. Expect FAIL (not implemented).

- [x] **0-3: Implement converter (GREEN)** *(complete — `configuration/v1_to_v2.go`; tests pass)*
  - Make tests pass. Keep it pure — no I/O.
  - Run: `go test ./configuration/ -run TestConvertV1ToV2 -v`. Expect PASS.

- [x] **0-4: Update loader to detect schema version** *(complete — `LoadPlumberConfig` dispatches v1/v2; rejects unsupported version; raw-YAML scan emits engine deprecation warning since the field was deleted)*
  - In `configuration/plumberconfig.go::LoadPlumberConfig`: read raw YAML to a `map[string]any` first, inspect top-level keys.
  - If `version` present and starts with `"1."` → unmarshal directly into v2 shape, validate.
  - If `version` absent or starts with `"0."` → unmarshal into v1 shape, log `WARN: legacy config schema detected; run 'plumber config migrate' to upgrade. v1 support will be removed in 1.0.0`, run `convertV1ToV2`, return v2.
  - If `version` is anything else → return error `unsupported config version %q; supported: ["1.0"]`.
  - Reject `engine:` key in v2: error `engine.enabled config has been removed; delete the 'engine' block from .plumber.yaml`.

- [x] **0-5: Loader tests** *(complete — added `TestLoadPlumberConfig_v1FlatAutoConverts`, `TestLoadPlumberConfig_v2NativeNoConversion`, `TestLoadPlumberConfig_rejectsUnsupportedVersion`, `TestLoadPlumberConfig_v1WithStaleVersionOnNestedFile`, plus the existing `TestLoadPlumberConfig_warnsOnEngineBlock`. Cover the v1→v2 dispatch, native v2 load, version rejection, and the silent-bump-on-stale-version edge case.)*
  - File: `configuration/plumberconfig_v2_test.go`. Cases:
    - Load v1 file → succeeds, warning emitted, GitLab controls populated.
    - Load v2 file → succeeds, no warning.
    - Load file with `version: "9.9"` → error.
    - Load v2 file with `engine:` block → error.
    - Load v2 file with control under wrong provider (e.g. `gitlab.controls.actionsMustBePinnedByCommitSha`) → warning, control still loaded (loose validation, since the loader doesn't know which controls are which provider's).

- [x] **0-6: Update all `PlumberConfig.Controls` call sites** *(complete — `cmd/legacy_json.go`, `cmd/render_details.go`, `cmd/init.go` use `pc.ControlsFor("gitlab")`; `control/task.go` `evaluatePolicies` takes a `provider` arg; `control/task_github.go` passes `"github"`; `control/catalog.go` `FilterFindingsByEnabledControls` and `DisabledControlNames` take `*ControlsConfig` directly; init.go writes `cfg.GitLab.Controls.X`; tests adjusted)*
  - `grep -rn "PlumberConfig.Controls\|conf.PlumberConfig.Controls" --include="*.go" .`
  - For each site, determine if it's GitLab or GitHub code path.
  - Replace with `PlumberConfig.GitLab.Controls` or `PlumberConfig.GitHub.Controls`.
  - Add nil-guards where the provider section may be absent (return zero/disabled).

- [x] **0-7: Delete EngineConfig** *(complete — `EngineConfig` type, `Engine` field, `IsEngineEnabled` method, `validEngineKeys` removed; the `if conf.PlumberConfig.IsEngineEnabled()` guard in `task.go:461` deleted; deprecation warning surfaces via raw-YAML detection in `LoadPlumberConfig`)*
  - Remove `Engine` field, `EngineConfig` type, `IsEngineEnabled` method, `validEngineKeys` slice from `configuration/plumberconfig.go`.
  - Remove `if conf.PlumberConfig.IsEngineEnabled()` guard in `control/task.go:461` — engine always runs.
  - Update `docs/REFACTOR_MULTI_PROVIDER.md` §8 (remove shadow-mode language).

- [x] **0-8: Finalise `.plumber.yaml`** *(complete — commented engine block deleted; `make embed` regenerates `internal/defaultconfig/default.yaml` in v2 shape; full test suite green; `./plumber analyze` end-to-end on this repo produces real findings via the GitHub path)*
  - Add `version: "1.0"` at top (already done by user).
  - Confirm GitLab controls are all under `gitlab.controls:` (already done by user).
  - Confirm GitHub controls (currently only `actionsMustBePinnedByCommitSha`) are under `github.controls:` (already done by user, but double-check indentation; the doc-comment block at lines 553-569 is currently mis-nested under `gitlab:`).
  - Delete the commented `engine:` block at lines 586-596.
  - Run `make embed` to regenerate `internal/defaultconfig/default.yaml`.

- [x] **0-9: `plumber config migrate` subcommand** *(complete — `cmd/config_migrate.go`. Uses yaml.v3 node API to preserve comments. Default writes `<input>.v2`; `--in-place` overwrites with `.bak` backup. Idempotent on already-v2 files. Refuses migration when both top-level `controls:` and `gitlab.controls:` exist (asks the user to resolve manually). Smoke-tested on v1, v1+comments, already-v2, conflict, and --in-place fixtures.)*
  - File: `cmd/config_migrate.go`.
  - Reads `.plumber.yaml` (or `--config <path>`).
  - If already v2 → print `already on schema v1.0`, exit 0.
  - Else → read with `yaml.v3` node API to preserve comments, transform tree (move `controls:` under `gitlab.controls:`, drop `engine:`, add `version: "1.0"` header), write to `<path>.v2` (don't clobber by default), print: `wrote migrated config to <path>.v2 — review and replace <path> when satisfied`.
  - Flag: `--in-place` to overwrite directly (with backup to `<path>.bak`).
  - Test: `cmd/config_migrate_test.go` with at least 3 fixtures (empty v1, full v1, already-v2).

- [x] **0-10: User docs** *(complete — created `docs/plumber-yaml-v2-migration.md` (TL;DR migration, before/after, why, backward-compat, anchors, edge cases, deprecation timeline, manual cookbook). Replaced the README "Multi-provider configuration (roadmap)" subsection with a real "Multi-provider configuration" section showing v2 example + anchor pattern + link to the migration guide. CHANGELOG entries skipped — this repo uses semantic-release; commit messages drive the changelog.)*

- [x] **0-11: End-to-end verification**
  - `make embed && make test && make lint` all pass.
  - `./plumber analyze` against the test repo with the new v2 `.plumber.yaml` produces the same findings as before.
  - `./plumber config migrate` against an old v1 fixture produces a valid v2 file.

- [x] **0-12: Commit (one focused commit per logical step above; this list is a guide for the final squashed history)**
  ```
  feat(config)!: per-provider YAML schema (v1.0); deprecate flat schema
  feat(cli): plumber config migrate subcommand for v1→v2 upgrade
  chore(config): remove vestigial engine.enabled setting
  docs(config): v2 migration guide and deprecation timeline
  ```

**Acceptance for Phase 0:**
- `.plumber.yaml` loads cleanly with `version: "1.0"`.
- A pre-existing v1 file still loads with a deprecation warning.
- `plumber config migrate` produces a working v2 file from a v1 file.
- `engine:` block is gone from code, default config, and tests.
- All existing tests pass; new v2 tests pass.
- `make lint` clean.

---

# Phase 1 — GitHub gating mechanism

**Status:** complete — 2026-05-06 — Claude Opus 4.7 — commit `f7a1c59` on `refacto-rego`

**Outcome:** Strict GitLab semantic parity for the YAML — per-control `enabled: true/false`, absent = enabled at the filter level. Bench gate is enforced at **engine load time** via `IsRegoFileBenchedForProvider` (control/bench_filter.go) + `LoadFromFSFiltered` (internal/engine/opa/engine.go): when every ISSUE-XXX in a rego file maps (via `errorCodeRegistry`) to a control benched for the running provider (per `configuration.benchedControls`, keyed by `{provider, controlName}`), the file is never registered with OPA. No execution, no findings, no wasted cycles. The post-evaluation filter is retained as defense-in-depth. No new mapping table — the bench-to-file link is derived from the rego files' own ISSUE-XXX references. To promote a benched control: remove its name from the bench map; if it has tunable config, also add a typed struct in `plumberconfig.go`. Cross-provider misplacement warnings via `controlsMeta` (e.g. putting `actionsMustBePinnedByCommitSha` under `gitlab.controls:` warns). `--github-url` flag for GitHub Enterprise Server (auth via `GH_ENTERPRISE_TOKEN` / `GH_TOKEN`). Scoring path unchanged (shared with GitLab). End-to-end verified.

**Goal:** Make the GitHub analyze path emit findings only for the eight shipping controls by default. Allowlist driven by `github.enabledControls` in v2 schema.

**Prereq:** Phase 0 complete.

### Files

- Modify: `cmd/analyze_github.go` — filter `result.Findings` after `RunGitHubAnalysis` returns, before counting/scoring/printing.
- Modify: `control/codes.go` — add helper `func AllControlNames() []string` returning every distinct `ControlName` in the registry (used to validate `enabledControls` entries).
- Test: `cmd/analyze_github_test.go` (create) — filter logic with synthetic findings.

### Default set

```go
// in cmd/analyze_github.go
var defaultEnabledGitHubControls = []string{
    "actionsMustBePinnedByCommitSha",
    "containerImageMustNotUseForbiddenTags",
    "pipelineMustNotUseDockerInDocker",
    "reusableWorkflowsMustNotInheritSecrets",
    "securityJobsMustNotBeWeakened",
    "workflowMustNotInjectUserInputInScripts",
    "workflowMustNotUseDangerousTriggers",
    "workflowsMustDeclarePermissions",
}
```

### Filter logic

```go
// resolveEnabledGitHubControls returns the allowlist to apply to findings.
// Empty/missing config → defaults. ["*"] → bypass.
func resolveEnabledGitHubControls(cfg *configuration.ProviderConfig) (set map[string]struct{}, bypass bool) {
    if cfg == nil || len(cfg.EnabledControls) == 0 {
        out := map[string]struct{}{}
        for _, n := range defaultEnabledGitHubControls {
            out[n] = struct{}{}
        }
        return out, false
    }
    if len(cfg.EnabledControls) == 1 && cfg.EnabledControls[0] == "*" {
        return nil, true
    }
    out := map[string]struct{}{}
    for _, n := range cfg.EnabledControls {
        out[n] = struct{}{}
    }
    return out, false
}

// applyControlAllowlist drops findings whose ControlName is not in the set.
func applyControlAllowlist(findings []opaengine.Finding, allow map[string]struct{}, bypass bool) []opaengine.Finding {
    if bypass {
        return findings
    }
    out := findings[:0]
    for _, f := range findings {
        info := control.LookupCode(control.ErrorCode(f.Code))
        if info == nil {
            continue
        }
        if _, ok := allow[info.ControlName]; ok {
            out = append(out, f)
        }
    }
    return out
}
```

Wire between `RunGitHubAnalysis(conf)` and the score/print block in `runGitHubAnalyze`.

### Tasks (Phase 1)

- [ ] **1-1: Add `control.AllControlNames()` helper** with table test.
- [ ] **1-2: Add `defaultEnabledGitHubControls` constant** in `cmd/analyze_github.go` (the eight shipping controls above).
- [ ] **1-3: Implement `resolveEnabledGitHubControls` + `applyControlAllowlist`** with unit tests covering: empty config → defaults, explicit list → exact set, `["*"]` → bypass, unknown control name → warning + drop.
- [ ] **1-4: Wire filter into `runGitHubAnalyze`** between line 72 (`RunGitHubAnalysis`) and line 82 (score block).
- [ ] **1-5: `make embed && make test`** — verify all existing tests still pass.
- [ ] **1-6: Commit:**
  ```
  feat(github): gate analyze findings via github.enabledControls allowlist
  ```

**Acceptance:** Running `plumber analyze` in a GitHub repo with no `github.enabledControls` configured reports findings only for the eight shipping controls.

---

# Phase 2 — Promote `containerImageMustComeFromAuthorizedSources` to ≥3 tests

**Status:** not started (blocked on Phase 1)

**Goal:** Bring the +1 control from lightly tested (2 tests) to fully tested (≥3 tests), then enable on GitHub.

### Files

- Read: `policies/image_authorized_sources.rego` (89 LOC, ISSUE-101).
- Read: existing test cases in `policies/rules_test.go` referencing `ISSUE-101` (search around lines 1179, 1492, 1516).
- Modify: `policies/rules_test.go` — add 1 test case to fill the coverage gap.
- Modify: `cmd/analyze_github.go` — add control to `defaultEnabledGitHubControls`.

### Test case to add (pick the missing one of these)

1. **Trusted-registry pass case**: image from a configured trusted registry → no finding.
2. **Untrusted-registry fail case**: image from unlisted registry → ISSUE-101.
3. **Docker Hub official-image toggle**: with `trustDockerHubOfficialImages: true`, `image: nginx:1.25` passes; with the toggle off, fails.

Read the existing 2 cases first, then add whichever is uncovered.

### Tasks (Phase 2)

- [ ] **2-1: Read the rego rule** to confirm its decision points.
- [ ] **2-2: Read existing 2 test cases** at the line numbers above; identify the gap.
- [ ] **2-3: Add the missing test case** to `runGitLabPolicyCases(t, "ISSUE-101", ...)` block (or `TestIssue101_*` if it lives in its own function).
- [ ] **2-4: Run** `make embed && go test ./policies/ -run TestIssue101 -v` — expect PASS.
- [ ] **2-5: Add `containerImageMustComeFromAuthorizedSources`** to `defaultEnabledGitHubControls` in `cmd/analyze_github.go`.
- [ ] **2-6: Commit:**
  ```
  test(policies): cover authorized image sources third case; enable on GitHub
  ```

**Acceptance:** Control appears in default GitHub findings; rule has ≥3 distinct test fixtures.

---

# Phase 3 — Sprint 1: promote 5 lightly-tested to fully tested

**Status:** not started (blocked on Phase 1)

**Goal:** Bring 5 lightly-tested controls (each with 1–2 tests) to ≥3 tests each, then bulk-enable on GitHub. End state after Phase 3: 14 controls shipping by default on GitHub.

### Test pattern reference

The codebase uses table-driven tests via the `runGitLabPolicyCases` (or sibling) helper. Reference: `TestIssue203_DebugTrace` at `policies/rules_test.go:781`. Shape:

```go
runGitLabPolicyCases(t, "ISSUE-XXX", []policyCase{
    {
        name: "descriptive_pass_case",
        yaml: `
stages: [test]
test:
  image: alpine:3.19
  script: ["echo ok"]
`,
        cfg:  `controls:\n  someControl:\n    enabled: true`,
        want: 0,
    },
    {
        name: "descriptive_fail_case",
        yaml: `...`,
        wantCodes: []string{"ISSUE-XXX"},
    },
})
```

For GitHub-side controls, build the IR via the GitHub fixture path. Reference: `TestIssue414_DangerousTriggers` at `policies/rules_test.go:409`.

### Tasks (Phase 3)

- [ ] **3-1: `pipelineMustNotIncludeHardcodedJobs`** (ISSUE-401, `policies/hardcoded_jobs.rego`, 20 LOC, 1 test → need 2 more)
  - Pass case: every job sourced from include/extend, no inline jobs.
  - Fail case: one locally-defined job alongside includes.
  - Existing test block: `TestIssue401_HardcodedJobs` at `rules_test.go:1114`.
  - Commit: `test(policies): expand hardcoded_jobs coverage`

- [ ] **3-2: `pipelineMustNotEnableDebugTrace`** (ISSUE-203, `policies/debug_trace.rego`, 60 LOC, 2 tests → need 1 more)
  - Add a configurable equivalent variable case (e.g. `CI_DEBUG_SERVICES: "true"` if not already covered, or env-level vs job-level distinction).
  - Existing test block: `TestIssue203_DebugTrace` at `rules_test.go:781`.
  - Commit: `test(policies): debug_trace covers configurable equivalents`

- [ ] **3-3: `pipelineMustNotExecuteUnverifiedScripts`** (ISSUE-411, `policies/unverified_scripts.rego`, 47 LOC, 2 tests → need 1 more)
  - Add a trusted-URL allowlist case: `curl https://trusted.example/install.sh | bash` passes when host is in `trustedUrls`.
  - Existing test block: `TestIssue411_UnverifiedScripts` at `rules_test.go:794`.
  - Commit: `test(policies): unverified_scripts covers trusted host allowlist`

- [ ] **3-4: `pipelineMustNotOverrideJobVariables`** (ISSUE-205, `policies/job_variable_override.rego`, 57 LOC, 2 tests → need 1 more)
  - Add a `default:` block override case (variable set in `default.variables` instead of job-level `variables`) → should still fire.
  - Commit: `test(policies): job_variable_override covers default-block overrides`

- [ ] **3-5: `pipelineMustNotUseUnsafeVariableExpansion`** (ISSUE-204, `policies/unsafe_variable_expansion.rego`, 92 LOC, 2 tests → need 1 more)
  - Add an `eval` re-interpretation case OR a `source <(...)` case, whichever is the gap.
  - Existing test block: `TestIssue204_UnsafeVariableExpansion` at `rules_test.go:1098`.
  - Commit: `test(policies): unsafe_variable_expansion covers eval re-interpretation`

- [ ] **3-6: `pullRequestTargetMustNotCheckoutHead`** (ISSUE-415, `policies/pull_request_target_head_checkout.rego`, 51 LOC, 2 tests → need 1 more)
  - Add a "no checkout at all" case: `pull_request_target` workflow with no `actions/checkout` step → no finding (must not over-fire).
  - Commit: `test(policies): pwn-request rule does not over-fire on no-checkout`

- [ ] **3-7: Bulk-enable** the 6 names (the 5 above + `containerImageMustComeFromAuthorizedSources` from Phase 2 if not already done) by appending to `defaultEnabledGitHubControls`.
  - Run `make embed && make test`.
  - Commit:
    ```
    feat(github): enable 6 additional controls in default analyze set
    ```

**Acceptance after Phase 3:** 14 controls shipping by default on the GitHub path. All 14 GitLab-parity-eligible controls except `branchMustBeProtected` are covered.

---

# Phase 4 — Sprint 2: backfill 4 untested controls

**Status:** not started (blocked on Phase 1)

**Goal:** Bring 4 controls from untested (rule body but 0 tests) to tested. Risk: rule body may not actually fire. **For each control: write a fail case FIRST and run it against the current rego — if it doesn't fire, the rego is broken and must be fixed before adding the pass case.**

### Tasks (Phase 4)

- [ ] **4-1: `includesMustBeUpToDate`** (ISSUE-403, `policies/includes_outdated.rego`, 52 LOC, 0 tests)
  - Fail case: include with version metadata behind latest catalog version → ISSUE-403.
  - Pass case: include at latest version.
  - Pass case: include with no version metadata → no finding (unknown ≠ outdated).
  - Existing block: `TestIssue403_IncludesOutdated` at `rules_test.go:803`.
  - Commit: `test(policies): cover includes_outdated rule`

- [ ] **4-2: `includesMustNotUseForbiddenVersions`** (ISSUE-404, `policies/includes_forbidden_version.rego`, 40 LOC, 0 tests)
  - Fail case: include using `latest` or `main`.
  - Pass case: include using a tagged semver.
  - Pass case: forbidden pattern configured to empty list → no findings.
  - Existing block: `TestIssue404_IncludesForbiddenVersion` at `rules_test.go:1060`.
  - Commit: `test(policies): cover includes_forbidden_version rule`

- [ ] **4-3: `pipelineMustIncludeComponent`** (ISSUE-408 + ISSUE-409, `policies/component_missing.rego` + `policies/component_overridden.rego`)
  - Fail case ISSUE-408: required component absent.
  - Fail case ISSUE-409: required component present but overridden by hardcoded job.
  - Pass case: required component present, no overrides.
  - Commit: `test(policies): cover component_missing + component_overridden`

- [ ] **4-4: `pipelineMustIncludeTemplate`** (ISSUE-405 + ISSUE-406, `policies/template_missing.rego` + `policies/template_overridden.rego`)
  - Same shape as 4-3 but for templates.
  - Commit: `test(policies): cover template_missing + template_overridden`

- [ ] **4-5: Bulk-enable** the 4 names by appending to `defaultEnabledGitHubControls`. Run `make test`. Commit:
  ```
  feat(github): enable 4 backfilled controls (includes/components/templates)
  ```

**Acceptance after Phase 4:** 18 controls shipping by default. Of the 14 GitLab parity controls, 13 ship on GitHub (only `branchMustBeProtected` remains).

---

# Phase 5 — Sprint 3: branch protection collector + auth UX

Two independent pieces (5A and 5B). They can be done in parallel by different agents/sessions if needed.

## Phase 5A — GitHub branch protection collector

**Status:** not started (blocked on Phase 1)

**Goal:** Wire `branchMustBeProtected` into the GitHub path by building a collector that calls the GitHub branch-protection API and populates the same IR shape the existing rego rules read.

### Files

- Create: `collector/github_branch_protection.go`
- Create: `collector/github_branch_protection_test.go`
- Modify: `collector/github_workflows.go` — call the new collector during scan; populate the IR field the rego reads.
- Modify (maybe): `policies/branch_non_compliant.rego` and `policies/branch_unprotected.rego` — only if the existing input keys (`input.pipeline.branches[*]`) need to be renamed; prefer to match existing keys exactly so rego is unchanged.
- Modify: `cmd/analyze_github.go` — surface "branch protection skipped: gh not authenticated" in the auth banner (Phase 5B).
- Modify: `cmd/analyze_github.go` — add `branchMustBeProtected` to `defaultEnabledGitHubControls`.

### Approach

- Reuse the `cli/go-gh` REST client pattern from `collector/github_metadata.go:115` (`api.DefaultRESTClient()`).
- Endpoint: `GET /repos/{owner}/{repo}/branches/{branch}/protection`.
- Map response → same IR shape `dataCollectionGitlabProtection.go` populates so existing rego rules apply unchanged.
- Degraded mode: same contract as `GitHubMetadataClient` — empty result, no crash, surface in the auth banner.

### Tasks (Phase 5A)

- [ ] **5A-1: Read `collector/dataCollectionGitlabProtection.go`** to learn the GitLab IR shape (target structure to match).
- [ ] **5A-2: Read `policies/branch_non_compliant.rego` + `policies/branch_unprotected.rego`** to confirm exact `input.pipeline.branches[*]` key names.
- [ ] **5A-3: Write failing test** in `collector/github_branch_protection_test.go` using `httptest.NewServer` to fake the GitHub API. Cover: protected branch, unprotected branch, branch absent, API 404, degraded (no auth).
- [ ] **5A-4: Implement `FetchGitHubBranchProtection`** following the metadata client pattern (auth via go-gh, cache, degraded-mode contract).
- [ ] **5A-5: Wire into `ScanGitHubWorkflowsWithProgress`** — populate the IR field the rego rules read.
- [ ] **5A-6: Adapt rego if key names differ** — small edit to one or both branch rules if needed; otherwise unchanged.
- [ ] **5A-7: Run existing `TestIssue501_*` and `TestIssue505_*`** with a GitHub IR fixture. Should pass without rego logic changes (only IR shape needs to match).
- [ ] **5A-8: Add `branchMustBeProtected`** to `defaultEnabledGitHubControls`.
- [ ] **5A-9: Commit:**
  ```
  feat(github): collect branch protection via gh API; enables ISSUE-501/505
  ```

## Phase 5B — Auth UX banner + `requireAuth` knob + engine cleanup

**Status:** not started (blocked on Phase 0)

**Goal:** Make GitHub's auth state visible to the user. Add `github.auth.requireAuth` for opt-in hard-fail. Tidy stale comments.

### Files

- Modify: `collector/github_metadata.go` — add public helpers:
  - `func (c *GitHubMetadataClient) Available() bool` (check if exists; if so, leave as-is).
  - `func (c *GitHubMetadataClient) AuthHelp() string` returning `"Run 'gh auth login' or set GH_TOKEN / GITHUB_TOKEN to enable API-backed controls."`.
  - `func APIBackedControls() []string` listing controls that depend on the API: `[]string{"actionsMustNotBeArchived", "actionsMustNotCarryKnownCVEs", "actionRefsMustExistUpstream", "actionPinsMustNotBeStale", "branchMustBeProtected"}`.
- Modify: `cmd/analyze_github.go`:
  - At top of `runGitHubAnalyze` (after project detection, before scanning), print:
    ```
    GitHub API: authenticated (via gh auth login)        — all controls active
        OR
    GitHub API: not authenticated                        — N controls require auth
        Skipped: actionsMustNotBeArchived, actionsMustNotCarryKnownCVEs, ...
        Run 'gh auth login' or set GH_TOKEN / GITHUB_TOKEN to enable.
    ```
  - If `conf.PlumberConfig.GitHub.Auth.RequireAuth == true` AND not authenticated → return error (hard-fail).
  - Fix the stale comment at lines 18-20: rewrite to reflect that the API IS called when credentials are available.
- Modify: `README.md` — clarify GitHub auth model in the same section that currently claims "tokenless".

### Tasks (Phase 5B)

- [ ] **5B-1: Add `Available()`, `AuthHelp()`, `APIBackedControls()` helpers** with unit tests. Use `PLUMBER_DISABLE_GITHUB_API=1` (existing env var, see `collector/github_metadata.go:19`) to simulate degraded mode.
- [ ] **5B-2: Print the banner** in `runGitHubAnalyze`. Test with `PLUMBER_DISABLE_GITHUB_API=1 ./plumber analyze`.
- [ ] **5B-3: Implement `requireAuth` hard-fail** when `PlumberConfig.GitHub.Auth.RequireAuth == true` and `Available() == false`. Return clear error with remediation.
- [ ] **5B-4: Update stale comments** in `cmd/analyze_github.go:18-20` and the README "GitHub" section so docs and code agree.
- [ ] **5B-5: Commit:**
  ```
  feat(github): visible auth-state banner + opt-in requireAuth hard-fail
  ```

**Acceptance for Phase 5:**
- Full 14/14 GitLab parity on GitHub + 5 GitHub-native = **19 controls shipping by default**.
- Running with no auth shows the banner; setting `github.auth.requireAuth: true` exits non-zero.
- `gh auth login` then re-run flips the banner to "authenticated".

## Phase 5C — Upstream fetch for GitHub (`--project` polymorphism)

**Status:** not started (blocked on Phase 1)

**Goal:** Bring GitHub up to GitLab parity for the "scan a project I haven't checked out locally" flow. Today GitLab supports `--gitlab-url + --project + GITLAB_TOKEN` to fetch and analyze any upstream project. GitHub has no equivalent — `./plumber analyze` only works inside a local clone. Security teams auditing many repositories need the upstream-fetch flow on GitHub too.

**Design:**

- `--project` becomes provider-polymorphic. Disambiguation rule:
  - `--gitlab-url` set → GitLab path. `--project` interpreted as GitLab project.
  - `--github-url` set → GitHub path. `--project` interpreted as GitHub `owner/repo` on that host.
  - Neither set → auto-detect from git origin (current behaviour).
  - Both set → error "ambiguous provider; pass exactly one of --gitlab-url / --github-url".
- `--branch` carries the same meaning on both providers: when set, fetch CI YAMLs from that ref instead of the project's default branch.
- A new entry point `collector.ScanGitHubWorkflowsRemote(host, owner, repo, ref string, enrichActionMetadata bool, progressFn ProgressFunc)` fetches `.github/workflows/*.yml` via the GitHub Contents API and runs them through the same parser used by the local scanner. Auth via `GH_TOKEN` / `GH_ENTERPRISE_TOKEN` (token mandatory in this mode — public repos rate-limit aggressively).
- `cmd/analyze_github.go` gets a remote-mode branch: when `--project` is set, route to `ScanGitHubWorkflowsRemote` and skip the local repo scan + Dockerfile/dependabot/SECURITY.md collectors (those need a checkout).

**Tasks:**

- [ ] **5C-1: Polymorphic dispatch in `cmd/analyze.go`.** Add `githubURLFromFlag := cmd.Flags().Changed("github-url")`. Build a `chooseProvider()` helper returning "gitlab" | "github" with the disambiguation rule above. Validate "both URL flags set" → error.
- [ ] **5C-2: Add `collector.ScanGitHubWorkflowsRemote`.** New file `collector/github_workflows_remote.go`. Lists workflows via `GET /repos/{o}/{r}/contents/.github/workflows?ref={ref}`, fetches each (Base64-decode the `content` field). Returns the same `*ir.NormalizedPipeline` shape as the local scanner. Reuses the existing `parseWorkflowYAML` (refactor that helper out of `ScanGitHubWorkflowsWithProgress` if needed).
- [ ] **5C-3: Wire remote-mode in `runGitHubAnalyze`.** Detect "are we in remote mode?" from flags; if so, call `ScanGitHubWorkflowsRemote(conf.GithubAPIHost, owner, repo, ref, ...)` instead of `ScanGitHubWorkflowsWithProgress`. Skip local-repo collectors. Set `result.CIConfigSource = "remote"`.
- [ ] **5C-4: Auth gate.** Remote mode requires a token. If neither `GH_TOKEN`, `GH_ENTERPRISE_TOKEN`, nor `gh auth` is available, exit with a clear "remote scan requires GitHub authentication" error. Local-clone mode keeps soft-degrade.
- [ ] **5C-5: Tests.** Add `collector/github_workflows_remote_test.go` using `httptest.NewServer` to fake the Contents API. Cover: list-then-fetch happy path, 404 → no workflows, partial Base64 errors, rate-limit response.
- [ ] **5C-6: README.** Replace the current "GitHub" Step 4 examples with both modes (local + remote) so users see the symmetry with GitLab.

**Acceptance:** `plumber analyze --github-url github.com --project getplumber/plumber --branch main` (with `GH_TOKEN` set) produces the same per-control parity output a local scan would, without any clone on disk.

**Out of scope:** Dockerfile / dependabot / SECURITY.md scans require local files. In remote mode the controls that depend on them simply see absent inputs and produce no findings (same degraded-mode contract as missing API auth elsewhere). Future work could fetch those files via the Contents API too.

---

# Phase 6 — Cross-cutting documentation

**Status:** not started (blocked on Phases 1–5)

Run after all functional Phases land.

- [ ] **6-1: Update README "Available Controls"** — split into a GitLab table and a GitHub Actions table mirroring the GitLab one. Add a "Bench (experimental, disabled by default)" subsection listing the ~30 non-tier-1 controls.
- [ ] **6-2: Update `docs/GITLAB_REGO_PARITY.md`** to mark all 14 GitLab controls as "GitHub: shipping" (or footnote `branchMustBeProtected` if Phase 5A is deferred).
- [ ] **6-3: Update `docs/REFACTOR_MULTI_PROVIDER.md`** to describe the v2 schema, the per-provider auth model, and that engine.enabled is gone.
- [ ] **6-4: README "Configuration" section** — show v2 example, link to `docs/plumber-yaml-v2-migration.md`, document YAML anchor pattern for cross-provider deduplication.
- [ ] **6-5: README "Authentication" subsection per provider**:
  - GitLab: token mandatory.
  - GitHub: `gh auth login` or `GH_TOKEN`/`GITHUB_TOKEN`; soft-degrades by default; `github.auth.requireAuth: true` to enforce.
- [ ] **6-6: ~~`CHANGELOG.md` entries~~ — N/A**: this repo's CHANGELOG is auto-generated by semantic-release from Conventional Commit messages. Make sure each commit message is well-scoped and descriptive (`feat(github)!: per-provider schema`, `feat(cli): plumber config migrate`, etc.) and the changelog will follow.
- [ ] **6-7: `make lint && make test`** end-to-end, fix anything that moves, final commit.

---

## Verification gate (run after each Phase)

```bash
make embed && make test
make lint
./plumber analyze --project-path ./testdata/<gitlab|github>/<fixture>  # if a fixture exists
```

Expected at end of plan:
- 19 control names appear in default analyze output on a known-bad GitHub fixture.
- `gh auth logout && plumber analyze` shows degraded banner + reduced control set, no crash.
- Setting `github.auth.requireAuth: true` and rerunning with no auth → exit non-zero with clear remediation message.
- `git log --oneline` shows ~20 small focused commits, all conventional-commits formatted.
- `plumber config migrate` upgrades a v1 fixture to a working v2 file.

---

## Out-of-plan follow-ups (capture, do not implement here)

These are real but separate efforts:

1. **Per-control compliance averaging on GitHub** — replace binary 0/100 in `cmd/analyze_github.go:94`. Bring scoring parity with GitLab.
2. **Promote bench controls** (the ~30 extras outside tier-1) one batch at a time as test coverage materializes. Same Phase 3/Phase 4 pattern.
3. **Integration tests for API-backed controls** (`actionsMustNotBeArchived`, `actionsMustNotCarryKnownCVEs`) using a recorded VCR-style HTTP fixture so we test the rego against real-shaped API responses.
4. **GitLab `auth.token` in `.plumber.yaml`** — currently the GitLab token is CLI-flag/env-only. Could move under `gitlab.auth.token` for consistency with the GitHub `auth.requireAuth` pattern. Likely defer for security reasons (don't want users committing tokens to YAML).
5. **1.0 release** — drop v1 schema support. Run after a stable 0.3.x has been out long enough that telemetry / issue traffic shows users have migrated.
6. **Provider auto-detection edge cases** — what if a repo has both `.gitlab-ci.yml` AND `.github/workflows/`? Today `cmd/analyze.go` chooses one based on `utils.GitRemoteInfo`. Worth a separate spec.

---

## Notes for future sessions / other LLMs picking this up

- **Branch:** all work happens on `refacto-rego` (or a derived feature branch off it). Do not branch from `main`.
- **The `.plumber.yaml` is currently in a half-migrated state** (v2 schema in YAML, v1 expectations in Go). Phase 0 is the only Phase that can ship until this is resolved. Do not attempt Phase 1+ before Phase 0 lands.
- **Always run `make embed` before `go test`** — embedded default config matters.
- **Do not edit `internal/defaultconfig/default.yaml` by hand** — it's generated.
- **Conventional Commits required**, scoped to package (`feat(github):`, `fix(config):`, `chore(release):`).
- **Releases are bot-generated** via `chore(release): ...` commits — do not hand-author release commits.
- **`docs/REFACTOR_MULTI_PROVIDER.md`** is the historical context document; consult before making architectural decisions.
- **The audit verdicts (fully/lightly/untested) are point-in-time** as of 2026-05-06. Re-run `grep -c "ISSUE-XXX" policies/rules_test.go` to verify current test counts before assuming a Phase task is still needed.
- **The existing `cli/go-gh` integration is the auth layer** — do not roll a separate token-handling path. `api.DefaultRESTClient()` already does the right thing.
