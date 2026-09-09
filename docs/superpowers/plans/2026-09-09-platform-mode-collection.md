# Platform-Mode Snapshot Lanes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In platform mode, `mergeRequestSettingsMustBeCompliant` (ISSUE-506) and `projectMustHaveSecurityPolicySource` (ISSUE-601) evaluate from the platform snapshot instead of reporting `lane_not_served`; the CLI decodes the snapshot fields the platform has served since 2026-08-27/28 (`project_details`, `security_policy_project`, `raw_config`, `merged_yaml_status`, `ci_errors`) and recognizes the four `degraded_fields` identifiers it currently lacks.

**Architecture:** Extend the EXISTING platform-mode machinery (`internal/platform` wire types, `gitlab/snapshot.go` lane decoders, `control/lanes.go` lane tables, the `RunAnalysis` platform branches in `control/task.go`); no new package. Every new lane follows the served/degraded/absent discipline the protection and variables lanes already implement.

**Tech Stack:** Go (module `github.com/getplumber/plumber`), golangci-lint v2 (`make lint`), Makefile deadcode target, `go test ./...`.

**Spec:** `docs/superpowers/specs/2026-09-09-platform-mode-collection-design.md` (rewritten 2026-09-09; the earlier draft's premise was stale). The revert commit ad9e93f removed the duplicate `cidigest` package that draft produced.

## Global Constraints

- English. No em dashes / smart quotes anywhere (byte-scan every diff). Conventional commits, lowercase subject, header <= 100 chars.
- Behavior outside platform mode is byte-identical; all new paths are gated on `conf.PlatformRun.Engaged()` (or inside functions only reached from it).
- Honest absence: a lane listed in `degraded_fields` -> `snapshot_lane_degraded` (`not_evaluable`); an absent `project_details` or `security_policy_project` -> the control stays `not_evaluable` (never a fabricated empty setting); values are never invented.
- Read the current code on THIS branch (origin/main + the plan/spec commits), never the clone's main checkout (it is stale at v0.4.44).
- Tests: `go test ./...`, `make lint`, and the deadcode target before every commit; foreground, one Bash call per run. Work in `/root/workspace/github.com/getplumber/plumber/.claude/worktrees/platform-mode-collection` (branch `platform-mode-collection`).
- Do not modify `gitlab.ToNormalizedPipeline`'s signature, any Rego control, scoring, or the push payload.

---

### Task 1: decode the served fields and recognize the four degraded identifiers

**Files:**
- Modify: `internal/platform/types.go` (`SnapshotData` ~:158-204; `DegradedField*` const block ~:206-215)
- Test: `internal/platform/types_test.go` (or the existing decode test file in that package: check `ls internal/platform/*_test.go`)

**Interfaces:**
- Produces on `SnapshotData`: `ProjectDetails *ProjectDetails` (`json:"project_details,omitempty"`) with `DefaultBranch string`, `Archived bool`, `PathWithNamespace string`, and eight optional pointers `MergeMethod *string`, `SquashOption *string`, `MergePipelinesEnabled *bool`, `MergeTrainsEnabled *bool`, `AllowMergeOnSkippedPipeline *bool`, `ResolveOutdatedDiffDiscussions *bool`, `PrintingMergeRequestLinkEnabled *bool`, `RemoveSourceBranchAfterMerge *bool` (pointers because the contract marks them optional on snapshots stored before 2026-08-28); `SecurityPolicyProject *SecurityPolicyProject` (`Known bool`, `ID *int`, `FullPath *string`); `RawConfig string` (`raw_config`), `MergedYamlStatus string` (`merged_yaml_status`), `CiErrors []string` (`ci_errors`). Constants `DegradedFieldRawConfig = "raw_config"`, `DegradedFieldSourceCatalog = "source_catalog"`, `DegradedFieldSecurityPolicyProject = "security_policy_project"`, `DegradedFieldIncludesJobs = "includes_jobs"`.

- [ ] **Step 1: RED.** Decode test over a schema-2 JSON body carrying every new field (copy the shapes from the platform contract: monorepo `docs/contracts/openapi.yaml` `ProjectContext.snapshot.data`, READ-ONLY at /root/workspace/github.com/getplumber/monorepo/.claude/worktrees/portfolio-batch/docs/contracts/openapi.yaml) asserting each field; a body omitting the merge settings decodes with nil pointers; the four new identifiers are members of whatever closed-set helper exists (grep `DegradedField` usages, e.g. a `knownDegradedFields`/`IsDegraded` helper) and an unknown identifier still passes through. Run `go test ./internal/platform/`: failures.
- [ ] **Step 2: GREEN.** Add the fields and constants; update the `SnapshotData` doc comment (which currently says several of these are absent by design: correct it). `go test ./internal/platform/`; `make lint`. Commit `feat(platform): decode project details, security policy, raw config and merge status from the snapshot`.

### Task 2: serve the two lanes from the snapshot

**Files:**
- Modify: `gitlab/snapshot.go` (`ProtectionFromSnapshot` ~:98-190: populate `MRSettings`; new `SecurityPolicyFromSnapshot`), `control/lanes.go` (`controlsWithNoPlatformLane` ~:521-524: remove both entries; the degraded-lane mapping tables: add `project_details -> mergeRequestSettingsMustBeCompliant` and `security_policy_project -> projectMustHaveSecurityPolicySource`; update the now-false comments ~:505-520 and the `gitlab/snapshot.go` ~:95 comment), `control/task.go` (~:1049: in platform mode read `gitlab.SecurityPolicyFromSnapshot(conf.PlatformRun)` instead of skipping; ~:991 the protection branch already consumes `ProtectionFromSnapshot`, so `MRSettings` flows with no change; verify `mrSettingsPremiumFieldsNeedingUpgrade` ~:1079 behaves with a snapshot-sourced `MRSettings`).
- Read first: `gitlab/gitlab_ir.go` `buildMRSettings` (which `glab.Project` members it reads) and `buildSecurityPolicyProject`; `gitlab/security_policy.go:124-134` (`SecurityPolicyData`, `SecurityPolicyProjectLink`); `control/lanes.go` in full (the degraded mapping and `MarkDegradedSnapshotLanes`).
- Tests: `gitlab/snapshot_test.go` (extend), `control/lanes_test.go` (extend), `control/task_*_test.go` platform-mode end-to-end (find the existing platform-mode RunAnalysis test fixture: grep `PlatformRun` in `control/*_test.go`).

**Interfaces:**
- Consumes Task 1's fields. Produces `gitlab.SecurityPolicyFromSnapshot(run *platform.RunContext) (*SecurityPolicyData, bool)`: `served=false` when not engaged, the key absent, or `security_policy_project` degraded (then the caller leaves the data nil -> `not_evaluable`); otherwise `Known` verbatim and `Project` set iff `known && id present`. `ProtectionFromSnapshot`: `MRSettings` built from `project_details` iff present and not degraded; nil otherwise.

- [ ] **Step 1: RED.** `ProtectionFromSnapshot` with `project_details` -> `MRSettings` populated field by field (a nil pointer in the snapshot leaves the `glab.Project` zero value AND the control's premium-caveat logic untouched: read how `buildMRSettings` treats zero values and assert the honest outcome); degraded `project_details` -> `MRSettings` nil; `SecurityPolicyFromSnapshot` four cases (known+linked, known+none, known=false, degraded); lanes tests: neither control is `lane_not_served`; each is `snapshot_lane_degraded` when listed; an end-to-end platform-mode run where both controls yield real findings (or passes) from the snapshot with zero GitLab HTTP calls (reuse the existing transport spy / httptest pattern). Run the three packages: failures.
- [ ] **Step 2: GREEN.** Implement; update the stale comments. `go test ./gitlab/ ./control/ ./internal/platform/`; `make lint`; deadcode. Commit `feat(platform): evaluate merge settings and security policy from the snapshot lanes`.

### Task 3: served merge status, errors and raw config; docs

**Files:**
- Modify: `gitlab/utilsCI.go` `platformMergedConfig` (grep it): when `MergedYamlStatus`/`CiErrors` are present on the snapshot, carry them into `MergedCIConfResponse.CiConfig.Status/Errors` instead of the current synthesis (keep the synthesis as the fallback for snapshots without them); `RawConfig`: read how the two pre-merge controls obtain the root file today in platform mode (`ReasonRawConfigUnavailable` in `control/lanes.go` and its producers) and use the served `raw_config` when the checkout is not the analyzed project or the file is unreadable, gated on `DegradedFieldRawConfig`.
- Modify: `CHANGELOG.md` (Unreleased: platform mode now evaluates ISSUE-506 and ISSUE-601 from the snapshot; served merge status/errors/raw config consumed; four degraded identifiers recognized; note that `GITLAB_TOKEN` has not been required in platform mode since v0.4.50), `README.md` platform section (one sentence), `docs/superpowers/specs/2026-09-09-platform-mode-collection-design.md` status -> IMPLEMENTED.
- Tests: `gitlab/utilsCI_test.go` (or the existing platform merged-config tests) for status/errors passthrough and fallback; a raw-config-served case.

- [ ] **Step 1: RED then GREEN** for each of the three behaviors; docs; byte-scan; `go test ./...`; `make lint`; deadcode. Commit `feat(platform): use the served merge status, ci errors and raw config; document the closed lanes`.

## Self-review notes

- Coverage vs spec: decision items 1 (Task 1), 2-4 (Task 2), 5-6 (Task 3). No placeholder: every "read how X works today" is an instruction to reuse existing code paths named by file and function.
- Load-bearing tests: the lanes table (neither control `lane_not_served`), the end-to-end zero-GitLab-calls run, and the degraded -> `not_evaluable` cases.
