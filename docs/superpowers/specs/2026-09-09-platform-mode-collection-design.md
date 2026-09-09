# Platform mode: close the snapshot lanes the CLI does not consume yet

Status: APPROVED scope (Thomas, 2026-09-09: "Go" on the token-free platform mode); REWRITTEN the same day after the first implementation pass found the premise stale. Decision owner: Thomas (interim CLI lead).

## Correction and problem

The first draft of this spec claimed the CLI still required `GITLAB_TOKEN` when `platform` is set. That was read from a stale checkout (v0.4.44). Since v0.4.50 (`feat(platform): fetch policies and collected data from the platform`, 9e3fb7e) the CLI already runs token-free in platform mode: `cmd/platform_mode.go` (`setupPlatformMode`) fetches `/context` once before collection with the CI OIDC id-token, `resolveGitLabToken` returns empty when a platform is configured, `internal/cidigest` computes the config digest for the `/resolved-config` handshake, `gitlab/snapshot.go` decodes branch protection, MR approvals and variables from the snapshot, and `control/lanes.go` tracks per control which "lane" feeds it (snapshot, checkout, or none) so an unserved lane reports `not_evaluable` (`lane_not_served`) rather than a false pass.

What remains is narrower and real. The platform contract grew on 2026-08-27/28 (`project_details` with the eight merge settings, `security_policy_project`, `raw_config`, `merged_yaml_status`, `ci_errors`, and four more `degraded_fields` identifiers), and the CLI never caught up:

- `control/lanes.go` `controlsWithNoPlatformLane` still marks `mergeRequestSettingsMustBeCompliant` and `projectMustHaveSecurityPolicySource` as `lane_not_served`, on comments saying the snapshot carries no `project_details` and no security-policy lane. Both are served today. In platform mode those two controls (ISSUE-506, ISSUE-601) are therefore permanently `not_evaluable` for no reason.
- `internal/platform.SnapshotData` does not decode `project_details`, `security_policy_project`, `raw_config`, `merged_yaml_status`, `ci_errors`; `gitlab/utilsCI.go` synthesizes status/errors for the platform-served merged config instead of reading the served ones.
- The CLI's closed set of `DegradedField*` identifiers lacks `raw_config`, `source_catalog`, `security_policy_project`, `includes_jobs`; an unknown identifier is carried through to the operator rather than mapped to its lane.

## Decision

Extend the existing platform-mode machinery; do not add a second decoder or a second digest. Concretely:

1. `internal/platform/types.go`: `SnapshotData` gains `ProjectDetails` (typed: `default_branch`, `archived`, `path_with_namespace`, the eight merge settings, all optional), `SecurityPolicyProject` (`known`, `id`, `full_path`), `RawConfig`, `MergedYamlStatus`, `CiErrors`. The `DegradedField*` set gains the four missing identifiers, and the lane tables in `control/lanes.go` map `project_details` and `security_policy_project` to the two controls above.
2. `gitlab/snapshot.go`: `ProtectionFromSnapshot` populates `MRSettings` from `project_details` (onto the `glab.Project` members `buildMRSettings` reads: merge method, squash option, merge pipelines, merge trains, allow merge on skipped pipeline, resolve outdated diff discussions, printing MR link, remove source branch after merge) when the lane is served and not degraded; a new `SecurityPolicyFromSnapshot(run) (*SecurityPolicyData, bool)` returns `Known` verbatim and the linked project when present. Both follow the existing served/degraded discipline of the other lanes.
3. `control/lanes.go`: the two controls leave `controlsWithNoPlatformLane`; their lanes join the degraded-lane mapping (degraded `project_details` -> `mergeRequestSettingsMustBeCompliant`, degraded `security_policy_project` -> `projectMustHaveSecurityPolicySource`) and, for `project_details`, `lanesWhoseAbsenceIsAFailure` is NOT extended (an absent project_details is a collection failure, never "no settings"; the control stays `not_evaluable` on absence, consistent with today's `FetchProjectDetails` hard stop).
4. `control/task.go`: `CollectSecurityPolicy` short-circuits on the snapshot in platform mode (today it is skipped entirely when `PlatformRun.Engaged()`); the MR-settings path reads the populated `MRSettings` with no further change.
5. `gitlab/utilsCI.go` `platformMergedConfig`: use the served `merged_yaml_status` and `ci_errors` when present (fall back to today's synthesis only when the platform omits them, older snapshots), carry `raw_config` where the two pre-merge controls need the root file and the checkout is not the analyzed project.
6. Docs: `CHANGELOG.md` entry (platform mode now evaluates ISSUE-506 and ISSUE-601 from the snapshot; the four degraded identifiers recognized), `README` platform section note.

Out of scope: everything the first draft proposed that already exists (token skipping, pre-analysis context fetch, digest, resolve handshake, protection/variables lanes); `mr_comment`/`badge` still need a token when enabled; the platform-side removal of its obsolete `gitlab_token_missing` onboarding warning and MR bullet is a monorepo change tracked there.

## Testing

Unit: `internal/platform` decode of a schema-2 body carrying every new field; `gitlab.ProtectionFromSnapshot` populates `MRSettings` field by field from `project_details` and leaves it nil when the lane is degraded or absent; `SecurityPolicyFromSnapshot` Known/linked/none/degraded cases; `control/lanes.go` table tests: neither control is `lane_not_served` any more, each is `snapshot_lane_degraded` when its lane is listed in `degraded_fields`; an end-to-end platform-mode `RunAnalysis` (existing httptest fixture pattern) where `mergeRequestSettingsMustBeCompliant` and `projectMustHaveSecurityPolicySource` produce real findings from the snapshot with zero GitLab calls. Lint: `make lint` + the deadcode target.

## Rollout

One release (next patch after v0.4.56); no behavior change outside platform mode; the platform pins the CLI module afterwards (no contract change needed: the fields were already served).
