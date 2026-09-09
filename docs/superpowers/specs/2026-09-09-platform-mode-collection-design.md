# Platform-mode collection: no GitLab token when a platform is linked

Status: DRAFT for review (Thomas, 2026-09-09). Decision owner: Thomas (interim CLI lead).

## Problem

When `--platform` (the `platform` component input, env `PLUMBER_ANALYZE_PLATFORM`) is set, the CLI still collects every GitLab fact itself through the GitLab REST/GraphQL APIs with `GITLAB_TOKEN`, and `resolveGitLabToken` (cmd/analyze_gitlab.go) fails the run without that variable. The platform already serves the same facts on `GET /projects/{path}/context` (`snapshot.data`: branch protection, MR approval rules and settings, CI variable names and flags, merged_yaml, raw_config, includes, ci_errors, project_details, security_policy_project, degraded_fields), collected by its own sync worker with the org token (platform ADR-0021, invariant I4). The CLI decodes only `policies` from that response (cmd/platform_context.go), at push time, for policy-id stamping.

Consequences today: every onboarded project needs a `GITLAB_TOKEN` CI/CD variable that the platform then has to warn about (`gitlab_token_missing`) and document in the onboarding MR, and the CLI's run makes N provider calls per pipeline that the platform has already made once.

## Decision (Thomas, 2026-09-09)

**Platform-only collection.** When a platform is linked, the CLI never calls the GitLab API: the platform's `/context` snapshot (and `/resolved-config` for a diverging CI config, platform ADR-0034) are the only sources. `GITLAB_TOKEN` is not read on that path. Anything the snapshot cannot supply is `not_evaluable` (platform invariant I3: never a fabricated pass, never a fake verdict), never a fallback to a live read. Users without a platform keep today's token path unchanged.

Rejected alternatives: (a) snapshot-first with token fallback: two code paths whose result depends on whether a token happened to be present; (b) token optional only for merged_yaml: leaves the structural problem for every other collection.

## Design

### 1. Mode detection and sequencing

- `platformMode := effectivePlatformPush()` is already the one place that decides "a platform is configured" (the sentinel `https://platform.invalid` means not configured). Platform mode is exactly that boolean; no new flag.
- In platform mode `resolveGitLabToken` is not called. `conf.GitlabToken` stays empty and every collector short-circuits on the snapshot path before touching a client (section 3). A present `GITLAB_TOKEN` is ignored for collection (it may still be consumed by the opt-in post-actions `mr_comment` and `badge`, unchanged; see section 6).
- `/context` is fetched ONCE, BEFORE analysis, with the OIDC id-token the component already mints (`PLUMBER_ANALYZE_PLATFORM_TOKEN`, `scoreOIDCToken`). The decoded document is kept for the run: policies (for the existing policy-id stamping at push time, no second call) and `snapshot`. The current push-time `/context` call goes away.
- A `/context` failure in platform mode (transport error, non-2xx, unparseable body): the run FAILS with an explicit reason (exit code 2 class, "platform context unavailable: <reason>"), the same posture the OIDC token failure already has (`platformTokenFailure`: the platform being the data source is a dependency of the run, not a third party the pipeline is decoupled from). It is not a degraded run: with no snapshot there is nothing honest to evaluate.

### 2. Snapshot decoding

New package `platformsnap` (cmd-independent, unit-testable): decodes `snapshot.data` (schema_version "2") into the existing GitLab collector structs, so `ToNormalizedPipeline` (gitlab/gitlab_ir.go) and every control stay untouched.

| snapshot.data field | target | rule |
|---|---|---|
| `project_details` (default_branch, archived, path_with_namespace, merge_*) + `ci_config_path` | `gitlab.ProjectInfo` / project fields of `AnalysisResult` (`DefaultBranch`, `ProjectID` from `CI_PROJECT_ID`) and `GitlabProtectionAnalysisData.MRSettings` (the merge_* fields map onto the `glab.Project` members `buildMRSettings` reads) | absent project_details, or `project_details` in `degraded_fields`: `CiMissing`-class hard stop, same as a failed `FetchProjectDetails` today |
| `branch_protection.branches`, `branch_protection.protections` | `GitlabProtectionAnalysisData.Branches`, `.BranchProtections` | key absent or in `degraded_fields`: nil protection data, the existing `not_evaluable` posture for branch controls |
| `mr_approvals` (rules + settings) | `.MRApprovalRules`, `.MRApprovalRulesKnown = true`, `.MRApprovalSettings` | absent or degraded: `MRApprovalRulesKnown = false` (ISSUE-502/504 not_evaluable, exactly today's 403 path) |
| `variables` (name, type, environment, protected, masked, hidden, scope; never values) | `GitlabVariablesAnalysisData{Variables, Known: true}` | absent or degraded: `Known = false` |
| `security_policy_project` | `SecurityPolicyData{Known, Project}` | verbatim; `known=false` stays not_evaluable |
| `merged_yaml`, `merged_yaml_status`, `ci_errors`, `raw_config`, `includes`, `resolution_anchor` | `GitlabPipelineOriginData.Conf/ConfString/MergedConf/MergedResponse/CiValid/CiErrors` via a constructor that builds the same `MergedCIConfResponse` the GraphQL client returns today (includes carried as-is: the platform serves the CLI's own `MergedCIConfResponseInclude` shape verbatim) | `merged_yaml` in `degraded_fields` or absent: `CiValid=false` + degraded run, today's "pipeline configuration could not be fetched" branch |
| `degraded_fields` | drives every "absent" rule above and `markDegraded` reasons | a name here means "could not be fetched": not_evaluable, never empty-means-clean |

Forward tolerance: unknown keys ignored; a `schema_version` other than "2" is decoded best-effort with a single warning line (the platform contract promises additive evolution).

### 3. Collector short-circuits (control/task.go RunAnalysis)

`RunAnalysis` gains a `conf.PlatformSnapshot *platformsnap.Snapshot` input (nil outside platform mode). Each step reads it first:

1. Project info: from the snapshot (section 2) instead of `FetchProjectDetails`; `LatestHeadCommitSha` from `CI_COMMIT_SHA`; `FetchLatestCommitSha` for a non-default `--branch` is replaced by the CI env (the job runs on that branch).
2. CI config source: unchanged priority (local checkout file when the repo IS the analyzed project, which is the normal component run). Merged config: `resolution_anchor.config_digest` is compared with the CLI's own digest of the checkout (the digest the platform's `/resolved-config` contract expects; `digest_version` versions never mix). Equal: use the snapshot's merged_yaml/includes/ci_errors. Different or absent: `POST /projects/{path}/resolved-config {sha, config_digest, digest_version}` (Bearer = the same OIDC token) and use its `merged_yaml/includes/ci_errors/valid`; a 503 (`ResolveUnavailable`) or any failure: `CiValid=false` + degraded run, never a live GitLab merge. This is ADR-0034 rule 3 step 4 as the platform contract already documents it; the CLI-side digest routine is part of this work (there is none today).
3. Pipeline origins: built from the merged config + includes as today, but the include-version facts that need the API (`GetGitlabCIComponentResource`, catalog latest version, `BranchExists`, `FetchGitlabInclude` for remote includes) are NOT fetched: `UpToDate`, `LatestVersion`, `RefIsAmbiguous` are unknown -> the controls that read them (`includesMustBeUpToDate`, `includesMustNotUseForbiddenVersions` where it needs upstream facts) report `not_evaluable` in platform mode v1. Follow-up (platform side, rule J): the sync worker can collect include latest-version facts into the snapshot; then the CLI reads them here with no CLI change beyond the decoder.
4. Images: the variable expansion that reads instance/group/project variable VALUES (`GetGitlab*Variables`) has no source: an image reference that still contains an unexpanded `$VAR` after job/global variable expansion is reported as unresolved and the image controls on that job are `not_evaluable` for it (no guess, no registry default).
5. Protection, variables, security policy: from the snapshot (section 2), no collector `Run`.

Everything downstream (IR build, Rego evaluation, score, report, push) is untouched: platform mode changes where the collected structs come from, not what controls see.

### 4. Not-evaluable inventory (honest v1 scope)

Controls whose inputs the snapshot does not carry today, therefore `not_evaluable` in platform mode until the platform snapshot grows: include up-to-date / latest-version facts (section 3.3) and image references needing settings-variable values (3.4). `GitlabProtectionAnalysisData.ProjectMembers` is collected today (`FetchProjectMembers`) but has no reader in the IR build or any control, so its absence in platform mode costs nothing; the implementer confirms this with a grep and records the inventory in the CHANGELOG. Each remaining gap is a named platform follow-up, not a CLI fallback.

### 5. Error handling and exit codes

- No platform: unchanged.
- Platform configured, `/context` unreachable: run fails with reason (section 1).
- Platform reachable, snapshot degraded in part: run proceeds; degraded fields are `not_evaluable`; `DataCollectionDegraded` is set when the CI config itself is unavailable (today's semantics), the push carries the degraded marker the platform already understands (X3-20).
- A present `GITLAB_TOKEN` in platform mode: one informational line ("platform linked: GITLAB_TOKEN is not used for collection"), nothing else.

### 6. Out of scope

- `mr_comment` and `badge` post-actions keep requiring a token when enabled (provider write-backs are the platform's ADR-0031 concern, off by default).
- GitHub path: already token-free for local workflows; untouched.
- Platform-side follow-ups (separate monorepo PR on the pin bump): drop the onboarding `gitlab_token_missing` warning and the MR "Prerequisites: GITLAB_TOKEN" bullet; make the component template's `gitlab_token` input documentation say "not needed when `platform` is set"; grow the snapshot with include-version facts (section 3.3).

### 7. Testing

- `platformsnap` decoder: golden test over a captured `/context` body (schema_version 2) asserting every collector struct field; table tests for each degraded_fields name and each absent key -> the not_evaluable posture; forward-tolerance (unknown keys, newer schema_version).
- `RunAnalysis` in platform mode with an httptest platform: no GitLab client is ever constructed (a transport spy asserting zero GitLab calls); end-to-end score identical to the token path over the same fixture project when the snapshot is complete (the load-bearing parity test); `/context` down -> the failing exit; `/resolved-config` used on digest divergence and skipped on match.
- Existing suites unchanged (token path).
- Linting: golangci-lint/staticcheck locally before push (repo rule).

### 8. Rollout

One release (v0.4.57): behavior changes only when `platform` is set. The component template's `gitlab_token` input keeps its default so existing pipelines are untouched. Platform pin bump + warning removal follow in the monorepo.
