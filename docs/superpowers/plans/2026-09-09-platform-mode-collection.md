# Platform-Mode Collection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a platform is linked (`--platform` / `PLUMBER_ANALYZE_PLATFORM` set to a real URL), the CLI never calls the GitLab API and never reads `GITLAB_TOKEN` for collection: the platform's `/context` snapshot (and `/resolved-config` when the CI config digest diverges) are the only data sources; anything the snapshot cannot supply is `not_evaluable`.

**Architecture:** Five additive pieces, no behavior change without a platform. (1) `cidigest`: a byte-for-byte replica of the platform's pure digest_v1 package (ADR-0034 rule 1) so the CLI can compare its checkout's CI config against the snapshot anchor. (2) `platformsnap`: decodes `/context`'s `snapshot.data` (schema_version "2") into the EXISTING GitLab collector structs (`gitlab.ProjectInfo`, `GitlabProtectionAnalysisData`, `GitlabVariablesAnalysisData`, `SecurityPolicyData`, `MergedCIConfResponse`) so `gitlab.ToNormalizedPipeline`, every control, scoring and the push stay untouched. (3) `cmd`: one pre-analysis `/context` fetch (OIDC id-token, `PLUMBER_ANALYZE_PLATFORM_TOKEN`) whose decoded document is kept for the run (policies for the existing push-time policy-id stamping, snapshot for collection); `resolveGitLabToken` skipped in platform mode; a `/context` failure fails the run (exit 2 class). (4) `control.RunAnalysis`: each collection step reads `conf.PlatformSnapshot` first and never constructs a GitLab client when it is set. (5) Docs: template input comment, README, CHANGELOG.

**Tech Stack:** Go (module `github.com/getplumber/plumber`), cobra, gopkg.in/yaml.v3, golangci-lint v2 (`make lint`), deadcode check (Makefile), `go test ./...`.

**Spec:** `docs/superpowers/specs/2026-09-09-platform-mode-collection-design.md` (approved by Thomas 2026-09-09: platform-only, token ignored; fail the run on a `/context` outage; the two not_evaluable families accepted for v1).

## Global Constraints

- English. No em dashes / smart quotes anywhere (byte-scan every diff). Conventional commits (`feat|fix|docs|test|refactor|chore(scope): lowercase subject`, header <= 100 chars to stay well inside this repo's conventions; lead word lowercase).
- Behavior outside platform mode is byte-identical: every existing test passes unchanged; new code paths are gated on `conf.PlatformSnapshot != nil` (or the `effectivePlatformPush()` predicate in `cmd`).
- Never a fabricated pass: a snapshot field named in `degraded_fields`, or absent, yields the SAME struct state today's failed fetch yields (nil protection data, `Known=false`, `MRApprovalRulesKnown=false`, `CiValid=false` + degraded run), never an empty-means-clean value. Never a live GitLab fallback in platform mode.
- The digest replica is WIRE-STABLE: `Compute` and `Traverse` must reproduce the platform's `platform/backend/cidigest` byte-for-byte (the monorepo checkout at `/root/workspace/github.com/getplumber/monorepo/.claude/worktrees/portfolio-batch/platform/backend/cidigest/{digest.go,traverse.go}` is the reference; copy the construction, keep `Version = "1"`, `prefix = "plumber-ci-digest/v1\n"`, `absentMarker = "ABSENT"`, `MaxFiles = 50`, abort semantics). Golden vectors (computed with the platform package, 2026-09-09) MUST pass:
  - vector1: files `{".gitlab-ci.yml": "include:\n  - local: ci/a.yml\nbuild:\n  script: make\n", "ci/a.yml": "test:\n  script: go test ./...\n"}` -> `3764764fe11d900c53f379e64f76dc3b3caea9f35585d843f2bdf6dfed59cfe6`
  - vector2: `{".gitlab-ci.yml": "include: ci/missing.yml\n", "ci/missing.yml": Absent}` -> `1dd84b96d3982eff5a7f7fbedc1acaa73d4ce4906c4358ab9db96aaee9fec189`
  - vector3: `{".gitlab-ci.yml": "build:\n  script: make\n"}` -> `1528d12b72f92bff0923675939fc248a70767402f744acde8c24c0d108a0cedf`
  - vector4 (Traverse then Compute): root `.gitlab-ci.yml` = `"include:\n  - local: /ci/a.yml\n  - remote: https://example.com/x.yml\n  - ci/b.yml\n  - { local: ./ci/a.yml }\n"`, `ci/a.yml` = `"include: { local: ci/c.yml }\n"`, `ci/b.yml` -> ErrNotFound, `ci/c.yml` = `"x: 1\n"` => visited set `{.gitlab-ci.yml, ci/a.yml, ci/b.yml (Absent), ci/c.yml}` -> `b428728cabc8be05f026a263f97b5ca4723970f4b4923fcc7d65e88990156b5b`.
- Tests: `go test ./...` (fast, no DB) plus `make lint` and the Makefile deadcode check before every commit; foreground, one Bash call per run. Work from the CLI worktree `/root/workspace/github.com/getplumber/plumber/.claude/worktrees/platform-mode-collection` (branch `platform-mode-collection`); never touch the monorepo.
- Do not modify `gitlab.ToNormalizedPipeline`, any control, the scoring, or the push payload.

---

### Task 1: `cidigest` replica

**Files:**
- Create: `cidigest/digest.go`, `cidigest/traverse.go`, `cidigest/digest_test.go`, `cidigest/traverse_test.go`

**Interfaces:**
- Produces: `cidigest.Version = "1"`, `cidigest.Compute(files map[string][]byte) string`, `cidigest.Traverse(root string, fetch func(path string) ([]byte, error)) (map[string][]byte, error)`, `cidigest.Absent []byte` (identity sentinel), `cidigest.ErrNotFound`, `cidigest.ErrTooManyFiles`, `cidigest.MaxFiles = 50`.

- [ ] **Step 1: RED.** Write `digest_test.go` with the four golden vectors above (vector4 through a fake fetch), a test that `Absent` is recognized by identity not content (a fresh `[]byte("cidigest:absent")` digests as content), and `traverse_test.go`: cycle safety (A includes B includes A), the 51st distinct file aborts with `ErrTooManyFiles`, a non-ErrNotFound fetch error aborts, `normalizeIncludePath` (leading slash, `./`), the include forms (bare string, string in array, `{local:}` map, map as whole value, remote/template/component ignored). Run `go test ./cidigest/`: compile failure.
- [ ] **Step 2: GREEN.** Port the reference files (copy the construction; adapt package doc to say "replica of the platform's package, ADR-0034 rule 1; any change is a new digest_version"). Do not import anything from the monorepo. `go test ./cidigest/` green.
- [ ] **Step 3:** `make lint`; commit `feat(cidigest): add the wire-stable ci config digest_v1 replica (ADR-0034 rule 1)`.

### Task 2: `platformsnap` decoder

**Files:**
- Create: `platformsnap/snapshot.go` (types + `Decode`), `platformsnap/collectors.go` (projections onto gitlab structs), `platformsnap/snapshot_test.go`, `platformsnap/testdata/context_v2.json` (a captured-shape body)
- Read first: `gitlab/utilsCI.go:134-144` (`ProjectInfo`), `gitlab/dataCollectionGitlabProtection.go:60-80` (`GitlabProtectionAnalysisData`, `BranchProtection`), `gitlab/dataCollectionGitlabVariables.go:16-19` + the `CICDVariable` type, `gitlab/security_policy.go:124-134`, `gitlab/response.go:84-121` (`MergedCIConfResponse`, `MergedCIConfResponseInclude`), the platform contract's `ProjectContext.snapshot.data` description (monorepo `docs/contracts/openapi.yaml`, grep `snapshot:` under `ProjectContext`, read-only reference for field names: `schema_version`, `branch_protection{branches, protections}`, `mr_approvals`, `variables`, `merged_yaml`, `merged_yaml_status`, `raw_config`, `ci_errors`, `includes`, `ci_config_path`, `project_details{default_branch, archived, path_with_namespace, merge_method, squash_option, merge_pipelines_enabled, merge_trains_enabled, allow_merge_on_skipped_pipeline, resolve_outdated_diff_discussions, printing_merge_request_link_enabled, remove_source_branch_after_merge}`, `security_policy_project{known, id, full_path}`, `resolution_anchor{ref, sha, config_digest, digest_version}`, `degraded_fields[]`), and the platform collector that WRITES `mr_approvals`, `variables` and `protections` (monorepo `platform/backend/snapshot/collector.go`) to learn their exact JSON shapes (they are the GitLab client-go shapes serialized as-is: `[]*gitlab.ProjectApprovalRule`, `*gitlab.ProjectApprovals`, `[]*gitlab.ProjectVariable`-like records with values blanked, `[]*gitlab.ProtectedBranch`).

**Interfaces:**
- Produces:
  - `type Snapshot struct { CollectedAt time.Time; SchemaVersion string; Degraded map[string]bool; data rawData }` and `func Decode(raw json.RawMessage) (*Snapshot, error)` (forward tolerant: unknown keys ignored; a `schema_version` other than "2" logs one warning and decodes best-effort).
  - `func (s *Snapshot) ProjectInfo(projectPath string, ciConfigPathOverride string) (gitlab.ProjectInfo, bool)` (false when `project_details` absent or degraded; `ID` left 0, the caller fills it from `CI_PROJECT_ID`).
  - `func (s *Snapshot) Protection() *gitlab.GitlabProtectionAnalysisData` (nil when `branch_protection` absent/degraded; `MRApprovalRulesKnown` false when `mr_approvals` absent/degraded; `MRSettings` built from `project_details` merge_* fields onto the `glab.Project` members `buildMRSettings` reads; `ProjectMembers` nil: no reader).
  - `func (s *Snapshot) Variables() *gitlab.GitlabVariablesAnalysisData` (`Known=false` when absent/degraded; values always blank).
  - `func (s *Snapshot) SecurityPolicy() *gitlab.SecurityPolicyData`.
  - `func (s *Snapshot) MergedCI() (resp *gitlab.MergedCIConfResponse, raw string, anchor Anchor, ok bool)` where `ok` is false when `merged_yaml` is degraded or absent; `resp.CiConfig.MergedYaml/Errors/Status/Includes` filled from `merged_yaml/ci_errors/merged_yaml_status/includes`; `raw` = `raw_config`; `Anchor{Ref, Sha, ConfigDigest, DigestVersion}`.
  - `func (s *Snapshot) IsDegraded(field string) bool`.

- [ ] **Step 1: RED.** Golden test over `testdata/context_v2.json` (author it from the contract: every field populated once) asserting each projection's fields; table tests: each `degraded_fields` name -> the not_evaluable struct state; each absent key -> same; unknown keys and `schema_version: "3"` -> decode still succeeds; `merged_yaml_status: "INVALID"` -> `resp.CiConfig.Status == "INVALID"` with errors carried. Run: compile failure.
- [ ] **Step 2: GREEN.** Implement. Keep the package free of `cmd` and `control` imports (it imports `gitlab` for the target structs and `github.com/xanzy/go-gitlab` or whichever client-go module the `gitlab` package already uses for `ProjectApprovalRule`/`ProjectApprovals`/`Project`: check `gitlab/dataCollectionGitlabProtection.go` imports and reuse the same module alias).
- [ ] **Step 3:** `make lint`; commit `feat(platformsnap): decode the platform context snapshot into the gitlab collector structs`.

### Task 3: platform client and pre-analysis fetch in `cmd`

**Files:**
- Modify: `cmd/platform_context.go` (decode `snapshot` alongside `policies`; add `postResolvedConfig(endpoint, token, projectPath string, req ResolveConfigRequest) (*ResolvedConfig, error)` with the contract shapes: request `{sha, config_digest?, digest_version?}`, response 200 `{merged_yaml, config_digest?, digest_version?, resolved_sha, valid, source, includes?, ci_errors?}`, 503 `{reason}` -> a typed `ErrResolveUnavailable`), `cmd/analyze_gitlab.go` (~:696: in platform mode skip `resolveGitLabToken`, fetch `/context` once BEFORE `buildGitLabConf`, set `conf.PlatformSnapshot` and `conf.PlatformPolicies`), `cmd/platform_push.go` / `platform_context.go:96-120` (`resolvePlatformPolicyID` reuses the already-fetched policies instead of a second call), `configuration/configuration.go` (new fields `PlatformSnapshot *platformsnap.Snapshot`, `PlatformPolicies []PlatformPolicy` or equivalent; keep `configuration` free of `cmd` imports).
- Tests: `cmd/platform_context_test.go` (extend), `cmd/analyze_gitlab_test.go` (extend).

**Interfaces:**
- Consumes Task 2's `platformsnap.Decode`; existing `effectivePlatformPush()` (`cmd/platform_push.go:33`), `scoreOIDCToken(p, endpoint)` (`cmd/score_push.go:195`), `resolveScoreTarget` for the project path, `platformTokenFailure`.
- Produces: `conf.PlatformSnapshot` non-nil iff platform mode and `/context` succeeded; a new `PlatformContextError{Reason}` classified by `classifyExecError` (`cmd/root.go:~90`) as "Error", exit 2; the informational line when `GITLAB_TOKEN` is set in platform mode ("platform linked: GITLAB_TOKEN is not used for collection").

- [ ] **Step 1: RED.** Tests: platform mode + `/context` 200 with a snapshot -> `conf.PlatformSnapshot != nil`, `resolveGitLabToken` never called (no `GITLAB_TOKEN` in env, run proceeds past token resolution); platform mode + `/context` 500 -> run returns `PlatformContextError`, exit 2 classification; no platform -> byte-identical path (`GITLAB_TOKEN` still required, existing test); push-time policy-id stamping still works from the pre-fetched policies (adapt `TestMaybePushPlatform_StampsPolicyIDOnExactNameMatch`: `/context` is called exactly once per run, assert the count); `postResolvedConfig` 200/503/other status handling.
- [ ] **Step 2: GREEN.** Implement; the `/context` fetch happens in `analyze_gitlab.go`'s run before `buildGitLabConf`; the decoded policies travel on `conf` to `maybePushPlatform`.
- [ ] **Step 3:** `make lint`; commit `feat(platform): fetch the context once before analysis and skip the gitlab token in platform mode`.

### Task 4: `RunAnalysis` reads the snapshot

**Files:**
- Modify: `control/task.go` `RunAnalysis` (~:652-985): project info (~:667), branch sha (~:720), CI config source + origin DC (~:776-800), image DC (~:880), protection (~:884-905), variables (~:915), security policy (~:935); `gitlab/dataCollectionGitlabPipelineOrigin.go` `Run` (~:440-560): a constructor path that takes an already-resolved `MergedCIConfResponse` + raw config and builds `GitlabPipelineOriginData` WITHOUT the API (`GetFullGitlabCI`, `BranchExists`, `GetGitlabCIComponentResource`, `FetchGitlabInclude` not called; `UpToDate`/`LatestVersion`/`RefIsAmbiguous` left unknown so the include-version controls report not_evaluable: read how `StatusFor`/the Rego inputs express "unknown" for these and use that exact representation); `gitlab/dataCollectionGitlabPipelineImage.go` `Run` (~:700-760): a path with empty instance/group/project variable maps (no `GetGitlab*Variables` calls) so unresolved `$VAR` image references stay unresolved (today's behavior for an unknown variable) and the image controls on that job report not_evaluable (verify how an unresolved reference flows today; do not invent a default registry).
- Modify: `configuration/configuration.go` (Task 3 fields) is consumed here.
- Tests: `control/task_platform_test.go` (new), `gitlab/*_test.go` additions for the two new constructor paths.

**Steps (RED then GREEN per step, one commit per step is fine):**
- [ ] **Step 1: project info + sha.** In platform mode: `snapshot.ProjectInfo(...)`; `ProjectID` from `CI_PROJECT_ID` (the env the push already reads, `cmd/platform_push.go:~271`; pass it through `conf` or read it in `RunAnalysis` via a small accessor); `LatestHeadCommitSha` from `CI_COMMIT_SHA`; `FetchProjectDetails`/`FetchLatestCommitSha` not called. `project_details` absent/degraded -> `CiMissing=true`, `CiValid=false`, return the same error shape a 404 yields today. Test: a fake snapshot + env; assert no GitLab HTTP call (inject a `http.RoundTripper` spy through `conf` if the `gitlab` package supports an injected transport: `gitlab/client_test.go` shows `GetNewGitlabClient_UsesInjectedTransport`; use that seam).
- [ ] **Step 2: CI config.** Keep the local-file priority. Compute `cidigest.Traverse(ciConfigPath, fetch-from-checkout)` + `Compute`; if `anchor.ConfigDigest != ""` and equal -> use `snapshot.MergedCI()`; else `postResolvedConfig({sha: CI_COMMIT_SHA, config_digest, digest_version})` and build the `MergedCIConfResponse` from its `merged_yaml/includes/ci_errors/valid`; a 503 or any error -> `CiValid=false`, `markDegraded(result, "platform could not resolve the CI config: <reason>")`, return like today's network branch. A traversal abort (`ErrTooManyFiles`/read failure) -> treat as "no digest": always call `/resolved-config` without `config_digest`. Then the origin constructor from Step 3 of Task 4's file list. Tests: digest match -> no `/resolved-config` call; mismatch -> one call with the right body; 503 -> degraded.
- [ ] **Step 3: origin and images without the API.** Wire the two constructor paths; tests assert the include-version controls' inputs are the "unknown" representation and that no GitLab client is built.
- [ ] **Step 4: protection, variables, security policy from the snapshot** (only when the corresponding control is enabled, same gates `protectionDataNeeded`/`cicdVariableControlEnabled`/`securityPolicyControlEnabled`); degraded fields -> the exact struct states the Global Constraints name; `markDegraded` reasons reuse the existing `degradedReason*Prefix` constants with a " (platform snapshot degraded)" suffix.
- [ ] **Step 5: parity test.** `control/task_platform_test.go`: ONE fixture project served two ways: (a) token path against an httptest GitLab (reuse an existing GitLab httptest fixture if one covers RunAnalysis end to end; otherwise build the smallest one that returns project details, the CI file, the merged-config GraphQL response, branches, approval rules, variables) and (b) platform path with a snapshot carrying the same facts. Assert identical findings and score, and zero GitLab calls in (b). Also: `/context` snapshot with `merged_yaml` in `degraded_fields` -> degraded run; snapshot with `branch_protection` degraded -> branch controls not_evaluable.
- [ ] **Step 6:** `make lint` + deadcode check; commit(s) `feat(analysis): collect from the platform snapshot in platform mode, no gitlab client`.

### Task 5: docs and release notes

**Files:** `templates/plumber.yml` (the `gitlab_token` input comment: "not needed when `platform` is set; the CLI collects from the platform snapshot"), `README.md` (the platform section: token-free platform mode, the two v1 not_evaluable families, `mr_comment`/`badge` still need a token), `CHANGELOG.md` (an Unreleased entry: platform mode collects from the platform, `GITLAB_TOKEN` no longer required when `platform` is set, `/context` outage fails the run, the not_evaluable inventory), `docs/superpowers/specs/2026-09-09-platform-mode-collection-design.md` (status DRAFT -> IMPLEMENTED with the final not_evaluable inventory from Task 4's report).

- [ ] **Step 1:** Edits; byte-scan; commit `docs(platform): token-free platform mode, what the snapshot covers and what stays not_evaluable`.

## Self-review notes

- Spec coverage: section 1 (mode + sequencing + failure posture) Task 3; section 2 (decoder) Task 2; section 3 (short-circuits, digest, /resolved-config, origins, images) Task 4 + Task 1; section 4 inventory Task 4 Step 3 + Task 5; section 5 exit codes Task 3; section 6 out of scope untouched; section 7 tests spread per task with the parity test in Task 4 Step 5; section 8 rollout Task 5.
- Load-bearing: the digest replica's golden vectors (wire stability), the "never a GitLab client in platform mode" transport spy, and the parity test.
- Placeholder scan: Task 4 leaves two representation lookups to the implementer ("how StatusFor expresses unknown include-version facts", "how an unresolved image reference flows"): both are reads of existing code, not design gaps; the implementer records the answer in its report.
