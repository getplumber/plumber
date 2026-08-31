package cmd

import (
	"sort"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/utils"
)

// _minAccessLevelGitlab returns the smallest accessLevel found in
// the list — the effective minimum required level for push or merge
// in a GitLab branch protection rule. Returns 0 when the list is
// empty (no rule, "no one" can do it).
func _minAccessLevelGitlab(levels []gitlab.BranchProtectionAccessLevel) int {
	min := 0
	for i, l := range levels {
		if i == 0 || l.AccessLevel < min {
			min = l.AccessLevel
		}
	}
	return min
}

// legacyResultsByName builds the per-control `*Result` JSON blocks
// that the v0.2.x analyzer emitted alongside the bare findings list.
// External consumers (CI gates, dashboards, MR comment generators)
// learned to parse those blocks: each control's issues list and its
// `metrics` object travel together under a stable JSON key. The Rego port had collapsed them into a
// single `findings` array, so we reconstruct them here from the IR
// data still attached to AnalysisResult plus the bucketed Rego
// findings.
//
// Returned map keys match the legacy JSON field names
// (imageForbiddenTagsResult, imageAuthorizedSourcesResult, …) so the
// caller can splice them straight into the output struct.
// legacyResultsByName builds the JSON blocks. The includeOnly / skip
// slices come from the `--controls` / `--skip-controls` flags and are
// applied via control.MarkSkippedByFilter so the per-block `skipped:`
// field tracks both the YAML enabled flag AND the CLI filter. Pass
// nil/empty when no filter is active.
func legacyResultsByName(result *control.AnalysisResult, pc *configuration.PlumberConfig, provider string, includeOnly, skip []string, noControls bool) map[string]any {
	if result == nil || pc == nil {
		return nil
	}
	// --no-controls: the blocks still describe the catalog, but every one of
	// them must read as "not evaluated". `status` exists so consumers stop
	// inferring a pass from an empty issues list, so it is exactly the field
	// that has to tell the truth for a run that evaluated nothing.
	markSkipped := func(entries []control.ControlEntry) {
		if noControls {
			control.MarkAllSkipped(entries, noControlsSkipReason)
			return
		}
		control.MarkSkippedByFilter(entries, includeOnly, skip)
	}
	out := map[string]any{}
	findingsByControl := control.FindingsByControl(result.Findings)

	switch provider {
	case "github":
		entries := control.GitHubControls(pc)
		markSkipped(entries)
		for _, e := range entries {
			fs := findingsByControl[e.ControlName]
			key, block := buildLegacyResultGitHub(e, result, pc, fs)
			if key == "" {
				continue
			}
			out[key] = _withControlMeta(block, e, result, len(fs))
		}
	default:
		entries := control.GitLabControls(pc)
		markSkipped(entries)
		for _, e := range entries {
			fs := findingsByControl[e.ControlName]
			key, block := buildLegacyResult(e, result, pc, fs)
			if key == "" {
				continue
			}
			out[key] = _withControlMeta(block, e, result, len(fs))
		}
	}
	return out
}

// _withControlMeta stamps the block's stable .plumber.yaml control name
// and its evaluation status onto the block itself.
//
// controlName lives here once rather than on every individual issue --
// every issue in a block's `issues` array is guaranteed to share the
// same controlName (FindingsByControl buckets strictly by it), so
// repeating it per-issue would be pure redundancy.
//
// status is the explicit passed/failed/skipped/error verdict
// (control.StatusFor) so consumers stop inferring pass from "issues is
// empty" -- an empty list can also mean the control never really
// evaluated (missing CI config, degraded collection). The existing
// `skipped` boolean stays untouched for backward compatibility;
// status: "skipped" mirrors it.
//
// Every `buildX...` function returns map[string]any; the type assertion
// only fails for a hand-built AnalysisResult in a test that skips the
// real builders.
func _withControlMeta(block any, e control.ControlEntry, result *control.AnalysisResult, findingCount int) any {
	if m, ok := block.(map[string]any); ok {
		m["controlName"] = e.ControlName
		// Display metadata next to the stable technical id (#440): the
		// docs-catalog wording and grouping, so no consumer has to maintain
		// a technicalName -> human-name map that drifts on every release.
		if meta, ok := configuration.ControlMetaFor(e.ControlName); ok {
			m["name"] = meta.DisplayName
			m["category"] = meta.Category
		}
		m["status"] = control.StatusFor(e, result, findingCount)
		if result != nil && result.ApprovalRulesTierCaveat && isApprovalRuleControl(e.ControlName) {
			// Structured so a consumer can key on it: the approvals API returned
			// no rules, which on GitLab Free means the feature is unavailable
			// (the API 200-empties) rather than a real misconfiguration.
			m["tierCaveat"] = map[string]any{
				"reason":       "no-approval-rules-returned",
				"requiresTier": "premium_or_ultimate",
				"message":      approvalRulesTierCaveatMessage,
			}
		}
		if result != nil && result.MRApprovalSettingsTierCaveat && e.ControlName == "mergeRequestApprovalSettingsMustBeCompliant" {
			// Same tier-ambiguity as the rules caveat, one step blinder: the
			// settings API 200-defaults every protection off on GitLab Free, so a
			// no-protection read can't be told apart from a genuinely unlocked paid
			// project. Keyed so a consumer can suppress or annotate ISSUE-503.
			m["tierCaveat"] = map[string]any{
				"reason":       "no-approval-protections",
				"requiresTier": "premium_or_ultimate",
				"message":      mrApprovalSettingsTierCaveatMessage,
			}
		}
		if result != nil && len(result.MRSettingsPremiumCaveatFields) > 0 && e.ControlName == "mergeRequestSettingsMustBeCompliant" {
			// One or more configured MR-setting expectations require a Premium/
			// Ultimate feature the project cannot turn on (merge trains, merged-
			// results pipelines). Keyed with the offending fields so a consumer can
			// annotate ISSUE-506 or advise disabling just those expectations.
			m["tierCaveat"] = map[string]any{
				"reason":       "premium-settings-expected-on",
				"requiresTier": "premium_or_ultimate",
				"fields":       result.MRSettingsPremiumCaveatFields,
				"message":      mrSettingsTierCaveatMessage,
			}
		}
		if result != nil && result.SecurityPolicyTierCaveat && e.ControlName == "projectMustHaveSecurityPolicySource" {
			// No policy project is linked, and security policies are an Ultimate
			// feature, so we cannot tell a non-Ultimate project (unable to link)
			// from an Ultimate project that left it unset. Keyed so a consumer can
			// annotate ISSUE-601.
			m["tierCaveat"] = map[string]any{
				"reason":       "no-security-policy-project-linked",
				"requiresTier": "ultimate",
				"message":      securityPolicyTierCaveatMessage,
			}
		}
	}
	return block
}

// approvalRulesTierCaveatMessage explains the Premium/Ultimate requirement for
// the MR approval-rule controls when the approvals API returned no rules.
// Shared by the terminal caveat (render_details.go) and the JSON tierCaveat.
const approvalRulesTierCaveatMessage = "MR approval rules are a GitLab Premium/Ultimate feature. Disable these controls if you don't have GitLab Premium or Ultimate."

// mrApprovalSettingsTierCaveatMessage explains the Premium/Ultimate requirement
// for the MR approval-settings control (ISSUE-503) when the project has no
// approval protection in effect. Shared by the terminal caveat
// (render_details.go) and the JSON tierCaveat.
const mrApprovalSettingsTierCaveatMessage = "MR approval settings are a GitLab Premium/Ultimate feature and this project has no approval protections in effect. If you're not on GitLab Premium or Ultimate you can't set them — disable this control."

// mrSettingsTierCaveatMessage explains that one or more configured MR-setting
// expectations (see the tierCaveat "fields") require a GitLab Premium/Ultimate
// feature the project cannot turn on. Shared by the terminal caveat
// (render_details.go) and the JSON tierCaveat.
const mrSettingsTierCaveatMessage = "One or more expected MR settings are GitLab Premium/Ultimate features that read as off (see fields). The API gives no tier signal, so this may be a Free project that cannot enable them or a paid project that left them off. If this project is not on GitLab Premium/Ultimate, set those expectations to false or remove them from mergeRequestSettingsMustBeCompliant; if it is, enable the feature to satisfy the check."

// isApprovalRuleControl reports whether a control name is one of the two
// GitLab MR approval-rule controls the tier caveat applies to.
func isApprovalRuleControl(name string) bool {
	return name == "mergeRequestApprovalRulesMustRequireMinimumApprovals" ||
		name == "mergeRequestApprovalRulesMustCoverAllProtectedBranches"
}

// securityPolicyTierCaveatMessage explains the Ultimate requirement for
// ISSUE-601 when no security policy project is linked. Shared by the terminal
// caveat (render_details.go) and the JSON tierCaveat.
const securityPolicyTierCaveatMessage = "Security policies require GitLab Ultimate, and no policy project is linked. If this project is not on GitLab Ultimate it cannot link one — disable this control. If it is, link the expected security policy project to satisfy the check."

// buildSecurityPolicyProjectBlock emits the legacy JSON block for the
// security-policy-project linkage control (ISSUE-601). The finding is a
// project-level singleton (no file/job); its linkedProjectId / linkedProjectPath
// / expectedProjectId ride in the issue's data, preserved by projectFindings.
func buildSecurityPolicyProjectBlock(c legacyCommon, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"projectWithoutExpectedSecurityPolicy": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildLegacyResult routes a control entry to its legacy JSON
// builder and returns the (jsonKey, block) pair.
func buildLegacyResult(e control.ControlEntry, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) (string, any) {
	common := legacyCommon{
		CiValid:   result.CiValid,
		CiMissing: result.CiMissing,
		Skipped:   e.Skipped,
	}

	switch e.ControlName {
	case "containerImageMustNotUseForbiddenTags":
		return "imageForbiddenTagsResult", buildImageForbiddenTagsBlock(common, result, pc, findings)
	case "containerImageMustComeFromAuthorizedSources":
		return "imageAuthorizedSourcesResult", buildImageAuthorizedSourcesBlock(common, result, findings)
	case "branchMustBeProtected":
		return "branchProtectionResult", buildBranchProtectionBlock(common, result, pc, findings)
	case "projectMustHaveSecurityPolicySource":
		return "securityPolicyProjectResult", buildSecurityPolicyProjectBlock(common, findings)
	case "pipelineMustNotIncludeHardcodedJobs":
		return "hardcodedJobsResult", buildHardcodedJobsBlock(common, result, findings)
	case "externalRefsMustNotCollide":
		return "includeRefConfusionResult", buildIncludeRefConfusionBlock(common, result, findings)
	case "includesMustBeUpToDate":
		return "outdatedIncludesResult", buildOutdatedIncludesBlock(common, result, findings)
	// (jobKey is dropped for the outdated builder — the legacy
	// shape replaces `job` with `gitlabIncludeLocation`.)
	case "includesMustNotUseForbiddenVersions":
		return "forbiddenVersionsIncludesResult", buildForbiddenVersionsBlock(common, result, findings)
	case "pipelineMustIncludeComponent":
		return "requiredComponentsResult", buildRequirementGroupsBlock(common, pc.ControlsFor("gitlab").PipelineMustIncludeComponent, result, findings)
	case "pipelineMustIncludeTemplate":
		return "requiredTemplatesResult", buildRequirementGroupsTemplateBlock(common, pc.ControlsFor("gitlab").PipelineMustIncludeTemplate, result, findings)
	case "pipelineMustNotEnableDebugTrace":
		return "debugTraceResult", buildDebugTraceBlock(common, result, findings)
	case "pipelineMustNotUseUnsafeVariableExpansion":
		return "variableInjectionResult", buildVariableInjectionBlock(common, result, findings)
	case "securityJobsMustNotBeWeakened":
		return "securityJobsWeakenedResult", buildSecurityJobsBlock(common, result, pc, findings)
	case "pipelineMustNotExecuteUnverifiedScripts":
		return "unverifiedScriptsResult", buildUnverifiedScriptsBlock(common, result, findings)
	case "pipelineMustNotOverrideJobVariables":
		return "jobVariablesOverrideResult", buildJobVariablesOverrideBlock(common, result, findings)
	case "pipelineMustNotUseDockerInDocker":
		return "dockerInDockerResult", buildDockerInDockerBlock(common, result, findings)
	case "mergeRequestApprovalRulesMustRequireMinimumApprovals":
		return "mrApprovalRulesMinApprovalsResult", buildMRApprovalRulesMinApprovalsBlock(common, findings)
	case "mergeRequestApprovalRulesMustCoverAllProtectedBranches":
		return "mrApprovalRulesCoverAllBranchesResult", buildMRApprovalRulesCoverAllBranchesBlock(common, findings)
	case "cicdVariablesMustBeProtected":
		return "cicdVariablesProtectedResult", buildCicdVariablesProtectedBlock(common, result, findings)
	case "cicdVariablesMustBeMasked":
		return "cicdVariablesMaskedResult", buildCicdVariablesMaskedBlock(common, result, findings)
	case "mergeRequestApprovalSettingsMustBeCompliant":
		return "mrApprovalSettingsResult", buildMRApprovalSettingsBlock(common, findings)
	case "mergeRequestSettingsMustBeCompliant":
		return "mrSettingsResult", buildMRSettingsBlock(common, findings)
	}
	return "", nil
}

// buildMRApprovalRulesMinApprovalsBlock and
// buildMRApprovalRulesCoverAllBranchesBlock emit the legacy JSON blocks for the
// merge-request approval-rule controls. The findings are settings-level (no
// file/job), so each issue carries the approval-rule identity (approvalRuleId)
// plus the ruleName / approvalsRequired / minApprovalsRequired data that
// projectFindings preserves from f.Data.
func buildMRApprovalRulesMinApprovalsBlock(c legacyCommon, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"rulesBelowMinimum": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildMRApprovalRulesCoverAllBranchesBlock(c legacyCommon, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"allProtectedBranchesRuleMissing": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildCicdVariablesProtectedBlock and buildCicdVariablesMaskedBlock emit the
// legacy JSON blocks for the settings-variable controls. The findings are
// settings-level (no file/job), so each issue carries the variable identity
// (variableName / variableType / environment) that projectFindings preserves;
// the value is never present, per the #370 variable-sensitivity tiers.
func buildCicdVariablesProtectedBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"totalVariablesChecked": variablesCheckedCount(result),
			"unprotectedFound":      len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildCicdVariablesMaskedBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"totalVariablesChecked": variablesCheckedCount(result),
			"unmaskedFound":         len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// variablesCheckedCount is the denominator for the settings-variable JSON
// blocks: how many variables were read (0 when the listing was unreadable or
// not collected — the block's status:error then carries the not-evaluable
// signal). Mirrors the totalVariablesChecked metric on the comparable
// pipelineMustNotOverrideJobVariables block.
func variablesCheckedCount(result *control.AnalysisResult) int {
	if result != nil && result.VariablesData != nil {
		return len(result.VariablesData.Variables)
	}
	return 0
}

// buildMRApprovalSettingsBlock emits the legacy JSON block for the
// merge-request approval-settings control (ISSUE-503). The finding is a
// settings-level singleton (no file/job); its deviatingSettings list and the
// project's behaviorWhenCommitIsAdded ride in the issue's data, preserved by
// projectFindings.
func buildMRApprovalSettingsBlock(c legacyCommon, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"hasNonCompliantSettings": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildMRSettingsBlock emits the legacy JSON block for the merge-request
// settings control (ISSUE-506). The finding is a settings-level singleton (no
// file/job); its deviatingSettings list rides in the issue's data, preserved by
// projectFindings.
func buildMRSettingsBlock(c legacyCommon, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"hasNonCompliantSettings": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// legacyCommon carries the bookkeeping fields shared by every
// `*Result` block: ciValid, ciMissing, skipped.
type legacyCommon struct {
	CiValid   bool
	CiMissing bool
	Skipped   bool
}

// projectFinding strips the verbose Rego-side fields (severity,
// message, file, line) so the returned issue keeps only what the
// legacy format documented: code, docUrl, plus whatever structured
// payload the rule emitted (link/tag/variableName/…).
//
// controlName is NOT repeated here: it lives once on the parent
// *Result block (see _withControlMeta in legacyResultsByName), since
// every issue in a block is guaranteed to share that block's
// controlName -- FindingsByControl buckets strictly by it. Only code
// varies within a block (e.g. containerImageMustNotUseForbiddenTags
// covers both ISSUE-102 and ISSUE-103), so code stays per-issue.
func projectFinding(f opaengine.Finding, jobKey string) map[string]any {
	out := map[string]any{
		"code":   f.Code,
		"docUrl": "https://getplumber.io/docs/cli/issues/" + f.Code,
	}
	// The issue TYPE's display name (#440), the docs wording from the code
	// registry, so grouping findings by code needs no hand-made code map.
	// The technical code above stays the stable key.
	if info := control.LookupCode(control.ErrorCode(f.Code)); info != nil && info.Title != "" {
		out["title"] = info.Title
	}
	if f.Job != "" && jobKey != "" {
		out[jobKey] = f.Job
	}
	// `url` is the per-finding clickable pointer populated by the
	// location linker. Emitted on every per-control issue block so
	// downstream consumers (dashboards, MR-comment renderers,
	// scripts) can hyperlink to the offending file at the analysed
	// commit without having to recompose it themselves.
	if f.URL != "" {
		out["url"] = f.URL
	}
	if f.Fingerprint != "" {
		out["fingerprint"] = f.Fingerprint
	}
	// The fingerprint above is a hash, so it cannot tell a consumer WHICH
	// fields it was built from, and this function strips message, file and
	// line, so those inputs are not recoverable from the issue entry either.
	// The identity block carries the selected field set itself, which is what
	// lets a platform group findings into long-lived issues across runs
	// without re-deriving (and eventually diverging from) the recipe. Its
	// version travels with it: see finding/identity.RecipeVersion.
	if fields, ok := f.Identity(); ok {
		out["identity"] = map[string]any{
			"version":            fields.Version,
			"fields":             fields.Pairs(),
			"subjectFromMessage": fields.SubjectFromMessage,
		}
	}
	for k, v := range f.Data {
		if k == "docUrl" || k == "url" || k == "fingerprint" || k == "identity" {
			continue
		}
		out[k] = v
	}
	return out
}

func projectFindings(findings []opaengine.Finding, jobKey string) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, projectFinding(f, jobKey))
	}
	return out
}

// _sortedFindings returns findings in a stable total order so legacy JSON
// issues[] do not flip between runs when Job matches (e.g. two codes on the
// same job). Primary key is Job, then Code, File, Line, Message — aligned
// with the OPA engine aggregate sort.
func _sortedFindings(findings []opaengine.Finding) []opaengine.Finding {
	out := make([]opaengine.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Job != b.Job:
			return a.Job < b.Job
		case a.Code != b.Code:
			return a.Code < b.Code
		case a.File != b.File:
			return a.File < b.File
		case a.Line != b.Line:
			return a.Line < b.Line
		default:
			return a.Message < b.Message
		}
	})
	return out
}

// _branchProtectionEntryForName returns the first GitLab protection rule
// whose pattern matches the branch name, consistent with the
// protectionByBranch indexing in buildBranchProtectionBlock.
func _branchProtectionEntryForName(data *gitlab.GitlabProtectionAnalysisData, branchName string) *gitlab.BranchProtection {
	if data == nil || branchName == "" {
		return nil
	}
	for i := range data.BranchProtections {
		p := &data.BranchProtections[i]
		if _matchesAnyGlob(branchName, []string{p.ProtectionPattern}) {
			return p
		}
	}
	return nil
}

// enrichBranchProtection505IssueMaps restores the v0.2.x issue shape for
// ISSUE-505: *Display flags and codeOwnerApprovalRequired from the
// protection API (Rego alone cannot express the legacy display semantics).
func enrichBranchProtection505IssueMaps(issues []map[string]any, result *control.AnalysisResult, pc *configuration.PlumberConfig) {
	var cfg *configuration.BranchProtectionControlConfig
	if pc != nil {
		cfg = pc.ControlsFor("gitlab").BranchMustBeProtected
	}
	allowForcePushPolicy := false
	if cfg != nil && cfg.AllowForcePush != nil {
		allowForcePushPolicy = *cfg.AllowForcePush
	}
	codeOwnerPolicy := false
	if cfg != nil && cfg.CodeOwnerApprovalRequired != nil {
		codeOwnerPolicy = *cfg.CodeOwnerApprovalRequired
	}
	minMergePolicy := 0
	if cfg != nil && cfg.MinMergeAccessLevel != nil {
		minMergePolicy = *cfg.MinMergeAccessLevel
	}
	minPushPolicy := 0
	if cfg != nil && cfg.MinPushAccessLevel != nil {
		minPushPolicy = *cfg.MinPushAccessLevel
	}
	for _, issue := range issues {
		code, _ := issue["code"].(string)
		if code != string(control.CodeBranchNonCompliant) {
			continue
		}
		branchName, _ := issue["branchName"].(string)
		if branchName == "" {
			continue
		}
		if result == nil || result.ProtectionData == nil {
			continue
		}
		p := _branchProtectionEntryForName(result.ProtectionData, branchName)
		if p == nil {
			continue
		}
		branchAllow := p.AllowForcePush
		branchCodeOwner := p.CodeOwnerApprovalRequired
		branchMinMerge := _minAccessLevelGitlab(p.MergeAccessLevels)
		branchMinPush := _minAccessLevelGitlab(p.PushAccessLevels)
		issue["codeOwnerApprovalRequired"] = branchCodeOwner
		// controlGitlabProtectionBranchProtectionNotCompliant.go display bits
		if !allowForcePushPolicy && branchAllow {
			issue["allowForcePushDisplay"] = true
		} else {
			delete(issue, "allowForcePushDisplay")
		}
		if codeOwnerPolicy && !branchCodeOwner {
			issue["codeOwnerApprovalRequiredDisplay"] = true
		} else {
			delete(issue, "codeOwnerApprovalRequiredDisplay")
		}
		if branchMinMerge != 0 && (minMergePolicy == 0 || minMergePolicy > branchMinMerge) {
			issue["minMergeAccessLevelDisplay"] = true
		} else {
			delete(issue, "minMergeAccessLevelDisplay")
		}
		if branchMinPush != 0 && (minPushPolicy == 0 || minPushPolicy > branchMinPush) {
			issue["minPushAccessLevelDisplay"] = true
		} else {
			delete(issue, "minPushAccessLevelDisplay")
		}
	}
}

func _originByIncludeSource(data *gitlab.GitlabPipelineOriginData, source string) *gitlab.GitlabPipelineOriginDataFull {
	if data == nil || source == "" {
		return nil
	}
	cleanedWant := utils.CleanOriginPath(source)
	for i := range data.Origins {
		o := &data.Origins[i]
		loc := o.GitlabIncludeOrigin.Location
		if loc == "" {
			loc = o.GitlabComponent.ComponentIncludePath
		}
		if loc == source || (loc != "" && utils.CleanOriginPath(loc) == cleanedWant) {
			return o
		}
	}
	return nil
}

// enrichForbiddenVersion404IssueMaps restores the v0.1.x
// GitlabPipelineIncludesForbiddenVersionIssue fields from
// collector data (Rego only emits a slim finding).
func enrichForbiddenVersion404IssueMaps(issues []map[string]any, result *control.AnalysisResult) {
	if result == nil || result.PipelineOriginData == nil {
		return
	}
	for _, issue := range issues {
		code, _ := issue["code"].(string)
		if code != string(control.CodeIncludeForbiddenVersion) {
			continue
		}
		// The rule emits includePath, not job: an include is not a job, and
		// includePath is what the identity recipe selects for this finding
		// (finding/identity). It carries the same include-source value job
		// used to carry, so reading it here restores the enrichment.
		src, _ := issue["includePath"].(string)
		if src == "" {
			continue
		}
		o := _originByIncludeSource(result.PipelineOriginData, src)
		if o == nil {
			continue
		}
		latest := ""
		plumberPath := ""
		if o.FromPlumber {
			latest = o.PlumberOrigin.LatestVersion
			plumberPath = o.PlumberOrigin.Path
		} else if o.FromGitlabCatalog {
			latest = o.GitlabComponent.ComponentLatestVersion
		}
		templateName := plumberPath
		if templateName != "" && strings.Contains(templateName, "/") {
			templateName = templateName[strings.LastIndex(templateName, "/")+1:]
		}
		componentName := o.GitlabComponent.ComponentName
		if o.GitlabIncludeOrigin.Type == "component" && componentName == "" && o.GitlabIncludeOrigin.Location != "" {
			loc := o.GitlabIncludeOrigin.Location
			if strings.Contains(loc, "/") {
				componentName = loc[strings.LastIndex(loc, "/")+1:]
			}
		}
		issue["version"] = o.Version
		if latest != "" {
			issue["latestVersion"] = latest
		}
		if plumberPath != "" {
			issue["plumberOriginPath"] = plumberPath
		}
		includeLoc := o.GitlabIncludeOrigin.Location
		if includeLoc == "" {
			includeLoc = o.GitlabComponent.ComponentIncludePath
		}
		if includeLoc != "" {
			issue["gitlabIncludeLocation"] = includeLoc
		}
		if t := o.GitlabIncludeOrigin.Type; t != "" {
			issue["gitlabIncludeType"] = t
		}
		if pr := o.GitlabIncludeOrigin.Project; pr != "" {
			issue["gitlabIncludeProject"] = pr
		}
		issue["nested"] = o.Nested
		if componentName != "" {
			issue["componentName"] = componentName
		}
		if templateName != "" {
			issue["plumberTemplateName"] = templateName
		}
		issue["originHash"] = o.OriginHash
	}
}

func buildImageForbiddenTagsBlock(c legacyCommon, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) map[string]any {
	// The metrics below are computed here rather than derived from the
	// findings, so they must make the same abstention the rules make. An
	// image whose reference never rendered to a literal is neither pinned
	// nor unpinned: the digest was looked for in placeholder text. Counting
	// it either way puts the metrics at odds with the issues list.
	total := 0
	notPinned := 0
	unresolved := 0
	usingForbidden := 0
	if result.PipelineImageData != nil {
		total = len(result.PipelineImageData.Images)
		for _, img := range result.PipelineImageData.Images {
			if img.Unresolved {
				unresolved++
				continue
			}
			if !utils.HasDigestPin(img.Link) {
				notPinned++
			}
		}
	}
	for _, f := range findings {
		if f.Code == string(control.CodeImageForbiddenTag) {
			usingForbidden++
		}
	}
	mustBePinned := false
	if pc.ControlsFor("gitlab").ContainerImageMustNotUseForbiddenTags != nil {
		mustBePinned = pc.ControlsFor("gitlab").ContainerImageMustNotUseForbiddenTags.IsPinnedByDigestRequired()
	}
	// Sort findings deterministically by job so consumer snapshots
	// stay stable across runs. Stable's order came out of Go map
	// iteration and is not reproducible itself; alphabetic-by-job
	// gives at least a single canonical ordering on the dev side.
	return map[string]any{
		"issues": projectFindings(_sortedFindings(findings), "job"),
		"metrics": map[string]any{
			"total":              total,
			"usingForbiddenTags": usingForbidden,
			"notPinnedByDigest":  notPinned,
			"pinnedByDigest":     total - notPinned - unresolved,
			"unresolvedRefs":     unresolved,
			"ciInvalid":          0,
			"ciMissing":          0,
		},
		"version":              "0.4.0",
		"ciValid":              c.CiValid,
		"ciMissing":            c.CiMissing,
		"skipped":              c.Skipped,
		"mustBePinnedByDigest": mustBePinned,
	}
}

func buildImageAuthorizedSourcesBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	// authorized is derived by subtraction, so an image the rule abstained
	// on would be reported as coming from an authorized source. Subtract the
	// unresolved references out and report them in their own field.
	total := 0
	unresolved := 0
	if result.PipelineImageMetrics != nil {
		total = int(result.PipelineImageMetrics.Total)
	}
	if result.PipelineImageData != nil {
		for _, img := range result.PipelineImageData.Images {
			if img.Unresolved {
				unresolved++
			}
		}
	}
	unauthorized := len(findings)
	authorized := total - unauthorized - unresolved
	if authorized < 0 {
		authorized = 0
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"total":          total,
			"authorized":     authorized,
			"unauthorized":   unauthorized,
			"unresolvedRefs": unresolved,
			"ciInvalid":      0,
			"ciMissing":      0,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// nonCompliantBranchNames collects the branches that fired ISSUE-505, read from
// the finding's branchName payload. Not from Finding.Job: that field is a CI
// job name, and a branch is not a job, so branch rules leave it empty.
func nonCompliantBranchNames(findings []opaengine.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if f.Code != string(control.CodeBranchNonCompliant) {
			continue
		}
		if name, ok := f.Data["branchName"].(string); ok && name != "" {
			out[name] = true
		}
	}
	return out
}

func buildBranchProtectionBlock(c legacyCommon, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) map[string]any {
	total, toProtect, protected, unprotected := _branchProtectionCounts(result, pc)
	nonCompliant := 0
	for _, f := range findings {
		if f.Code == string(control.CodeBranchNonCompliant) {
			nonCompliant++
		}
	}
	data := []map[string]any{}
	if result.ProtectionData != nil && pc.ControlsFor("gitlab").BranchMustBeProtected != nil {
		cfg := pc.ControlsFor("gitlab").BranchMustBeProtected
		policyPatterns := cfg.NamePatterns
		defaultProtected := cfg.DefaultMustBeProtected != nil && *cfg.DefaultMustBeProtected
		// Mirror v0.2.x: only branches that fall under the project's
		// protection policy land in `data` — non-policy branches are
		// noise for compliance consumers and bloat the JSON. For each
		// kept branch we surface the full protection settings vs the
		// authorized thresholds, so consumers see at a glance which
		// dimension breaks the contract.
		authMerge := 0
		if cfg.MinMergeAccessLevel != nil {
			authMerge = *cfg.MinMergeAccessLevel
		}
		authPush := 0
		if cfg.MinPushAccessLevel != nil {
			authPush = *cfg.MinPushAccessLevel
		}
		// Index protections by the matched branch so we can read the
		// concrete settings (force-push, access levels) per branch.
		protectionByBranch := map[string]int{}
		for i := range result.ProtectionData.BranchProtections {
			pattern := result.ProtectionData.BranchProtections[i].ProtectionPattern
			for _, name := range result.ProtectionData.Branches {
				if _, seen := protectionByBranch[name]; seen {
					continue
				}
				if _matchesAnyGlob(name, []string{pattern}) {
					protectionByBranch[name] = i
				}
			}
		}
		// v0.2.x exposes the full protection settings (allowForcePush,
		// access levels, authorized thresholds) only on branches that
		// fired a non-compliance finding — compliant branches keep
		// the slim {branchName, default, protected} shape so the JSON
		// stays focused on what reviewers need to act on.
		nonCompliantBranches := nonCompliantBranchNames(findings)
		// Iterate the branches with the default branch first, then the
		// rest sorted alphabetically — matches v0.2.x's display order
		// where the project's flagship branch leads the data list.
		ordered := make([]string, 0, len(result.ProtectionData.Branches))
		if result.DefaultBranch != "" {
			for _, b := range result.ProtectionData.Branches {
				if b == result.DefaultBranch {
					ordered = append(ordered, b)
					break
				}
			}
		}
		others := make([]string, 0, len(result.ProtectionData.Branches))
		for _, b := range result.ProtectionData.Branches {
			if b != result.DefaultBranch {
				others = append(others, b)
			}
		}
		sort.Strings(others)
		ordered = append(ordered, others...)
		for _, name := range ordered {
			matchesPolicy := _matchesAnyGlob(name, policyPatterns)
			if !matchesPolicy && defaultProtected && name == result.DefaultBranch {
				matchesPolicy = true
			}
			if !matchesPolicy {
				continue
			}
			entry := map[string]any{
				"branchName": name,
				"default":    name == result.DefaultBranch,
				"protected":  false,
			}
			if idx, ok := protectionByBranch[name]; ok {
				p := &result.ProtectionData.BranchProtections[idx]
				entry["protected"] = true
				if nonCompliantBranches[name] {
					entry["allowForcePush"] = p.AllowForcePush
					entry["minMergeAccessLevel"] = _minAccessLevelGitlab(p.MergeAccessLevels)
					entry["minPushAccessLevel"] = _minAccessLevelGitlab(p.PushAccessLevels)
					entry["authorizedMinMergeAccessLevel"] = authMerge
					entry["authorizedMinPushAccessLevel"] = authPush
				}
			}
			data = append(data, entry)
		}
	}
	// branchProtection projects findings as `issues` with the branch
	// fields the legacy format documented (type, branchName, force-
	// push toggles, access levels). The ISSUE-501/505 rules emit
	// these directly so we just strip Rego-only fields. v0.2.19
	// omits the `issues` key entirely when the list is empty rather
	// than emitting `"issues": []`; reproduce that quirk so byte-for-
	// byte JSON consumers (snapshot tests, etc.) stay aligned.
	block := map[string]any{
		"enabled": !c.Skipped,
		"version": "0.2.0",
		"data":    data,
		"metrics": map[string]any{
			"branches":                   total,
			"branchesToProtect":          toProtect,
			"unprotectedBranches":        unprotected,
			"nonCompliantBranches":       nonCompliant,
			"totalProtectedBranches":     protected,
			"projectsCorrectlyProtected": protected - nonCompliant,
		},
	}
	if len(findings) > 0 {
		issues := projectFindings(findings, "")
		enrichBranchProtection505IssueMaps(issues, result, pc)
		block["issues"] = issues
	}
	return block
}

func buildHardcodedJobsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	total := uint(0)
	hardcoded := uint(0)
	if result.PipelineOriginMetrics != nil {
		total = result.PipelineOriginMetrics.JobTotal
		hardcoded = result.PipelineOriginMetrics.JobHardcoded
	}
	return map[string]any{
		"issues": projectFindings(_sortedFindings(findings), "job"),
		"metrics": map[string]any{
			"total":         total,
			"hardcodedJobs": hardcoded,
			"ciInvalid":     0,
			"ciMissing":     0,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildOutdatedIncludesBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	total := _externalIncludeCount(result)
	outdated := uint(0)
	if result.PipelineOriginMetrics != nil {
		outdated = result.PipelineOriginMetrics.OriginOutdated
	}
	// Outdated-include issues drop the `job` field; the legacy shape
	// already carries the include path under `gitlabIncludeLocation`.
	// Sort by include location so the JSON stays deterministic across
	// runs (Rego's set iteration order does not).
	issues := projectFindings(_sortedFindings(findings), "")
	sort.SliceStable(issues, func(i, j int) bool {
		a, _ := issues[i]["gitlabIncludeLocation"].(string)
		b, _ := issues[j]["gitlabIncludeLocation"].(string)
		return a < b
	})
	// originHash is uint64. The Rego pipeline marshals it as a JSON
	// number, OPA loads it as float64 (losing precision past 2^53),
	// then emits it back the same way. Re-inject the precise integer
	// from the IR by matching on the include location.
	hashByLocation := map[string]uint64{}
	if result.PipelineOriginData != nil {
		for i := range result.PipelineOriginData.Origins {
			o := &result.PipelineOriginData.Origins[i]
			loc := o.GitlabIncludeOrigin.Location
			if loc == "" {
				loc = o.GitlabComponent.ComponentIncludePath
			}
			if loc != "" && o.OriginHash != 0 {
				hashByLocation[loc] = o.OriginHash
			}
		}
	}
	for _, iss := range issues {
		if loc, ok := iss["gitlabIncludeLocation"].(string); ok {
			if h, ok := hashByLocation[loc]; ok {
				iss["originHash"] = h
			}
		}
	}
	return map[string]any{
		"issues": issues,
		"metrics": map[string]any{
			"total":          total,
			"originOutdated": outdated,
			"ciInvalid":      0,
			"ciMissing":      0,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildIncludeRefConfusionBlock — ISSUE-402. Denominator is the number of
// external includes scanned (same as the outdated block), numerator the
// finding count, one per include whose ref resolves as both a tag and a
// branch. Mirrors buildOutdatedIncludesBlock, including the precise
// originHash re-injection lost in the Rego float64 round-trip.
func buildIncludeRefConfusionBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	total := _externalIncludeCount(result)
	issues := projectFindings(_sortedFindings(findings), "")
	sort.SliceStable(issues, func(i, j int) bool {
		a, _ := issues[i]["gitlabIncludeLocation"].(string)
		b, _ := issues[j]["gitlabIncludeLocation"].(string)
		return a < b
	})
	hashByLocation := map[string]uint64{}
	if result.PipelineOriginData != nil {
		for i := range result.PipelineOriginData.Origins {
			o := &result.PipelineOriginData.Origins[i]
			loc := o.GitlabIncludeOrigin.Location
			if loc == "" {
				loc = o.GitlabComponent.ComponentIncludePath
			}
			if loc != "" && o.OriginHash != 0 {
				hashByLocation[loc] = o.OriginHash
			}
		}
	}
	for _, iss := range issues {
		if loc, ok := iss["gitlabIncludeLocation"].(string); ok {
			if h, ok := hashByLocation[loc]; ok {
				iss["originHash"] = h
			}
		}
	}
	return map[string]any{
		"issues": issues,
		"metrics": map[string]any{
			"total":         total,
			"ambiguousRefs": len(findings),
			"ciInvalid":     0,
			"ciMissing":     0,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildForbiddenVersionsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	total := _externalIncludeCount(result)
	usingForbidden := len(findings)
	usingAuthorized := total - usingForbidden
	if usingAuthorized < 0 {
		usingAuthorized = 0
	}
	issues := projectFindings(findings, "")
	enrichForbiddenVersion404IssueMaps(issues, result)
	return map[string]any{
		"issues": issues,
		"metrics": map[string]any{
			"total":                  total,
			"usingForbiddenVersion":  usingForbidden,
			"usingAuthorizedVersion": usingAuthorized,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildRequirementGroupsBlock(c legacyCommon, cfg *configuration.RequiredComponentsControlConfig, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	var groups [][]string
	if cfg != nil && !c.Skipped {
		groups = cfg.RequiredGroups
	}
	requirementGroups, satisfied := _resolveRequirementGroups(groups, result)
	return map[string]any{
		"requirementGroups": requirementGroups,
		"issues":            projectFindings(findings, ""),
		"overriddenIssues":  []any{},
		"metrics": map[string]any{
			"totalGroups":       len(requirementGroups),
			"satisfiedGroups":   satisfied,
			"anySatisfiedGroup": len(requirementGroups) > 0 && satisfied > 0,
			"ciInvalid":         0,
			"ciMissing":         0,
		},
		"version":   "0.2.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildRequirementGroupsTemplateBlock(c legacyCommon, cfg *configuration.RequiredTemplatesControlConfig, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	var groups [][]string
	if cfg != nil && !c.Skipped {
		groups = cfg.RequiredGroups
	}
	requirementGroups, satisfied := _resolveRequirementGroups(groups, result)
	return map[string]any{
		"requirementGroups": requirementGroups,
		"issues":            projectFindings(findings, ""),
		"overriddenIssues":  []any{},
		"metrics": map[string]any{
			"totalGroups":       len(requirementGroups),
			"satisfiedGroups":   satisfied,
			"anySatisfiedGroup": len(requirementGroups) > 0 && satisfied > 0,
			"ciInvalid":         0,
			"ciMissing":         0,
		},
		"version":   "0.2.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// _resolveRequirementGroups expands each AND-group into the legacy
// {requiredOrigins, foundOrigins, missingOrigins, overriddenOrigins,
// isFullySatisfied} shape by matching every requirement string
// against the origins the GitLab collector tracked. A requirement is
// satisfied when an origin's normalised path equals it; it is also
// flagged "overridden" when CollectOverriddenJobs returned at least
// one entry for that origin.
func _resolveRequirementGroups(groups [][]string, result *control.AnalysisResult) ([]map[string]any, int) {
	out := make([]map[string]any, 0, len(groups))
	satisfied := 0
	// Build a path → overridden lookup so a single pass over each
	// requirement can answer both "is it present?" and "is it
	// overridden?" without rescanning origins per check.
	originIsOverridden := map[string]bool{}
	knownPaths := map[string]bool{}
	if result != nil && result.PipelineOriginData != nil {
		for i := range result.PipelineOriginData.Origins {
			o := &result.PipelineOriginData.Origins[i]
			loc := o.GitlabIncludeOrigin.Location
			if loc == "" {
				loc = o.GitlabComponent.ComponentIncludePath
			}
			if loc == "" {
				continue
			}
			cleaned := utils.CleanOriginPath(loc)
			knownPaths[cleaned] = true
			for _, ov := range o.Jobs {
				if ov.IsOverridden {
					originIsOverridden[cleaned] = true
					break
				}
			}
		}
	}
	for idx, required := range groups {
		found := []string{}
		missing := []string{}
		overridden := []string{}
		for _, want := range required {
			if knownPaths[want] {
				found = append(found, want)
				if originIsOverridden[want] {
					overridden = append(overridden, want)
				}
				continue
			}
			missing = append(missing, want)
		}
		isFull := len(missing) == 0
		if isFull {
			satisfied++
		}
		out = append(out, map[string]any{
			"groupIndex":        idx,
			"requiredOrigins":   required,
			"foundOrigins":      found,
			"missingOrigins":    missing,
			"overriddenOrigins": overridden,
			"isFullySatisfied":  isFull,
		})
	}
	return out, satisfied
}

func buildDebugTraceBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"totalVariablesChecked": _countAllVariableBindings(result),
			"forbiddenFound":        len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildVariableInjectionBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	jobs := 0
	if result.PipelineOriginMetrics != nil {
		jobs = int(result.PipelineOriginMetrics.JobTotal)
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"jobsChecked":             jobs,
			"totalScriptLinesChecked": _countScriptLines(result),
			"unsafeExpansionsFound":   len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildSecurityJobsBlock(c legacyCommon, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"securityJobsFound": _countSecurityJobs(result, pc),
			"weakenedJobs":      len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildUnverifiedScriptsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	jobs := 0
	if result.PipelineOriginMetrics != nil {
		jobs = int(result.PipelineOriginMetrics.JobTotal)
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"jobsChecked":             jobs,
			"totalScriptLinesChecked": _countScriptLines(result),
			"unverifiedScriptsFound":  len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildJobVariablesOverrideBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	// v0.2.x parity: when the user supplied no protected-variable
	// list (control absent from .plumber.yaml, hence Skipped), there
	// is nothing to compare against — report 0 variables checked
	// instead of the project-authored count, matching the legacy
	// JSON consumers key on.
	totalChecked := 0
	if !c.Skipped {
		totalChecked = _countProjectAuthoredVariables(result)
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"totalVariablesChecked": totalChecked,
			"overriddenFound":       len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildDockerInDockerBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	jobs := 0
	if result.PipelineOriginMetrics != nil {
		jobs = int(result.PipelineOriginMetrics.JobTotal)
	}
	insecure := 0
	for _, f := range findings {
		if f.Code == string(control.CodeDockerInDockerInsecure) {
			insecure++
		}
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"totalJobsChecked":    jobs,
			"dindServicesFound":   _countDinDServices(result),
			"insecureDaemonFound": insecure,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}
