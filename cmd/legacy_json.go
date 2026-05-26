package cmd

import (
	"sort"
	"strings"

	"github.com/getplumber/plumber/collector"
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
// learned to parse those blocks: each control's issues list, its
// `metrics` object, and the binary `compliance` flag travel together
// under a stable JSON key. The Rego port had collapsed them into a
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
func legacyResultsByName(result *control.AnalysisResult, pc *configuration.PlumberConfig, provider string, includeOnly, skip []string) map[string]any {
	if result == nil || pc == nil {
		return nil
	}
	out := map[string]any{}
	findingsByControl := control.FindingsByControl(result.Findings)

	switch provider {
	case "github":
		entries := control.GitHubControls(pc)
		control.MarkSkippedByFilter(entries, includeOnly, skip)
		for _, e := range entries {
			fs := findingsByControl[e.ControlName]
			key, block := buildLegacyResultGitHub(e, result, pc, fs)
			if key == "" {
				continue
			}
			out[key] = block
		}
	default:
		entries := control.GitLabControls(pc)
		control.MarkSkippedByFilter(entries, includeOnly, skip)
		for _, e := range entries {
			fs := findingsByControl[e.ControlName]
			key, block := buildLegacyResult(e, result, pc, fs)
			if key == "" {
				continue
			}
			out[key] = block
		}
	}
	return out
}

// buildLegacyResult routes a control entry to its legacy JSON
// builder and returns the (jsonKey, block) pair.
func buildLegacyResult(e control.ControlEntry, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) (string, any) {
	compliance := 100.0
	if !e.Skipped && len(findings) > 0 {
		compliance = 0
	}
	common := legacyCommon{
		Compliance: compliance,
		CiValid:    result.CiValid,
		CiMissing:  result.CiMissing,
		Skipped:    e.Skipped,
	}

	switch e.ControlName {
	case "containerImageMustNotUseForbiddenTags":
		return "imageForbiddenTagsResult", buildImageForbiddenTagsBlock(common, result, pc, findings)
	case "containerImageMustComeFromAuthorizedSources":
		return "imageAuthorizedSourcesResult", buildImageAuthorizedSourcesBlock(common, result, findings)
	case "branchMustBeProtected":
		return "branchProtectionResult", buildBranchProtectionBlock(common, result, pc, findings)
	case "pipelineMustNotIncludeHardcodedJobs":
		return "hardcodedJobsResult", buildHardcodedJobsBlock(common, result, findings)
	case "includesMustBeUpToDate":
		return "outdatedIncludesResult", buildOutdatedIncludesBlock(common, result, findings)
	// (jobNameKey is dropped for the outdated builder — the legacy
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
	}
	return "", nil
}

// legacyCommon carries the bookkeeping fields shared by every
// `*Result` block: compliance, ciValid, ciMissing, skipped.
type legacyCommon struct {
	Compliance float64
	CiValid    bool
	CiMissing  bool
	Skipped    bool
}

// projectFinding strips the verbose Rego-side fields (severity,
// message, file, line) so the returned issue keeps only what the
// legacy format documented: code, docUrl, plus whatever structured
// payload the rule emitted (link/tag/variableName/…).
func projectFinding(f opaengine.Finding, jobNameKey string) map[string]any {
	out := map[string]any{
		"code":   f.Code,
		"docUrl": "https://getplumber.io/docs/cli/issues/" + f.Code,
	}
	if f.Job != "" && jobNameKey != "" {
		out[jobNameKey] = f.Job
	}
	// `url` is the per-finding clickable pointer populated by the
	// location linker. Emitted on every per-control issue block so
	// downstream consumers (dashboards, MR-comment renderers,
	// scripts) can hyperlink to the offending file at the analysed
	// commit without having to recompose it themselves.
	if f.URL != "" {
		out["url"] = f.URL
	}
	for k, v := range f.Data {
		if k == "docUrl" || k == "url" {
			continue
		}
		out[k] = v
	}
	return out
}

func projectFindings(findings []opaengine.Finding, jobNameKey string) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, projectFinding(f, jobNameKey))
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
func _branchProtectionEntryForName(data *collector.GitlabProtectionAnalysisData, branchName string) *gitlab.BranchProtection {
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
			if j, ok := issue["job"].(string); ok {
				branchName = j
			}
		}
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

func _originByIncludeSource(data *collector.GitlabPipelineOriginData, source string) *collector.GitlabPipelineOriginDataFull {
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
		src, _ := issue["job"].(string)
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
	total := 0
	notPinned := 0
	usingForbidden := 0
	if result.PipelineImageData != nil {
		total = len(result.PipelineImageData.Images)
		for _, img := range result.PipelineImageData.Images {
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
			"pinnedByDigest":     total - notPinned,
			"ciInvalid":          0,
			"ciMissing":          0,
		},
		"compliance":           c.Compliance,
		"version":              "0.4.0",
		"ciValid":              c.CiValid,
		"ciMissing":            c.CiMissing,
		"skipped":              c.Skipped,
		"mustBePinnedByDigest": mustBePinned,
	}
}

func buildImageAuthorizedSourcesBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	total := 0
	if result.PipelineImageMetrics != nil {
		total = int(result.PipelineImageMetrics.Total)
	}
	unauthorized := len(findings)
	authorized := total - unauthorized
	if authorized < 0 {
		authorized = 0
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"total":        total,
			"authorized":   authorized,
			"unauthorized": unauthorized,
			"ciInvalid":    0,
			"ciMissing":    0,
		},
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
	}
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
		nonCompliantBranches := map[string]bool{}
		for _, f := range findings {
			if f.Code == string(control.CodeBranchNonCompliant) {
				nonCompliantBranches[f.Job] = true
			}
		}
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
		"enabled":    !c.Skipped,
		"compliance": c.Compliance,
		"version":    "0.2.0",
		"data":       data,
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
		"issues": projectFindings(_sortedFindings(findings), "jobName"),
		"metrics": map[string]any{
			"total":         total,
			"hardcodedJobs": hardcoded,
			"ciInvalid":     0,
			"ciMissing":     0,
		},
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
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
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
	}
}

func buildForbiddenVersionsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	total := _externalIncludeCount(result)
	usingForbidden := len(findings)
	usingAuthorized := total - usingForbidden
	if usingAuthorized < 0 {
		usingAuthorized = 0
	}
	issues := projectFindings(findings, "job")
	enrichForbiddenVersion404IssueMaps(issues, result)
	return map[string]any{
		"issues": issues,
		"metrics": map[string]any{
			"total":                  total,
			"usingForbiddenVersion":  usingForbidden,
			"usingAuthorizedVersion": usingAuthorized,
		},
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
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
		"issues":            projectFindings(findings, "job"),
		"overriddenIssues":  []any{},
		"metrics": map[string]any{
			"totalGroups":       len(requirementGroups),
			"satisfiedGroups":   satisfied,
			"anySatisfiedGroup": len(requirementGroups) > 0 && satisfied > 0,
			"ciInvalid":         0,
			"ciMissing":         0,
		},
		"compliance": c.Compliance,
		"version":    "0.2.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
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
		"issues":            projectFindings(findings, "job"),
		"overriddenIssues":  []any{},
		"metrics": map[string]any{
			"totalGroups":       len(requirementGroups),
			"satisfiedGroups":   satisfied,
			"anySatisfiedGroup": len(requirementGroups) > 0 && satisfied > 0,
			"ciInvalid":         0,
			"ciMissing":         0,
		},
		"compliance": c.Compliance,
		"version":    "0.2.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
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
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
	}
}

func buildVariableInjectionBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	jobs := 0
	if result.PipelineOriginMetrics != nil {
		jobs = int(result.PipelineOriginMetrics.JobTotal)
	}
	return map[string]any{
		"issues": projectFindings(findings, "jobName"),
		"metrics": map[string]any{
			"jobsChecked":             jobs,
			"totalScriptLinesChecked": _countScriptLines(result),
			"unsafeExpansionsFound":   len(findings),
		},
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
	}
}

func buildSecurityJobsBlock(c legacyCommon, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) map[string]any {
	return map[string]any{
		"issues": projectFindings(findings, "jobName"),
		"metrics": map[string]any{
			"securityJobsFound": _countSecurityJobs(result, pc),
			"weakenedJobs":      len(findings),
		},
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
	}
}

func buildUnverifiedScriptsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	jobs := 0
	if result.PipelineOriginMetrics != nil {
		jobs = int(result.PipelineOriginMetrics.JobTotal)
	}
	return map[string]any{
		"issues": projectFindings(findings, "jobName"),
		"metrics": map[string]any{
			"jobsChecked":             jobs,
			"totalScriptLinesChecked": _countScriptLines(result),
			"unverifiedScriptsFound":  len(findings),
		},
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
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
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
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
		"issues": projectFindings(findings, "jobName"),
		"metrics": map[string]any{
			"totalJobsChecked":    jobs,
			"dindServicesFound":   _countDinDServices(result),
			"insecureDaemonFound": insecure,
		},
		"compliance": c.Compliance,
		"version":    "0.1.0",
		"ciValid":    c.CiValid,
		"ciMissing":  c.CiMissing,
		"skipped":    c.Skipped,
	}
}
