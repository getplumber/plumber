package cmd

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/getplumber/plumber/collector"
	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/utils"
)

// statLine is a single labelled metric rendered above the findings
// listing of a findingGroup. Values are free-form strings so each
// converter can format numbers however it needs (plain int, percent…).
type statLine struct {
	Label string
	Value string
}

// detailedFinding is the unified shape used to render per-rule detail
// listings, independent of the original source. Message is printed
// verbatim; Location, when set, is rendered as a clickable file:line
// path right after the message so editors and terminals that detect
// source references (VS Code, IntelliJ, iTerm, ...) can jump straight
// to the offending job.
type detailedFinding struct {
	Code     control.ErrorCode
	Message  string
	DocURL   string
	Location string
	// DetailLines is optional (e.g. ISSUE-505: one headline, several sub-reasons).
	DetailLines []string
}

// findingGroup collects everything needed to render one per-rule
// section: its title, compliance, optional stats block, and the list
// of findings.
type findingGroup struct {
	Title      string
	Compliance float64
	Skipped    bool
	Stats      []statLine
	Findings   []detailedFinding
}

// renderFindingGroups prints each group in the canonical Plumber
// format used across providers: horizontal separator header with the
// rule title and compliance (or "skipped"), the stat lines, and an
// "Issues Found" listing with severity tag, code, message and doc URL.
// Groups with no stats, no findings and not marked skipped are not
// rendered (they would just be empty noise).
func renderFindingGroups(groups []findingGroup) {
	for _, g := range groups {
		if !g.Skipped && len(g.Stats) == 0 && len(g.Findings) == 0 {
			continue
		}
		printControlHeader(g.Title, g.Compliance, g.Skipped)
		if g.Skipped {
			fmt.Printf("  %sStatus: SKIPPED (disabled in configuration)%s\n\n", colorDim, colorReset)
			continue
		}
		for _, s := range g.Stats {
			fmt.Printf("  %s: %s\n", s.Label, s.Value)
		}
		if len(g.Findings) > 0 {
			fmt.Printf("\n  %sIssues Found:%s\n", colorYellow, colorReset)
			for _, f := range g.Findings {
				tag := severityTag(f.Code)
				fmt.Printf("     %s [%s] %s\n", tag, f.Code, f.Message)
				for _, line := range f.DetailLines {
					fmt.Printf("      └─ %s\n", line)
				}
				if f.Location != "" {
					// The bare path is emitted last so VS Code, iTerm
					// and similar tools detect it as a clickable
					// file:line reference and jump straight to the job.
					fmt.Printf("      %s↳ at %s%s\n", colorDim, f.Location, colorReset)
				}
				if f.DocURL != "" {
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, f.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}
}

// formatFindingLocation returns "file:line" when both fields are set,
// "file" when only File is set, and "" otherwise. The Line suffix
// lets editors and terminals that detect source references jump
// straight to the offending job (Ctrl-click in VS Code, Cmd-click
// in iTerm, …).
func formatFindingLocation(f opaengine.Finding) string {
	if f.File == "" {
		return ""
	}
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

// detailLinesFromFinding unpacks ISSUE-505 structured reasons into CLI sub-lines.
func detailLinesFromFinding(f opaengine.Finding) []string {
	if f.Code != string(control.CodeBranchNonCompliant) || f.Data == nil {
		return nil
	}
	raw, ok := f.Data["reasons"]
	if !ok || raw == nil {
		return nil
	}
	lines := reasonsArrayToStrings(raw)
	if len(lines) == 0 {
		return nil
	}
	return sortBranchProtectionDetailLines(lines)
}

func reasonsArrayToStrings(raw interface{}) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// sortBranchProtectionDetailLines applies a stable product order (force push,
// code owner, then other reasons lexicographically).
func sortBranchProtectionDetailLines(lines []string) []string {
	if len(lines) < 2 {
		return lines
	}
	out := slices.Clone(lines)
	slices.SortFunc(out, func(a, b string) int {
		return cmp.Or(
			cmp.Compare(branchProtectionDetailRank(a), branchProtectionDetailRank(b)),
			cmp.Compare(a, b),
		)
	})
	return out
}

func branchProtectionDetailRank(s string) int {
	switch {
	case strings.HasPrefix(s, "Force push"):
		return 0
	case strings.HasPrefix(s, "Code owner"):
		return 1
	case strings.HasPrefix(s, "Merge access level"):
		return 2
	case strings.HasPrefix(s, "Push access level"):
		return 3
	default:
		return 50
	}
}

// sortBranchProtectionFindingsForDisplay prints ISSUE-505 before ISSUE-501 so the
// protected-but-misconfigured branch appears above plain unprotected branches.
func sortBranchProtectionFindingsForDisplay(findings []opaengine.Finding) {
	if len(findings) < 2 {
		return
	}
	rank := func(code string) int {
		switch code {
		case "ISSUE-505":
			return 0
		case "ISSUE-501":
			return 1
		default:
			return 10
		}
	}
	slices.SortFunc(findings, func(a, b opaengine.Finding) int {
		return cmp.Or(
			cmp.Compare(rank(a.Code), rank(b.Code)),
			cmp.Compare(a.Job, b.Job),
			cmp.Compare(a.Message, b.Message),
		)
	})
}

// buildGitLabControlStats returns the legacy aggregated metrics that
// the v0.2.x analyzer printed under each control header — the
// "Total Images: 9 / Authorized: 9 / Unauthorized: 0" block. The
// Rego engine emits findings only, so we recompute the totals here
// from the IR data still attached to AnalysisResult, the user
// configuration (for "checked-list" sizes), and the per-control
// findings list (for denominators and code-specific counts such as
// ISSUE-102 / ISSUE-505). Each control name matches the entry
// registered by control.GitLabControls().
// buildGitHubControlStats produces the per-control stats block for
// the GitHub renderer using the pre-aggregated GitHubAnalysisStats
// computed by control.AggregateGitHubStats. Mirrors the GitLab
// equivalent — same Label/Value shape rendered identically by
// renderFindingGroups.
func buildGitHubControlStats(controlName string, stats *control.GitHubAnalysisStats) []statLine {
	if stats == nil {
		return nil
	}
	switch controlName {
	case "containerImageMustNotUseForbiddenTags":
		notPinned := stats.ImagesTotal - stats.ImagesPinnedByDigest
		if notPinned < 0 {
			notPinned = 0
		}
		return []statLine{
			{"Total Images", fmt.Sprintf("%d", stats.ImagesTotal)},
			{"Pinned By Digest", fmt.Sprintf("%d", stats.ImagesPinnedByDigest)},
			{"Not Pinned By Digest", fmt.Sprintf("%d", notPinned)},
			{"Using Forbidden Tags", fmt.Sprintf("%d", stats.ImagesUsingForbidden)},
		}
	case "actionsMustBePinnedByCommitSha":
		pinned := stats.ActionRefsTotal - stats.ActionRefsUnpinned
		if pinned < 0 {
			pinned = 0
		}
		return []statLine{
			{"Total Action Refs", fmt.Sprintf("%d", stats.ActionRefsTotal+stats.ActionRefsExempt)},
			{"Pinned By SHA", fmt.Sprintf("%d", pinned)},
			{"Not Pinned By SHA", fmt.Sprintf("%d", stats.ActionRefsUnpinned)},
			{"Trusted-Owner Exempt", fmt.Sprintf("%d", stats.ActionRefsExempt)},
		}
	case "securityJobsMustNotBeWeakened":
		return []statLine{
			{"Security Jobs Found", fmt.Sprintf("%d", stats.SecurityJobsTotal)},
			{"Weakened Jobs", fmt.Sprintf("%d", stats.SecurityJobsWeakened)},
		}
	case "pipelineMustNotUseDockerInDocker":
		return []statLine{
			{"Jobs Checked", fmt.Sprintf("%d", stats.JobsTotal)},
			{"DinD Services Found", fmt.Sprintf("%d", stats.JobsWithDinD)},
			{"Insecure Daemon Config", fmt.Sprintf("%d", stats.JobsWithInsecureDaemon)},
		}
	case "reusableWorkflowsMustNotInheritSecrets":
		return []statLine{
			{"Reusable Workflow Calls", fmt.Sprintf("%d", stats.ReusableCalls)},
			{"With secrets: inherit", fmt.Sprintf("%d", stats.ReusableCallsSecretsInherit)},
		}
	case "workflowMustNotInjectUserInputInScripts":
		return []statLine{
			{"Workflows Scanned", fmt.Sprintf("%d", stats.WorkflowsTotal)},
			{"Script Lines Checked", fmt.Sprintf("%d", stats.ScriptLinesTotal)},
		}
	case "workflowMustNotUseDangerousTriggers":
		return []statLine{
			{"Workflows Scanned", fmt.Sprintf("%d", stats.WorkflowsTotal)},
			{"Using Dangerous Triggers", fmt.Sprintf("%d", stats.WorkflowsWithDangerousTrigger)},
		}
	case "workflowsMustDeclarePermissions":
		withPerms := stats.WorkflowsTotal - stats.WorkflowsMissingPermissions
		if withPerms < 0 {
			withPerms = 0
		}
		return []statLine{
			{"Total Workflows", fmt.Sprintf("%d", stats.WorkflowsTotal)},
			{"With permissions block", fmt.Sprintf("%d", withPerms)},
			{"Missing permissions block", fmt.Sprintf("%d", stats.WorkflowsMissingPermissions)},
		}
	case "branchMustBeProtected":
		unprotectedMatched := stats.BranchesMatched - stats.BranchesProtected
		if unprotectedMatched < 0 {
			unprotectedMatched = 0
		}
		lines := []statLine{
			{"Total Branches", fmt.Sprintf("%d", stats.BranchesTotal)},
			{"Branches to Protect", fmt.Sprintf("%d", stats.BranchesMatched)},
			{"Protected", fmt.Sprintf("%d", stats.BranchesProtected)},
			{"Unprotected (matched)", fmt.Sprintf("%d", unprotectedMatched)},
		}
		// Surface partial-evaluation when /branches/{name}/protection
		// 403'd (token lacked Administration:Read). Without this line
		// the section header shows "100.0% compliant" while ISSUE-505
		// silently abstained — exactly the silent-success-on-
		// incomplete-data footgun we want to avoid.
		if stats.BranchesProtectionDetailsUnknown > 0 {
			lines = append(lines, statLine{
				"⚠ Force-push & code-owner rules",
				fmt.Sprintf("skipped on %d branch(es) — token lacks Administration:Read", stats.BranchesProtectionDetailsUnknown),
			})
		}
		return lines
	}
	return nil
}

// gitHubControlCompliance returns binary per-control compliance,
// matching the GitLab semantics: any finding on the control → 0%,
// otherwise 100%. The stats parameter is retained on the signature
// because the per-control stats blocks (rendered separately by
// buildGitHubControlStats) still consume it; only the percentage
// itself is binary.
//
// Why binary: GitLab's outputText computes compliance the same way
// (`if !skipped && len(items) > 0 { compliance = 0.0 }`). Mixing a
// gradient on the GitHub side led to "100.0% compliant" headers
// rendering above HIGH-severity findings for the same control —
// confusing and contradictory. A control either passed or it
// didn't; the stats block already shows the underlying numerators
// for users who want the gradient view.
func gitHubControlCompliance(controlName string, stats *control.GitHubAnalysisStats, findings int) float64 {
	_ = controlName
	_ = stats
	if findings > 0 {
		return 0
	}
	return 100
}

func buildGitLabControlStats(controlName string, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) []statLine {
	if result == nil {
		return nil
	}
	findingsCount := len(findings)
	jobTotal := uint(0)
	if result.PipelineOriginMetrics != nil {
		jobTotal = result.PipelineOriginMetrics.JobTotal
	}
	switch controlName {
	case "containerImageMustNotUseForbiddenTags":
		// Two distinct user intents share this control: forbid mutable
		// tags, OR require a digest pin. The pin-by-digest variant
		// counts how many images carry an OCI digest reference (any
		// algorithm — sha256, sha512, …).
		total := 0
		pinned := 0
		if result.PipelineImageData != nil {
			total = len(result.PipelineImageData.Images)
			for _, img := range result.PipelineImageData.Images {
				if utils.HasDigestPin(img.Link) {
					pinned++
				}
			}
		}
		notPinned := total - pinned
		if notPinned < 0 {
			notPinned = 0
		}
		usingForbidden := 0
		for _, f := range findings {
			if f.Code == string(control.CodeImageForbiddenTag) {
				usingForbidden++
			}
		}
		lines := []statLine{
			{"Total Images", fmt.Sprintf("%d", total)},
		}
		if pc != nil && pc.ControlsFor("gitlab").ContainerImageMustNotUseForbiddenTags.IsPinnedByDigestRequired() {
			lines = append(lines,
				statLine{"Pinned By Digest", fmt.Sprintf("%d", pinned)},
				statLine{"Not Pinned By Digest", fmt.Sprintf("%d", notPinned)},
			)
		}
		lines = append(lines, statLine{"Using Forbidden Tags", fmt.Sprintf("%d", usingForbidden)})
		return lines
	case "containerImageMustComeFromAuthorizedSources":
		total := 0
		if result.PipelineImageMetrics != nil {
			total = int(result.PipelineImageMetrics.Total)
		}
		unauthorized := findingsCount
		authorized := total - unauthorized
		if authorized < 0 {
			authorized = 0
		}
		return []statLine{
			{"Total Images", fmt.Sprintf("%d", total)},
			{"Authorized", fmt.Sprintf("%d", authorized)},
			{"Unauthorized", fmt.Sprintf("%d", unauthorized)},
		}
	case "pipelineMustNotIncludeHardcodedJobs":
		total := uint(0)
		hardcoded := uint(0)
		if result.PipelineOriginMetrics != nil {
			total = result.PipelineOriginMetrics.JobTotal
			hardcoded = result.PipelineOriginMetrics.JobHardcoded
		}
		return []statLine{
			{"Total Jobs", fmt.Sprintf("%d", total)},
			{"Hardcoded Jobs", fmt.Sprintf("%d", hardcoded)},
		}
	case "includesMustBeUpToDate":
		// _externalIncludeCount strips the project's own pseudo-origin
		// and the FromPlumber injection so "Total Includes" lines up
		// with the count of *external* includes the v0.2.x analyzer
		// reported.
		total := _externalIncludeCount(result)
		outdated := uint(0)
		if result.PipelineOriginMetrics != nil {
			outdated = result.PipelineOriginMetrics.OriginOutdated
		}
		return []statLine{
			{"Total Includes", fmt.Sprintf("%d", total)},
			{"Outdated", fmt.Sprintf("%d", outdated)},
		}
	case "includesMustNotUseForbiddenVersions":
		total := _externalIncludeCount(result)
		authorized := total - findingsCount
		if authorized < 0 {
			authorized = 0
		}
		return []statLine{
			{"Total Includes", fmt.Sprintf("%d", total)},
			{"Using Authorized Versions", fmt.Sprintf("%d", authorized)},
			{"Using Forbidden Versions", fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotEnableDebugTrace":
		// "Variables Checked" mirrors v0.2.x: the total number of
		// variable bindings the analyzer scanned across every job and
		// the pipeline globals — not the size of the forbidden list.
		// On a 27-job pipeline this lands around 50–60 because
		// imported security templates each carry their own set.
		return []statLine{
			{"Variables Checked", fmt.Sprintf("%d", _countAllVariableBindings(result))},
			{"Forbidden Found", fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotOverrideJobVariables":
		// Override checks only apply to bindings authored by the
		// project (globals + hardcoded jobs); imported components
		// legitimately set their own. Mirror that scope here so
		// "Variables Checked" matches the count actually scanned.
		return []statLine{
			{"Variables Checked", fmt.Sprintf("%d", _countProjectAuthoredVariables(result))},
			{"Overridden Found", fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotUseUnsafeVariableExpansion":
		return []statLine{
			{"Jobs Checked", fmt.Sprintf("%d", jobTotal)},
			{"Script Lines Checked", fmt.Sprintf("%d", _countScriptLines(result))},
			{"Unsafe Expansions", fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotExecuteUnverifiedScripts":
		return []statLine{
			{"Jobs Checked", fmt.Sprintf("%d", jobTotal)},
			{"Script Lines Checked", fmt.Sprintf("%d", _countScriptLines(result))},
			{"Unverified Scripts", fmt.Sprintf("%d", findingsCount)},
		}
	case "securityJobsMustNotBeWeakened":
		// Stable's "Security Jobs Found" counts how many of the merged
		// jobs match a configured security pattern — a context-rich
		// denominator for "0 weakened" findings: 0/14 reads very
		// differently from 0/0.
		return []statLine{
			{"Security Jobs Found", fmt.Sprintf("%d", _countSecurityJobs(result, pc))},
			{"Weakened Jobs", fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustIncludeComponent":
		var resolved [][]string
		if pc != nil && pc.ControlsFor("gitlab").PipelineMustIncludeComponent != nil {
			if g, err := pc.ControlsFor("gitlab").PipelineMustIncludeComponent.GetResolvedRequiredGroups(); err == nil {
				resolved = g
			}
		}
		satisfied := countSatisfiedGroups(resolved, result, "component")
		return []statLine{
			{"Requirement Groups", fmt.Sprintf("%d", len(resolved))},
			{"Satisfied Groups", fmt.Sprintf("%d", satisfied)},
		}
	case "pipelineMustIncludeTemplate":
		var resolved [][]string
		if pc != nil && pc.ControlsFor("gitlab").PipelineMustIncludeTemplate != nil {
			if g, err := pc.ControlsFor("gitlab").PipelineMustIncludeTemplate.GetResolvedRequiredGroups(); err == nil {
				resolved = g
			}
		}
		satisfied := countSatisfiedGroups(resolved, result, "template")
		return []statLine{
			{"Requirement Groups", fmt.Sprintf("%d", len(resolved))},
			{"Satisfied Groups", fmt.Sprintf("%d", satisfied)},
		}
	case "pipelineMustNotUseDockerInDocker":
		return []statLine{
			{"Jobs Checked", fmt.Sprintf("%d", jobTotal)},
			{"DinD Services Found", fmt.Sprintf("%d", _countDinDServices(result))},
			{"Insecure Daemon Config", fmt.Sprintf("%d", findingsCount)},
		}
	case "branchMustBeProtected":
		total, toProtect, protected, unprotected := _branchProtectionCounts(result, pc)
		nonCompliant := 0
		for _, f := range findings {
			if f.Code == string(control.CodeBranchNonCompliant) {
				nonCompliant++
			}
		}
		return []statLine{
			{"Total Branches", fmt.Sprintf("%d", total)},
			{"Branches to Protect", fmt.Sprintf("%d", toProtect)},
			{"Protected Branches", fmt.Sprintf("%d", protected)},
			{"Unprotected", fmt.Sprintf("%d", unprotected)},
			{"Non-Compliant", fmt.Sprintf("%d", nonCompliant)},
		}
	}
	return nil
}

// _countScriptLines walks the merged GitLab CI conf and totals every
// script line declared on every job (script, before_script,
// after_script). Used as the "Script Lines Checked" denominator
// printed under script-scanning controls. The merged conf may be
// produced by either yaml.v2 (which yields `map[interface{}]any` for
// nested maps) or yaml.v3 (`map[string]any`); accept both shapes.
func _countScriptLines(result *control.AnalysisResult) int {
	if result == nil || result.PipelineImageData == nil || result.PipelineImageData.MergedConf == nil {
		return 0
	}
	total := 0
	for _, raw := range result.PipelineImageData.MergedConf.GitlabJobs {
		for _, key := range []string{"script", "before_script", "after_script"} {
			switch v := _readMapKey(raw, key).(type) {
			case string:
				if v != "" {
					total++
				}
			case []interface{}:
				total += len(v)
			}
		}
	}
	return total
}

// _externalIncludeCount returns the number of external origins
// (component / template / local / remote / project) excluding the
// project itself, matching the v0.2.x "Total Includes" denominator.
// Walks origin.Origins directly so we can skip both the FromPlumber
// component (which Plumber injects implicitly when used) and the
// project's own pseudo-origin even when OriginProject stays at 0 in
// the metrics summary.
func _externalIncludeCount(result *control.AnalysisResult) int {
	if result == nil || result.PipelineOriginData == nil {
		return 0
	}
	count := 0
	for i := range result.PipelineOriginData.Origins {
		o := &result.PipelineOriginData.Origins[i]
		if o.FromPlumber {
			continue
		}
		// Skip the project's own root origin: the .gitlab-ci.yml is
		// not an "include" in the user-facing sense. The origin type
		// surfaces as either "project" or "hardcoded" depending on
		// the collector path.
		if o.OriginType == "" || o.OriginType == "project" || o.OriginType == "hardcoded" {
			continue
		}
		count++
	}
	return count
}

// _countProjectAuthoredVariables counts variable bindings the project
// owns: pipeline-level globals plus any job whose origin is the
// project's own .gitlab-ci.yml (originType == "project" or hardcoded).
// Imported component / template jobs are excluded — those bindings
// belong to upstream and the user cannot remove them.
func _countProjectAuthoredVariables(result *control.AnalysisResult) int {
	if result == nil || result.PipelineImageData == nil || result.PipelineImageData.MergedConf == nil {
		return 0
	}
	total := 0
	if g := result.PipelineImageData.MergedConf.GlobalVariables; g != nil {
		total += len(g)
	}
	if result.PipelineOriginData == nil || result.PipelineOriginData.JobMap == nil {
		return total
	}
	hardcoded := result.PipelineOriginData.JobHardcodedMap
	for name, raw := range result.PipelineImageData.MergedConf.GitlabJobs {
		// Only count jobs the user authors directly; imported
		// component / template variables fall outside this control's
		// scope (see ISSUE-205 rule guard).
		if hardcoded == nil || !hardcoded[name] {
			continue
		}
		v := _readMapKey(raw, "variables")
		switch m := v.(type) {
		case map[string]interface{}:
			total += len(m)
		case map[interface{}]interface{}:
			total += len(m)
		}
	}
	return total
}

// _countAllVariableBindings totals every distinct (job, variable)
// binding the analyzer can see, plus pipeline-level globals. The
// merged conf is the source of truth — it materialises variables
// inherited from imported components/templates that the IR Job map
// flattens away.
func _countAllVariableBindings(result *control.AnalysisResult) int {
	if result == nil || result.PipelineImageData == nil || result.PipelineImageData.MergedConf == nil {
		return 0
	}
	total := 0
	for _, raw := range result.PipelineImageData.MergedConf.GitlabJobs {
		v := _readMapKey(raw, "variables")
		switch m := v.(type) {
		case map[string]interface{}:
			total += len(m)
		case map[interface{}]interface{}:
			total += len(m)
		}
	}
	if g := result.PipelineImageData.MergedConf.GlobalVariables; g != nil {
		total += len(g)
	}
	return total
}

// _countSecurityJobs walks the merged conf and counts how many job
// names match a configured security-job pattern. When the user has
// not customised the patterns, fall back to the conventional GitLab
// security-template suffixes (-sast, secret_detection, dependency-
// scanning, container-scanning, license-scanning, dast).
func _countSecurityJobs(result *control.AnalysisResult, pc *configuration.PlumberConfig) int {
	if result == nil || result.PipelineImageData == nil || result.PipelineImageData.MergedConf == nil {
		return 0
	}
	patterns := []string{}
	if pc != nil && pc.ControlsFor("gitlab").SecurityJobsMustNotBeWeakened != nil {
		patterns = pc.ControlsFor("gitlab").SecurityJobsMustNotBeWeakened.SecurityJobPatterns
	}
	if len(patterns) == 0 {
		patterns = []string{
			"*-sast", "*sast*", "secret_detection", "secret-detection",
			"dependency_scanning", "dependency-scanning",
			"container_scanning", "container-scanning",
			"license_scanning", "license-scanning",
			"dast", "*dast*",
		}
	}
	count := 0
	for name := range result.PipelineImageData.MergedConf.GitlabJobs {
		if _matchesAnyGlob(name, patterns) {
			count++
		}
	}
	return count
}

// _matchesAnyGlob is a tiny wildcard matcher (only '*' is meaningful)
// so we stay free of an external glob dependency in the renderer.
func _matchesAnyGlob(name string, patterns []string) bool {
	for _, p := range patterns {
		if _globMatch(p, name) {
			return true
		}
	}
	return false
}

func _globMatch(pattern, name string) bool {
	// Trivial cases with no wildcard: exact match.
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(name[pos:], part)
		if idx < 0 {
			return false
		}
		// First non-empty part must anchor at start unless the pattern
		// began with '*'.
		if i == 0 && idx != 0 && !strings.HasPrefix(pattern, "*") {
			return false
		}
		pos += idx + len(part)
	}
	// Last non-empty part must anchor at end unless pattern ended in '*'.
	if !strings.HasSuffix(pattern, "*") && pos != len(name) {
		return false
	}
	return true
}

// _branchProtectionCounts mirrors v0.2.x: walks every detected branch
// against the user policy patterns and the upstream protection rules,
// returning Total / ToProtect / Protected / Unprotected.
func _branchProtectionCounts(result *control.AnalysisResult, pc *configuration.PlumberConfig) (total, toProtect, protected, unprotected int) {
	if result == nil || result.ProtectionData == nil {
		return 0, 0, 0, 0
	}
	branches := result.ProtectionData.Branches
	total = len(branches)
	if pc == nil || pc.ControlsFor("gitlab").BranchMustBeProtected == nil {
		return total, 0, 0, 0
	}
	cfg := pc.ControlsFor("gitlab").BranchMustBeProtected
	defaultBranch := result.DefaultBranch
	patterns := cfg.NamePatterns
	defaultProtected := cfg.DefaultMustBeProtected != nil && *cfg.DefaultMustBeProtected
	// Branch protections in GitLab are patterns themselves (e.g.
	// "main", "release/*"); a branch is "protected" iff at least one
	// declared protection pattern matches its name.
	protectionPatterns := make([]string, 0, len(result.ProtectionData.BranchProtections))
	for _, p := range result.ProtectionData.BranchProtections {
		protectionPatterns = append(protectionPatterns, p.ProtectionPattern)
	}
	for _, name := range branches {
		matches := false
		if defaultProtected && name == defaultBranch {
			matches = true
		}
		if !matches && _matchesAnyGlob(name, patterns) {
			matches = true
		}
		if matches {
			toProtect++
			if _matchesAnyGlob(name, protectionPatterns) {
				protected++
			} else {
				unprotected++
			}
		}
	}
	return total, toProtect, protected, unprotected
}

// _readMapKey reads `key` from a value that may be either a
// map[string]any or a map[interface{}]any. Returns nil otherwise.
func _readMapKey(raw any, key string) any {
	switch m := raw.(type) {
	case map[string]interface{}:
		return m[key]
	case map[interface{}]interface{}:
		return m[key]
	}
	return nil
}

// _countDinDServices counts jobs that wire a Docker-in-Docker
// service (an entry under `services:` whose image string contains
// "dind"). Walks the merged conf so we see services declared in
// imported templates, not just the main job images. Mirrors the
// legacy "DinD Services Found" stat.
func _countDinDServices(result *control.AnalysisResult) int {
	if result == nil || result.PipelineImageData == nil || result.PipelineImageData.MergedConf == nil {
		return 0
	}
	count := 0
	for _, raw := range result.PipelineImageData.MergedConf.GitlabJobs {
		v := _readMapKey(raw, "services")
		switch s := v.(type) {
		case []interface{}:
			for _, item := range s {
				if _serviceLooksLikeDind(item) {
					count++
					break
				}
			}
		case string:
			if strings.Contains(s, "dind") {
				count++
			}
		}
	}
	return count
}

// _serviceLooksLikeDind decodes a single services list entry — which
// may be a bare image string or a {name, alias, ...} map — and
// reports whether it references a Docker-in-Docker daemon image.
func _serviceLooksLikeDind(item interface{}) bool {
	switch v := item.(type) {
	case string:
		return strings.Contains(v, "dind")
	case map[string]interface{}:
		if name, ok := v["name"].(string); ok {
			return strings.Contains(name, "dind")
		}
	case map[interface{}]interface{}:
		if name, ok := v["name"].(string); ok {
			return strings.Contains(name, "dind")
		}
	}
	return false
}

// countSatisfiedGroups returns how many DNF requirement groups have
// every required component (or template) actually present in the
// pipeline. Mirrors the rego matching rules in component_missing /
// template_missing: an origin matches when its cleaned location, the
// raw location, or any Plumber-augmented path equals the required
// entry. The kindFilter is "component" for ISSUE-408 and "template"
// for ISSUE-405 (anything that is not "component" or "hardcoded").
func countSatisfiedGroups(groups [][]string, result *control.AnalysisResult, kindFilter string) int {
	if result == nil || result.PipelineOriginData == nil || len(groups) == 0 {
		return 0
	}
	satisfied := 0
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		all := true
		for _, required := range group {
			if !originGroupMatch(required, result.PipelineOriginData, kindFilter) {
				all = false
				break
			}
		}
		if all {
			satisfied++
		}
	}
	return satisfied
}

func originGroupMatch(required string, data *collector.GitlabPipelineOriginData, kindFilter string) bool {
	cleanRequired := utils.CleanOriginPath(required)
	for i := range data.Origins {
		o := &data.Origins[i]
		if !originKindMatches(o.OriginType, kindFilter) {
			continue
		}
		loc := o.GitlabIncludeOrigin.Location
		if loc == required || utils.CleanOriginPath(loc) == cleanRequired {
			return true
		}
		if o.PlumberOrigin.Path != "" && o.PlumberOrigin.Path == required {
			return true
		}
	}
	return false
}

func originKindMatches(originType, kindFilter string) bool {
	switch kindFilter {
	case "component":
		return originType == "component"
	case "template":
		return originType != "component" && originType != "hardcoded" && originType != ""
	default:
		return false
	}
}

