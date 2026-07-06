package cmd

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	"github.com/getplumber/plumber/gitlab"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
)

const (
	statTotalImages        = "Total Images"
	statJobsChecked        = "Jobs Checked"
	statScriptLinesChecked = "Script Lines Checked"
	statRequirementGroups  = "Requirement Groups"
	statSatisfiedGroups    = "Satisfied Groups"
	statActionRefsChecked  = "Action Refs Checked"
	statVariablesChecked   = "Variables Checked"
)

// statLine is an alias for control.StatLine used within the cmd package.
type statLine = control.StatLine

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
	// SkipReason overrides the default "disabled in configuration"
	// string printed under a skipped header. Empty → renderer uses
	// the default; non-empty → the renderer prints "(<reason>)".
	SkipReason string
	Stats      []statLine
	Findings   []detailedFinding
}

// renderWarnings prints the run's non-fatal "could not verify" messages,
// e.g. a known-CVE check skipped because an action's pinned commit could
// not be resolved to a version. Surfacing them keeps a degraded check
// visible instead of letting it pass silently (ISSUE-228). No-op when
// there are none.
func renderWarnings(warnings []string) {
	if len(warnings) == 0 {
		return
	}
	fmt.Println()
	fmt.Printf("  %s⚠ Could not verify %d item(s):%s\n", colorYellow, len(warnings), colorReset)
	for _, w := range warnings {
		fmt.Printf("    %s•%s %s\n", colorYellow, colorReset, sanitizeTerminal(w))
	}
	// When a version stays unresolved (the authenticated read was blocked and
	// the anonymous fallback did not succeed), a user-supplied token resolves
	// it. Point there rather than leaving the user with a dead end (ISSUE-228).
	fmt.Printf("    %s↳ if an action above is in an org with an IP allow list, set PLUMBER_METADATA_TOKEN (a token with public-repo read) to resolve its version; see the README \"GitHub Action\" section.%s\n", colorYellow, colorReset)
}

// renderDegradedCaveat prints an up-front warning that the run scored
// against incomplete data because one or more collection/enrichment
// steps failed (#220). Without it a partial GitHub run looks identical
// to a clean one. No-op when there are no reasons.
func renderDegradedCaveat(reasons []string) {
	if len(reasons) == 0 {
		return
	}
	fmt.Printf("  %s⚠ Data collection was incomplete — results may be partial:%s\n", colorYellow, colorReset)
	for _, r := range reasons {
		fmt.Printf("    %s•%s %s\n", colorYellow, colorReset, sanitizeTerminal(r))
	}
	fmt.Printf("    %s↳ controls with un-collected data are marked \"not evaluated\"; the letter score is withheld until the run completes cleanly.%s\n\n", colorDim, colorReset)
}

// filterGroupsForDegraded drops every group that has no findings when the
// run is data-collection-degraded, leaving only the real findings (#220).
// A control that showed "100% compliant" over partial data is untrustworthy
// (the un-collected inputs could hold violations), so its green stat block
// is suppressed; a control that found a violation keeps it, because a
// finding on partial data is still real. Returns the input unchanged when
// not degraded.
func filterGroupsForDegraded(groups []findingGroup, degraded bool) []findingGroup {
	if !degraded {
		return groups
	}
	kept := make([]findingGroup, 0, len(groups))
	for _, g := range groups {
		if len(g.Findings) > 0 {
			kept = append(kept, g)
		}
	}
	return kept
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
			reason := g.SkipReason
			if reason == "" {
				reason = "disabled in configuration"
			}
			fmt.Printf("  %sStatus: SKIPPED (%s)%s\n\n", colorDim, reason, colorReset)
			continue
		}
		for _, s := range g.Stats {
			fmt.Printf("  %s: %s\n", s.Label, s.Value)
		}
		if len(g.Findings) > 0 {
			fmt.Printf("\n  %sIssues Found:%s\n", colorYellow, colorReset)
			for _, f := range g.Findings {
				tag := severityTag(f.Code)
				fmt.Printf("     %s [%s] %s\n", tag, f.Code, sanitizeTerminal(f.Message))
				for _, line := range f.DetailLines {
					fmt.Printf("      └─ %s\n", sanitizeTerminal(line))
				}
				if f.Location != "" {
					// The bare path is emitted last so VS Code, iTerm
					// and similar tools detect it as a clickable
					// file:line reference and jump straight to the job.
					fmt.Printf("      %s↳ at %s%s\n", colorDim, sanitizeTerminal(f.Location), colorReset)
				}
				if f.DocURL != "" {
					fmt.Printf("      %s↳ docs: %s%s\n", colorDim, f.DocURL, colorReset)
				}
			}
		}
		fmt.Println()
	}
}

// sanitizeTerminal strips control characters from repo-controlled text before
// it is printed to a terminal. Finding messages, detail lines and locations
// embed data taken from the scanned repository (job names, image refs, script
// lines, file paths); a crafted value could otherwise carry ANSI/OSC escape
// sequences that rewrite the operator's terminal. Tabs become spaces; every
// other control rune (including ESC) is dropped. Ordinary printable text — the
// whole legitimate case — is returned unchanged.
func sanitizeTerminal(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r == '\t' || unicode.IsControl(r) }) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			// drop C0/C1 control runes (incl. ESC) — neutralizes ANSI/OSC injection
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// formatFindingLocation returns the link the terminal should print
// for a finding. Priority:
//  1. f.URL when set — populated by the location linker before
//     rendering, so this is either a remote forge URL (CI / remote-
//     project runs) or an absolute "<path>:<line>" reference (local
//     runs). Both forms turn into a clickable link in VS Code, iTerm
//     and similar terminals.
//  2. The bare "<file>:<line>" string as a last-resort fallback in case
//     the linker did not run (older callers, tests).
//  3. "" when even the file is unknown.
func formatFindingLocation(f opaengine.Finding) string {
	if f.URL != "" {
		return f.URL
	}
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
func buildGitHubControlStats(controlName string, stats *control.GitHubAnalysisStats, findings []opaengine.Finding) []statLine {
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
			{Label: statTotalImages, Value: fmt.Sprintf("%d", stats.ImagesTotal)},
			{Label: "Pinned By Digest", Value: fmt.Sprintf("%d", stats.ImagesPinnedByDigest)},
			{Label: "Not Pinned By Digest", Value: fmt.Sprintf("%d", notPinned)},
			{Label: "Using Forbidden Tags", Value: fmt.Sprintf("%d", stats.ImagesUsingForbidden)},
		}
	case "actionsMustBePinnedByCommitSha":
		pinned := stats.ActionRefsTotal - stats.ActionRefsUnpinned
		if pinned < 0 {
			pinned = 0
		}
		return []statLine{
			{Label: "Total Action Refs", Value: fmt.Sprintf("%d", stats.ActionRefsTotal+stats.ActionRefsExempt)},
			{Label: "Pinned By SHA", Value: fmt.Sprintf("%d", pinned)},
			{Label: "Not Pinned By SHA", Value: fmt.Sprintf("%d", stats.ActionRefsUnpinned)},
			{Label: "Trusted-Owner Exempt", Value: fmt.Sprintf("%d", stats.ActionRefsExempt)},
		}
	case "githubActionMustComeFromAuthorizedSources":
		// findings is the per-control list (one per unauthorized ref,
		// including job-level reusable-workflow calls). Authorized =
		// total in-scope refs minus the flagged ones.
		total := stats.ActionRefsTotal + stats.ActionRefsExempt
		unauthorized := len(findings)
		authorized := total - unauthorized
		if authorized < 0 {
			authorized = 0
		}
		return []statLine{
			{Label: "Total Action Refs", Value: fmt.Sprintf("%d", total)},
			{Label: "Authorized", Value: fmt.Sprintf("%d", authorized)},
			{Label: "Unauthorized", Value: fmt.Sprintf("%d", unauthorized)},
		}
	case "securityJobsMustNotBeWeakened":
		return []statLine{
			{Label: "Security Jobs Found", Value: fmt.Sprintf("%d", stats.SecurityJobsTotal)},
			{Label: "Weakened Jobs", Value: fmt.Sprintf("%d", stats.SecurityJobsWeakened)},
		}
	case "pipelineMustNotUseDockerInDocker":
		return []statLine{
			{Label: statJobsChecked, Value: fmt.Sprintf("%d", stats.JobsTotal)},
			{Label: "DinD Services Found", Value: fmt.Sprintf("%d", stats.JobsWithDinD)},
			{Label: "Insecure Daemon Config", Value: fmt.Sprintf("%d", stats.JobsWithInsecureDaemon)},
		}
	case "pipelineMustNotExecuteUnverifiedScripts":
		return []statLine{
			{Label: statJobsChecked, Value: fmt.Sprintf("%d", stats.JobsTotal)},
			{Label: statScriptLinesChecked, Value: fmt.Sprintf("%d", stats.ScriptLinesTotal)},
			{Label: "Unverified Scripts", Value: fmt.Sprintf("%d", stats.UnverifiedScriptsFound)},
		}
	case "reusableWorkflowsMustNotInheritSecrets":
		return []statLine{
			{Label: "Reusable Workflow Calls", Value: fmt.Sprintf("%d", stats.ReusableCalls)},
			{Label: "With secrets: inherit", Value: fmt.Sprintf("%d", stats.ReusableCallsSecretsInherit)},
		}
	case "workflowMustNotInjectUserInputInScripts":
		return []statLine{
			{Label: "Workflows Scanned", Value: fmt.Sprintf("%d", stats.WorkflowsTotal)},
			{Label: statScriptLinesChecked, Value: fmt.Sprintf("%d", stats.ScriptLinesTotal)},
		}
	case "workflowMustNotWriteUntrustedContentToGitHubEnv":
		return []statLine{
			{Label: "Workflows Scanned", Value: fmt.Sprintf("%d", stats.WorkflowsTotal)},
			{Label: statScriptLinesChecked, Value: fmt.Sprintf("%d", stats.ScriptLinesTotal)},
		}
	case "workflowMustNotExportEntireSecretsContext":
		return []statLine{
			{Label: "Workflows Scanned", Value: fmt.Sprintf("%d", stats.WorkflowsTotal)},
		}
	case "workflowMustNotUseDangerousTriggers":
		return []statLine{
			{Label: "Workflows Scanned", Value: fmt.Sprintf("%d", stats.WorkflowsTotal)},
			{Label: "Using Dangerous Triggers", Value: fmt.Sprintf("%d", stats.WorkflowsWithDangerousTrigger)},
		}
	case "workflowsMustDeclarePermissions":
		withPerms := stats.WorkflowsTotal - stats.WorkflowsMissingPermissions
		if withPerms < 0 {
			withPerms = 0
		}
		return []statLine{
			{Label: "Total Workflows", Value: fmt.Sprintf("%d", stats.WorkflowsTotal)},
			{Label: "With permissions block", Value: fmt.Sprintf("%d", withPerms)},
			{Label: "Missing permissions block", Value: fmt.Sprintf("%d", stats.WorkflowsMissingPermissions)},
		}
	case "workflowMustNotGrantPermissionsWriteAll":
		return []statLine{
			{Label: statJobsChecked, Value: fmt.Sprintf("%d", stats.JobsTotal)},
			{Label: "Jobs With write-all", Value: fmt.Sprintf("%d", stats.JobsWithWriteAll)},
		}
	case "externalRefsMustNotCollide":
		return []statLine{
			{Label: statActionRefsChecked, Value: fmt.Sprintf("%d", stats.ActionRefsTotal+stats.ActionRefsExempt)},
			{Label: "Ambiguous Refs Found", Value: fmt.Sprintf("%d", stats.ActionRefsAmbiguous)},
		}
	case "actionsMustNotBeArchived":
		return []statLine{
			{Label: statActionRefsChecked, Value: fmt.Sprintf("%d", stats.ActionRefsTotal+stats.ActionRefsExempt)},
			{Label: "Archived Refs Found", Value: fmt.Sprintf("%d", stats.ActionRefsArchived)},
		}
	case "actionsMustNotCarryKnownCVEs":
		return []statLine{
			{Label: statActionRefsChecked, Value: fmt.Sprintf("%d", stats.ActionRefsTotal+stats.ActionRefsExempt)},
			{Label: "Refs With Advisories", Value: fmt.Sprintf("%d", stats.ActionRefsVulnerable)},
		}
	case "releaseWorkflowsMustNotRestoreUntrustedCache":
		return []statLine{
			{Label: "Workflows Scanned", Value: fmt.Sprintf("%d", stats.WorkflowsTotal)},
		}
	case "pipelineMustNotEnableDebugTrace":
		return []statLine{
			{Label: statVariablesChecked, Value: fmt.Sprintf("%d", stats.VariableBindingsTotal)},
			{Label: "Forbidden Found", Value: fmt.Sprintf("%d", stats.DebugTraceFound)},
		}
	case "pipelineMustNotLeakSecretsInConfig":
		// Mirrors the GitLab side: count hits and distinct gitleaks
		// rules from findings. GitHubAnalysisStats doesn't carry these
		// counters (the rule reads pipeline.gitleaksHits directly), so
		// the per-control findings list is the only source. Returning
		// stats here also ensures the section renders even with zero
		// hits — otherwise an enabled-but-clean run produced no body
		// block, which read as "the control didn't run".
		uniqueRules := map[string]struct{}{}
		for _, f := range findings {
			if v, ok := f.Data["ruleId"].(string); ok && v != "" {
				uniqueRules[v] = struct{}{}
			}
		}
		return []statLine{
			{Label: "Hits Found", Value: fmt.Sprintf("%d", len(findings))},
			{Label: "Distinct Rules Matched", Value: fmt.Sprintf("%d", len(uniqueRules))},
		}
	case "branchMustBeProtected":
		unprotectedMatched := stats.BranchesMatched - stats.BranchesProtected
		if unprotectedMatched < 0 {
			unprotectedMatched = 0
		}
		lines := []statLine{
			{Label: "Total Branches", Value: fmt.Sprintf("%d", stats.BranchesTotal)},
			{Label: "Branches to Protect", Value: fmt.Sprintf("%d", stats.BranchesMatched)},
			{Label: "Protected", Value: fmt.Sprintf("%d", stats.BranchesProtected)},
			{Label: "Unprotected (matched)", Value: fmt.Sprintf("%d", unprotectedMatched)},
		}
		// Surface partial-evaluation when /branches/{name}/protection
		// 403'd (token lacked Administration:Read). Without this line
		// the section header shows "100.0% compliant" while ISSUE-505
		// silently abstained — exactly the silent-success-on-
		// incomplete-data footgun we want to avoid.
		if stats.BranchesProtectionDetailsUnknown > 0 {
			lines = append(lines, statLine{
				Label: "⚠ Force-push & code-owner rules",
				Value: fmt.Sprintf("skipped on %d branch(es) — token lacks Administration:Read", stats.BranchesProtectionDetailsUnknown),
			})
		}
		return lines
	}
	return nil
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
			{Label: statTotalImages, Value: fmt.Sprintf("%d", total)},
		}
		if pc != nil && pc.ControlsFor("gitlab").ContainerImageMustNotUseForbiddenTags.IsPinnedByDigestRequired() {
			lines = append(lines,
				statLine{Label: "Pinned By Digest", Value: fmt.Sprintf("%d", pinned)},
				statLine{Label: "Not Pinned By Digest", Value: fmt.Sprintf("%d", notPinned)},
			)
		}
		lines = append(lines, statLine{Label: "Using Forbidden Tags", Value: fmt.Sprintf("%d", usingForbidden)})
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
			{Label: statTotalImages, Value: fmt.Sprintf("%d", total)},
			{Label: "Authorized", Value: fmt.Sprintf("%d", authorized)},
			{Label: "Unauthorized", Value: fmt.Sprintf("%d", unauthorized)},
		}
	case "pipelineMustNotIncludeHardcodedJobs":
		total := uint(0)
		hardcoded := uint(0)
		if result.PipelineOriginMetrics != nil {
			total = result.PipelineOriginMetrics.JobTotal
			hardcoded = result.PipelineOriginMetrics.JobHardcoded
		}
		return []statLine{
			{Label: "Total Jobs", Value: fmt.Sprintf("%d", total)},
			{Label: "Hardcoded Jobs", Value: fmt.Sprintf("%d", hardcoded)},
		}
	case "externalRefsMustNotCollide":
		// Cross-provider control: GitHub counts action refs, GitLab counts
		// external includes. Branch on which collector populated the result.
		if result.GitHubStats != nil {
			return []statLine{
				{Label: statActionRefsChecked, Value: fmt.Sprintf("%d", result.GitHubStats.ActionRefsTotal)},
				{Label: "Ambiguous Refs Found", Value: fmt.Sprintf("%d", findingsCount)},
			}
		}
		return []statLine{
			{Label: "Total Includes", Value: fmt.Sprintf("%d", _externalIncludeCount(result))},
			{Label: "Ambiguous Refs Found", Value: fmt.Sprintf("%d", findingsCount)},
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
			{Label: "Total Includes", Value: fmt.Sprintf("%d", total)},
			{Label: "Outdated", Value: fmt.Sprintf("%d", outdated)},
		}
	case "includesMustNotUseForbiddenVersions":
		total := _externalIncludeCount(result)
		authorized := total - findingsCount
		if authorized < 0 {
			authorized = 0
		}
		return []statLine{
			{Label: "Total Includes", Value: fmt.Sprintf("%d", total)},
			{Label: "Using Authorized Versions", Value: fmt.Sprintf("%d", authorized)},
			{Label: "Using Forbidden Versions", Value: fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotEnableDebugTrace":
		// "Variables Checked" mirrors v0.2.x: the total number of
		// variable bindings the analyzer scanned across every job and
		// the pipeline globals — not the size of the forbidden list.
		// On a 27-job pipeline this lands around 50–60 because
		// imported security templates each carry their own set.
		// GitHub workflows don't have GitLab's globals/Origins
		// machinery — the merged workflow/job/step `env:` lives on
		// each Job.Variables — so sum those for the GitHub path.
		var checked int
		if result.GitHubPipeline != nil {
			for _, j := range result.GitHubPipeline.Jobs {
				checked += len(j.Variables)
			}
		} else {
			checked = _countAllVariableBindings(result)
		}
		return []statLine{
			{Label: statVariablesChecked, Value: fmt.Sprintf("%d", checked)},
			{Label: "Forbidden Found", Value: fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotOverrideJobVariables":
		// Override checks only apply to bindings authored by the
		// project (globals + hardcoded jobs); imported components
		// legitimately set their own. Mirror that scope here so
		// "Variables Checked" matches the count actually scanned.
		return []statLine{
			{Label: statVariablesChecked, Value: fmt.Sprintf("%d", _countProjectAuthoredVariables(result))},
			{Label: "Overridden Found", Value: fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotUseUnsafeVariableExpansion":
		return []statLine{
			{Label: statJobsChecked, Value: fmt.Sprintf("%d", jobTotal)},
			{Label: statScriptLinesChecked, Value: fmt.Sprintf("%d", _countScriptLines(result))},
			{Label: "Unsafe Expansions", Value: fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotExecuteUnverifiedScripts":
		return []statLine{
			{Label: statJobsChecked, Value: fmt.Sprintf("%d", jobTotal)},
			{Label: statScriptLinesChecked, Value: fmt.Sprintf("%d", _countScriptLines(result))},
			{Label: "Unverified Scripts", Value: fmt.Sprintf("%d", findingsCount)},
		}
	case "pipelineMustNotLeakSecretsInConfig":
		// One scanned input (the merged GitLab pipeline). Hits are
		// already enumerated below as findings — adding a denominator
		// here would just be "Hits Found: N" duplicated above the
		// finding list. Return a single stat that's not redundant: the
		// count of unique secret patterns matched.
		uniqueRules := map[string]struct{}{}
		for _, f := range findings {
			if v, ok := f.Data["ruleId"].(string); ok && v != "" {
				uniqueRules[v] = struct{}{}
			}
		}
		return []statLine{
			{Label: "Hits Found", Value: fmt.Sprintf("%d", findingsCount)},
			{Label: "Distinct Rules Matched", Value: fmt.Sprintf("%d", len(uniqueRules))},
		}
	case "securityJobsMustNotBeWeakened":
		// Stable's "Security Jobs Found" counts how many of the merged
		// jobs match a configured security pattern — a context-rich
		// denominator for "0 weakened" findings: 0/14 reads very
		// differently from 0/0.
		return []statLine{
			{Label: "Security Jobs Found", Value: fmt.Sprintf("%d", _countSecurityJobs(result, pc))},
			{Label: "Weakened Jobs", Value: fmt.Sprintf("%d", findingsCount)},
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
			{Label: statRequirementGroups, Value: fmt.Sprintf("%d", len(resolved))},
			{Label: statSatisfiedGroups, Value: fmt.Sprintf("%d", satisfied)},
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
			{Label: statRequirementGroups, Value: fmt.Sprintf("%d", len(resolved))},
			{Label: statSatisfiedGroups, Value: fmt.Sprintf("%d", satisfied)},
		}
	case "pipelineMustNotUseDockerInDocker":
		return []statLine{
			{Label: statJobsChecked, Value: fmt.Sprintf("%d", jobTotal)},
			{Label: "DinD Services Found", Value: fmt.Sprintf("%d", _countDinDServices(result))},
			{Label: "Insecure Daemon Config", Value: fmt.Sprintf("%d", findingsCount)},
		}
	case "workflowMustIncludeRequiredActions":
		var resolved [][]string
		if pc != nil && pc.ControlsFor("github").WorkflowMustIncludeRequiredActions != nil {
			if g, err := pc.ControlsFor("github").WorkflowMustIncludeRequiredActions.GetResolvedRequiredGroups(); err == nil {
				resolved = g
			}
		}
		satisfied := countSatisfiedRequiredActionGroups(resolved, result)
		return []statLine{
			{Label: statRequirementGroups, Value: fmt.Sprintf("%d", len(resolved))},
			{Label: statSatisfiedGroups, Value: fmt.Sprintf("%d", satisfied)},
		}
	case "workflowMustNotGrantPermissionsWriteAll":
		return []statLine{
			{Label: statJobsChecked, Value: fmt.Sprintf("%d", jobTotal)},
			{Label: "Jobs With write-all", Value: fmt.Sprintf("%d", findingsCount)},
		}
	case "actionsMustNotBeArchived":
		actionRefs := 0
		if result.GitHubStats != nil {
			actionRefs = result.GitHubStats.ActionRefsTotal
		}
		return []statLine{
			{Label: statActionRefsChecked, Value: fmt.Sprintf("%d", actionRefs)},
			{Label: "Archived Refs Found", Value: fmt.Sprintf("%d", findingsCount)},
		}
	case "actionsMustNotCarryKnownCVEs":
		actionRefs := 0
		if result.GitHubStats != nil {
			actionRefs = result.GitHubStats.ActionRefsTotal
		}
		return []statLine{
			{Label: statActionRefsChecked, Value: fmt.Sprintf("%d", actionRefs)},
			{Label: "Refs With Advisories", Value: fmt.Sprintf("%d", findingsCount)},
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
			{Label: "Total Branches", Value: fmt.Sprintf("%d", total)},
			{Label: "Branches to Protect", Value: fmt.Sprintf("%d", toProtect)},
			{Label: "Protected Branches", Value: fmt.Sprintf("%d", protected)},
			{Label: "Unprotected", Value: fmt.Sprintf("%d", unprotected)},
			{Label: "Non-Compliant", Value: fmt.Sprintf("%d", nonCompliant)},
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

// _externalIncludeCount returns the number of include origins, matching
// the v0.3.0 "Total Includes" denominator. The project's own jobs
// surface as `hardcoded` and are excluded; everything else is an
// include (component / template / local / remote / project, with
// `project` being an external `include: project:` reference, not the
// root .gitlab-ci.yml). FromPlumber origins are real includes too and
// stay counted.
func _externalIncludeCount(result *control.AnalysisResult) int {
	if result == nil || result.PipelineOriginData == nil {
		return 0
	}
	count := 0
	for i := range result.PipelineOriginData.Origins {
		o := &result.PipelineOriginData.Origins[i]
		if o.OriginType == "" || o.OriginType == "hardcoded" {
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

// countSatisfiedRequiredActionGroups is the GitHub equivalent of
// countSatisfiedGroups: each AND group is satisfied when every
// required `owner/repo[/path]` entry is referenced by at least one
// step-level `uses:` or job-level reusable-workflow `uses:` in the
// pipeline IR. Matching is ref-agnostic with a slash guard so
// `org/repo` matches `org/repo@v1` and `org/repo/sub@v1`, but not
// `org/repo-other@v1`.
func countSatisfiedRequiredActionGroups(groups [][]string, result *control.AnalysisResult) int {
	if result == nil || result.GitHubPipeline == nil || len(groups) == 0 {
		return 0
	}
	satisfied := 0
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		all := true
		for _, required := range group {
			if !requiredActionReferenced(required, result.GitHubPipeline) {
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

func requiredActionReferenced(required string, pipeline *ir.NormalizedPipeline) bool {
	if pipeline == nil || required == "" {
		return false
	}
	for i := range pipeline.Jobs {
		job := &pipeline.Jobs[i]
		if job.ReusableWorkflowUses != "" && actionRefMatches(job.ReusableWorkflowUses, required) {
			return true
		}
		for k := range job.Uses {
			if actionRefMatches(job.Uses[k].Uses, required) {
				return true
			}
		}
	}
	return false
}

func actionRefMatches(reference, required string) bool {
	if reference == "" || required == "" {
		return false
	}
	normalized := reference
	if idx := strings.Index(normalized, "@"); idx >= 0 {
		normalized = normalized[:idx]
	}
	if normalized == required {
		return true
	}
	return strings.HasPrefix(normalized, required+"/")
}

func originGroupMatch(required string, data *gitlab.GitlabPipelineOriginData, kindFilter string) bool {
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
