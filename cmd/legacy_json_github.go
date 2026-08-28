package cmd

import (
	"sort"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// buildLegacyResultGitHub is the GitHub-flavoured router that mirrors
// buildLegacyResult on the GitLab side. For each control entry the
// GitHub catalog emits, route to the per-control builder that knows
// how to extract the right denominators from result.GitHubStats and
// findings. Returns ("", nil) when the control is not yet wired —
// caller skips it so we don't pollute the JSON with empty placeholder
// blocks (the bug the GitLab-only legacyResultsByName had).
func buildLegacyResultGitHub(e control.ControlEntry, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) (string, any) {
	common := legacyCommon{
		CiValid:   result.CiValid,
		CiMissing: result.CiMissing,
		Skipped:   e.Skipped,
	}

	switch e.ControlName {
	case "actionsMustBePinnedByCommitSha":
		return "actionPinningResult", buildActionPinningBlock(common, result, findings)
	case "githubActionMustComeFromAuthorizedSources":
		return "authorizedActionSourcesResult", buildAuthorizedActionSourcesBlock(common, result, findings)
	case "containerImageMustNotUseForbiddenTags":
		return "imageForbiddenTagsResult", buildImageForbiddenTagsBlockGitHub(common, result, pc, findings)
	case "branchMustBeProtected":
		return "branchProtectionResult", buildBranchProtectionBlockGitHub(common, result, pc, findings)
	case "pipelineMustNotUseDockerInDocker":
		return "dockerInDockerResult", buildDockerInDockerBlockGitHub(common, result, findings)
	case "reusableWorkflowsMustNotInheritSecrets":
		return "reusableSecretsResult", buildReusableSecretsBlock(common, result, findings)
	case "securityJobsMustNotBeWeakened":
		return "securityJobsWeakenedResult", buildSecurityJobsBlockGitHub(common, result, findings)
	case "workflowMustNotInjectUserInputInScripts":
		return "templateInjectionResult", buildTemplateInjectionBlock(common, result, findings)
	case "workflowMustNotWriteUntrustedContentToGitHubEnv":
		return "githubEnvInjectionResult", buildGitHubEnvInjectionBlock(common, result, findings)
	case "workflowMustNotExportEntireSecretsContext":
		return "overprovisionedSecretsResult", buildOverprovisionedSecretsBlock(common, result, findings)
	case "workflowMustNotUseDangerousTriggers":
		return "dangerousTriggersResult", buildDangerousTriggersBlock(common, result, findings)
	case "checkoutMustNotPersistCredentials":
		return "checkoutCredentialsResult", buildCheckoutCredentialsBlock(common, result, findings)
	case "pullRequestTargetMustNotCheckoutHead":
		return "pullRequestTargetHeadCheckoutResult", buildPullRequestTargetHeadCheckoutBlock(common, result, findings)
	case "workflowsMustDeclarePermissions":
		return "permissionsResult", buildPermissionsBlock(common, result, findings)
	case "workflowMustIncludeRequiredActions":
		return "requiredActionsResult", buildRequiredActionsBlock(common, pc.ControlsFor("github").WorkflowMustIncludeRequiredActions, result, findings)
	case "workflowMustNotGrantPermissionsWriteAll":
		return "excessivePermissionsResult", buildExcessivePermissionsBlock(common, result, findings)
	case "externalRefsMustNotCollide":
		return "refConfusionResult", buildRefConfusionBlock(common, result, findings)
	case "actionsMustNotBeArchived":
		return "archivedActionsResult", buildArchivedActionsBlock(common, result, findings)
	case "actionRefsMustExistUpstream":
		return "impostorCommitResult", buildImpostorCommitBlock(common, result, findings)
	case "actionsMustNotCarryKnownCVEs":
		return "knownVulnerableActionsResult", buildKnownVulnerableActionsBlock(common, result, findings)
	case "actionsMustNotExecuteMutableRemoteCode":
		return "mutableRemoteExecResult", buildMutableRemoteExecBlock(common, result, findings)
	case "releaseWorkflowsMustNotRestoreUntrustedCache":
		return "cachePoisoningResult", buildCachePoisoningBlock(common, result, findings)
	case "pipelineMustNotEnableDebugTrace":
		return "debugTraceResult", buildDebugTraceBlockGitHub(common, result, findings)
	case "pipelineMustNotExecuteUnverifiedScripts":
		return "unverifiedScriptsResult", buildUnverifiedScriptsBlockGitHub(common, result, findings)
	}
	return "", nil
}

// statsOf safely dereferences result.GitHubStats. The GitHub task
// funcs always set the field, but stats-of-zero-value is the right
// fallback for unit tests that build AnalysisResult by hand.
func statsOf(result *control.AnalysisResult) control.GitHubAnalysisStats {
	if result == nil || result.GitHubStats == nil {
		return control.GitHubAnalysisStats{}
	}
	return *result.GitHubStats
}

// buildActionPinningBlock — ISSUE-701. Total = third-party action
// references in scope (i.e. excluding trustedOwners). Findings are
// the unpinned subset.
func buildActionPinningBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(_sortedFindings(findings), "job"),
		"metrics": map[string]any{
			"actionRefsTotal":    s.ActionRefsTotal,
			"actionRefsUnpinned": s.ActionRefsUnpinned,
			"actionRefsExempt":   s.ActionRefsExempt,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildImageForbiddenTagsBlockGitHub mirrors the GitLab block but
// reads the GitHub stats (pre-aggregated denominators) instead of
// PipelineImageData (a GitLab-collector type that is nil on GitHub).
func buildImageForbiddenTagsBlockGitHub(c legacyCommon, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	usingForbidden := 0
	for _, f := range findings {
		if f.Code == string(control.CodeImageForbiddenTag) {
			usingForbidden++
		}
	}
	mustBePinned := false
	if cfg := pc.ControlsFor("github").ContainerImageMustNotUseForbiddenTags; cfg != nil {
		mustBePinned = cfg.IsPinnedByDigestRequired()
	}
	notPinned := s.ImagesTotal - s.ImagesPinnedByDigest
	if notPinned < 0 {
		notPinned = 0
	}
	return map[string]any{
		"issues": projectFindings(_sortedFindings(findings), "job"),
		"metrics": map[string]any{
			"total":              s.ImagesTotal,
			"usingForbiddenTags": usingForbidden,
			"notPinnedByDigest":  notPinned,
			"pinnedByDigest":     s.ImagesPinnedByDigest,
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

// buildBranchProtectionBlockGitHub reads result.GitHubPipeline.Branches
// for the per-branch `data:` array (the GitLab equivalent reads
// result.ProtectionData, which is GitLab-only). Filters branches to
// the in-scope set (matching namePatterns or default-branch when
// defaultMustBeProtected is true), populates protection details for
// branches we have authoritative data on (ProtectionDetailsKnown=true),
// and clamps `projectsCorrectlyProtected` to ≥ 0 — fixes the prior
// `-1` math bug.
func buildBranchProtectionBlockGitHub(c legacyCommon, result *control.AnalysisResult, pc *configuration.PlumberConfig, findings []opaengine.Finding) map[string]any {
	cfg := pc.ControlsFor("github").BranchMustBeProtected

	var branches []ir.Branch
	if result.GitHubPipeline != nil {
		branches = result.GitHubPipeline.Branches
	}

	// in-scope = matches namePatterns OR (default branch when defaultMustBeProtected).
	inScope := func(b ir.Branch) bool {
		if cfg == nil {
			return false
		}
		if matchesAnyPatternSimple(b.Name, cfg.NamePatterns) {
			return true
		}
		if cfg.DefaultMustBeProtected != nil && *cfg.DefaultMustBeProtected &&
			result.DefaultBranch != "" && b.Name == result.DefaultBranch {
			return true
		}
		return false
	}

	// Order: default branch first (when in scope), then alphabetical.
	ordered := make([]ir.Branch, 0, len(branches))
	if result.DefaultBranch != "" {
		for i := range branches {
			if branches[i].Name == result.DefaultBranch {
				ordered = append(ordered, branches[i])
				break
			}
		}
	}
	others := make([]ir.Branch, 0, len(branches))
	for i := range branches {
		if branches[i].Name != result.DefaultBranch {
			others = append(others, branches[i])
		}
	}
	sort.SliceStable(others, func(i, j int) bool { return others[i].Name < others[j].Name })
	ordered = append(ordered, others...)

	data := []map[string]any{}
	totalProtected := 0
	totalToProtect := 0
	totalUnprotected := 0
	for _, b := range ordered {
		if !inScope(b) {
			continue
		}
		totalToProtect++
		entry := map[string]any{
			"branchName": b.Name,
			"default":    b.Name == result.DefaultBranch,
			"protected":  b.Protected,
		}
		if b.Protected {
			totalProtected++
			if b.ProtectionDetailsKnown {
				entry["allowForcePush"] = b.AllowForcePush
				entry["codeOwnerApprovalRequired"] = b.CodeOwnerApprovalRequired
				entry["protectionDetailsKnown"] = true
			} else {
				// Surface the partial-eval state so JSON consumers don't
				// confuse "no rule details" with "rule says zero".
				entry["protectionDetailsKnown"] = false
			}
		} else {
			totalUnprotected++
		}
		data = append(data, entry)
	}

	nonCompliant := 0
	for _, f := range findings {
		if f.Code == string(control.CodeBranchNonCompliant) {
			nonCompliant++
		}
	}
	correctlyProtected := totalProtected - nonCompliant
	if correctlyProtected < 0 {
		correctlyProtected = 0
	}

	block := map[string]any{
		"enabled": !c.Skipped,
		"version": "0.2.0",
		"data":    data,
		"metrics": map[string]any{
			"branches":                   len(branches),
			"branchesToProtect":          totalToProtect,
			"unprotectedBranches":        totalUnprotected,
			"nonCompliantBranches":       nonCompliant,
			"totalProtectedBranches":     totalProtected,
			"projectsCorrectlyProtected": correctlyProtected,
		},
	}
	if len(findings) > 0 {
		issues := projectFindings(findings, "")
		block["issues"] = issues
	}
	return block
}

// matchesAnyPatternSimple is a small glob matcher mirroring the
// branch_unprotected.rego selection: exact name OR `prefix/*` style
// suffix wildcards. Kept independent of go-wildcard to avoid a new
// dep for one call site.
func matchesAnyPatternSimple(name string, patterns []string) bool {
	for _, p := range patterns {
		if p == name {
			return true
		}
		if len(p) > 2 && p[len(p)-2:] == "/*" {
			prefix := p[:len(p)-2]
			if len(name) > len(prefix) && name[:len(prefix)+1] == prefix+"/" {
				return true
			}
		}
	}
	return false
}

// buildDockerInDockerBlockGitHub uses GitHub stats (jobs walked) for
// the totals; otherwise mirrors the GitLab block.
func buildDockerInDockerBlockGitHub(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	insecure := 0
	for _, f := range findings {
		if f.Code == string(control.CodeDockerInDockerInsecure) {
			insecure++
		}
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"totalJobsChecked":    s.JobsTotal,
			"dindServicesFound":   s.JobsWithDinD,
			"insecureDaemonFound": insecure,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildSecurityJobsBlockGitHub uses pre-aggregated stats — the
// GitLab variant indexes findings to count weakening, which works
// here too, but the denominator must come from the GitHub stats
// (different security-job pattern set).
func buildSecurityJobsBlockGitHub(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"securityJobsFound": s.SecurityJobsTotal,
			"weakenedJobs":      len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildReusableSecretsBlock — ISSUE-302. Counts reusable-workflow
// calls (denominator) and the secrets-inherit subset (numerator).
func buildReusableSecretsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"reusableCalls":               s.ReusableCalls,
			"reusableCallsSecretsInherit": s.ReusableCallsSecretsInherit,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildTemplateInjectionBlock — ISSUE-207. Denominator is the total
// scanned script lines.
func buildTemplateInjectionBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"workflowsScanned":        s.WorkflowsTotal,
			"scriptLinesChecked":      s.ScriptLinesTotal,
			"templateInjectionsFound": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildGitHubEnvInjectionBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"workflowsScanned":         s.WorkflowsTotal,
			"scriptLinesChecked":       s.ScriptLinesTotal,
			"githubEnvInjectionsFound": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildOverprovisionedSecretsBlock — ISSUE-309. One finding per job that
// serialises the whole secrets context via toJson(secrets) into a run
// script, env binding, or action `with:` input.
func buildOverprovisionedSecretsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"workflowsScanned":           s.WorkflowsTotal,
			"secretsContextExportsFound": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildCachePoisoningBlock — ISSUE-705. One finding per release/publish
// job that restores a build cache with a key not scoped to the release ref.
func buildCachePoisoningBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"workflowsScanned":          s.WorkflowsTotal,
			"unscopedCacheRestoreFound": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildDangerousTriggersBlock — ISSUE-802. Denominator is workflows
// total; numerator is workflows whose trigger set intersects the
// dangerous-triggers list.
// buildCheckoutCredentialsBlock — ISSUE-307 / ISSUE-310. One control, two
// codes graded by exploitability: the credential merely persisting (latent)
// versus the credential also being packed into a downloadable artifact (a
// demonstrable leak). The two are counted separately because a consumer
// triaging this needs to know which of the two it has; a single total would
// make a hygiene backlog and an exfiltrable token look alike.
//
// The counts come from the findings rather than from a stats field: nothing
// in the collector counts checkout steps, and adding a stat to serve one
// block would be plumbing for its own sake.
func buildCheckoutCredentialsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	latent, packed := 0, 0
	for _, f := range findings {
		switch f.Code {
		case string(control.CodeArtipacked):
			latent++
		case string(control.CodeArtipackedExfiltrated):
			packed++
		}
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"workflowsScanned":            statsOf(result).WorkflowsTotal,
			"checkoutsPersistingLatent":   latent,
			"checkoutsPackedIntoArtifact": packed,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildDangerousTriggersBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"workflowsScanned":              s.WorkflowsTotal,
			"workflowsWithDangerousTrigger": s.WorkflowsWithDangerousTrigger,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildPullRequestTargetHeadCheckoutBlock — ISSUE-804. The exploitable
// pull_request_target + PR-head-checkout combination (tj-actions /
// CVE-2025-30066). Mirrors dangerousTriggersResult so dashboards get the
// same issue/metric shape; the issues[] carry the file/job/line the
// terminal already shows but the JSON previously dropped (only a
// plumberScore.codeLosses line remained). Findings are per-job; the
// metric counts the flagged (job, checkout) pairs.
func buildPullRequestTargetHeadCheckoutBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(_sortedFindings(findings), "job"),
		"metrics": map[string]any{
			"workflowsScanned":           s.WorkflowsTotal,
			"headCheckoutsUnderPrTarget": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildPermissionsBlock — ISSUE-801. Denominator is total workflows;
// numerator is workflows missing an explicit `permissions:` block.
func buildPermissionsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"workflowsTotal":              s.WorkflowsTotal,
			"workflowsMissingPermissions": s.WorkflowsMissingPermissions,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildRequiredActionsBlock builds the ISSUE-417 result block. Per-group requirement
// satisfaction shape mirrors the GitLab requiredComponentsResult /
// requiredTemplatesResult blocks so any consumer that already
// scripts the GitLab side gets the same fields back. Each
// `requirementGroups[i]` is one AND group; `present` shows which
// required entries the scan found referenced in the workflows;
// `missing` lists the gaps the user must add. `satisfiedGroups`
// counts groups whose every entry resolved, matching the
// `anySatisfiedGroup` boolean. Compliance follows the catalog's
// binary rule (100 when no finding, 0 otherwise).
func buildRequiredActionsBlock(c legacyCommon, cfg *configuration.RequiredActionsControlConfig, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	var groups [][]string
	if cfg != nil && !c.Skipped {
		groups, _ = cfg.GetResolvedRequiredGroups()
	}
	requirementGroups, satisfied := _resolveRequiredActionGroups(groups, result)
	return map[string]any{
		"requirementGroups": requirementGroups,
		"issues":            projectFindings(findings, ""),
		"metrics": map[string]any{
			"totalGroups":       len(requirementGroups),
			"satisfiedGroups":   satisfied,
			"anySatisfiedGroup": len(requirementGroups) > 0 && satisfied > 0,
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// _resolveRequiredActionGroups walks the configured DNF and returns
// the per-group present/missing breakdown plus the satisfied-group
// count. Same ref-agnostic, slash-guarded match as required_actions.rego
// so the JSON view and the rule never disagree on what counts as
// "present".
func _resolveRequiredActionGroups(groups [][]string, result *control.AnalysisResult) ([]map[string]any, int) {
	out := make([]map[string]any, 0, len(groups))
	satisfied := 0
	for _, group := range groups {
		present := make([]string, 0, len(group))
		missing := make([]string, 0, len(group))
		for _, req := range group {
			if _requiredActionReferenced(req, result) {
				present = append(present, req)
			} else {
				missing = append(missing, req)
			}
		}
		allPresent := len(missing) == 0 && len(group) > 0
		if allPresent {
			satisfied++
		}
		out = append(out, map[string]any{
			"required":  group,
			"present":   present,
			"missing":   missing,
			"satisfied": allPresent,
		})
	}
	return out, satisfied
}

func _requiredActionReferenced(required string, result *control.AnalysisResult) bool {
	if result == nil || result.GitHubPipeline == nil {
		return false
	}
	for i := range result.GitHubPipeline.Jobs {
		job := &result.GitHubPipeline.Jobs[i]
		if job.ReusableWorkflowUses != "" && _actionRefMatches(job.ReusableWorkflowUses, required) {
			return true
		}
		for k := range job.Uses {
			if _actionRefMatches(job.Uses[k].Uses, required) {
				return true
			}
		}
	}
	return false
}

func _actionRefMatches(reference, required string) bool {
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

// buildExcessivePermissionsBlock — ISSUE-803. Denominator is total
// jobs (workflow-level permissions: write-all gets propagated to each
// job by the collector, so the per-job denominator gives the right
// "X jobs of Y" ratio whether the offending grant lives at workflow
// or job scope). Numerator is the finding count, which the rego
// emits one-per-job that resolves to write-all.
func buildExcessivePermissionsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"jobsTotal":        s.JobsTotal,
			"jobsWithWriteAll": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildAuthorizedActionSourcesBlock — ISSUE-713. Denominator is the
// number of action refs scanned (same denominator the action-pinning /
// archived blocks use); numerator is the finding count, one per (job,
// unauthorized-action) pair, including job-level reusable-workflow
// calls. Each issue carries the offending `uses` value via the finding
// Data so dashboards can list the exact unauthorized sources.
func buildAuthorizedActionSourcesBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(_sortedFindings(findings), "job"),
		"metrics": map[string]any{
			// ISSUE-713 evaluates every ref, including the pin-exempt
			// actions/* and github/* owners, so the denominator must
			// include ActionRefsExempt — matching the terminal stats
			// (buildGitHubControlStats) so the two views never disagree.
			"actionRefsTotal":        s.ActionRefsTotal + s.ActionRefsExempt,
			"actionRefsUnauthorized": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildRefConfusionBlock — ISSUE-402. Denominator is the number of
// action refs scanned (same denominator the archived/CVE blocks use),
// so a "X of Y" ratio stays meaningful even when the GitHub API
// metadata enrichment hit a quota and some refs went unresolved.
// Numerator is the finding count, one per (job, ambiguous-ref) pair.
func buildRefConfusionBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"actionRefsTotal":     s.ActionRefsTotal,
			"actionRefsAmbiguous": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildArchivedActionsBlock — ISSUE-702. Denominator is the number
// of action refs scanned (same denominator the action-pinning block
// uses), so a "X of Y" ratio is meaningful even when the GitHub API
// metadata enrichment hit a quota and some refs went unresolved.
// Numerator is the finding count, one per (job, archived-action) pair.
func buildArchivedActionsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"actionRefsTotal":    s.ActionRefsTotal,
			"actionRefsArchived": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildMutableRemoteExecBlock — ISSUE-714/715/716. Surfaces each action
// whose own source fetches and runs mutable remote code (plus the
// producer-side self-action signal) with its code/job/uses/url, so the
// JSON export carries the finding and its location rather than only a
// plumberScore.codeLosses line. Denominator is the action-ref count
// scanned; numerator is the finding count across all three tiers
// (obfuscated / exec / unverified).
func buildMutableRemoteExecBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(_sortedFindings(findings), "job"),
		"metrics": map[string]any{
			"actionRefsTotal":              s.ActionRefsTotal,
			"actionsWithMutableRemoteExec": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildImpostorCommitBlock — ISSUE-707. Denominator is the number of
// action refs scanned (the same denominator the action-pinning block
// uses); numerator is the finding count, one per (job, SHA) pinned to a
// commit the upstream repo confirmed does not exist. Only a definitive
// absence answer (404 / 422) from a readable repo reaches here — refs
// the API could not verify never become findings (see commitResolves).
func buildImpostorCommitBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"actionRefsTotal":          s.ActionRefsTotal,
			"actionRefsAbsentUpstream": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildDebugTraceBlockGitHub — ISSUE-203 on the GitHub path. The
// GitLab equivalent (buildDebugTraceBlock) leans on
// _countAllVariableBindings, which walks GitLab-only `Origins`
// metadata. GitHub jobs carry their merged `env:` block directly in
// `Job.Variables`, so the denominator here is the sum of those map
// sizes across the IR. Numerator is the finding count; the rego
// emits one finding per (job, debug-variable) pair that resolves to
// a truthy value.
func buildDebugTraceBlockGitHub(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	total := 0
	if result != nil && result.GitHubPipeline != nil {
		for _, j := range result.GitHubPipeline.Jobs {
			total += len(j.Variables)
		}
	}
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"totalVariablesChecked": total,
			"forbiddenFound":        len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

// buildKnownVulnerableActionsBlock — ISSUE-703. Same denominator as
// the archived-actions block (total action refs); numerator counts
// every (job, vulnerable-action) pair the rego flagged. The list of
// GHSA IDs per finding is preserved inside `issues[*].advisories` —
// downstream consumers (dashboards) typically aggregate on the IDs to
// dedupe across multiple callers of the same compromised action.
func buildKnownVulnerableActionsBlock(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(findings, "job"),
		"metrics": map[string]any{
			"actionRefsTotal":      s.ActionRefsTotal,
			"actionRefsVulnerable": len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}

func buildUnverifiedScriptsBlockGitHub(c legacyCommon, result *control.AnalysisResult, findings []opaengine.Finding) map[string]any {
	s := statsOf(result)
	return map[string]any{
		"issues": projectFindings(_sortedFindings(findings), "job"),
		"metrics": map[string]any{
			"jobsChecked":             s.JobsTotal,
			"totalScriptLinesChecked": s.ScriptLinesTotal,
			"unverifiedScriptsFound":  len(findings),
		},
		"version":   "0.1.0",
		"ciValid":   c.CiValid,
		"ciMissing": c.CiMissing,
		"skipped":   c.Skipped,
	}
}
