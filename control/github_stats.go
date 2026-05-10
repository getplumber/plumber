package control

import (
	"regexp"
	"strings"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/internal/ir"
)

// AggregateGitHubStats walks the normalized pipeline IR once and
// produces the per-control denominators the GitHub renderer needs to
// emit "(X.X% compliant)" headers and stats blocks (Total Images:
// 19, Pinned By Digest: 1, …) — matching the GitLab output style.
//
// All counts are derived from the IR; no second collection pass is
// needed. Configuration knobs (trustedOwners, forbiddenTags,
// security-job-pattern list) are read from pc when present, falling
// back to sensible defaults so the function works on a bare config.
func AggregateGitHubStats(pipeline *ir.NormalizedPipeline, pc *configuration.PlumberConfig) *GitHubAnalysisStats {
	if pipeline == nil {
		return &GitHubAnalysisStats{}
	}
	stats := &GitHubAnalysisStats{}

	gh := pc.ControlsFor("github")
	trustedOwners := defaultTrustedActionOwners
	if gh.ActionsMustBePinnedByCommitSha != nil && len(gh.ActionsMustBePinnedByCommitSha.TrustedOwners) > 0 {
		trustedOwners = gh.ActionsMustBePinnedByCommitSha.TrustedOwners
	}
	forbiddenTags := defaultForbiddenImageTags
	pinnedByDigestRequired := false
	if gh.ContainerImageMustNotUseForbiddenTags != nil {
		if len(gh.ContainerImageMustNotUseForbiddenTags.Tags) > 0 {
			forbiddenTags = gh.ContainerImageMustNotUseForbiddenTags.Tags
		}
		pinnedByDigestRequired = gh.ContainerImageMustNotUseForbiddenTags.IsPinnedByDigestRequired()
	}
	securityPatterns := defaultSecurityJobPatterns
	if gh.SecurityJobsMustNotBeWeakened != nil && len(gh.SecurityJobsMustNotBeWeakened.SecurityJobPatterns) > 0 {
		securityPatterns = gh.SecurityJobsMustNotBeWeakened.SecurityJobPatterns
	}

	// Workflow set — distinct workflow files. Triggers/permissions
	// are propagated to every job, so we walk jobs but dedupe on
	// WorkflowName + the dangerous-trigger / permissions presence is
	// a workflow-level property.
	workflowsSeen := map[string]struct{}{}
	workflowsWithDangerousTrigger := map[string]struct{}{}
	workflowsWithPermissions := map[string]struct{}{}

	for i := range pipeline.Jobs {
		job := &pipeline.Jobs[i]

		// Workflow tracking.
		wf := job.WorkflowName
		if wf == "" {
			wf = job.OriginFile
		}
		if wf != "" {
			workflowsSeen[wf] = struct{}{}
			if hasDangerousTrigger(job.Triggers) {
				workflowsWithDangerousTrigger[wf] = struct{}{}
			}
			if job.Permissions != nil {
				workflowsWithPermissions[wf] = struct{}{}
			}
		}

		// Jobs total (denominator for Docker-in-Docker).
		stats.JobsTotal++

		// Container images: job-level + services.
		if job.Image != nil {
			stats.ImagesTotal++
			countImage(imageRef(*job.Image), forbiddenTags, &stats.ImagesPinnedByDigest, &stats.ImagesUsingForbidden)
		}
		for j := range job.Services {
			stats.ImagesTotal++
			countImage(imageRef(job.Services[j]), forbiddenTags, &stats.ImagesPinnedByDigest, &stats.ImagesUsingForbidden)
		}

		// Docker-in-Docker services.
		if jobHasDinD(job) {
			stats.JobsWithDinD++
			if jobHasInsecureDaemon(job) {
				stats.JobsWithInsecureDaemon++
			}
		}

		// Reusable workflow calls + secrets:inherit.
		if job.ReusableWorkflowUses != "" {
			stats.ReusableCalls++
			if job.SecretsInherit {
				stats.ReusableCallsSecretsInherit++
			}
		}

		// Security jobs.
		if matchesAnyPattern(job.Name, securityPatterns) {
			stats.SecurityJobsTotal++
			if jobIsWeakened(job) {
				stats.SecurityJobsWeakened++
			}
		}

		// Action refs — count steps[].uses, exclude trustedOwners.
		for k := range job.Uses {
			ref := job.Uses[k].Uses
			if ownerOf(ref) != "" && isTrustedOwner(ref, trustedOwners) {
				stats.ActionRefsExempt++
				continue
			}
			stats.ActionRefsTotal++
			if !isShaPinned(ref) {
				stats.ActionRefsUnpinned++
			}
		}

		// Script lines for template-injection denominator.
		stats.ScriptLinesTotal += len(job.Scripts)
	}

	// Pinned-by-digest accounting: when "all images must be pinned by
	// digest" is required, Not Pinned = total - pinned. Otherwise
	// the field is informational only.
	_ = pinnedByDigestRequired

	stats.WorkflowsTotal = len(workflowsSeen)
	stats.WorkflowsWithDangerousTrigger = len(workflowsWithDangerousTrigger)
	stats.WorkflowsMissingPermissions = stats.WorkflowsTotal - len(workflowsWithPermissions)
	if stats.WorkflowsMissingPermissions < 0 {
		stats.WorkflowsMissingPermissions = 0
	}

	// Branch protection — populated when the GitHub branch-protection
	// collector ran (it only does so when the control is enabled +
	// the user's token has scope). Empty when in degraded mode.
	//
	// "In scope" mirrors the rego rule: a branch is in scope when
	// it matches a configured namePattern OR is the repo's default
	// branch and defaultMustBeProtected is true. BranchesMatched and
	// BranchesProtected are both bounded to the in-scope set so the
	// stats block reads "Branches to Protect: 2 / Protected: 1 /
	// Unprotected: 1" instead of conflating "protected anywhere in
	// the repo" with "protected among the ones we required".
	stats.BranchesTotal = len(pipeline.Branches)
	if gh.BranchMustBeProtected != nil {
		patterns := gh.BranchMustBeProtected.NamePatterns
		defaultRequired := gh.BranchMustBeProtected.DefaultMustBeProtected != nil &&
			*gh.BranchMustBeProtected.DefaultMustBeProtected
		for i := range pipeline.Branches {
			b := &pipeline.Branches[i]
			inScope := branchMatchesPattern(b.Name, patterns)
			if !inScope && defaultRequired && b.Name == pipeline.DefaultBranch {
				inScope = true
			}
			if !inScope {
				continue
			}
			stats.BranchesMatched++
			if b.Protected {
				stats.BranchesProtected++
			}
			if !b.ProtectionDetailsKnown {
				stats.BranchesProtectionDetailsUnknown++
			}
		}
	}
	return stats
}

// branchMatchesPattern is a tiny matcher that mirrors the rego
// glob.match used in branch_unprotected.rego. Only handles the
// common cases the stats block needs (exact name, "release/*"-style
// suffix wildcards). Anything more elaborate falls through to false
// — the rego rule remains the source of truth for actual findings;
// this counter is informational only.
func branchMatchesPattern(name string, patterns []string) bool {
	for _, p := range patterns {
		if p == name {
			return true
		}
		if strings.HasSuffix(p, "/*") && strings.HasPrefix(name, strings.TrimSuffix(p, "/*")+"/") {
			return true
		}
	}
	return false
}

// defaultTrustedActionOwners mirrors the .plumber.yaml default for
// actionsMustBePinnedByCommitSha.trustedOwners.
var defaultTrustedActionOwners = []string{"actions", "github"}

// defaultForbiddenImageTags mirrors containerImageMustNotUseForbiddenTags.tags.
var defaultForbiddenImageTags = []string{"latest", "dev", "development", "staging", "main", "master"}

// defaultSecurityJobPatterns mirrors securityJobsMustNotBeWeakened.securityJobPatterns.
var defaultSecurityJobPatterns = []string{
	"*-sast", "secret_detection", "container_scanning",
	"*_dependency_scanning", "gemnasium-*", "dast", "dast_*", "license_scanning",
}

// shaRefRegex matches a 40-character lowercase hex SHA at the end of
// an action ref ("owner/repo@<sha>").
var shaRefRegex = regexp.MustCompile(`@[0-9a-f]{40}$`)

// dangerousTriggers are the GitHub Actions event names that grant
// access to base-repo secrets while being influenceable by an
// unprivileged caller. Mirrors policies/dangerous_triggers.rego.
var dangerousTriggers = map[string]struct{}{
	"pull_request_target": {},
	"workflow_run":        {},
}

func ownerOf(ref string) string {
	if i := strings.IndexByte(ref, '/'); i > 0 {
		return ref[:i]
	}
	return ""
}

func isTrustedOwner(ref string, trustedOwners []string) bool {
	owner := ownerOf(ref)
	for _, t := range trustedOwners {
		if owner == t {
			return true
		}
	}
	return false
}

func isShaPinned(ref string) bool {
	return shaRefRegex.MatchString(ref)
}

func countImage(image string, forbiddenTags []string, pinned, forbidden *int) {
	if strings.Contains(image, "@sha256:") {
		*pinned++
		return
	}
	if i := strings.LastIndexByte(image, ':'); i > 0 {
		tag := image[i+1:]
		for _, f := range forbiddenTags {
			if tag == f {
				*forbidden++
				return
			}
		}
	}
}

func imageRef(img ir.Image) string {
	ref := img.Name
	if img.Tag != "" {
		ref += ":" + img.Tag
	}
	if img.Digest != "" {
		ref += "@" + img.Digest
	}
	if img.Registry != "" && !strings.Contains(ref, "/") {
		ref = img.Registry + "/" + ref
	}
	return ref
}

func jobHasDinD(job *ir.Job) bool {
	for i := range job.Services {
		ref := imageRef(job.Services[i])
		if strings.HasPrefix(ref, "docker:") && strings.Contains(ref, "dind") {
			return true
		}
		if strings.Contains(job.Services[i].Name, "dind") {
			return true
		}
	}
	return false
}

func jobHasInsecureDaemon(job *ir.Job) bool {
	if v, ok := job.Variables["DOCKER_TLS_CERTDIR"]; ok && v == "" {
		return true
	}
	if v, ok := job.Variables["DOCKER_HOST"]; ok && strings.Contains(v, ":2375") {
		return true
	}
	return false
}

func jobIsWeakened(job *ir.Job) bool {
	if job.AllowFailure {
		return true
	}
	if job.When == "manual" {
		return true
	}
	for _, rule := range job.Rules {
		if w, ok := rule["when"].(string); ok && (w == "never" || w == "manual") {
			return true
		}
	}
	return false
}

func hasDangerousTrigger(triggers []string) bool {
	for _, t := range triggers {
		if _, ok := dangerousTriggers[t]; ok {
			return true
		}
	}
	return false
}

func matchesAnyPattern(name string, patterns []string) bool {
	for _, p := range patterns {
		if globMatch(p, name) {
			return true
		}
	}
	return false
}

// globMatch is a tiny glob matcher supporting a single '*' wildcard
// at the start, end, or middle. Mirrors the patterns the rego rules
// accept (e.g. "*-sast", "gemnasium-*"). Not a full glob — adequate
// for the security-job pattern set.
func globMatch(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(name, pattern[1:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(name, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, pattern[:len(pattern)-1])
	}
	return false
}
