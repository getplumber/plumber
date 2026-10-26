package control

import (
	"regexp"
	"slices"
	"strings"

	"github.com/getplumber/plumber/configuration"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/utils"
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
	stats := &GitHubAnalysisStats{WorkflowLockfilePath: pipeline.WorkflowLockfilePath}

	gh := pc.ControlsFor("github")
	trustedOwners := defaultTrustedActionOwners
	if gh.ActionsMustBePinnedByCommitSha != nil && len(gh.ActionsMustBePinnedByCommitSha.TrustedOwners) > 0 {
		trustedOwners = gh.ActionsMustBePinnedByCommitSha.TrustedOwners
	}
	forbiddenTags := defaultForbiddenImageTags
	pinnedByDigestRequired := false
	// The exemption reads the configured tags as written: the rules see no
	// forbidden tag when none is configured, so the defaults above must not
	// exempt anything the rules still judge.
	var exempt imageExemption
	if gh.ContainerImageMustNotUseForbiddenTags != nil {
		if len(gh.ContainerImageMustNotUseForbiddenTags.Tags) > 0 {
			forbiddenTags = gh.ContainerImageMustNotUseForbiddenTags.Tags
		}
		pinnedByDigestRequired = gh.ContainerImageMustNotUseForbiddenTags.IsPinnedByDigestRequired()
		exempt = imageExemption{
			images: gh.ContainerImageMustNotUseForbiddenTags.ExemptImages,
			tags:   gh.ContainerImageMustNotUseForbiddenTags.Tags,
		}
	}
	securityPatterns := defaultSecurityJobPatterns
	if gh.SecurityJobsMustNotBeWeakened != nil && len(gh.SecurityJobsMustNotBeWeakened.SecurityJobPatterns) > 0 {
		securityPatterns = gh.SecurityJobsMustNotBeWeakened.SecurityJobPatterns
	}
	// Debug-trace forbidden-variable list — mirrors the same field
	// the rego rule reads. Empty when the user has not configured
	// the control or its enabled-toggle is off; in that case the
	// matcher below short-circuits and DebugTraceFound stays at 0.
	var debugForbidden []string
	if gh.PipelineMustNotEnableDebugTrace != nil && gh.PipelineMustNotEnableDebugTrace.IsEnabled() {
		debugForbidden = gh.PipelineMustNotEnableDebugTrace.ForbiddenVariables
	}

	// Workflow set — distinct workflow files. Triggers/permissions
	// are propagated to every job, so we walk jobs but dedupe on
	// WorkflowName + the dangerous-trigger / permissions presence is
	// a workflow-level property.
	workflowsSeen := map[string]struct{}{}
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
			if job.Permissions != nil {
				workflowsWithPermissions[wf] = struct{}{}
			}
		}

		// Jobs total (denominator for Docker-in-Docker, write-all,
		// and any other per-job rule).
		stats.JobsTotal++

		// ISSUE-803: count jobs whose effective permissions block is
		// the literal "write-all" string. The collector propagates a
		// workflow-level write-all to every job's Permissions, so a
		// per-job match handles both authoring styles uniformly.
		if perms, ok := job.Permissions.(string); ok && perms == "write-all" {
			stats.JobsWithWriteAll++
		}

		// ISSUE-203 (GitHub side): scan every merged env-var binding
		// for the configured forbidden-variable names. The collector
		// folds workflow / job / step env into job.Variables, so a
		// single per-job walk covers every authoring location.
		stats.VariableBindingsTotal += len(job.Variables)
		for k, v := range job.Variables {
			if isDebugTraceMatch(k, v, debugForbidden) {
				stats.DebugTraceFound++
			}
		}

		// Container images: job-level, the job's docker:// steps, services.
		if job.Image != nil {
			countJobImage(stats, *job.Image, forbiddenTags, exempt)
		}
		for j := range job.StepImages {
			countJobImage(stats, job.StepImages[j], forbiddenTags, exempt)
		}
		for j := range job.Services {
			countJobImage(stats, job.Services[j], forbiddenTags, exempt)
		}

		countCacheWriteExemption(stats, job, gh.UntrustedTriggersMustNotWriteCache)

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

		// Action refs — count steps[].uses, exclude trustedOwners for
		// the pin-by-SHA accounting. Supply-chain checks (ISSUE-702
		// archived, ISSUE-703 known CVEs, ISSUE-402 ref-confusion)
		// inspect EVERY ref because the rules themselves don't exempt
		// trusted owners; in
		// practice the API enrichment phase skips first-party refs,
		// so their metadata is nil and neither counter ticks.
		for k := range job.Uses {
			use := &job.Uses[k]
			ref := use.Uses
			// A docker:// step runs an image, not an action: ISSUE-701
			// skips it and the image counters below count it (#571).
			if strings.HasPrefix(ref, "docker://") {
				continue
			}
			if use.Metadata != nil {
				if use.Metadata.RepoArchived {
					stats.ActionRefsArchived++
				}
				if len(use.Metadata.Advisories) > 0 {
					stats.ActionRefsVulnerable++
				}
				if use.Metadata.RefIsAmbiguous {
					stats.ActionRefsAmbiguous++
				}
				if use.Metadata.RefKnownAbsent && isShaPinned(ref) {
					stats.ActionRefsAbsentUpstream++
				}
			}
			if use.Nested {
				stats.ActionRefsNested++
			}
			if ownerOf(ref) != "" && isTrustedOwner(ref, trustedOwners) {
				stats.ActionRefsExempt++
				continue
			}
			stats.ActionRefsTotal++
			switch {
			case isShaPinned(ref):
			case isImmutableReleaseTag(use.Metadata):
				stats.ActionRefsImmutableRelease = append(stats.ActionRefsImmutableRelease, PinnedRef{
					Job: job.Name, Uses: ref, Line: use.Line, PinnedVia: PinnedViaImmutableRelease,
				})
			case lockfileCovers(pipeline, job) && !isLocalRef(ref):
				stats.ActionRefsWorkflowLockfile = append(stats.ActionRefsWorkflowLockfile, PinnedRef{
					Job: job.Name, Uses: ref, Line: use.Line, PinnedVia: PinnedViaWorkflowLockfile,
				})
			default:
				stats.ActionRefsUnpinned++
			}
		}

		// Job-level reusable workflow calls (`jobs.<id>.uses: ...@ref`)
		// are subject to the same pin-by-SHA rule as step-level action
		// refs — the action_unpinned rego rule fires a separate `deny`
		// block on them. Mirror that here so actionRefsTotal /
		// actionRefsUnpinned / actionRefsExempt stay aligned with the
		// number of ISSUE-701 findings (previously this counter only
		// looked at steps[].uses, which produced reports showing
		// "0 unpinned" alongside ten unpinned reusable workflows).
		if ref := job.ReusableWorkflowUses; ref != "" {
			if ownerOf(ref) != "" && isTrustedOwner(ref, trustedOwners) {
				stats.ActionRefsExempt++
			} else {
				stats.ActionRefsTotal++
				switch {
				case isShaPinned(ref):
				case isImmutableReleaseTag(job.ReusableWorkflowMetadata):
					stats.ActionRefsImmutableRelease = append(stats.ActionRefsImmutableRelease, PinnedRef{
						Job: job.Name, Uses: ref, PinnedVia: PinnedViaImmutableRelease,
					})
				default:
					stats.ActionRefsUnpinned++
				}
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
	stats.WorkflowFilesInvalid = len(pipeline.InvalidWorkflows)
	// WorkflowsWithDangerousTrigger is set from the emitted ISSUE-802
	// findings in ApplyGitHubFindingCounts, not from a structural scan
	// here — the rule's fork-guard logic lives in Rego (#235 follow-up).
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

// ApplyGitHubFindingCounts fills per-control finding counters on stats
// after Rego evaluation (denominators come from AggregateGitHubStats).
func ApplyGitHubFindingCounts(stats *GitHubAnalysisStats, findings []opaengine.Finding) {
	if stats == nil {
		return
	}
	dangerousWorkflows := map[string]struct{}{}
	for _, f := range findings {
		switch f.Code {
		case string(CodeUnverifiedScriptExecution):
			stats.UnverifiedScriptsFound++
		case string(CodeDangerousTriggers):
			dangerousWorkflows[dangerousTriggerWorkflowKey(f)] = struct{}{}
		}
	}
	// The dangerous-trigger metric is the count of distinct workflows the
	// ISSUE-802 rule actually flagged — not a structural scan of trigger
	// names. The rule's fork-guard recognition (push-event / author-
	// association guards) lives in Rego, so a guarded workflow emits no
	// finding and must not inflate this metric (#235 follow-up).
	stats.WorkflowsWithDangerousTrigger = len(dangerousWorkflows)
}

// dangerousTriggerWorkflowKey returns a stable per-workflow key for an
// ISSUE-802 finding: the workflow file when known, else the workflow
// prefix of the "<workflow>/<job>" name. Per-job findings in the same
// workflow collapse to one entry.
func dangerousTriggerWorkflowKey(f opaengine.Finding) string {
	if f.File != "" {
		return f.File
	}
	if i := strings.IndexByte(f.Job, '/'); i >= 0 {
		return f.Job[:i]
	}
	return f.Job
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

// shaRefRegex matches a 40-character hex SHA at the end of an action
// ref ("owner/repo@<sha>"). Case-insensitive: git / the GitHub API
// resolve SHAs regardless of case, so an uppercase pin is still a SHA
// pin. Matching both keeps this aligned with impostor_commit.rego (which
// lowercases before matching) so the ActionRefsAbsentUpstream counter
// cannot drift from the findings.
var shaRefRegex = regexp.MustCompile(`@[0-9a-fA-F]{40}$`)

// isImmutableReleaseTag mirrors _is_immutable_release_tag in
// action_unpinned.rego: a tag backed by an immutable release, not
// shadowed by a same-named branch. Nil metadata (enrichment did not run
// or learned nothing) is never accepted.
func isImmutableReleaseTag(md *ir.ActionMetadata) bool {
	return md != nil && md.RefKind == "tag" && md.RefIsImmutableRelease && !md.RefIsAmbiguous
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

// lockfileCovers mirrors _lockfile_covers in action_unpinned.rego: the
// scanned branch commits a workflow lockfile and the job is one of the
// repository's own (its same-repo reusable workflows included). A job
// appended from another repository's reusable workflow is governed by that
// repository's lockfile, which is not read yet (#542).
func lockfileCovers(pipeline *ir.NormalizedPipeline, job *ir.Job) bool {
	return pipeline.WorkflowLockfilePath != "" && !job.Nested
}

// isLocalRef is the reference forms _is_local in action_unpinned.rego
// exempts (./, /, $/, docker://). The counter does not exempt the local
// forms (a docker:// step is skipped earlier, as an image); it only keeps
// them out of the lockfile list, which would otherwise name a
// same-repo `$/` action (the form `gh actions-lock` writes) as locked.
func isLocalRef(ref string) bool {
	for _, p := range []string{"./", "/", "$/", "docker://"} {
		if strings.HasPrefix(ref, p) {
			return true
		}
	}
	return false
}

// countCacheWriteExemption lists a job ISSUE-705 would flag (cache write
// granted on an untrusted trigger) that the control's exemptWorkflows or
// exemptJobs skip, so the accepted risk shows in the output instead of
// hiding the job.
func countCacheWriteExemption(stats *GitHubAnalysisStats, job *ir.Job, c *configuration.CacheWriteControlConfig) {
	if c == nil || job.CacheMode == nil {
		return
	}
	if len(utils.CacheWriteRiskyTriggers(job.CacheMode.Effective, effectiveTriggers(job))) == 0 {
		return
	}
	if utils.CacheWriteExempt(c.ExemptWorkflows, c.ExemptJobs, job.Name, job.OriginFile) {
		stats.CacheWriteExempted = append(stats.CacheWriteExempted, job.Name)
		slices.Sort(stats.CacheWriteExempted)
	}
}

// effectiveTriggers is the events a job runs on: its own, and for a
// reusable workflow (workflow_call) each caller's instead. Mirrors
// _effective_triggers in policies/cache_poisoning.rego.
func effectiveTriggers(job *ir.Job) []string {
	var out []string
	for _, t := range job.Triggers {
		if t != "workflow_call" {
			out = append(out, t)
		}
	}
	if slices.Contains(job.Triggers, "workflow_call") {
		for _, c := range job.Callers {
			out = append(out, c.Triggers...)
		}
	}
	return out
}

// imageExemption is the exemptImages list with the configured forbidden
// tags: an image is exempt on one of those tags only.
type imageExemption struct {
	images, tags []string
}

// countJobImage adds one container image to the image counters. An exempt
// image (exemptImages entry on a forbidden tag) is judged by neither
// ISSUE-102 nor ISSUE-103, so it stays out of "using forbidden" and "not
// pinned", and is listed so the exemption shows in the output instead of
// hiding the image.
func countJobImage(stats *GitHubAnalysisStats, img ir.Image, forbiddenTags []string, exempt imageExemption) {
	stats.ImagesTotal++
	ref := imageRef(img)
	if !utils.ImageExempt(exempt.images, exempt.tags, img.Registry, img.Name, img.Tag) {
		countImage(ref, forbiddenTags, &stats.ImagesPinnedByDigest, &stats.ImagesUsingForbidden)
		return
	}
	if strings.Contains(ref, "@sha256:") {
		stats.ImagesPinnedByDigest++
	} else {
		stats.ImagesExemptUnpinned++
	}
	stats.ImagesExempted = append(stats.ImagesExempted, ref)
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

// isDebugTraceMatch mirrors policies/debug_trace.rego's match logic:
// variable name comparison is case-insensitive, value is truthy when
// the trimmed lowercase form is "true", "1", or "yes". Returns false
// fast when the forbidden list is empty (the rego rule short-circuits
// the same way).
func isDebugTraceMatch(name, value string, forbidden []string) bool {
	if len(forbidden) == 0 {
		return false
	}
	upperName := strings.ToUpper(name)
	matched := false
	for _, f := range forbidden {
		if strings.ToUpper(f) == upperName {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true
	}
	return false
}
