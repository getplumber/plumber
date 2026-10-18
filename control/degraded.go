package control

import (
	"fmt"
	"strings"

	githubpkg "github.com/getplumber/plumber/github"
	"github.com/getplumber/plumber/internal/ir"
)

// isNetworkError reports whether err looks like a transient network /
// connectivity failure (timeout, cancellation, DNS, refused connection)
// rather than a definitive API answer (404, 401/403, parse error). It is the
// gate that decides whether a GitLab collection failure degrades the run
// (exit 3, partial, honest) or hard-fails it (exit 2) — a dropped network
// should not look the same as a misconfigured project (#220). Matches on the
// error string because the GitLab client wraps transport errors in %w chains
// that do not expose a single typed sentinel.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"context deadline exceeded",
		"request canceled",
		"client.timeout",
		"timeout exceeded",
		"no such host",
		"connection refused",
		"connection reset",
		"network is unreachable",
		"i/o timeout",
		"tls handshake timeout",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// markDegraded flags a result as data-collection-degraded and records a
// human-readable reason (deduplicated). Single entry point so every GitLab
// collection site sets the flag the same way GitHub's applyGitHubDegraded
// does, instead of each call inventing its own hard-fail / soft-warn / silent
// behaviour (#220).
func markDegraded(result *AnalysisResult, reason string) {
	if result == nil {
		return
	}
	result.DataCollectionDegraded = true
	for _, r := range result.DegradedReasons {
		if r == reason {
			return
		}
	}
	result.DegradedReasons = append(result.DegradedReasons, reason)
}

// degradedReasonBranchProtectionPrefix is the shared prefix of every
// branch-protection-fetch degraded reason, on both providers. It is the
// compile-time contract between the two writers below / in task.go and
// the StatusFor classifier (degradedReasonIsBranchProtection): rewording
// a reason without keeping this prefix would silently break per-control
// status classification, so both writers build their strings from it.
const degradedReasonBranchProtectionPrefix = "branch protection could not be fetched"

// degradedReasonVariablesPrefix is the shared prefix of the settings-variable
// fetch degraded reason. Like the branch-protection prefix, it is the
// compile-time contract between task.go (the writer) and StatusFor's
// degradedReasonIsVariables classifier, so a network failure fetching the
// variables listing degrades only the two variable controls rather than
// flipping every unrelated CI-file control to error.
const degradedReasonVariablesPrefix = "CI/CD variables could not be fetched"

// degradedReasonSecurityPolicyPrefix is the shared prefix of the
// security-policy-linkage fetch degraded reason. Same contract as the two
// above: a transient network failure on the GraphQL read degrades the run so a
// blip cannot read as a clean exit-0 pass, while the carve-out in StatusFor
// keeps every unrelated control from flipping to error over it.
const degradedReasonSecurityPolicyPrefix = "security policy project could not be fetched"

// degradedReasonsFromGitHubCollection builds the human-readable list of
// collection failures behind a degraded GitHub run (#220). partialCount
// is the number of workflow files that could not be read or fetched and
// were skipped; a file that was fetched but does not parse as a workflow
// is not counted here, it is an invalid workflow reported through
// ISSUE-423 (#517), never a collection failure. branchFetchFailed reports
// that the branch-protection fetch failed outright. Returns nil when
// neither happened, which is the signal callers use to leave
// DataCollectionDegraded false.
func degradedReasonsFromGitHubCollection(partialCount int, branchFetchFailed bool) []string {
	var reasons []string
	if partialCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d workflow file(s) could not be fetched and were skipped", partialCount))
	}
	if branchFetchFailed {
		reasons = append(reasons, degradedReasonBranchProtectionPrefix+"; branch controls were not evaluated")
	}
	return reasons
}

// applyGitHubDegraded stamps the degraded-collection signals onto a
// GitHub AnalysisResult from the two collection failure modes (#220):
// partialCount workflow files that could not be read or fetched and were
// skipped, and a failed branch-protection fetch. A file that was fetched
// but could not be parsed is not one of partialCount's files (#517). No-op
// when neither happened, so a healthy run is left clean.
func applyGitHubDegraded(result *AnalysisResult, partialCount int, branchFetchFailed bool) {
	if result == nil {
		return
	}
	reasons := degradedReasonsFromGitHubCollection(partialCount, branchFetchFailed)
	if len(reasons) == 0 {
		return
	}
	result.DataCollectionDegraded = true
	result.DegradedReasons = append(result.DegradedReasons, reasons...)
}

// degradedReasonNestedActionsPrefix and degradedReasonNestedEntriesPrefix
// are the shared prefixes of the nested resolution's two degraded reasons
// (monorepo spec 2026-10-16 section 7, R3, plan ruling 5): the container
// budget and the per-job entry bound. They are the contract between
// applyNestedActions (the writer) and StatusFor
// (degradedReasonIsNestedActions), which degrades the action controls only.
const (
	degradedReasonNestedActionsPrefix = "nested actions closure exceeded the budget"
	degradedReasonNestedEntriesPrefix = "one job's nested closure exceeded"
)

func degradedReasonIsNestedActions(reason string) bool {
	return strings.HasPrefix(reason, degradedReasonNestedActionsPrefix) || strings.HasPrefix(reason, degradedReasonNestedEntriesPrefix)
}

// maxFetchWarnings caps the warnings naming one unreadable definition
// each: a rate limit in the middle of a run makes every later read fail,
// and the unexpanded list names them all anyway.
const maxFetchWarnings = 10

// maxWarnedReference bounds the untrusted reference a fetch warning
// quotes, whichever of the two fetch-warning branches below writes it.
const maxWarnedReference = 200

// boundedRef truncates an untrusted reference to maxWarnedReference runes,
// so neither fetch-warning branch in applyNestedActions embeds an
// attacker-controlled string of unbounded length in result.Warnings
// (review of PR 549).
func boundedRef(ref string) string {
	if r := []rune(ref); len(r) > maxWarnedReference {
		return string(r[:maxWarnedReference])
	}
	return ref
}

// referencesNotExpanded is "N references not expanded", in the singular
// for one.
func referencesNotExpanded(n int) string {
	if n == 1 {
		return "1 reference not expanded"
	}
	return fmt.Sprintf("%d references not expanded", n)
}

// applyNestedActions turns the collector's nested resolution outcome into
// the run's warnings and degradation (spec section 7): past the budget the
// run is degraded and the score withheld (R3); with no API at all one
// warning (the pipeline's advisory warnings, result.Warnings) names the
// cause and the score is computed (R6); a definition that could not be
// fetched warns and names the reference, ten at most. Past the per-job
// entry bound (plan ruling 5) the degraded reason says so in its own words,
// and so does the run-wide cap on appended nested jobs (MaxNestedJobs).
// The collector decides the cause
// on the run's first remote read only, so NestedUnresolvedCause and
// NestedBudgetExceeded cannot both be set; if they ever are, the overflow
// wins (coordinator ruling L7): the run degrades and the R6 warning, which
// says the score stands, is not given.
func applyNestedActions(result *AnalysisResult, pipeline *ir.NormalizedPipeline) {
	if result == nil || pipeline == nil {
		return
	}
	if pipeline.NestedUnresolvedCause != "" && !pipeline.NestedBudgetExceeded {
		result.Warnings = append(result.Warnings, "nested actions were not resolved: "+pipeline.NestedUnresolvedCause)
	}
	budget, fetch := 0, 0
	for _, u := range result.UnexpandedActions {
		switch u.Reason {
		case ir.UnexpandedBudget:
			budget++
		case ir.UnexpandedFetch:
			fetch++
			switch {
			case fetch > maxFetchWarnings:
			case u.Invalid:
				// Refused before any fetch: the one line names the reason, the
				// untrusted reference quoted and bounded.
				result.Warnings = append(result.Warnings, fmt.Sprintf("the reference %q was not fetched, it is not a valid GitHub reference", boundedRef(u.Uses)))
			default:
				result.Warnings = append(result.Warnings, fmt.Sprintf("the definition of %s could not be fetched, the actions it pulls in were not expanded", boundedRef(u.Uses)))
			}
		}
	}
	if fetch > maxFetchWarnings {
		result.Warnings = append(result.Warnings, fmt.Sprintf("and %d more action definitions could not be fetched", fetch-maxFetchWarnings))
	}
	if !pipeline.NestedBudgetExceeded {
		return
	}
	result.NestedActionsBudgetExceeded = true
	entries := min(pipeline.NestedEntriesOverflow, budget)
	jobs := min(pipeline.NestedJobsOverflow, budget-entries)
	if containers := budget - entries - jobs; containers > 0 || (entries == 0 && jobs == 0) {
		markDegraded(result, fmt.Sprintf("%s of %d containers, %s", degradedReasonNestedActionsPrefix, githubpkg.MaxNestedContainers, referencesNotExpanded(containers)))
	}
	if jobs > 0 {
		markDegraded(result, fmt.Sprintf("%s of %d nested jobs, %s", degradedReasonNestedActionsPrefix, githubpkg.MaxNestedJobs, referencesNotExpanded(jobs)))
	}
	if entries > 0 {
		markDegraded(result, fmt.Sprintf("%s %d entries, %s", degradedReasonNestedEntriesPrefix, githubpkg.MaxNestedEntriesPerJob, referencesNotExpanded(entries)))
	}
}

// degradedReasonPolicyPrefix is the shared prefix of every DegradedReasons
// entry a failed policy module writes (#489). The StatusFor classifier
// (degradedReasonIsPolicyFailure) keeps such a reason from reading as a
// whole-run failure: only the controls the failed policy declares are
// affected, through NotEvaluable.
const degradedReasonPolicyPrefix = "policy could not be evaluated"

// degradedReasonEnginePrefix is the shared prefix of a DegradedReasons entry
// written when no policy could run at all (#489): the embedded policies did
// not load, or the engine input could not be built. Unlike
// degradedReasonPolicyPrefix it is NOT excluded from StatusFor's whole-run
// classification, so every control reads not evaluated.
const degradedReasonEnginePrefix = "policy engine could not run"

// degradedReasonIsPolicyFailure classifies a DegradedReasons entry as a
// failed policy module.
func degradedReasonIsPolicyFailure(reason string) bool {
	return strings.HasPrefix(reason, degradedReasonPolicyPrefix)
}

// policyFailure is one Rego module that failed to evaluate, with the
// controls it declares (read off the issue codes in its source), which are
// the controls its failure leaves not evaluable.
type policyFailure struct {
	Module   string
	Err      error
	Controls []string
}

// applyPolicyFailures records what a failed policy module means for the run
// (#489): the run is degraded, so the score is withheld and the exit code
// says incomplete, with one reason per module naming it and the engine's
// error; and every control the module declares is marked not evaluable, so
// it reads "not evaluated" while the other controls keep their real findings
// and statuses.
func applyPolicyFailures(result *AnalysisResult, failures []policyFailure) {
	if result == nil {
		return
	}
	for _, f := range failures {
		if len(f.Controls) == 0 {
			// Nothing could run at all (the policies did not load, the engine
			// input could not be built): no control was evaluated, so the
			// reason deliberately does NOT carry the policy-failure prefix.
			// StatusFor reads any other degraded reason as a whole-run
			// failure and reports every control not evaluated.
			markDegraded(result, fmt.Sprintf("%s: %s: %v", degradedReasonEnginePrefix, f.Module, f.Err))
			continue
		}
		markDegraded(result, fmt.Sprintf("%s: %s: %v", degradedReasonPolicyPrefix, f.Module, f.Err))
		for _, control := range f.Controls {
			result.MarkNotEvaluable(control, ReasonPolicyEvaluationFailed)
		}
	}
}
