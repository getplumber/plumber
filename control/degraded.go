package control

import (
	"fmt"
	"strings"
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

// degradedReasonMembersPrefix is the shared prefix of the degraded reason the
// members collection records on a network failure (ISSUE-507).
const degradedReasonMembersPrefix = "project members could not be fetched"

// degradedReasonsFromGitHubCollection builds the human-readable list of
// collection failures behind a degraded GitHub run (#220). partialCount
// is the number of workflow files that could not be fetched/parsed and
// were skipped; branchFetchFailed reports that the branch-protection
// fetch failed outright. Returns nil when neither happened, which is the
// signal callers use to leave DataCollectionDegraded false.
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
// partialCount workflow files skipped, and a failed branch-protection
// fetch. No-op when neither happened, so a healthy run is left clean.
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
