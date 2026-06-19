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
		reasons = append(reasons, "branch protection could not be fetched; branch controls were not evaluated")
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
