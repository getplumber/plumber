package cmd

import "fmt"

// ComplianceError is returned when analysis completes successfully but the
// measured compliance score falls below the required threshold.
//
// It is distinct from a generic runtime error so that callers (e.g. Execute)
// can map it to a dedicated exit code:
//
//	0 – analysis passed (compliance ≥ threshold)
//	1 – compliance failure (compliance < threshold)
//	2 – runtime / configuration error
type ComplianceError struct {
	Compliance float64
	Threshold  float64
}

func (e *ComplianceError) Error() string {
	return fmt.Sprintf("compliance %.1f%% is below threshold %.1f%%", e.Compliance, e.Threshold)
}

// DegradedError is returned when --fail-warnings is set and the run produced
// one or more "could not verify" warnings — e.g. a known-CVE check skipped
// because an action's pinned commit could not be resolved to a version (tag
// list blocked by an org IP allow list, rate limit, or network). The run
// itself completed; some data could not be checked. It maps to exit code 3
// (runtime / data condition), distinct from a compliance failure (1) and a
// configuration error (2), so strict CI can tell "we could not fully verify"
// apart from "a real control failed".
type DegradedError struct {
	Count int
}

func (e *DegradedError) Error() string {
	return fmt.Sprintf("%d check(s) could not be verified and --fail-warnings is set", e.Count)
}

// IncompleteDataError is returned when a run is data-collection-degraded:
// a GitLab merged-CI fetch failed, or some GitHub workflow files / the
// branch-protection fetch could not be retrieved. The analysis ran on
// partial data, so Plumber withholds the verdict — score and compliance
// tables in the terminal, badge/MR updates — and fails the run rather than
// pass an incomplete scan. Artifacts are still written but stamped degraded
// (#220). Maps to exit code 3, the same "could not fully verify" lane as
// DegradedError, distinct from a real compliance failure (1) and a
// configuration error (2).
type IncompleteDataError struct {
	Reasons []string
}

func (e *IncompleteDataError) Error() string {
	return fmt.Sprintf("data collection was incomplete (%d issue(s)); score withheld, re-run when complete", len(e.Reasons))
}
