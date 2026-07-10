package cmd

import "fmt"

// ScoreGateError is returned when analysis completes successfully but the
// Plumber Score falls below the configured gate (--min-points and/or
// --min-score).
//
// It is distinct from a generic runtime error so that callers (e.g. Execute)
// can map it to a dedicated exit code:
//
//	0 – analysis passed (score gate met)
//	1 – gate failure (score below --min-points / --min-score)
//	2 – runtime / configuration error
type ScoreGateError struct {
	Points    float64
	MinPoints float64
	// PointsGate reports whether the points gate was the one that failed;
	// otherwise the letter gate did.
	PointsGate bool
	Letter     string
	MinLetter  string
	// NoControls marks a run where zero controls were evaluated: a
	// .plumber.yaml that only configures the other provider, all controls
	// disabled, a skip-all filter, or — on GitLab, whose compliance zeroes
	// the control count on a missing/invalid CI — a project with no usable
	// CI configuration. Zero findings then means "nothing was checked",
	// not "clean", so the gate fails. On GitHub, a repository with no (or
	// unparseable) workflows keeps its control count and passes on a clean
	// score — the pre-0.4.0 behavior, restored on purpose so fleet
	// scanners don't fail on CI-less repositories.
	NoControls bool
}

func (e *ScoreGateError) Error() string {
	switch {
	case e.NoControls:
		return "no controls were evaluated (no usable CI configuration, none enabled for this provider in .plumber.yaml, or all skipped); the gate fails rather than passing an unchecked run"
	case e.PointsGate:
		return fmt.Sprintf("Plumber Score %.1f pts (%s) is below the required %.1f pts", e.Points, e.Letter, e.MinPoints)
	default:
		return fmt.Sprintf("Plumber Score %s is below the required minimum score %s", e.Letter, e.MinLetter)
	}
}

// ComplianceError is returned when the deprecated --threshold gate is active
// and the measured percentage of passing controls falls below it. It maps to
// the same exit code 1 as ScoreGateError and disappears with --threshold.
type ComplianceError struct {
	Compliance float64
	Threshold  float64
}

func (e *ComplianceError) Error() string {
	return fmt.Sprintf("passing controls %.1f%% is below the deprecated --threshold %.1f%%; migrate to --min-points / --min-score", e.Compliance, e.Threshold)
}

// DegradedError is returned when --fail-warnings is set and the run produced
// one or more "could not verify" warnings — e.g. a known-CVE check skipped
// because an action's pinned commit could not be resolved to a version (tag
// list blocked by an org IP allow list, rate limit, or network). The run
// itself completed; some data could not be checked. It maps to exit code 3
// (runtime / data condition), distinct from a gate failure (1) and a
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
// partial data, so Plumber withholds the verdict — the score banner in the
// terminal, badge/MR updates — and fails the run rather than pass an
// incomplete scan. Artifacts are still written but stamped degraded
// (#220). Maps to exit code 3, the same "could not fully verify" lane as
// DegradedError, distinct from a real gate failure (1) and a
// configuration error (2).
type IncompleteDataError struct {
	Reasons []string
}

func (e *IncompleteDataError) Error() string {
	return fmt.Sprintf("data collection was incomplete (%d issue(s)); score withheld, re-run when complete", len(e.Reasons))
}
