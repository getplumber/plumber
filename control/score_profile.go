package control

import "strings"

// ScoreProfile is the scoring formula this run uses: "v3" (per-code
// severities; stays the default until the flip to v4) or "v4" (attack
// paths, contextual severity, explanations). It is a process-wide
// setting: the CLI is single-run, so the cmd layer validates the
// --score-profile flag once in runAnalyze and sets this before any
// scoring happens, and both the run-level score (cmd/analyze_shared.go's
// computeScoreResult) and every per-policy score (ReEvaluateForConfig
// below) read it, so platform mode gets v4 at the same time as the run's
// own score (spec ruling 5).
//
//nolint:gochecknoglobals // process-wide by design, see above.
var ScoreProfile = "v3"

// ComputeScoreForProfile runs the formula the profile names. "v4"
// assembles the attack paths, prices them, and fills the situation
// paragraph and the best fix (ScoreV4WithExplanations), recording the
// paths on the result for the outputs that read them. "v3" runs the
// per-code formula over the same findings, unchanged. Any other value
// falls back to v3: the cmd layer validates the flag before this is ever
// called with something else.
//
// A "v4" request over a run whose situation facts never evaluated falls
// back to v3 as well (spec section 2, Points: withholding rules;
// invariant I3: never a fake verdict). Pricing every entry finding as
// hygiene because there is no situation to walk would hand out a
// fake-good score, not an honest "could not evaluate" one, so this never
// prices anything as v4 without a real situation to price it against.
//
// The run-level score and every per-policy score (ReEvaluateForConfig) go
// through here alike, so the v3-fallback decision is made in one place.
func ComputeScoreForProfile(profile string, result *AnalysisResult) PlumberScoreResult {
	if profile == "v4" {
		if situationUnavailable(result) {
			addContextualScoreUnavailableWarning(result)
			return ComputePlumberScore(AggregateIssueCodeCounts(result))
		}
		return ScoreV4WithExplanations(result)
	}
	return ComputePlumberScore(AggregateIssueCodeCounts(result))
}

// situationUnavailable reports whether result carries no real situation
// to price a v4 score against: the situation never evaluated at all, it
// evaluated to the degraded empty value (no jobs recorded while the
// pipeline itself has jobs), or attachSituation already recorded a
// "situation facts unavailable" warning for this run.
func situationUnavailable(result *AnalysisResult) bool {
	if result == nil || result.Situation == nil {
		return true
	}
	if len(result.Situation.Jobs) == 0 {
		if pipeline := result.evaluatedPipeline(); pipeline != nil && len(pipeline.Jobs) > 0 {
			return true
		}
	}
	for _, w := range result.Warnings {
		if strings.HasPrefix(w, "situation facts unavailable:") {
			return true
		}
	}
	return false
}

// contextualScoreUnavailableWarning is appended, at most once, when a "v4"
// request falls back to v3 for want of a situation to price.
const contextualScoreUnavailableWarning = "contextual score unavailable, scoring-v3 used"

func addContextualScoreUnavailableWarning(result *AnalysisResult) {
	if result == nil {
		return
	}
	for _, w := range result.Warnings {
		if w == contextualScoreUnavailableWarning {
			return
		}
	}
	result.Warnings = append(result.Warnings, contextualScoreUnavailableWarning)
}
