package control

import (
	"math"
	"sort"
)

// PlumberScoreProfileID identifies the scoring rules version (see docs/scoring.md).
const PlumberScoreProfileID = "scoring-v1"

// PlumberScoreDocURL is the canonical user-facing explanation of the Plumber letter score.
const PlumberScoreDocURL = "https://github.com/getplumber/plumber/blob/main/docs/scoring.md"

// SeverityCounts is the number of detected issues per documented severity bucket.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// SeverityLoss is points lost for one severity bucket after weight, log growth, and cap.
type SeverityLoss struct {
	Severity     IssueSeverity `json:"severity"`
	Count        int           `json:"count"`
	Weight       float64       `json:"weight"`
	Cap          float64       `json:"cap,omitempty"` // omitted when infinite (critical)
	UncappedLoss float64       `json:"uncappedLoss"`
	CappedLoss   float64       `json:"cappedLoss"`
}

// PlumberScoreResult is the official result: letter Score (A–E) derived from numeric Points (0–100).
type PlumberScoreResult struct {
	ProfileID string `json:"profileId"`

	Counts SeverityCounts `json:"counts"`

	// RawPoints is 100 minus summed capped severity losses (before Critical malus).
	RawPoints float64 `json:"rawPoints"`
	// FinalPoints applies Critical category malus (max points in E band when any Critical exists).
	FinalPoints float64 `json:"finalPoints"`
	// Score is the letter A–E from final points (what people mean by “how did we score?”).
	Score string `json:"score"`

	CriticalMalusApplied bool    `json:"criticalMalusApplied"`
	CriticalMalusMax     float64 `json:"criticalMalusMax,omitempty"` // max points when malus applies (30)

	Losses []SeverityLoss `json:"losses"`
}

// forEachIssueCode invokes fn for every issue code from enabled (non-skipped) controls.
func forEachIssueCode(result *AnalysisResult, fn func(ErrorCode)) {
	if result == nil {
		return
	}
	if r := result.ImageForbiddenTagsResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.ImageAuthorizedSourcesResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.BranchProtectionResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.HardcodedJobsResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.OutdatedIncludesResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.ForbiddenVersionsIncludesResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.RequiredComponentsResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
		for _, issue := range r.OverriddenIssues {
			fn(issue.Code)
		}
	}
	if r := result.RequiredTemplatesResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
		for _, issue := range r.OverriddenIssues {
			fn(issue.Code)
		}
	}
	if r := result.DebugTraceResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.VariableInjectionResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.SecurityJobsWeakenedResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.UnverifiedScriptsResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.JobVariablesOverrideResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
	if r := result.DockerInDockerResult; r != nil && !r.Skipped {
		for _, issue := range r.Issues {
			fn(issue.Code)
		}
	}
}

// SeverityCountsFromIssueCodes tallies severities for individual findings (one code per finding).
func SeverityCountsFromIssueCodes(codes []ErrorCode) SeverityCounts {
	var c SeverityCounts
	for _, code := range codes {
		switch SeverityForCode(code) {
		case SeverityCritical:
			c.Critical++
		case SeverityHigh:
			c.High++
		case SeverityMedium:
			c.Medium++
		case SeverityLow:
			c.Low++
		default:
			c.Medium++
		}
	}
	return c
}

// AggregateSeverityCounts walks analysis issues and counts occurrences per severity.
func AggregateSeverityCounts(result *AnalysisResult) SeverityCounts {
	var c SeverityCounts
	forEachIssueCode(result, func(code ErrorCode) {
		switch SeverityForCode(code) {
		case SeverityCritical:
			c.Critical++
		case SeverityHigh:
			c.High++
		case SeverityMedium:
			c.Medium++
		case SeverityLow:
			c.Low++
		default:
			c.Medium++
		}
	})
	return c
}

// CriticalIssueCodesSorted returns unique Critical-level issue codes present in the analysis, sorted.
func CriticalIssueCodesSorted(result *AnalysisResult) []string {
	seen := make(map[ErrorCode]struct{})
	forEachIssueCode(result, func(code ErrorCode) {
		if SeverityForCode(code) != SeverityCritical {
			return
		}
		seen[code] = struct{}{}
	})
	out := make([]string, 0, len(seen))
	for code := range seen {
		out = append(out, string(code))
	}
	sort.Strings(out)
	return out
}

// ComputePlumberScore applies the scoring-v1 rules (see docs/scoring.md).
func ComputePlumberScore(counts SeverityCounts) PlumberScoreResult {
	// weights and caps (documented in docs/scoring.md)
	const (
		w_crit = 30.0
		w_high = 30.0
		w_med  = 10.0
		w_low  = 5.0

		cap_high = 100.0
		cap_med  = 30.0
		cap_low  = 15.0
	)

	out := PlumberScoreResult{
		ProfileID: PlumberScoreProfileID,
		Counts:    counts,
		Losses:    make([]SeverityLoss, 0, 4),
	}

	losses := []struct {
		sev    IssueSeverity
		n      int
		weight float64
		cap    float64
	}{
		{SeverityCritical, counts.Critical, w_crit, math.Inf(1)},
		{SeverityHigh, counts.High, w_high, cap_high},
		{SeverityMedium, counts.Medium, w_med, cap_med},
		{SeverityLow, counts.Low, w_low, cap_low},
	}

	var totalLoss float64
	for _, row := range losses {
		if row.n <= 0 {
			continue
		}
		uncapped := row.weight * (1.0 + math.Log2(float64(row.n)))
		capped := uncapped
		if !math.IsInf(row.cap, 1) {
			capped = math.Min(uncapped, row.cap)
		}
		sl := SeverityLoss{
			Severity:     row.sev,
			Count:        row.n,
			Weight:       row.weight,
			UncappedLoss: uncapped,
			CappedLoss:   capped,
		}
		if !math.IsInf(row.cap, 1) {
			sl.Cap = row.cap
		}
		out.Losses = append(out.Losses, sl)
		totalLoss += capped
	}

	raw := 100.0 - totalLoss
	if raw < 0 {
		raw = 0
	}
	out.RawPoints = raw

	final := raw
	if counts.Critical > 0 {
		const maxPointsWithCritical = 30.0 // E band: points < 31; malus caps at 30
		out.CriticalMalusApplied = true
		out.CriticalMalusMax = maxPointsWithCritical
		final = math.Min(raw, maxPointsWithCritical)
	}
	out.FinalPoints = final
	out.Score = scoreLetterFromPoints(out.FinalPoints)

	return out
}

func scoreLetterFromPoints(finalPoints float64) string {
	switch {
	case finalPoints >= 90:
		return "A"
	case finalPoints >= 71:
		return "B"
	case finalPoints >= 51:
		return "C"
	case finalPoints >= 31:
		return "D"
	default:
		return "E"
	}
}

// ScoreLetterMeaning returns a short human-readable description of what a
// letter score implies about the pipeline. It is used by CLI banners,
// merge request comments, and documentation so wording stays consistent.
func ScoreLetterMeaning(letter string) string {
	switch letter {
	case "A":
		return "Excellent — very low risk, clean pipeline"
	case "B":
		return "Good — a few Low/Medium issues"
	case "C":
		return "Moderate — Medium issues or accumulating Low findings, worth fixing"
	case "D":
		return "Poor — High-severity issues impacting the pipeline"
	case "E":
		return "Critical — at least one Critical issue or heavy accumulated losses"
	default:
		return ""
	}
}
