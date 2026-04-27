package control

import (
	"math"
	"sort"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// PlumberScoreProfileID identifies the scoring rules version (see docs/scoring.md).
const PlumberScoreProfileID = "scoring-v3"

// PlumberScoreDocURL is the canonical user-facing explanation of the Plumber letter score.
const PlumberScoreDocURL = "https://github.com/getplumber/plumber/blob/main/docs/scoring.md"

// SeverityCounts is the number of detected issues per documented severity bucket.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// CodeLoss is the points lost for a single issue code after weight, log growth, and per-severity cap.
// scoring-v3 caps loss per (code), so distinct types at the same severity each contribute their own bucket.
type CodeLoss struct {
	Code         ErrorCode     `json:"code"`
	Severity     IssueSeverity `json:"severity"`
	Count        int           `json:"count"`
	Weight       float64       `json:"weight"`
	Cap          float64       `json:"cap,omitempty"` // omitted when infinite (critical)
	UncappedLoss float64       `json:"uncappedLoss"`
	CappedLoss   float64       `json:"cappedLoss"`
}

// SeverityLoss is a rollup per severity bucket: sum of capped losses across all codes in that severity.
// In scoring-v3 the cap is applied per code, so this rollup can exceed any single per-code cap.
type SeverityLoss struct {
	Severity   IssueSeverity `json:"severity"`
	Count      int           `json:"count"`
	CappedLoss float64       `json:"cappedLoss"`
}

// PlumberScoreResult is the official result: letter Score (A–E) derived from numeric Points (0–100).
type PlumberScoreResult struct {
	ProfileID string `json:"profileId"`

	Counts SeverityCounts `json:"counts"`

	// RawPoints is 100 minus summed capped per-code losses (before Critical malus).
	RawPoints float64 `json:"rawPoints"`
	// FinalPoints applies Critical category malus (max points in E band when any Critical exists).
	FinalPoints float64 `json:"finalPoints"`
	// Score is the letter A–E from final points (what people mean by "how did we score?").
	Score string `json:"score"`

	CriticalMalusApplied bool    `json:"criticalMalusApplied"`
	CriticalMalusMax     float64 `json:"criticalMalusMax,omitempty"` // max points when malus applies (30)

	// Losses is a per-severity rollup of capped per-code losses.
	Losses []SeverityLoss `json:"losses"`
	// CodeLosses is the per-code breakdown that drives the score in scoring-v3.
	CodeLosses []CodeLoss `json:"codeLosses"`
}

// forEachIssueCode invokes fn for every issue code emitted by the
// Rego/OPA rule engine. The legacy Go controls still populate their
// per-control *Result fields in AnalysisResult for JSON backwards
// compatibility (Phase A.2 of the refactor), but scoring and
// aggregation read from the Rego Findings list — the single source
// of truth now that all 19 codes are ported. See
// docs/REFACTOR_MULTI_PROVIDER.md §8 Phase A.
func forEachIssueCode(result *AnalysisResult, fn func(ErrorCode)) {
	if result == nil {
		return
	}
	for _, f := range result.Findings {
		fn(ErrorCode(f.Code))
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
// Kept for callers that only need totals per severity (banners, summary tables).
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

// AggregateIssueCodeCounts walks analysis issues and counts occurrences per ErrorCode.
// This is the input expected by ComputePlumberScore in scoring-v3 (per-code caps).
func AggregateIssueCodeCounts(result *AnalysisResult) map[ErrorCode]int {
	out := map[ErrorCode]int{}
	forEachIssueCode(result, func(code ErrorCode) {
		out[code]++
	})
	return out
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

// severitySpec is the weight and per-code cap for one severity bucket.
type severitySpec struct {
	weight float64
	cap    float64
}

// scoreSeveritySpecs returns the active scoring-v3 weights and per-code caps.
//
//nolint:gochecknoglobals // tied to PlumberScoreProfileID; bumped together when rules change.
func scoreSeveritySpecs() map[IssueSeverity]severitySpec {
	const (
		wCrit = 25.0
		wHigh = 15.0
		wMed  = 6.0
		wLow  = 3.0

		capHigh = 60.0
		capMed  = 20.0
		capLow  = 10.0
	)
	return map[IssueSeverity]severitySpec{
		SeverityCritical: {wCrit, math.Inf(1)},
		SeverityHigh:     {wHigh, capHigh},
		SeverityMedium:   {wMed, capMed},
		SeverityLow:      {wLow, capLow},
	}
}

// ComputePlumberScore applies the scoring-v3 rules (see docs/scoring.md).
//
// For each issue code with count n > 0:
//
//	loss = w × (1 + 0.5·log2(n))   (capped at the per-severity cap)
//
// Each ErrorCode is treated as its own bucket: distinct codes at the same
// severity each consume their own per-code cap, so accumulating different
// types of issues keeps reducing the score even after one code is capped.
//
// Raw points are 100 minus the sum of capped per-code losses. When at least
// one Critical issue is present, final points are capped at 30 (Critical
// malus), forcing the letter score into the E band. The A–E letter is read
// from final points using the thresholds in scoreLetterFromPoints.
func ComputePlumberScore(codeCounts map[ErrorCode]int) PlumberScoreResult {
	specs := scoreSeveritySpecs()

	out := PlumberScoreResult{
		ProfileID:  PlumberScoreProfileID,
		Losses:     make([]SeverityLoss, 0, 4),
		CodeLosses: make([]CodeLoss, 0, len(codeCounts)),
	}

	codes := make([]ErrorCode, 0, len(codeCounts))
	for c, n := range codeCounts {
		if n > 0 {
			codes = append(codes, c)
		}
	}
	sort.Slice(codes, func(i, j int) bool { return string(codes[i]) < string(codes[j]) })

	type sevAgg struct {
		count int
		loss  float64
	}
	sevTotals := map[IssueSeverity]*sevAgg{}

	var totalLoss float64
	for _, c := range codes {
		n := codeCounts[c]
		sev := SeverityForCode(c)
		spec, ok := specs[sev]
		if !ok {
			// Unknown severity defaults to Medium, matching SeverityForCode fallbacks elsewhere.
			sev = SeverityMedium
			spec = specs[SeverityMedium]
		}

		uncapped := spec.weight * (1.0 + 0.5*math.Log2(float64(n)))
		capped := uncapped
		if !math.IsInf(spec.cap, 1) {
			capped = math.Min(uncapped, spec.cap)
		}

		cl := CodeLoss{
			Code:         c,
			Severity:     sev,
			Count:        n,
			Weight:       spec.weight,
			UncappedLoss: uncapped,
			CappedLoss:   capped,
		}
		if !math.IsInf(spec.cap, 1) {
			cl.Cap = spec.cap
		}
		out.CodeLosses = append(out.CodeLosses, cl)
		totalLoss += capped

		agg := sevTotals[sev]
		if agg == nil {
			agg = &sevAgg{}
			sevTotals[sev] = agg
		}
		agg.count += n
		agg.loss += capped

		switch sev {
		case SeverityCritical:
			out.Counts.Critical += n
		case SeverityHigh:
			out.Counts.High += n
		case SeverityMedium:
			out.Counts.Medium += n
		case SeverityLow:
			out.Counts.Low += n
		}
	}

	for _, sev := range []IssueSeverity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if agg, ok := sevTotals[sev]; ok && agg.count > 0 {
			out.Losses = append(out.Losses, SeverityLoss{
				Severity:   sev,
				Count:      agg.count,
				CappedLoss: agg.loss,
			})
		}
	}

	raw := 100.0 - totalLoss
	if raw < 0 {
		raw = 0
	}
	out.RawPoints = raw

	final := raw
	if out.Counts.Critical > 0 {
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

// FindingsByControl groups Rego findings by their declared ControlName
// (from the issue-code registry). Findings whose code has no registry
// entry land under the "" key so the caller can still surface them if
// they want. The map values preserve the input order so downstream
// tables read deterministically.
func FindingsByControl(findings []opaengine.Finding) map[string][]opaengine.Finding {
	out := map[string][]opaengine.Finding{}
	for _, f := range findings {
		control := ""
		if info := LookupCode(ErrorCode(f.Code)); info != nil {
			control = info.ControlName
		}
		out[control] = append(out[control], f)
	}
	return out
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
