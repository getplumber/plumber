package control

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// BucketLosses is what the two buckets took off 100.
func BucketLosses(score *PlumberScoreResult) (paths, other float64) {
	for _, pl := range score.PathLosses {
		paths += pl.CappedLoss
	}
	if score.OtherFindings != nil {
		other = score.OtherFindings.CappedLoss
	}
	return paths, other
}

// CapNotes says which caps kept less than the prices add up to, the lines
// under the subtraction that make it add up by hand: one per nested cap
// that held, the widest first ("high, medium and low items count for 69 at
// most"), then one for the individual findings ("individual findings count
// for 30 at most"); none when no cap held.
func CapNotes(score *PlumberScoreResult) []string {
	var out []string
	_, held := nestLosses(scoreSums(score))
	for i := 1; i < len(severityOrder); i++ {
		if held[i] {
			out = append(out, nestedCapNote(severityOrder[i], "count"))
		}
	}
	if o := score.OtherFindings; o != nil && o.CapApplied {
		out = append(out, "individual findings count for "+formatPoints(o.Cap)+" at most")
	}
	return out
}

// nestedCapNote says the nested cap of sev, with verb ("count",
// "counting"): "medium and low items count for 49 at most".
func nestedCapNote(sev IssueSeverity, verb string) string {
	items := map[IssueSeverity]string{SeverityHigh: "high, medium and low items", SeverityMedium: "medium and low items", SeverityLow: "low items"}[sev]
	return fmt.Sprintf("%s %s for %s at most", items, verb, formatPoints(nestedCaps()[sev]))
}

// heldCapOver is the innermost nested cap that holds the items of sev in
// s, false when none does (a Critical item is never capped).
func heldCapOver(s *PlumberScoreResult, sev IssueSeverity) (IssueSeverity, bool) {
	_, held := nestLosses(scoreSums(s))
	for i := severityIndex(sev); i >= 1; i-- {
		if held[i] {
			return severityOrder[i], true
		}
	}
	return "", false
}

// OtherFindingsSummary reads the other-findings bucket out: the counts by
// severity, worst first; "none" when empty.
func OtherFindingsSummary(score *PlumberScoreResult) string {
	o := score.OtherFindings
	if o == nil || o.Count == 0 {
		return "none"
	}
	var parts []string
	for _, c := range []struct {
		n    int
		name string
	}{{o.Counts.Critical, "critical"}, {o.Counts.High, "high"}, {o.Counts.Medium, "medium"}, {o.Counts.Low, "low"}} {
		if c.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c.n, c.name))
		}
	}
	return strings.Join(parts, ", ")
}

// ScoreAdjustment says how the force or the bottom of the scale changed
// the final points, "" when neither did.
func ScoreAdjustment(score *PlumberScoreResult) string {
	switch {
	case score.CriticalMalusApplied && score.RawPoints > score.FinalPoints:
		return fmt.Sprintf("Capped at %s: a Critical attack path remains.", formatPoints(score.CriticalMalusMax))
	case score.RawPointsUnclamped < 0 && score.FinalPoints == 0:
		return "The score does not go below 0."
	}
	return ""
}

// whyTheScoreStays says what still holds the final points once a fix is
// made (trial), read in this order: the rest still taking the score below
// 0 with nothing raising it, the individual findings still over their 30
// (finding), the nested cap still holding the fixed item's tier, a
// Critical path still holding the score at 30. tier is the fixed path's
// tier, or the fixed finding's registry severity. "" when none of these
// applies.
func whyTheScoreStays(trial *PlumberScoreResult, tier PathTier, finding bool) string {
	if trial.RawPointsUnclamped < 0 && trial.FinalPoints == 0 {
		return " while the rest takes it below 0"
	}
	if o := trial.OtherFindings; finding && o != nil && o.Cap > 0 && o.UncappedLoss >= o.Cap-0.05 {
		return " until fewer individual findings remain"
	}
	// PathTier and IssueSeverity share their strings
	// (TestTierAndSeverityStringsAgree), so the cast is exact.
	if c, ok := heldCapOver(trial, IssueSeverity(tier)); ok {
		return " while " + nestedCapNote(c, "count")
	}
	if trial.CriticalMalusApplied && trial.RawPoints > trial.FinalPoints {
		return " while a Critical attack path remains"
	}
	return ""
}

// formatPoints rounds p to one decimal first, so floating-point noise
// below the printed precision never flips the integer/decimal choice,
// then renders it as a bare integer when that rounds to a whole number
// ("45", never "45.0"), one decimal otherwise ("2.2").
func formatPoints(p float64) string {
	rounded := math.Round(p*10) / 10
	if rounded == math.Trunc(rounded) {
		return strconv.Itoa(int(rounded))
	}
	return fmt.Sprintf("%.1f", p)
}

// pointsWord is "point" when p rounds to exactly 1, "points" otherwise
// (zero, fractional, or more than one).
func pointsWord(p float64) string {
	if math.Round(p*10)/10 == 1 {
		return "point"
	}
	return "points"
}

// ScoreV4WithExplanations is the scoring-v4 entry point, for the run-level
// score and for every per-policy score alike (ComputeScoreForProfile calls
// it for both): it assembles the attack paths onto result, prices them
// (ComputePlumberScoreV4), then adds the best fix and the situation
// paragraph.
func ScoreV4WithExplanations(result *AnalysisResult) PlumberScoreResult {
	sit := result.Situation
	if sit == nil {
		sit = &Situation{Exposure: ir.VisibilityUnknown, Jobs: map[string]JobSituation{}}
	}
	pipeline := result.Pipeline
	if pipeline == nil {
		pipeline = result.GitHubPipeline
	}
	if pipeline == nil {
		pipeline = &ir.NormalizedPipeline{}
	}
	project := pipeline.ProjectPath
	if project == "" {
		project = result.ProjectPath
	}
	result.Paths = AssemblePaths(result.Findings, sit, project)
	in := ScoreInputV4{Findings: result.Findings, Paths: result.Paths, ProjectPath: project, DefaultBranch: sit.DefaultBranch}
	s := ComputePlumberScoreV4(in)
	s.BestFix = ComputeBestFix(in, sit, s)
	s.Situation = SituationText(SituationFacts(sit, pipeline))
	fillPathReportFields(s.Paths, s.PathLosses, result.Findings)
	return s
}

// fillPathReportFields writes each priced path's report fields in place
// (spec section 4): its sentence, its findingIds (every anchor's hash in
// AnchorHashes order, then the gates' in GateHashes order, then the hashes of the non-dismissed
// privilege findings riding the path, sorted) and its loss, the price of
// its tier (what the nested cap keeps of it is in pathLosses, not per path).
// paths is the slice the score and the result share, so both see them.
// The formula itself (ComputePlumberScoreV4) never reads these fields.
func fillPathReportFields(paths []AttackPath, losses []PathLoss, findings []opaengine.Finding) {
	price := map[string]float64{}
	for _, pl := range losses {
		for _, id := range pl.PathIDs {
			price[id] = pl.Weight
		}
	}
	privileges := map[string][]string{} // path id -> privilege hashes
	for _, f := range findings {
		if f.Dismissed {
			continue
		}
		hash, ok := findingAnchorHash(f)
		if !ok {
			continue
		}
		for _, p := range privilegeWalkedPaths(f, paths) {
			privileges[p.ID] = append(privileges[p.ID], hash)
		}
	}
	for i := range paths {
		p := &paths[i]
		p.Sentence = PathSentence(*p)
		p.Loss = price[p.ID]
		var ids []string
		seen := map[string]bool{}
		for _, h := range p.AllAnchorHashes() {
			if !seen[h] {
				seen[h] = true
				ids = append(ids, h)
			}
		}
		for _, h := range p.GateHashes {
			if !seen[h] {
				seen[h] = true
				ids = append(ids, h)
			}
		}
		priv := append([]string(nil), privileges[p.ID]...)
		sort.Strings(priv)
		for _, h := range priv {
			if !seen[h] {
				seen[h] = true
				ids = append(ids, h)
			}
		}
		p.FindingIDs = ids
	}
}
