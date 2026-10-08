package control

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// BestFixSummary is the best fix in one line: what to do, the points it
// recovers, the points and letter it leads to; or, when no fix moves the
// score, what to do and why the score stays.
func BestFixSummary(score *PlumberScoreResult) string {
	fix := score.BestFix
	if fix == nil {
		return "nothing to fix"
	}
	named := findingFix(fix.Code, fix.Subject)
	if fix.Subject != "" {
		named += " (" + ShortenCommitSHA(fix.Subject) + ")"
	}
	for _, p := range score.Paths {
		if fix.PathID != "" && p.ID == fix.PathID {
			label := entryFamily(p) + " " + ShortenCommitSHA(p.Entry.Subject)
			if p.EntryKind == EntryPoisonedCache && namedCacheSubject(p.Entry.Subject) {
				label = p.Entry.Subject // the name already says it is a cache
			}
			named = pathFixOf(p) + " (" + label + ")"
		}
	}
	if fix.Stays != "" {
		return named + ". " + fix.Stays
	}
	return fmt.Sprintf("%s, +%s pts, %s / 100 (%s)", named, formatPoints(fix.PointsGained), formatPoints(fix.NewPoints), fix.NewLetter)
}

// BestFix is the single highest-value fix ComputeBestFix found among a
// run's attack paths and non-dismissed findings: fixing it (every finding
// anchoring the path, or every finding sharing the finding's identity)
// recovers the most FinalPoints of any candidate.
type BestFix struct {
	AnchorHash string    `json:"anchorHash"`
	Code       ErrorCode `json:"code"`
	Job        string    `json:"job,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	// PathID is the attack path the fix removes, empty when the fix is a
	// finding on no path.
	PathID       string  `json:"pathId,omitempty"`
	PointsGained float64 `json:"pointsGained"`
	// NewPoints is the final points once the fix is made.
	NewPoints float64 `json:"newPoints"`
	NewLetter string  `json:"newLetter"`
	Sentence  string  `json:"sentence"`
	// Reason says why PointsGained differs from the price of what the fix
	// removes ("+13 pts: the path's 15, less 2 for a finding that then
	// stands alone"), empty when it does not or when no reason can be read
	// off the two scores. The reports print it; the JSON does not carry it.
	Reason string `json:"-"`
	// Stays is set when no fix moves the final points: the best fix is
	// then the one that recovers the most before the caps, PointsGained is
	// 0, and Stays says why the score does not move yet ("The score stays
	// at 31 until fewer High paths remain."). The reports print it after
	// the fix; the JSON carries it in Sentence.
	Stays string `json:"-"`

	// severity is the individual severity of a finding candidate
	// (IndividualSeverity), empty for a path. Never serialized.
	severity IssueSeverity
	// rank is the path's place in the report order (PathsWorstFirst), the
	// tie-break between two paths recovering the same points; -1 for a
	// finding on no path. Never serialized.
	rank int
}

// MarshalJSON writes pointsGained and newPoints rounded to one decimal,
// the precision the best-fix sentence prints and the push sends; the
// struct keeps the raw figures, which ComputeBestFix compares candidates
// on.
func (b BestFix) MarshalJSON() ([]byte, error) {
	type wire BestFix // no methods: marshals with the field tags above
	w := wire(b)
	w.PointsGained = math.Round(w.PointsGained*10) / 10
	w.NewPoints = math.Round(w.NewPoints*10) / 10
	return json.Marshal(w)
}

// bestFixSubjectKeys are the structured-data fields that name a finding's
// subject without ever carrying a secret or settings value, includePath
// included, so a job-less include finding (ISSUE-404) names its include
// path instead of falling through to an empty subject.
var bestFixSubjectKeys = []string{"uses", "image", "expression", "variableName", "branchName", "url", "includePath"}

// bestFixWins reports whether a candidate (gain, code, hash) beats
// whatever ComputeBestFix has kept as best so far: the largest gain
// (within a 1e-9 tolerance, so two logically equal gains that differ only
// in their last float bit never pick a winner by accident), then the
// path the report numbers first when both are paths (rank), then the
// lower code string, then the lower anchor hash. Comparing the running
// candidate against the current best this way, for every candidate in
// whatever order the caller's findings happen to be in, always settles on
// the same (code, hash) pair for the largest gain found: a strict total
// order over (gain bucket, code, hash) picks the same minimum element
// regardless of visit order.
func bestFixWins(gain float64, rank int, fcode, hash string, best *BestFix) bool {
	if best == nil {
		return true
	}
	diff := gain - best.PointsGained
	if diff > 1e-9 {
		return true
	}
	if diff < -1e-9 {
		return false
	}
	if rank >= 0 && best.rank >= 0 && rank != best.rank {
		return rank < best.rank
	}
	if fcode != string(best.Code) {
		return fcode < string(best.Code)
	}
	return hash < best.AnchorHash
}

// bestFixSentence renders the best fix's third sentence (spec section 3):
// the registry title, the subject in backticks when there is one (never
// empty backtick parentheses when no key matched and the job is empty),
// how many points fixing it recovers (rounded to one decimal first, "1
// point" singular), and whether the letter actually changes ("moves" only
// then, "keeps" otherwise).
func bestFixSentence(title, subject string, gain float64, oldLetter, newLetter string) string {
	named := title
	if subject != "" {
		named = fmt.Sprintf("%s (%s)", title, code(subject))
	}
	outcome := fmt.Sprintf("keeps the score at %s", newLetter)
	if newLetter != oldLetter {
		outcome = fmt.Sprintf("moves the score to %s", newLetter)
	}
	return fmt.Sprintf("Fixing %s recovers %s %s and %s.", named, formatPoints(gain), pointsWord(gain), outcome)
}

// ComputeBestFix re-scores the run once per candidate and keeps the trial
// that recovers the most final points: ties go to the lower code string,
// then the lower anchor hash (bestFixWins), so the result never depends on
// the input order. A candidate is one attack path, every finding anchoring
// it dismissed together (fixing an entry removes every finding on it), or
// one live identity that anchors no path (an other finding, or a gate that
// amplifies one). Only a gate can change the paths, so only a gate's trial
// re-assembles them. A gain that rounds to 0.0 is not a gain. When no
// candidate gains anything (the caps saturated, or the force holding the
// score), the best fix is the candidate that recovers the most of the
// prices before the caps, in the same order, with 0 points gained and
// Stays saying why; nil only when there is no candidate at all.
//
// Every finding's hash is computed once, up front, and every trial is
// scored on those hashes (scoreWithHashes) rather than re-hashing the run
// per candidate.
func ComputeBestFix(in ScoreInputV4, sit *Situation, current PlumberScoreResult) *BestFix {
	hashes := make([]string, len(in.Findings))
	oks := make([]bool, len(in.Findings))
	for i, f := range in.Findings {
		hashes[i], oks[i] = findingAnchorHash(f)
	}
	var best *BestFix
	var bestTrial PlumberScoreResult
	// held is the candidate that recovers the most of the prices before
	// the caps, kept for when no candidate moves the final points.
	var held *BestFix
	var heldTrial PlumberScoreResult
	var heldTier PathTier
	// named is what a candidate's sentence names: its code's title and its
	// subject for a finding, the path's own fix for a path (pathFixNamed).
	var heldNamed string
	rank := map[string]int{}
	for i, p := range PathsWorstFirst(in.Paths) {
		rank[p.ID] = i
	}
	consider := func(s PlumberScoreResult, code ErrorCode, sev IssueSeverity, hash, job, subject, pathID, named string) {
		r, ok := rank[pathID]
		if pathID == "" || !ok {
			r = -1
		}
		if recovered := uncappedLoss(&current) - uncappedLoss(&s); bestFixWins(recovered, r, string(code), hash, held) {
			held = &BestFix{AnchorHash: hash, Code: code, Job: job, Subject: subject, PathID: pathID, PointsGained: recovered, rank: r, severity: sev}
			heldTrial, heldTier, heldNamed = s, PathTier(sev), named
			for _, p := range in.Paths {
				if pathID != "" && p.ID == pathID {
					heldTier = p.Tier
				}
			}
		}
		gain := s.FinalPoints - current.FinalPoints
		if math.Round(gain*10)/10 <= 0 || !bestFixWins(gain, r, string(code), hash, best) {
			return
		}
		best = &BestFix{
			AnchorHash: hash, Code: code, Job: job, Subject: subject, PathID: pathID,
			PointsGained: gain, NewPoints: s.FinalPoints, NewLetter: s.Score, rank: r, severity: sev,
			Sentence: bestFixSentence(named, "", gain, current.Score, s.Score),
		}
		bestTrial = s
	}

	anchors := map[string]bool{}
	for _, p := range in.Paths {
		drop := map[string]bool{}
		for _, h := range p.AllAnchorHashes() {
			anchors[h] = true
			drop[h] = true
		}
		trial := dismissedCopy(in.Findings, hashes, oks, drop)
		s := scoreWithHashes(ScoreInputV4{Findings: trial, Paths: AssemblePaths(trial, sit, in.ProjectPath), DefaultBranch: in.DefaultBranch}, hashes, oks)
		consider(s, p.AnchorCode, IssueSeverity(p.Tier), p.AnchorHash, p.Jobs[0], p.Entry.Subject, p.ID, pathFixNamed(p))
	}

	// A finding that is neither a gate nor a privilege finding leaves the
	// paths as they are and costs its code's price wherever it sits. Its
	// fix is about its subject (an action, an image), so every such
	// finding of one code on one subject is fixed together, one trial for
	// the group, named by its lowest hash; groups of the same size and
	// code give the same trial, and only the lowest hash among them can
	// win the tie (bestFixWins), so one trial per (code, size) stands for
	// them all.
	seen := map[string]bool{}
	groups := map[string][]int{}
	var trials [][]int
	for i, f := range in.Findings {
		h := hashes[i]
		if f.Dismissed || !oks[i] || anchors[h] || seen[h] {
			continue
		}
		seen[h] = true
		code := ErrorCode(f.Code)
		if role := RoleForCode(code); role == RoleGate || role == RolePrivilege {
			trials = append(trials, []int{i})
			continue
		}
		key := f.Code + "|" + bestFixSubject(f)
		groups[key] = append(groups[key], i)
	}
	lowest := map[string][]int{}
	for _, g := range groups {
		sort.Slice(g, func(a, b int) bool { return hashes[g[a]] < hashes[g[b]] })
		key := fmt.Sprintf("%s|%d", in.Findings[g[0]].Code, len(g))
		if cur, ok := lowest[key]; !ok || hashes[g[0]] < hashes[cur[0]] {
			lowest[key] = g
		}
	}
	for _, g := range lowest {
		trials = append(trials, g)
	}
	for _, group := range trials {
		i := group[0]
		f, h := in.Findings[i], hashes[i]
		drop := map[string]bool{}
		for _, j := range group {
			drop[hashes[j]] = true
		}
		trial := dismissedCopy(in.Findings, hashes, oks, drop)
		paths := in.Paths
		if RoleForCode(ErrorCode(f.Code)) == RoleGate {
			paths = AssemblePaths(trial, sit, in.ProjectPath)
		}
		s := scoreWithHashes(ScoreInputV4{Findings: trial, Paths: paths, DefaultBranch: in.DefaultBranch}, hashes, oks)
		consider(s, ErrorCode(f.Code), IndividualSeverity(f, in.DefaultBranch), h, f.Job, bestFixSubject(f), "", findingNamed(ErrorCode(f.Code), bestFixSubject(f)))
	}
	if best != nil {
		best.Reason = bestFixReason(&current, &bestTrial, best)
		return best
	}
	if held == nil {
		return nil
	}
	held.PointsGained, held.NewPoints, held.NewLetter = 0, current.FinalPoints, current.Score
	held.Stays = fmt.Sprintf("The score stays at %s%s.", formatPoints(current.FinalPoints), whyTheScoreStays(&heldTrial, heldTier, held.PathID == ""))
	held.Sentence = fmt.Sprintf("Fixing %s does not move the score yet. %s", heldNamed, held.Stays)
	return held
}

// findingNamed is what the best fix sentence names a finding candidate
// by: its code's title, then its subject.
func findingNamed(c ErrorCode, subject string) string {
	named := string(c)
	if info := LookupCode(c); info != nil {
		named = info.Title
	}
	if subject != "" {
		named = fmt.Sprintf("%s (%s)", named, code(subject))
	}
	return named
}

// pathFixNamed is what the best fix sentence names a path candidate by:
// the path through its entry, with the very fix its block's Fix line
// prints (pathFixOf, the most serious anchor's), never the fix of the
// code its identity is kept by.
func pathFixNamed(p AttackPath) string {
	if p.Entry.Subject == "" {
		return fmt.Sprintf("the path (%s)", pathFixOf(p))
	}
	return fmt.Sprintf("the path through %s (%s)", code(ShortenCommitSHA(p.Entry.Subject)), pathFixOf(p))
}

// uncappedLoss is what the paths and the other findings cost at their
// prices, before any cap: what a fix recovers when the caps would keep its
// gain from showing in the final points.
func uncappedLoss(s *PlumberScoreResult) float64 {
	total := 0.0
	for _, pl := range s.PathLosses {
		total += float64(pl.Count) * pl.Weight
	}
	if s.OtherFindings != nil {
		total += s.OtherFindings.UncappedLoss
	}
	return total
}

// reasonClause is one part of a best fix's reason and the words that join
// it to the part before.
type reasonClause struct{ join, text string }

// bestFixReason says why the points a fix recovers differ from the price
// of what it removes, read off the score before (cur) and after (trial)
// the fix: what the attack paths and the other findings then take off,
// the nested cap or the individual findings' 30 that kept part of the
// price, and what the force or the bottom of the scale did on either
// side. "" when the gain is the price and nothing else moved, or when
// part of the difference has no cause it can name.
func bestFixReason(cur, trial *PlumberScoreResult, fix *BestFix) string {
	const eps = 0.05
	curPaths, curOther := BucketLosses(cur)
	newPaths, newOther := BucketLosses(trial)
	dPaths, dOther := curPaths-newPaths, curOther-newOther
	var clauses []reasonClause
	add := func(join, text string) { clauses = append(clauses, reasonClause{join, text}) }
	// atPrice is set when the first clause is the plain price of what the
	// fix removes: alone, it explains nothing the gain does not say.
	atPrice := false

	var target *AttackPath
	for i := range cur.Paths {
		if fix.PathID != "" && cur.Paths[i].ID == fix.PathID {
			target = &cur.Paths[i]
		}
	}
	// What the fix took off both buckets: under a nested cap shared by
	// paths and findings, a share moves between them, so a capped price
	// reads against the total.
	dTotal := dPaths + dOther
	switch {
	case target != nil:
		price := pathPrices()[target.Tier]
		c, capped := heldCapOver(cur, IssueSeverity(target.Tier))
		switch {
		case math.Abs(dPaths-price) < eps:
			add("", "the path's "+formatPoints(price))
			atPrice = true
		case dTotal < price-eps && capped:
			add("", fmt.Sprintf("the path's %s, of which %s counts, %s", formatPoints(price), formatPoints(dTotal), nestedCapNote(c, "counting")))
			dOther = 0
		case dPaths > eps:
			add("", formatPoints(dPaths)+" off the attack paths")
		}
	case samePaths(cur, trial):
		// A finding on no path: its price is its individual severity's.
		sev := fix.severity
		if sev == "" {
			sev = SeverityForCode(fix.Code)
		}
		price, ok := otherFindingPrices()[sev]
		if !ok {
			sev, price = SeverityMedium, otherFindingPrices()[SeverityMedium]
		}
		c, capped := heldCapOver(cur, sev)
		switch {
		case math.Abs(dTotal-price) < eps:
			add("", "the finding's "+formatPoints(price))
			atPrice = true
		case cur.OtherFindings != nil && cur.OtherFindings.CapApplied && dTotal < price:
			add("", fmt.Sprintf("the finding's %s, of which %s counts, the individual findings being capped at %s", formatPoints(price), formatPoints(dTotal), formatPoints(cur.OtherFindings.Cap)))
		case dTotal < price-eps && capped:
			add("", fmt.Sprintf("the finding's %s, of which %s counts, %s", formatPoints(price), formatPoints(dTotal), nestedCapNote(c, "counting")))
		}
		dOther = 0
	default:
		// A protection: fixing it changes the paths it amplified.
		if text := pathsChange(cur, trial); text != "" {
			add("", text)
		} else {
			add("", formatPoints(dPaths)+" off the attack paths")
		}
	}
	switch n := otherCount(trial) - otherCount(cur); {
	case dOther <= -eps && n == 1:
		add(", less ", formatPoints(-dOther)+" for a finding that then stands alone")
	case dOther <= -eps && n > 1:
		add(", less ", fmt.Sprintf("%s for %d findings that then stand alone", formatPoints(-dOther), n))
	case dOther <= -eps:
		add(", less ", formatPoints(-dOther)+" on the individual findings")
	case dOther >= eps:
		add(", and ", formatPoints(dOther)+" off the individual findings")
	}

	// What the force or the bottom of the scale added or took on either
	// side: final points minus the plain subtraction.
	adjCur := cur.FinalPoints - cur.RawPointsUnclamped
	adjNew := trial.FinalPoints - trial.RawPointsUnclamped
	if math.Abs(adjNew-adjCur) >= eps {
		curForce := cur.CriticalMalusApplied && cur.RawPoints > cur.FinalPoints
		newForce := trial.CriticalMalusApplied && trial.RawPoints > trial.FinalPoints
		// What held the gain back, joined by "but", then what added to it.
		var held []string
		if cur.RawPointsUnclamped < 0 {
			held = append(held, "the score was "+formatPoints(-cur.RawPointsUnclamped)+" below 0")
		}
		if newForce {
			if len(held) > 0 {
				held = append(held, "stays capped at "+formatPoints(trial.CriticalMalusMax))
			} else {
				held = append(held, "the score stays capped at "+formatPoints(trial.CriticalMalusMax))
			}
		}
		if len(held) > 0 {
			add(", but ", strings.Join(held, " and "))
		}
		named := len(held) > 0
		if curForce && !newForce {
			add(" and ", "the cap is lifted")
			named = true
		}
		if !named {
			return ""
		}
	}
	if len(clauses) == 0 || len(clauses) == 1 && atPrice {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "+%s pts: ", formatPoints(fix.PointsGained))
	for i, c := range clauses {
		if i > 0 {
			b.WriteString(c.join)
		}
		b.WriteString(c.text)
	}
	return b.String()
}

// samePaths reports whether a fix left the assembled paths as they were:
// the same IDs at the same tiers, so what it recovers is a finding's.
func samePaths(cur, trial *PlumberScoreResult) bool {
	return slices.EqualFunc(cur.Paths, trial.Paths, func(a, b AttackPath) bool { return a.ID == b.ID && a.Tier == b.Tier })
}

func otherCount(s *PlumberScoreResult) int {
	if s.OtherFindings == nil {
		return 0
	}
	return s.OtherFindings.Count
}

// pathsChange names what a fix did to the paths when it is one change: a
// single path that drops a tier ("the path drops to High", or "path 2"
// when there are several) or that goes. "" otherwise.
func pathsChange(cur, trial *PlumberScoreResult) string {
	after := map[string]PathTier{}
	for _, p := range trial.Paths {
		after[p.ID] = p.Tier
	}
	ordered := PathsWorstFirst(cur.Paths)
	text, changes := "", 0
	for i, p := range ordered {
		name := "the path"
		if len(ordered) > 1 {
			name = fmt.Sprintf("path %d", i+1)
		}
		tier, kept := after[p.ID]
		switch {
		case !kept:
			text, changes = name+" goes", changes+1
		case tier != p.Tier:
			text, changes = fmt.Sprintf("%s drops to %s", name, tierTitle(tier)), changes+1
		}
	}
	if changes != 1 || len(trial.Paths) > len(cur.Paths) {
		return ""
	}
	return text
}

// dismissedCopy is findings with every finding whose hash is in drop
// dismissed; the caller's slice is never changed.
func dismissedCopy(findings []opaengine.Finding, hashes []string, oks []bool, drop map[string]bool) []opaengine.Finding {
	trial := make([]opaengine.Finding, len(findings))
	copy(trial, findings)
	for j := range trial {
		if oks[j] && drop[hashes[j]] {
			trial[j].Dismissed = true
		}
	}
	return trial
}

// bestFixSubject names an other finding by the first structured-data field
// that names its subject (bestFixSubjectKeys), else its job.
func bestFixSubject(f opaengine.Finding) string {
	for _, key := range bestFixSubjectKeys {
		if v, ok := f.Data[key].(string); ok && v != "" {
			return v
		}
	}
	return f.Job
}
