package control

import (
	"math"
	"slices"
	"sort"
	"strconv"

	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// PlumberScoreProfileIDV4 names the contextual formula (spec section 2).
const PlumberScoreProfileIDV4 = "scoring-v4"

const (
	// otherFindingsCap is the most every finding no path consumes can cost
	// together, whatever their number and severity: the budget is spent
	// worst first (otherFindingsBudget).
	otherFindingsCap = 30.0
	// criticalPathCap is the final-points ceiling while at least one
	// assembled path is Critical. Nothing else applies it: a Critical
	// finding on no path costs its price, it does not force the letter.
	criticalPathCap = 30.0
)

// pathPrices prices one attack path of each tier, flat.
func pathPrices() map[PathTier]float64 {
	return map[PathTier]float64{TierCritical: 30, TierHigh: 15, TierMedium: 6, TierLow: 3}
}

// nestedCaps is the one nested cap every non-Critical item enters, paths
// and individual findings alike: the items of this severity and every
// lower one count for this much at most together. Critical items are
// never capped. The caps are what keeps a run with no Critical item at 31
// or more, with no High at 51 or more, with no Medium at 71 or more.
func nestedCaps() map[IssueSeverity]float64 {
	return map[IssueSeverity]float64{SeverityHigh: 69, SeverityMedium: 49, SeverityLow: 29}
}

// otherFindingPrices prices one finding no path consumes, by its registry
// severity.
func otherFindingPrices() map[IssueSeverity]float64 {
	return map[IssueSeverity]float64{SeverityCritical: 20, SeverityHigh: 10, SeverityMedium: 5, SeverityLow: 2}
}

// severityOrder is the order the formula reads severities in, worst
// first; a [4]float64 of losses is indexed in it.
var severityOrder = [4]IssueSeverity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

// severityIndex is sev's place in severityOrder, Medium for anything
// unknown (the price an unknown severity pays).
func severityIndex(sev IssueSeverity) int {
	switch sev {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityLow:
		return 3
	}
	return 2
}

// otherFindingsBudget spends the individual findings' 30 worst first: the
// Critical prices, then the High, the Medium and the Low, until the 30 are
// spent. What does not fit is not counted.
func otherFindingsBudget(prices [4]float64) [4]float64 {
	var out [4]float64
	left := otherFindingsCap
	for i, p := range prices {
		out[i] = math.Min(p, left)
		left -= out[i]
	}
	return out
}

// nestLosses is the nested cap over the summed prices of every counted
// item by severity (sums, in severityOrder): the Critical sum as it is,
// then Critical + min(69, High + min(49, Medium + min(29, Low))). parts is
// what each severity takes off, read from the lowest up: Low first up to
// 29, then Medium up to what is left of 49, then High up to what is left
// of 69. held reports, per severity, that its cap kept less than the
// items under it add up to.
func nestLosses(sums [4]float64) (parts [4]float64, held [4]bool) {
	parts[0] = sums[0]
	counted := 0.0
	caps := nestedCaps()
	for i := 3; i >= 1; i-- {
		ceiling := caps[severityOrder[i]]
		parts[i] = math.Min(sums[i], ceiling-counted)
		held[i] = sums[i]+counted > ceiling
		counted += parts[i]
	}
	return parts, held
}

// scoreSums reads back, from a computed score, the prices the nested cap
// read: the paths' by tier, and the individual findings' within their 30
// by severity. CapNotes and the best fix's reasons read the caps this way,
// so they always agree with the formula.
func scoreSums(s *PlumberScoreResult) (sums [4]float64) {
	for _, pl := range s.PathLosses {
		sums[severityIndex(IssueSeverity(pl.Tier))] += float64(pl.Count) * pl.Weight
	}
	var others [4]float64
	for _, cl := range s.CodeLosses {
		others[severityIndex(cl.Severity)] += cl.UncappedLoss
	}
	for i, b := range otherFindingsBudget(others) {
		sums[i] += b
	}
	return sums
}

// PathLoss is what every assembled path of one tier takes off: the flat
// price per path, as much of it as the nested cap counts. Cap is the
// nested cap that holds the tier with the tiers below it (69 for High, 49
// for Medium, 29 for Low), omitted for Critical, which is never capped.

type PathLoss struct {
	Tier       PathTier `json:"tier"`
	Count      int      `json:"count"`
	Weight     float64  `json:"weight"`
	Cap        float64  `json:"cap,omitempty"` // omitted when infinite (critical)
	CappedLoss float64  `json:"cappedLoss"`
	PathIDs    []string `json:"pathIds"`
}

// OtherFindingsLoss is what the findings no path consumes cost: one price
// per distinct identity at its registry severity, spent worst first within
// Cap (CapApplied when the prices add up to more), then, outside Critical,
// within the nested cap they share with the paths. CappedLoss is what they
// take off once both caps held.
type OtherFindingsLoss struct {
	Count        int            `json:"count"`
	Counts       SeverityCounts `json:"counts"`
	UncappedLoss float64        `json:"uncappedLoss"`
	Cap          float64        `json:"cap"`
	CappedLoss   float64        `json:"cappedLoss"`
	CapApplied   bool           `json:"capApplied"`
}

// addSeverityCount adds n to the bucket of sev.
func addSeverityCount(c *SeverityCounts, sev IssueSeverity, n int) {
	switch sev {
	case SeverityCritical:
		c.Critical += n
	case SeverityHigh:
		c.High += n
	case SeverityMedium:
		c.Medium += n
	default:
		c.Low += n
	}
}

// ScoreInputV4 is everything the scoring-v4 formula reads: the assembled
// attack paths (control.AssemblePaths) and every finding the run produced,
// dismissed or not.
type ScoreInputV4 struct {
	Findings []opaengine.Finding
	Paths    []AttackPath
	// ProjectPath is the analysed repository's "owner/repo", which the
	// best fix re-assembles the paths for (AssemblePaths); empty when
	// unknown.
	ProjectPath string
	// DefaultBranch is the pipeline's default branch, which a finding on
	// no path is priced against (IndividualSeverity); empty when unknown.
	DefaultBranch string
}

// IndividualSeverity is what a finding on no path is priced and labelled
// at: its registry severity, except a missing branch protection on a
// branch other than the default one (High; Critical on the default
// branch, or when the default branch is unknown) and an action from an
// unauthorized owner pinned by a full commit SHA (Medium; High
// otherwise). The policy says so on the finding (Data
// "occurrenceSeverity"), which is read when it holds a severity; the same
// rule is computed here for a finding that carries none.
func IndividualSeverity(f opaengine.Finding, defaultBranch string) IssueSeverity {
	if occ, _ := f.Data["occurrenceSeverity"].(string); occ != "" {
		switch sev := IssueSeverity(occ); sev {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
			return sev
		}
	}
	switch code := ErrorCode(f.Code); code {
	case CodeBranchUnprotected:
		if branch, _ := f.Data["branchName"].(string); branch != "" && defaultBranch != "" && branch != defaultBranch {
			return SeverityHigh
		}
	case CodeActionUnauthorizedSource:
		if fullCommitSHARef.MatchString(entrySubject(f)) {
			return SeverityMedium
		}
		return SeverityHigh
	}
	return SeverityForCode(ErrorCode(f.Code))
}

// findingHash is identity.PlatformHash(f.IdentityInput()) with the ok flag
// folded into deduped: false only for a codeless finding, which has
// nothing to dedupe against and counts on its own (the same fallback
// codeCountsForFindings documents and applies in scoring-v3).
func findingHash(f opaengine.Finding) (hash string, deduped bool) {
	h, _, ok := identity.PlatformHash(f.IdentityInput())
	return h, ok
}

// ComputePlumberScoreV4 applies the contextual score (spec section 2,
// Points): 100 minus the attack paths, each at a flat price by tier, and
// the other findings, every live finding no path consumes (not an anchor,
// not an amplifying gate, not a privilege finding on a path's surviving
// jobs) at its registry price within 30 spent worst first. Critical items
// count in full; every other item, path or finding, enters one nested cap
// by severity (nestLosses). A Critical path then caps the final points.
// No floor applies: FloorApplied and FloorPoints stay empty.
func ComputePlumberScoreV4(in ScoreInputV4) PlumberScoreResult {
	hashes := make([]string, len(in.Findings))
	deduped := make([]bool, len(in.Findings))
	for i, f := range in.Findings {
		hashes[i], deduped[i] = findingHash(f)
	}
	return scoreWithHashes(in, hashes, deduped)
}

// scoreWithHashes is ComputePlumberScoreV4 over findings whose identity
// hashes are already known (hashes[i] and deduped[i] are findingHash of
// in.Findings[i]): ComputeBestFix re-scores the run once per candidate, and
// hashing every finding again per trial would dominate its cost.
func scoreWithHashes(in ScoreInputV4, hashes []string, dedupedAt []bool) PlumberScoreResult {
	res := PlumberScoreResult{
		ProfileID:  PlumberScoreProfileIDV4,
		Paths:      in.Paths,
		Losses:     []SeverityLoss{},
		CodeLosses: []CodeLoss{},
	}

	consumed := map[string]bool{}
	byTier := map[PathTier][]string{}
	for _, p := range in.Paths {
		for _, h := range p.AllAnchorHashes() {
			consumed[h] = true
		}
		for _, h := range p.GateHashes {
			consumed[h] = true
		}
		byTier[p.Tier] = append(byTier[p.Tier], p.ID)
		if res.PathCounts == nil {
			res.PathCounts = map[string]int{}
		}
		res.PathCounts[string(p.Tier)]++
		if p.Tier == TierCritical {
			res.CriticalPaths++
		}
	}

	// The other-findings bucket, one price per distinct identity, by code
	// and by the severity each finding is priced at (IndividualSeverity).
	type identities struct {
		hashes   map[string]bool
		ordinals int
	}
	type codeSeverity struct {
		code ErrorCode
		sev  IssueSeverity
	}
	perCode := map[codeSeverity]*identities{}
	for i, f := range in.Findings {
		if f.Dismissed {
			continue
		}
		hash, deduped := hashes[i], dedupedAt[i]
		if deduped && consumed[hash] {
			continue
		}
		code := ErrorCode(f.Code)
		if RoleForCode(code) == RolePrivilege && len(privilegeWalkedPaths(f, in.Paths)) > 0 {
			continue
		}
		key := codeSeverity{code, IndividualSeverity(f, in.DefaultBranch)}
		d := perCode[key]
		if d == nil {
			d = &identities{hashes: map[string]bool{}}
			perCode[key] = d
		}
		if deduped {
			d.hashes[hash] = true
		} else {
			d.ordinals++
		}
	}
	codes := make([]codeSeverity, 0, len(perCode))
	for c := range perCode {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, j int) bool {
		if codes[i].code != codes[j].code {
			return codes[i].code < codes[j].code
		}
		return severityIndex(codes[i].sev) < severityIndex(codes[j].sev)
	})
	prices := otherFindingPrices()
	other := OtherFindingsLoss{Cap: otherFindingsCap}
	var otherSums [4]float64
	for _, key := range codes {
		c, sev := key.code, key.sev
		n := len(perCode[key].hashes) + perCode[key].ordinals
		price, ok := prices[sev]
		if !ok {
			sev, price = SeverityMedium, prices[SeverityMedium]
		}
		loss := price * float64(n)
		other.Count += n
		addSeverityCount(&other.Counts, sev, n)
		other.UncappedLoss += loss
		otherSums[severityIndex(sev)] += loss
		res.CodeLosses = append(res.CodeLosses, CodeLoss{Code: c, Severity: sev, Count: n, Weight: price, UncappedLoss: loss})
	}
	other.CapApplied = other.UncappedLoss > otherFindingsCap

	// The nested cap over the paths and the counted individual findings
	// together, by severity, in a fixed tier order so the total never
	// depends on map iteration.
	tiers := [4]PathTier{TierCritical, TierHigh, TierMedium, TierLow}
	pathPrice := pathPrices()
	var pathSums [4]float64
	for i, tier := range tiers {
		pathSums[i] = pathPrice[tier] * float64(len(byTier[tier]))
	}
	counted := otherFindingsBudget(otherSums)
	var sums [4]float64
	for i := range sums {
		sums[i] = pathSums[i] + counted[i]
	}
	parts, _ := nestLosses(sums)

	// Within a severity, the paths and the individual findings share its
	// part by their prices, and each code shares the findings' part by its
	// own, so every figure adds up to what the score took off.
	share := func(part, of, total float64) float64 {
		if total == 0 {
			return 0
		}
		return part * of / total
	}
	var total float64
	caps := nestedCaps()
	for i, tier := range tiers {
		total += parts[i]
		ids := byTier[tier]
		if len(ids) == 0 {
			continue
		}
		sort.Strings(ids)
		res.PathLosses = append(res.PathLosses, PathLoss{Tier: tier, Count: len(ids), Weight: pathPrice[tier], Cap: caps[severityOrder[i]],
			CappedLoss: share(parts[i], pathSums[i], sums[i]), PathIDs: ids})
	}
	for i := range res.CodeLosses {
		cl := &res.CodeLosses[i]
		k := severityIndex(cl.Severity)
		cl.CappedLoss = share(share(parts[k], counted[k], sums[k]), cl.UncappedLoss, otherSums[k])
		other.CappedLoss += cl.CappedLoss
	}
	if other.Count > 0 {
		res.OtherFindings = &other
	}

	res.RawPointsUnclamped = 100 - total
	res.RawPoints = math.Max(0, res.RawPointsUnclamped)
	res.FinalPoints = res.RawPoints
	if res.CriticalPaths > 0 {
		res.CriticalMalusApplied = true
		res.CriticalMalusMax = criticalPathCap
		res.FinalPoints = math.Min(res.FinalPoints, criticalPathCap)
	}
	res.Score = ScoreLetterFromPoints(res.FinalPoints)
	res.Counts = v4Counts(in, hashes, dedupedAt)
	return res
}

// privilegeWalkedPaths is spec section 2's "Findings on no path" exception:
// a privilege-role finding whose Job is a walked job of a path, AND whose
// privilege on that job survived the platform pruning rules (a GitHub
// fork entry job whose secrets and token were dropped carries nothing,
// even though the job is still walked), is ON that path, not hygiene,
// even though it never anchors anything itself. Every path whose
// survivingJobs contains the job counts, not only the strongest:
// ContextualSeverity, FindingLine and v4Counts all read this same list and
// pick the strongest one themselves (strongestPath), so none of the three
// can ever disagree with another about which path, or which tier, a given
// finding rides.
//
// A privilege finding without a job (a GitLab settings variable, ISSUE-201
// and ISSUE-202) is on a path when the variable it names is one of the
// path's surviving reach secrets, by exact name: Reach.Secrets is already
// pruned by the platform rules, so a variable a fork run never sees stays
// off the path. Without a job and without a variable name it is on no path.
func privilegeWalkedPaths(f opaengine.Finding, paths []AttackPath) []AttackPath {
	if RoleForCode(ErrorCode(f.Code)) != RolePrivilege {
		return nil
	}
	if f.Job == "" {
		return pathsReachingVariable(f, paths)
	}
	var out []AttackPath
	for _, p := range paths {
		for _, j := range p.survivingJobs {
			if j == f.Job {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// pathsReachingVariable is privilegeWalkedPaths' job-less half: every path
// one of whose branches reaches, among its surviving secrets, the one the
// finding names (Data["variableName"]).
func pathsReachingVariable(f opaengine.Finding, paths []AttackPath) []AttackPath {
	name, _ := f.Data["variableName"].(string)
	if name == "" {
		return nil
	}
	var out []AttackPath
	for _, p := range paths {
		reached := slices.Contains(p.Reach.Secrets, name)
		for _, b := range p.Branches {
			reached = reached || slices.Contains(b.Reach.Secrets, name)
		}
		if reached {
			out = append(out, p)
		}
	}
	return out
}

// strongestPath returns the highest-tier path in ps, the lowest ID first
// on a tie: the one shared selection ContextualSeverity, FindingLine
// and v4Counts all use for a privilege-role finding's walked paths, so
// picking "the" path a finding rides never depends on the order the
// caller happened to hand the paths in.
func strongestPath(ps []AttackPath) AttackPath {
	best := ps[0]
	for _, p := range ps[1:] {
		if TierRank(p.Tier) > TierRank(best.Tier) || (TierRank(p.Tier) == TierRank(best.Tier) && p.ID < best.ID) {
			best = p
		}
	}
	return best
}

// v4Counts tallies the contextual severity (spec section 2) of every
// non-dismissed finding exactly once: an anchor at its strongest path's
// Tier, a gate finding at its registered severity whether or not it
// amplified a path (the gate is shown ON the path, but its severity stays
// the registry one, never silently dropped because a path's cap already
// covers its cost), a privilege-role finding on a walked (and
// pruning-surviving) path at that path's strongest tier (the same
// privilegeWalkedPaths/strongestPath pair ContextualSeverity reads, so the
// two can never disagree), and its registry severity for every other
// finding, the price it pays. An anchor is counted exactly once through
// its strongest path's tier, never again on its own: that exclusion (not a general "already consumed" one)
// is what keeps this in agreement with ContextualSeverity, which reads the
// same anchor/gate distinction.
func v4Counts(in ScoreInputV4, hashes []string, dedupedAt []bool) SeverityCounts {
	var c SeverityCounts
	bump := func(s IssueSeverity) {
		switch s {
		case SeverityCritical:
			c.Critical++
		case SeverityHigh:
			c.High++
		case SeverityMedium:
			c.Medium++
		default:
			c.Low++
		}
	}
	// The strongest tier per anchor, independent of the caller's own path
	// order: AssemblePaths happens to sort its output by tier today, but
	// this function is exported and takes any []AttackPath.
	seen := map[string]bool{}
	strongest := map[string]PathTier{}
	var anchorOrder []string
	for _, p := range in.Paths {
		for _, h := range p.AllAnchorHashes() {
			if !seen[h] {
				seen[h] = true
				anchorOrder = append(anchorOrder, h)
			}
			if cur, ok := strongest[h]; !ok || TierRank(p.Tier) > TierRank(cur) {
				strongest[h] = p.Tier
			}
		}
	}
	for _, h := range anchorOrder {
		// PathTier and IssueSeverity share the critical/high/medium/low
		// strings (TestTierAndSeverityStringsAgree), so this cast is exact.
		bump(IssueSeverity(strongest[h]))
	}
	for i, f := range in.Findings {
		if f.Dismissed {
			continue
		}
		hash, deduped := hashes[i], dedupedAt[i]
		key := hash
		if !deduped {
			// A codeless finding has no identity to key seen on; its slice
			// position is unique within this loop, which is all that is
			// needed here (it can never collide with a real hash, a fixed
			// 64 hex-char sha256 digest).
			key = "#ordinal#" + strconv.Itoa(i)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if walked := privilegeWalkedPaths(f, in.Paths); len(walked) > 0 {
			bump(IssueSeverity(strongestPath(walked).Tier))
			continue
		}
		bump(IndividualSeverity(f, in.DefaultBranch))
	}
	return c
}
