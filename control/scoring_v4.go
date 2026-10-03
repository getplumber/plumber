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
	// hygieneWeight and hygieneCap price every remaining hygiene/privilege
	// finding together, as one dampened-and-capped bucket rather than per
	// code: a pile of low-stakes findings on no path should cost little,
	// and never more than hygieneCap regardless of how many there are.
	hygieneWeight = 2.0
	hygieneCap    = 10.0
	// criticalPathCap is the final-points ceiling scoring-v4 applies when
	// at least one assembled path is Tier Critical. A gate-coded finding
	// on no path (TestV4FormulaNeverCapsAGateWithNoPath) never applies
	// this: only a Critical path does.
	criticalPathCap = 30.0
)

// pathTierSpecs prices one path of each tier; n paths sharing the same
// tier and entry kind are dampened the same way v3 dampens repeated
// occurrences of one code.
func pathTierSpecs() map[PathTier]severitySpec {
	return map[PathTier]severitySpec{
		TierCritical: {30, math.Inf(1)},
		TierHigh:     {15, 60},
		TierMedium:   {6, 20},
		TierLow:      {3, 10},
	}
}

// PathLoss is the points lost to every assembled path sharing one tier and
// entry kind, after weight, log growth, and the per-tier cap (mirrors
// CodeLoss, scoring-v3's per-code equivalent).
type PathLoss struct {
	Tier       PathTier  `json:"tier"`
	EntryKind  EntryKind `json:"entryKind"`
	Count      int       `json:"count"`
	Weight     float64   `json:"weight"`
	Cap        float64   `json:"cap,omitempty"` // omitted when infinite (critical)
	CappedLoss float64   `json:"cappedLoss"`
	PathIDs    []string  `json:"pathIds"`
}

// ScoreInputV4 is everything the scoring-v4 formula reads: the assembled
// attack paths (control.AssemblePaths) and every finding the run produced,
// dismissed or not.
type ScoreInputV4 struct {
	Findings []opaengine.Finding
	Paths    []AttackPath
}

// dampened is the shared growth curve: one occurrence costs exactly w,
// repeats cost more but less than linearly. n <= 0 costs nothing (no
// occurrence, no loss).
func dampened(w float64, n int) float64 {
	if n <= 0 {
		return 0
	}
	return w * (1 + 0.5*math.Log2(float64(n)))
}

// findingHash is identity.PlatformHash(f.IdentityInput()) with the ok flag
// folded into deduped: false only for a codeless finding, which has
// nothing to dedupe against and counts on its own (the same fallback
// codeCountsForFindings documents and applies in scoring-v3).
func findingHash(f opaengine.Finding) (hash string, deduped bool) {
	h, _, ok := identity.PlatformHash(f.IdentityInput())
	return h, ok
}

// ComputePlumberScoreV4 applies the scoring-v4 rules (spec section 2): it
// prices every assembled attack path, then the gate and hygiene findings no
// path consumed (a path's AnchorHash and GateHashes), then applies the
// Critical-path malus (never a gate-coded finding alone).
func ComputePlumberScoreV4(in ScoreInputV4) PlumberScoreResult {
	res := PlumberScoreResult{ProfileID: PlumberScoreProfileIDV4, Paths: in.Paths}

	consumed := map[string]bool{}
	type groupKey struct {
		tier PathTier
		kind EntryKind
	}
	groups := map[groupKey][]string{}
	for _, p := range in.Paths {
		consumed[p.AnchorHash] = true
		for _, h := range p.GateHashes {
			consumed[h] = true
		}
		k := groupKey{p.Tier, p.EntryKind}
		groups[k] = append(groups[k], p.ID)
		if res.PathCounts == nil {
			res.PathCounts = map[string]int{}
		}
		res.PathCounts[string(p.Tier)]++
		if p.Tier == TierCritical {
			res.CriticalPaths++
		}
	}

	specs := pathTierSpecs()
	for k, ids := range groups {
		spec := specs[k.tier]
		sortedIDs := append([]string(nil), ids...)
		sort.Strings(sortedIDs)
		loss := math.Min(dampened(spec.weight, len(sortedIDs)), spec.cap)
		pl := PathLoss{Tier: k.tier, EntryKind: k.kind, Count: len(sortedIDs), Weight: spec.weight, CappedLoss: loss, PathIDs: sortedIDs}
		if !math.IsInf(spec.cap, 1) {
			pl.Cap = spec.cap
		}
		res.PathLosses = append(res.PathLosses, pl)
	}
	sort.Slice(res.PathLosses, func(i, j int) bool {
		ri, rj := TierRank(res.PathLosses[i].Tier), TierRank(res.PathLosses[j].Tier)
		if ri != rj {
			return ri > rj // tier desc: Critical first
		}
		return res.PathLosses[i].EntryKind < res.PathLosses[j].EntryKind
	})
	// The total is summed AFTER the sort above, in PathLosses' own
	// (now-fixed) order, never while iterating the groups map: floating-
	// point addition is not associative, so summing during the map walk
	// made the low bits of RawPointsUnclamped (and everything derived from
	// it) depend on Go's randomized map iteration order, a different
	// result from one run to the next on the same input.
	var total float64
	for _, pl := range res.PathLosses {
		total += pl.CappedLoss
	}

	// Remaining findings: gate-role ones priced per code (codeCountsForFindings's
	// own dedupe recipe); a privilege-role finding whose job is walked by at
	// least one path (spec section 2, Findings on no path) costs nothing
	// extra, the same as a gate the path already consumed; everything else
	// (hygiene, privilege off any path, and an entry finding that anchored
	// no path) priced together as hygiene.
	type dedupeSet struct {
		hashes   map[string]bool
		ordinals int
	}
	add := func(d *dedupeSet, hash string, deduped bool) {
		if deduped {
			if d.hashes == nil {
				d.hashes = map[string]bool{}
			}
			d.hashes[hash] = true
			return
		}
		d.ordinals++
	}
	count := func(d *dedupeSet) int {
		if d == nil {
			return 0
		}
		return len(d.hashes) + d.ordinals
	}

	gateCounts := map[ErrorCode]*dedupeSet{}
	hygiene := &dedupeSet{}
	for _, f := range in.Findings {
		if f.Dismissed {
			continue
		}
		hash, deduped := findingHash(f)
		if deduped && consumed[hash] {
			continue
		}
		code := ErrorCode(f.Code)
		if RoleForCode(code) == RoleGate {
			d := gateCounts[code]
			if d == nil {
				d = &dedupeSet{}
				gateCounts[code] = d
			}
			add(d, hash, deduped)
			continue
		}
		if RoleForCode(code) == RolePrivilege && len(privilegeWalkedPaths(f, in.Paths)) > 0 {
			continue
		}
		add(hygiene, hash, deduped)
	}

	// scoreSeveritySpecs' Critical entry carries an infinite cap (v3's own
	// rule: a Critical-severity gate is never capped, only dampened), so a
	// gate-coded finding here is priced exactly the way v3 prices the same
	// code, uncapped at Critical.
	sevSpecs := scoreSeveritySpecs()
	codes := make([]ErrorCode, 0, len(gateCounts))
	for c := range gateCounts {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })

	type sevAgg struct {
		count int
		loss  float64
	}
	gateSevTotals := map[IssueSeverity]*sevAgg{}
	for _, c := range codes {
		n := count(gateCounts[c])
		sev := SeverityForCode(c)
		spec, ok := sevSpecs[sev]
		if !ok {
			sev = SeverityMedium
			spec = sevSpecs[SeverityMedium]
		}
		uncapped := dampened(spec.weight, n)
		capped := uncapped
		if !math.IsInf(spec.cap, 1) {
			capped = math.Min(uncapped, spec.cap)
		}
		cl := CodeLoss{Code: c, Severity: sev, Count: n, Weight: spec.weight, UncappedLoss: uncapped, CappedLoss: capped}
		if !math.IsInf(spec.cap, 1) {
			cl.Cap = spec.cap
		}
		res.GateLosses = append(res.GateLosses, cl)
		res.CodeLosses = append(res.CodeLosses, cl)
		total += capped

		agg := gateSevTotals[sev]
		if agg == nil {
			agg = &sevAgg{}
			gateSevTotals[sev] = agg
		}
		agg.count += n
		agg.loss += capped
	}
	for _, sev := range []IssueSeverity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if agg, ok := gateSevTotals[sev]; ok && agg.count > 0 {
			res.Losses = append(res.Losses, SeverityLoss{Severity: sev, Count: agg.count, CappedLoss: agg.loss})
		}
	}

	res.HygieneCount = count(hygiene)
	res.HygieneLoss = math.Min(dampened(hygieneWeight, res.HygieneCount), hygieneCap)
	total += res.HygieneLoss

	res.RawPointsUnclamped = 100 - total
	res.RawPoints = math.Max(0, res.RawPointsUnclamped)
	res.FinalPoints = res.RawPoints
	if res.CriticalPaths > 0 {
		res.CriticalMalusApplied = true
		res.CriticalMalusMax = criticalPathCap
		res.FinalPoints = math.Min(res.FinalPoints, criticalPathCap)
	}
	res.Score = ScoreLetterFromPoints(res.FinalPoints)
	res.Counts = v4Counts(in)
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
// whose surviving reach secrets name the finding's Data["variableName"].
func pathsReachingVariable(f opaengine.Finding, paths []AttackPath) []AttackPath {
	name, _ := f.Data["variableName"].(string)
	if name == "" {
		return nil
	}
	var out []AttackPath
	for _, p := range paths {
		if slices.Contains(p.Reach.Secrets, name) {
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
// two can never disagree), and Low for everything else left (hygiene,
// privilege off any path, an entry finding that anchored no path). An
// anchor is counted exactly once through its strongest path's tier, never
// again on its own: that exclusion (not a general "already consumed" one)
// is what keeps this in agreement with ContextualSeverity, which reads the
// same anchor/gate distinction.
func v4Counts(in ScoreInputV4) SeverityCounts {
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
		if !seen[p.AnchorHash] {
			seen[p.AnchorHash] = true
			anchorOrder = append(anchorOrder, p.AnchorHash)
		}
		if cur, ok := strongest[p.AnchorHash]; !ok || TierRank(p.Tier) > TierRank(cur) {
			strongest[p.AnchorHash] = p.Tier
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
		hash, deduped := findingHash(f)
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
		switch {
		case RoleForCode(ErrorCode(f.Code)) == RoleGate:
			bump(SeverityForCode(ErrorCode(f.Code)))
		default:
			if walked := privilegeWalkedPaths(f, in.Paths); len(walked) > 0 {
				bump(IssueSeverity(strongestPath(walked).Tier))
			} else {
				bump(SeverityLow)
			}
		}
	}
	return c
}
