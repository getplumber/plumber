package control

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// maxSentenceLen bounds every path explanation (spec section 3: a platform
// push cap and a terminal width budget at once).
const maxSentenceLen = 500

// maxCodeRunes bounds one name rendered in backticks.
const maxCodeRunes = 200

// code renders a name as a code span. The name is read off the workflow,
// and on a merge-request pipeline the workflow is the author's own text, so
// it can never break out of its span: every backtick and control character
// (a newline, a carriage return) becomes a space, the runs collapse, and
// the result is cut at maxCodeRunes on a rune boundary, marked "...".
func code(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '`' || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > maxCodeRunes {
		s = string([]rune(s)[:maxCodeRunes-3]) + "..."
	}
	return "`" + s + "`"
}

// codeList renders each name as its own code span, comma-separated.
func codeList(items []string) string {
	spans := make([]string, len(items))
	for i, s := range items {
		spans[i] = code(s)
	}
	return strings.Join(spans, ", ")
}

// entryClause renders how an attacker reaches this path's entry job, from
// the entry fact's own evidence (spec section 3). Every slot here is a
// name already visible in the workflow text (a job, a ref, an expression),
// never a secret or a settings value.
func entryClause(p AttackPath) string {
	job := code(p.Jobs[0])
	switch p.EntryKind {
	case EntryForkPR:
		return "A fork pull request can start " + job
	case EntryPRTarget:
		return fmt.Sprintf("A pull request from anyone runs inside %s with the base repository's privileges (%s)", job, code(p.Entry.Evidence))
	case EntryUntrustedExpression:
		return fmt.Sprintf("Anyone who can open a pull request or push a commit controls %s, which %s passes to a shell", code(p.Entry.Subject), job)
	case EntryMutableDependency:
		return fmt.Sprintf("A new version of %s runs inside %s without any change in this repository", code(p.Entry.Subject), job)
	case EntryUnprotectedPush:
		return fmt.Sprintf("Anyone who can push to %s runs %s", code(p.Entry.Subject), job)
	}
	return "An attacker can reach " + job
}

// foldList renders at most three names and folds the rest into a count.
// The names are already public: they are read straight off the workflow or
// the project's settings (a secret or token name, never its value).
func foldList(items []string) string {
	if len(items) <= 3 {
		return codeList(items)
	}
	return fmt.Sprintf("%s and %d more", codeList(items[:3]), len(items)-3)
}

// impactClause names what the path's impact facts let the attacker do, one
// clause per kind present, in the fixed order the spec lists them.
func impactClause(impacts []ImpactFact) string {
	kinds := map[string]ImpactFact{}
	for _, i := range impacts {
		if _, ok := kinds[i.Kind]; !ok {
			kinds[i.Kind] = i
		}
	}
	var parts []string
	for _, k := range []string{"publishes", "deploys", "writes_repo", "signs_or_releases"} {
		i, ok := kinds[k]
		if !ok {
			continue
		}
		switch k {
		case "publishes":
			parts = append(parts, "publishes the package")
		case "deploys":
			if env := strings.TrimPrefix(i.Evidence, "environment: "); env != i.Evidence {
				parts = append(parts, "deploys to "+code(env))
			} else {
				parts = append(parts, "deploys")
			}
		case "writes_repo":
			parts = append(parts, "pushes to the repository")
		case "signs_or_releases":
			parts = append(parts, "signs or publishes releases")
		}
	}
	return strings.Join(parts, " and ")
}

// reachClause names what the attacker holds once inside the path: the
// secrets and the token write scopes, rendered in the order the assembler
// already sorted them (sortedKeys, never re-sorted here), then the impact
// the walked jobs can cause.
func reachClause(r Reach) string {
	var hold string
	switch {
	case len(r.Secrets) > 0 && len(r.TokenWrite) > 0:
		hold = fmt.Sprintf("holding %s and a token with %s write", foldList(r.Secrets), codeList(r.TokenWrite))
	case len(r.Secrets) > 0:
		hold = "holding " + foldList(r.Secrets)
	case len(r.TokenWrite) > 0:
		hold = fmt.Sprintf("holding a token with %s write", codeList(r.TokenWrite))
	default:
		hold = "but it holds no secret and cannot write anything"
	}
	if imp := impactClause(r.Impacts); imp != "" {
		hold += ", and it " + imp
	}
	return hold
}

// consequence is the path's tier read out loud.
func consequence(t PathTier) string {
	switch t {
	case TierCritical:
		return "a compromise here ships a malicious release to your users or into production"
	case TierHigh:
		return "the secrets can be read and reused elsewhere"
	case TierMedium:
		return "the runner can be abused and anything it caches or uploads can be poisoned"
	}
	return "no exploitable reach was found"
}

// modifierSentences renders each of the path's modifiers as its own
// trailing sentence, in Modifiers order (the order AssemblePaths built
// them in).
func modifierSentences(p AttackPath) []string {
	var out []string
	for _, m := range p.Modifiers {
		switch {
		case m == "private_exposure":
			out = append(out, "The repository is private, so this entry needs an account with access.")
		case m == "unresolvable":
			out = append(out, unresolvableSentence(p))
		case strings.HasPrefix(m, "gate:"):
			gateCode := strings.TrimPrefix(m, "gate:")
			title := gateCode
			if info := LookupCode(ErrorCode(gateCode)); info != nil {
				title = info.Title
			}
			leadIn := "A protection is missing on this job"
			if ErrorCode(gateCode) == CodeBranchUnprotected || ErrorCode(gateCode) == CodeBranchNonCompliant {
				leadIn = "Nothing stands between this and the default branch"
			}
			out = append(out, fmt.Sprintf("%s: %s.", leadIn, title))
		}
	}
	return out
}

// unresolvableEvidence names the fact on the path that is itself the
// unresolvable one, for the "unresolvable" modifier sentence: the entry
// fact's own evidence, or an unresolvable impact fact's evidence. Empty
// when neither is itself unresolvable, which means the real cause is the
// job's SecretsState or a bare default token (unresolvableSentence picks
// between those from the path's own cause).
func unresolvableEvidence(p AttackPath) string {
	if p.Entry.State == "unresolvable" {
		return p.Entry.Evidence
	}
	for _, i := range p.Reach.Impacts {
		if i.State == "unresolvable" {
			return i.Evidence
		}
	}
	return ""
}

// unresolvableSentence renders the "unresolvable" modifier's trailing
// sentence: an unresolvable entry or impact fact's own evidence, quoted as
// a name, as today; "the secrets in scope", quoted the same way, for an
// unresolvable SecretsState, as today; or, for a bare default token with
// nothing else on the path to go on, a plain-language sentence naming the
// real cause rather than quoting a secret that does not exist.
func unresolvableSentence(p AttackPath) string {
	if ev := unresolvableEvidence(p); ev != "" {
		return fmt.Sprintf("Plumber could not verify %s, so this path is unverified.", code(ev))
	}
	if p.cause == unresolvableDefaultToken {
		return "Plumber could not verify that `GITHUB_TOKEN` is really writable (no `permissions` block), so this path is unverified."
	}
	return fmt.Sprintf("Plumber could not verify %s, so this path is unverified.", code("the secrets in scope"))
}

// PathSentence renders one attack path as a single plain-language sentence
// built from its own evidence (spec section 3): entry clause, reach
// clause and consequence joined into one sentence, then one trailing
// sentence per modifier, the whole thing capped at maxSentenceLen on a
// word boundary. A path with no job (should not happen once AssemblePaths
// has run) renders as the empty string rather than panic on Jobs[0].
func PathSentence(p AttackPath) string {
	if len(p.Jobs) == 0 {
		return ""
	}
	// The consequence clause follows BaseTier, what the attacker actually
	// reaches, never the amplified or lowered Tier; a gate or an
	// unresolvable modifier gets its own trailing sentence instead (below),
	// so the consequence clause itself never claims a reach the path does
	// not have.
	s := entryClause(p) + ", " + reachClause(p.Reach) + ": " + consequence(p.BaseTier) + "."
	for _, m := range modifierSentences(p) {
		s += " " + m
	}
	return truncateWords(s, maxSentenceLen)
}

// truncateWords cuts s to at most n bytes on a word boundary, marking the
// cut with an ellipsis. A string already within the bound comes back
// unchanged. The cut point never lands inside a multi-byte UTF-8 sequence:
// n-3 can fall mid-rune (a run of multi-byte characters, say), and slicing
// there would produce invalid UTF-8, so the boundary backs up to the start
// of whatever rune it landed inside first.
func truncateWords(s string, n int) string {
	if len(s) <= n {
		return s
	}
	limit := n - 3
	if limit < 0 {
		limit = 0
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	cut := strings.LastIndex(s[:limit], " ")
	if cut <= 0 {
		cut = limit
	}
	return s[:cut] + "..."
}

// pathsFor splits paths into the ones the finding anchors and the ones it
// gates, keyed by the same hash the assembler used for AnchorHash and
// GateHashes: always findingAnchorHash, never identity.PlatformHash
// directly, so this and AssemblePaths never disagree on which hash
// belongs to this finding. A codeless finding hashes to nothing and so
// anchors and gates nothing.
func pathsFor(f opaengine.Finding, paths []AttackPath) (anchored []AttackPath, gated []AttackPath) {
	h, ok := findingAnchorHash(f)
	if !ok {
		return nil, nil
	}
	for _, p := range paths {
		if p.AnchorHash == h {
			anchored = append(anchored, p)
		}
		for _, g := range p.GateHashes {
			if g == h {
				gated = append(gated, p)
			}
		}
	}
	return anchored, gated
}

// FindingLine says what role the finding plays in the score (spec section
// 3): the path it anchors or amplifies when it is on one, the strongest
// path a privilege-role finding is walked on (spec section 2, Findings on
// no path: on a walked job, not on no path), else its registered role
// read out loud.
func FindingLine(f opaengine.Finding, paths []AttackPath) string {
	anchored, gated := pathsFor(f, paths)
	switch {
	case len(anchored) > 0:
		return "Entry of path " + anchored[0].ID
	case len(gated) > 0:
		return "Gate: amplifies path " + gated[0].ID
	}
	if walked := privilegeWalkedPaths(f, paths); len(walked) > 0 {
		// strongestPath, not walked[0]: privilegeWalkedPaths returns
		// its matches in the caller's own path order, so picking the first
		// entry would make the line (and ContextualSeverity below) depend
		// on an order neither this function nor its caller is required to
		// sort first.
		return "Privilege: on path " + strongestPath(walked).ID
	}
	switch RoleForCode(ErrorCode(f.Code)) {
	case RoleGate:
		return "Gate: no path to amplify today"
	case RolePrivilege:
		return "Privilege: on no attack path"
	case RoleEntry:
		return "Entry: no attack path found from here"
	}
	return "Hygiene: on no attack path"
}

// RoleOnPath is FindingLine relative to ONE path, for a renderer listing a
// finding under every path it belongs to: "Entry of path <id>" only under
// the path the finding anchors, "Gate: amplifies path <id>" under a path it
// amplifies, "Privilege: on path <id>" under a path it rides as a privilege
// finding. A finding on none of those terms with p reads its registered
// role, as FindingLine does for a finding on no path at all.
func RoleOnPath(f opaengine.Finding, p AttackPath) string {
	anchored, gated := pathsFor(f, []AttackPath{p})
	switch {
	case len(anchored) > 0:
		return "Entry of path " + p.ID
	case len(gated) > 0:
		return "Gate: amplifies path " + p.ID
	case len(privilegeWalkedPaths(f, []AttackPath{p})) > 0:
		return "Privilege: on path " + p.ID
	}
	return FindingLine(f, nil)
}

// ContextualSeverity is what the run shows for the finding: its strongest
// path's tier when it anchors one or more, the strongest walked path's
// tier for a privilege-role finding on one (spec section 2, Findings on no
// path; strongestPath, the same selection FindingLine and v4Counts use,
// so the three can never disagree), its registered severity when it is a
// gate finding on no path, Low otherwise.
func ContextualSeverity(f opaengine.Finding, paths []AttackPath) IssueSeverity {
	anchored, _ := pathsFor(f, paths)
	if len(anchored) > 0 {
		sort.Slice(anchored, func(i, j int) bool { return TierRank(anchored[i].Tier) > TierRank(anchored[j].Tier) })
		return IssueSeverity(anchored[0].Tier)
	}
	if walked := privilegeWalkedPaths(f, paths); len(walked) > 0 {
		return IssueSeverity(strongestPath(walked).Tier)
	}
	if RoleForCode(ErrorCode(f.Code)) == RoleGate {
		return SeverityForCode(ErrorCode(f.Code))
	}
	return SeverityLow
}

// PathIDsFor lists every path id a finding is associated with (spec
// section 3's "pathIds" slot, read by the terminal and JSON outputs):
// anchored first, then gated, then privilege-on-path (spec section 2,
// Findings on no path), in path order, deduplicated.
func PathIDsFor(f opaengine.Finding, paths []AttackPath) []string {
	anchored, gated := pathsFor(f, paths)
	walked := privilegeWalkedPaths(f, paths)
	seen := map[string]bool{}
	var out []string
	add := func(ps []AttackPath) {
		for _, p := range ps {
			if seen[p.ID] {
				continue
			}
			seen[p.ID] = true
			out = append(out, p.ID)
		}
	}
	add(anchored)
	add(gated)
	add(walked)
	return out
}

// plural renders n with the singular word when n == 1, the plural word
// otherwise.
func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// SituationParagraph is the plain-language summary ScoreV4WithExplanations
// attaches to a scoring-v4 result: exposure and pipeline shape, the
// assembled paths by tier (or none), and the best fix (or "Nothing to
// fix."). Every slot renders a name or a count, never an evidence value.
func SituationParagraph(sit *Situation, pipeline *ir.NormalizedPipeline, score PlumberScoreResult) string {
	exposure := map[string]string{
		ir.VisibilityPublic:  "Public repository",
		ir.VisibilityPrivate: "Private repository",
	}[sit.Exposure]
	if exposure == "" {
		exposure = "Repository of unknown visibility (treated as public)"
	}
	workflows := map[string]bool{}
	for _, j := range pipeline.Jobs {
		workflows[j.WorkflowName] = true
	}
	unit := "workflow"
	if pipeline.Provider == ir.ProviderGitLab {
		unit = "pipeline"
	}
	impacting := 0
	for _, js := range sit.Jobs {
		if len(js.Impact) > 0 {
			impacting++
		}
	}
	first := fmt.Sprintf("%s, %s in %s", exposure, plural(len(pipeline.Jobs), "job", "jobs"), plural(len(workflows), unit, unit+"s"))
	if impacting > 0 {
		verb := "publishes or deploys"
		if impacting > 1 {
			verb = "publish or deploy"
		}
		first += fmt.Sprintf(", %d %s", impacting, verb)
	}
	first += "."

	var tiers [4]int
	for _, p := range score.Paths {
		tiers[4-TierRank(p.Tier)]++
	}
	second := "No attack path found"
	if n := len(score.Paths); n > 0 {
		second = fmt.Sprintf("%s: %d critical, %d high, %d medium, %d low", plural(n, "attack path", "attack paths"), tiers[0], tiers[1], tiers[2], tiers[3])
	}
	// "protections missing" counts every distinct GATE FINDING, whether it
	// amplifies a path (consumed: counted once per GateHashes entry across
	// every path, deduplicated, since one gate can amplify more than one
	// path) or sits lone (counted once per CodeLoss's Count, the distinct
	// identities ComputePlumberScoreV4 priced per code): never just the
	// lone ones grouped by code, which silently dropped every amplifying
	// gate from the count.
	amplifying := map[string]bool{}
	for _, p := range score.Paths {
		for _, h := range p.GateHashes {
			amplifying[h] = true
		}
	}
	lone := 0
	for _, cl := range score.GateLosses {
		lone += cl.Count
	}
	var extras []string
	if protections := len(amplifying) + lone; protections > 0 {
		extras = append(extras, plural(protections, "protection missing", "protections missing"))
	}
	if score.HygieneCount > 0 {
		extras = append(extras, plural(score.HygieneCount, "hygiene finding", "hygiene findings"))
	}
	if len(extras) > 0 {
		second += "; " + strings.Join(extras, ", ")
	}
	second += "."

	third := "Nothing to fix."
	if score.BestFix != nil {
		third = score.BestFix.Sentence
	}
	return first + " " + second + " " + third
}

// BestFix is the single highest-value fix ComputeBestFix found among a
// run's non-dismissed findings: dismissing it (and every finding sharing
// its identity) recovers the most FinalPoints of any candidate.
type BestFix struct {
	AnchorHash   string    `json:"anchorHash"`
	Code         ErrorCode `json:"code"`
	Job          string    `json:"job,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	PointsGained float64   `json:"pointsGained"`
	NewLetter    string    `json:"newLetter"`
	Sentence     string    `json:"sentence"`
}

// bestFixSubjectKeys are the structured-data fields that name a finding's
// subject without ever carrying a secret or settings value: the exact key
// list and order subjectMatches (paths.go) reads, includePath included,
// so a job-less include finding (ISSUE-404) names its include path
// instead of falling through to an empty subject.
var bestFixSubjectKeys = []string{"uses", "image", "expression", "variableName", "branchName", "url", "includePath"}

// isCostlyCandidate reports whether f currently costs something on its
// own: an anchor of one of paths, or any gate-role finding, amplifying or
// lone. A gate always qualifies regardless of paths, since dismissing it
// can lower a path it amplifies even though the gate itself may price at
// zero once consumed.
func isCostlyCandidate(f opaengine.Finding, paths []AttackPath) bool {
	if RoleForCode(ErrorCode(f.Code)) == RoleGate {
		return true
	}
	anchored, _ := pathsFor(f, paths)
	return len(anchored) > 0
}

// runHasAnchorOrGate reports whether the run has at least one assembled
// path (which can only exist because something anchored it) or at least
// one non-dismissed gate finding, anywhere, not only among the findings a
// particular candidate check is looking at. ComputeBestFix reads this
// once per call: only when it is false do hygiene and consumed-privilege
// findings become candidates at all, since they are then the only things
// left that could possibly gain points.
func runHasAnchorOrGate(in ScoreInputV4) bool {
	if len(in.Paths) > 0 {
		return true
	}
	for _, f := range in.Findings {
		if !f.Dismissed && RoleForCode(ErrorCode(f.Code)) == RoleGate {
			return true
		}
	}
	return false
}

// bestFixWins reports whether a candidate (gain, code, hash) beats
// whatever ComputeBestFix has kept as best so far: the largest gain
// (within a 1e-9 tolerance, so two logically equal gains that differ only
// in their last float bit never pick a winner by accident), then the
// lower code string, then the lower anchor hash. Comparing the running
// candidate against the current best this way, for every candidate in
// whatever order the caller's findings happen to be in, always settles on
// the same (code, hash) pair for the largest gain found: a strict total
// order over (gain bucket, code, hash) picks the same minimum element
// regardless of visit order.
func bestFixWins(gain float64, fcode, hash string, best *BestFix) bool {
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

// ComputeBestFix re-scores the run once per distinct non-dismissed
// candidate finding identity (an anchor of a path, or any gate finding,
// amplifying or lone; a hygiene or consumed-privilege finding is a
// candidate only when the run has no anchor and no gate at all, since
// those are then the only things that could possibly gain points) with
// that identity dismissed, and keeps the trial that recovers the most
// FinalPoints: ties go to the lower code string, then the lower anchor
// hash (bestFixWins), so the result never depends on the input order.
// Every finding sharing the candidate's hash is dismissed in the trial,
// not only the first one found, so a duplicate finding under the same
// identity cannot keep the loss alive behind the trial's back. A gain
// that rounds to 0.0 is not a gain. nil when no candidate gains anything.
//
// Every finding's hash is computed once, up front, rather than re-hashed
// per candidate trial: hashing is the dominant cost once the candidate
// pool is restricted to anchors and gates, which on a run of a few
// thousand findings (the CLI's practical ceiling) is normally a handful,
// not the whole set.
func ComputeBestFix(in ScoreInputV4, sit *Situation, current PlumberScoreResult) *BestFix {
	hashes := make([]string, len(in.Findings))
	oks := make([]bool, len(in.Findings))
	for i, f := range in.Findings {
		hashes[i], oks[i] = findingAnchorHash(f)
	}
	restrict := runHasAnchorOrGate(in)

	var best *BestFix
	seen := map[string]bool{}
	for i, f := range in.Findings {
		if f.Dismissed {
			continue
		}
		h, ok := hashes[i], oks[i]
		if !ok || seen[h] {
			continue
		}
		seen[h] = true
		if restrict && !isCostlyCandidate(f, in.Paths) {
			continue // nothing else to fix, so this finding is skipped
		}

		trial := make([]opaengine.Finding, len(in.Findings))
		copy(trial, in.Findings)
		for j := range trial {
			if oks[j] && hashes[j] == h {
				trial[j].Dismissed = true
			}
		}
		paths := AssemblePaths(trial, sit)
		s := ComputePlumberScoreV4(ScoreInputV4{Findings: trial, Paths: paths})
		gain := s.FinalPoints - current.FinalPoints
		if gain <= 1e-9 {
			continue
		}
		if rounded := math.Round(gain*10) / 10; rounded <= 0 {
			continue // a gain that rounds to 0.0 is not a gain
		}
		if !bestFixWins(gain, f.Code, h, best) {
			continue
		}

		subject := f.Job
		for _, key := range bestFixSubjectKeys {
			if v, ok := f.Data[key].(string); ok && v != "" {
				subject = v
				break
			}
		}
		title := f.Code
		if info := LookupCode(ErrorCode(f.Code)); info != nil {
			title = info.Title
		}
		best = &BestFix{
			AnchorHash:   h,
			Code:         ErrorCode(f.Code),
			Job:          f.Job,
			Subject:      subject,
			PointsGained: gain,
			NewLetter:    s.Score,
			Sentence:     bestFixSentence(title, subject, gain, current.Score, s.Score),
		}
	}
	return best
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
	result.Paths = AssemblePaths(result.Findings, sit)
	in := ScoreInputV4{Findings: result.Findings, Paths: result.Paths}
	s := ComputePlumberScoreV4(in)
	s.BestFix = ComputeBestFix(in, sit, s)

	pipeline := result.Pipeline
	if pipeline == nil {
		pipeline = result.GitHubPipeline
	}
	if pipeline == nil {
		pipeline = &ir.NormalizedPipeline{}
	}
	s.Situation = SituationParagraph(sit, pipeline, s)
	return s
}
