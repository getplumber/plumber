package control

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// pathsFor splits paths into the ones the finding anchors (its hash is one
// of the path's AnchorHashes) and the ones it gates, keyed by the same hash
// the assembler used for AnchorHashes and GateHashes: always findingAnchorHash, never identity.PlatformHash
// directly, so this and AssemblePaths never disagree on which hash
// belongs to this finding. A codeless finding hashes to nothing and so
// anchors and gates nothing.
func pathsFor(f opaengine.Finding, paths []AttackPath) (anchored []AttackPath, gated []AttackPath) {
	h, ok := findingAnchorHash(f)
	if !ok {
		return nil, nil
	}
	for _, p := range paths {
		if p.anchoredBy(h) {
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
// so the three can never disagree), its individual severity otherwise
// (IndividualSeverity, read against the pipeline's default branch): a
// finding on no path is priced at it.
func ContextualSeverity(f opaengine.Finding, paths []AttackPath, defaultBranch string) IssueSeverity {
	anchored, _ := pathsFor(f, paths)
	if len(anchored) > 0 {
		sort.Slice(anchored, func(i, j int) bool { return TierRank(anchored[i].Tier) > TierRank(anchored[j].Tier) })
		return IssueSeverity(anchored[0].Tier)
	}
	if walked := privilegeWalkedPaths(f, paths); len(walked) > 0 {
		return IssueSeverity(strongestPath(walked).Tier)
	}
	return IndividualSeverity(f, defaultBranch)
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

// SituationFact is one labelled line of the situation block that closes
// the report (spec section 3).
type SituationFact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// SituationFacts reads the repository and the pipeline out as labelled
// facts: visibility, the default branch and its protection, and the jobs
// with how many publish or deploy. Every value is a name or a count, never
// an evidence value.
func SituationFacts(sit *Situation, pipeline *ir.NormalizedPipeline) []SituationFact {
	visibility := map[string]string{ir.VisibilityPublic: "public", ir.VisibilityPrivate: "private"}[sit.Exposure]
	if visibility == "" {
		visibility = "unknown visibility, scored as public"
	}
	branch := "unknown"
	if pipeline.DefaultBranch != "" {
		branch = pipeline.DefaultBranch + ", protection unknown"
		for _, b := range pipeline.Branches {
			if b.Name != pipeline.DefaultBranch {
				continue
			}
			branch = pipeline.DefaultBranch + ", not protected"
			if b.Protected {
				branch = pipeline.DefaultBranch + ", protected"
			}
		}
	}
	workflows := map[string]bool{}
	for _, j := range pipeline.Jobs {
		workflows[j.WorkflowName] = true
	}
	label, unit := "Workflows", "workflow"
	if pipeline.Provider == ir.ProviderGitLab {
		label, unit = "Pipeline", "pipeline"
	}
	jobs := fmt.Sprintf("%s in %s", plural(len(pipeline.Jobs), "job", "jobs"), plural(len(workflows), unit, unit+"s"))
	impacting := 0
	for _, js := range sit.Jobs {
		if slices.ContainsFunc(js.Impact, countedImpact) {
			impacting++
		}
	}
	if impacting == 1 {
		jobs += ", 1 publishes or deploys"
	} else if impacting > 1 {
		jobs += fmt.Sprintf(", %d publish or deploy", impacting)
	}
	return []SituationFact{{"Repository", visibility}, {"Default branch", branch}, {label, jobs}}
}

// SituationText is the facts as one line of "Label: value." sentences,
// the form the JSON report and the platform push carry.
func SituationText(facts []SituationFact) string {
	parts := make([]string, len(facts))
	for i, f := range facts {
		parts[i] = f.Label + ": " + f.Value + "."
	}
	return strings.Join(parts, " ")
}

// PathsWorstFirst orders paths the way every report numbers them
// (worseFirst: tier descending, then reach strength, then id), so path 1
// is always the worst. The caller's slice is never reordered.
func PathsWorstFirst(paths []AttackPath) []AttackPath {
	out := append([]AttackPath(nil), paths...)
	sort.SliceStable(out, func(i, j int) bool { return worseFirst(out[i], out[j]) })
	return out
}

// PathBlockFinding is one finding listed under a path block: its code, its
// registry title, and where it is. Count is above 1 when the line folds
// that many privilege findings of one code, and Location is then empty.
type PathBlockFinding struct {
	Code     ErrorCode
	Title    string
	Location string
	Count    int
}

// PathBlock is one attack path read out as a graph (spec section 4), the
// content the terminal and the merge request comment both render
// (PathGraph). Every value is a name already visible in the workflow or
// the settings, never a value.
type PathBlock struct {
	Tier         PathTier
	Unverified   bool
	Loss         float64
	Entry        string // "image docker.io/alpine:latest"
	EntrySubject string // the part of Entry read off the workflow: "docker.io/alpine:latest"
	// Branches is one per entry job of the path, in the path's job order.
	Branches []PathBlockBranch
	// EntryWriter names, for a poisoned cache, the one job whose run can
	// write the cache ("a run of job pr-preview/preview can write the
	// cache"); empty when several can, or for any other entry.
	EntryWriter string
	// EntryUnverified and ReachUnverified say what could not be checked:
	// about the entry, or about what it reaches. Empty when there is
	// nothing to say.
	EntryUnverified string
	RunsIn          string // "job est_file" | "jobs build, deploy": the entry jobs
	ReachesShort    string
	ReachUnverified string
	So              string
	// Cap says, on a path a cap lowered (the push entry cap, the
	// dependency cap), why it stops at its tier (Medium or High); empty
	// otherwise. It is how the score was computed, not what the path is,
	// so a graph prints it as a Note only when ShowCap is set, which the
	// renderers set under --score-point.
	Cap     string
	ShowCap bool
	// Environment is what the block says about the environment the path's
	// entry job runs in: its name, then that it requires a review, when it
	// does. A protection, never an impact.
	Environment []string
	Fix         string
	Findings    []PathBlockFinding
}

// environmentReviewNote is the Note of an environment that requires a
// review before the job runs.
const environmentReviewNote = "the environment requires a review before the job runs"

// NewPathBlock reads p out as a block; findings supply the anchoring and
// amplifying findings listed under it (nil lists none).
func NewPathBlock(p AttackPath, findings []opaengine.Finding) PathBlock {
	subject := entryLineSubject(p)
	entry := entryNature(p)
	if subject != "" {
		entry = subject + " (" + entry + ")"
	}
	b := PathBlock{
		Tier:         p.Tier,
		Unverified:   p.State == PathUnverified,
		Loss:         p.Loss,
		Entry:        entry,
		EntrySubject: subject,
		Branches:     blockBranches(p, findings),
		RunsIn:       runsIn(p.EntryJobs()),
		ReachesShort: reachesShort(p),
		So:           soLine(p),
		Fix:          pathFixOf(p),
		Findings:     pathBlockFindings(p, findings),
	}
	if len(p.Jobs) > 0 && p.situation != nil {
		if name, reviewers, ok := environmentOf(p.situation.Jobs[p.Jobs[0]]); ok {
			b.Environment = append(b.Environment, "the job runs in environment "+code(name))
			if reviewers != "none" && reviewers != "unknown" {
				b.Environment = append(b.Environment, environmentReviewNote)
			}
		}
	}
	if p.EntryKind == EntryPoisonedCache {
		files := jobFiles(p, findings)
		b.EntryWriter = cacheWriterLine(p.cacheWriters, files, onGitHub(files, slices.Concat(p.Jobs, p.cacheWriters)))
	}
	switch {
	case slices.Contains(p.Modifiers, "cache_writer_cap"):
		need := "a dependency compromise"
		if slices.Contains(p.Modifiers, "push_entry_cap") {
			need = "write access"
		}
		b.Cap = "Capped at " + tierTitle(p.Tier) + ": the jobs that can write the cache need " + need + " first"
	case slices.Contains(p.Modifiers, "push_entry_cap"):
		b.Cap = "Capped at High: it needs write access first"
	case slices.Contains(p.Modifiers, "source_cap"):
		b.Cap = "Capped at High: the source is not authorized, so a compromise is more likely"
	case slices.Contains(p.Modifiers, "dependency_cap"):
		b.Cap = "Capped at " + tierTitle(p.Tier) + ": it needs a dependency compromise first"
	}
	// The lines read the branch the path holds its tier from.
	if p.State == PathUnverified || slices.Contains(p.Modifiers, "unresolvable") {
		b.EntryUnverified, b.ReachUnverified = unverifiedLines(p)
	}
	if assumedTokenOnProvenPath(p) {
		b.ReachUnverified = defaultTokenUnchecked
	}
	if b.ReachUnverified == "" && assumesToken(p) {
		b.ReachUnverified = defaultTokenUnchecked
	}
	if b.ReachUnverified == "" && p.cause == unresolvableSecrets {
		b.ReachUnverified = secretsUnlisted
	}
	return b
}

// cacheWriterLine names the jobs whose run can write a poisoned cache the
// way a branch names its job (jobPhrase), the first three, grouped by the
// workflow they are in, then a count of the rest; "" with none.
func cacheWriterLine(writers []string, files map[string]string, github bool) string {
	if len(writers) == 0 {
		return ""
	}
	if len(writers) == 1 {
		return "a run of " + jobPhrase(writers[0], files, github) + " can write the cache"
	}
	shown := writers[:min(len(writers), 3)]
	type group struct {
		workflow string
		jobs     []string
	}
	var groups []*group
	for _, w := range shown {
		id, workflow := jobAndWorkflow(w, files, github)
		if len(groups) == 0 || groups[len(groups)-1].workflow != workflow {
			groups = append(groups, &group{workflow: workflow})
		}
		g := groups[len(groups)-1]
		g.jobs = append(g.jobs, code(id))
	}
	parts := make([]string, len(groups))
	for i, g := range groups {
		parts[i] = joinAnd(g.jobs)
		if g.workflow != "" {
			parts[i] += " from workflow " + code(g.workflow)
		}
	}
	list := joinAnd(parts)
	if rest := len(writers) - len(shown); rest > 0 {
		list = fmt.Sprintf("%s and %d more", strings.Join(parts, ", "), rest)
	}
	return "runs of jobs " + list + " can write the cache"
}

// assumedTokenOnProvenPath reports whether a proven path holds a default
// token whose write is assumed: its tier rests on what else it reaches,
// and it still says the token could not be checked.
func assumedTokenOnProvenPath(p AttackPath) bool {
	return p.State != PathUnverified && p.cause == unresolvableDefaultToken
}

// assumesToken reports whether the reach p reads (its strongest branch's)
// holds a write token that is only the repository default's, assumed: a
// token of one walked job is enough, whatever the others declare.
func assumesToken(p AttackPath) bool {
	return slices.ContainsFunc(partsOf(p.Reach), func(part reachPart) bool { return part.assumed })
}

// WorstCase is what attack path 1, the worst (PathsWorstFirst), means:
// "<who gets in>, an attacker can <capability> (attack path 1:
// <subject>)", the block's own So words and the subject of its Entry
// line; "" with no path.
func WorstCase(paths []AttackPath) string {
	if len(paths) == 0 {
		return ""
	}
	b := NewPathBlock(PathsWorstFirst(paths)[0], nil)
	if b.EntrySubject == "" {
		return b.So + " (attack path 1)"
	}
	return b.So + " (attack path 1: " + b.EntrySubject + ")"
}

// PathSummary is a path in one line: what its entry is (the block's Entry
// line), where it runs, and what it reaches.
func PathSummary(p AttackPath) string {
	b := NewPathBlock(p, nil)
	return b.Entry + " in " + b.RunsIn + ", reaches " + b.ReachesShort
}

// PathRow is a path as one row of the attack paths table: its entry, the
// jobs it runs in, and what it reaches.
type PathRow struct {
	Entry   string // "docker.io/alpine:latest (mutable image tag)"
	Jobs    string // "build" | "build, deploy"
	Reaches string // "7 secrets; token: write"
}

// PathRowOf reads p out as a table row; the entry is what identifies the
// row, in the words of the block's Entry line (<subject> (<nature>)).
func PathRowOf(p AttackPath) PathRow {
	b := NewPathBlock(p, nil)
	jobs := p.EntryJobs()
	if len(jobs) > 2 {
		jobs = append(jobs[:2:2], fmt.Sprintf("+%d", len(jobs)-2))
	}
	return PathRow{Entry: b.Entry, Jobs: strings.Join(jobs, ", "), Reaches: b.ReachesShort}
}

// pathBlockFindings lists the live findings anchoring p, then the ones
// amplifying it, once each, by code within each part, with their registry
// title and location; then the privilege findings it rides (the rest of
// its FindingIDs), one line per code.
func pathBlockFindings(p AttackPath, findings []opaengine.Finding) []PathBlockFinding {
	byHash := map[string]opaengine.Finding{}
	for _, f := range findings {
		if f.Dismissed {
			continue
		}
		if h, ok := findingAnchorHash(f); ok {
			if _, dup := byHash[h]; !dup {
				byHash[h] = f
			}
		}
	}
	var out []PathBlockFinding
	seen := map[string]bool{}
	// One line per code across the block, however many findings of it the
	// path carries: how many, and the first location in file and line
	// order.
	byCode := map[ErrorCode]int{}
	first := map[ErrorCode]opaengine.Finding{}
	add := func(hashes []string) {
		var part []opaengine.Finding
		for _, h := range hashes {
			if f, ok := byHash[h]; ok && !seen[h] {
				seen[h] = true
				part = append(part, f)
			}
		}
		sort.SliceStable(part, func(i, j int) bool { return part[i].Code < part[j].Code })
		for _, f := range part {
			line := pathBlockFindingOf(f)
			if p.EntryKind == EntryMutableDependency && sameOwner(entrySubject(f), p.ownRepo) {
				line.Title = firstParty(line.Title)
			}
			i, ok := byCode[line.Code]
			if !ok {
				byCode[line.Code], first[line.Code] = len(out), f
				out = append(out, line)
				continue
			}
			out[i].Count = max(out[i].Count, 1) + 1
			if g := first[line.Code]; f.File < g.File || f.File == g.File && f.Line < g.Line {
				first[line.Code] = f
				out[i].Location = line.Location
			}
		}
	}
	add(p.AllAnchorHashes())
	add(p.GateHashes)
	add(p.FindingIDs)
	return out
}

// firstParty is a registry title for a dependency of the repository's own
// owner, which is no third party: "Third-party action reference ..." reads
// "Action reference ...".
func firstParty(title string) string {
	if rest, ok := strings.CutPrefix(title, "Third-party "); ok && rest != "" {
		return strings.ToUpper(rest[:1]) + rest[1:]
	}
	return title
}

// pathBlockFindingOf is one finding's line: its code, its registry title
// and its file:line.
func pathBlockFindingOf(f opaengine.Finding) PathBlockFinding {
	title := f.Code
	if info := LookupCode(ErrorCode(f.Code)); info != nil {
		title = info.Title
	}
	loc := f.File
	if loc != "" && f.Line > 0 {
		loc += ":" + strconv.Itoa(f.Line)
	}
	return PathBlockFinding{Code: ErrorCode(f.Code), Title: title, Location: loc}
}
