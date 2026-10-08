package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/getplumber/plumber/finding/identity"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// PathTier is how severe an attack path is, independent of the state
// (proven/unverified) it was assembled with.
type PathTier string

const (
	TierCritical PathTier = "critical"
	TierHigh     PathTier = "high"
	TierMedium   PathTier = "medium"
	TierLow      PathTier = "low"
)

// PathState says whether every fact on the path is settled (proven), or at
// least one of them could not be decided statically (unverified).
type PathState string

const (
	PathProven     PathState = "proven"
	PathUnverified PathState = "unverified"
)

// unresolvableCause names which fact behind the path's "unresolvable"
// modifier could not be decided statically, when neither the entry fact
// nor an impact fact is itself the unresolvable one: a job's SecretsState,
// or a bare default token with nothing else on the path to go on. Read
// only by explain.go's modifierSentences, which renders a different
// sentence per cause rather than naming a secret that does not exist.
type unresolvableCause string

const (
	unresolvableSecrets      unresolvableCause = "secrets"
	unresolvableDefaultToken unresolvableCause = "default_token"
)

// Reach is what an attacker who walks in through a path's entry can touch:
// the privilege held by the walked jobs, and the impact they can cause.
type Reach struct {
	Secrets []string `json:"secrets"` // names reachable by the attacker, after platform rules
	// AllSecrets is true when a walked job holds every secret of the
	// repository (Privilege.AllSecrets), after platform rules.
	AllSecrets bool         `json:"allSecrets"`
	TokenWrite []string     `json:"tokenWrite"` // write scopes reachable by the attacker, after platform rules
	Impacts    []ImpactFact `json:"impacts"`    // impact facts of the walked jobs, concatenated
	// Executes is true for every path: a push runs the job's own steps, and
	// a job with no script of its own (a bare `uses:` push trigger, for
	// instance) still runs whatever that uses target executes. The field
	// stays (the outputs read it, and a future entry kind may need to turn
	// it off) but under the current entry kinds it is always true.
	Executes bool `json:"executes"`

	// tokenAssumed is set when TokenWrite comes only from jobs with no
	// permissions block (the repository default, an assumption), none
	// declaring a write token. Never serialized.
	tokenAssumed bool
	// parts is what each walked job adds to the reach, in walk order (the
	// entry job first), after the platform rules: the job each item comes
	// from, and whether that job's token is assumed. Never serialized; a
	// reach built by hand has none and reads as one job's.
	parts []reachPart
}

// reachPart is what one walked job holds of a reach: its surviving
// secrets and write scopes, whether its token is the repository default
// (assumed: no permissions block), and the impacts of its steps and of its
// surviving token.
type reachPart struct {
	job        string
	secrets    []string
	allSecrets bool
	scopes     []string
	assumed    bool
	impacts    []ImpactFact
}

// AttackPath is one way a finding's entry fact can be walked to privilege or
// impact (spec section 2): the anchoring finding, the jobs walked to compute
// Reach, and the tier/state/modifiers the assembly rules derived from it.
type AttackPath struct {
	ID         string    `json:"id"`
	Tier       PathTier  `json:"tier"`
	BaseTier   PathTier  `json:"baseTier"`
	State      PathState `json:"state"`
	EntryKind  EntryKind `json:"entryKind"`
	Entry      EntryFact `json:"entry"`
	AnchorHash string    `json:"anchorHash"` // the first of AnchorHashes
	AnchorCode ErrorCode `json:"anchorCode"` // the first known-bad code of AnchorCodes, else the first entry-role one
	// AnchorHashes is every anchoring finding (identity.PlatformHash),
	// sorted: findings sharing the path's entry kind and entry subject are
	// one attack, whichever job they enter, so they anchor one path
	// together, and a finding of subjectFindingCodes on that subject and
	// an entry job joins them. AnchorCodes is their codes, sorted and
	// deduplicated.
	AnchorHashes []string    `json:"anchorHashes"`
	AnchorCodes  []ErrorCode `json:"anchorCodes"`
	Jobs         []string    `json:"jobs"` // the entry jobs, strongest branch first, then the jobs they feed
	Reach        Reach       `json:"reach"`
	ReachKind    string      `json:"reachKind"`  // the first of ReachKinds: "impact:<kind>" | "secrets" | "token" | "execution" | "none"
	ReachKinds   []string    `json:"reachKinds"` // every reach kind of Reach, strongest first
	Modifiers    []string    `json:"modifiers"`  // "private_exposure", "unresolvable", "gate:<code>", "push_entry_cap", "dependency_cap", "source_cap"
	GateHashes   []string    `json:"gateHashes"` // findings that amplified this path
	Exposure     string      `json:"exposure"`
	// Branches is one per entry job, in Jobs order: the walk from that job,
	// what it reaches, and the tier, state and modifiers it gives on its
	// own. The path takes its tier, modifiers and reach from the first.
	Branches []PathBranch `json:"branches"`

	// Sentence, FindingIDs and Loss are the report fields spec section 4
	// lists, filled by ScoreV4WithExplanations once the path is priced
	// (AssemblePaths leaves them empty): the path's plain-language
	// sentence; the anchor's hash, then the gates', then the consumed
	// privilege findings'; and the price of the path's tier, what the
	// path costs before the nested cap (pathLosses carries what it keeps).
	Sentence   string   `json:"sentence"`
	FindingIDs []string `json:"findingIds"`
	Loss       float64  `json:"loss"`

	// cause names the fact on the path that could not be decided when
	// neither the entry fact nor an impact fact is itself the unresolvable
	// one, so explain.go's modifierSentences can name the real cause. It is
	// set for secrets that could not be listed even when a proven privilege
	// keeps the path off the "unresolvable" modifier, so the path still
	// says so. Never serialized, never read outside this package.
	cause unresolvableCause

	// survivingJobs is the subset of Jobs whose privilege the platform
	// pruning rules (applyPlatformReachRules, via survivingPrivilegeJobs)
	// did not drop entirely: a GitHub fork pull_request run's own entry
	// job loses its privilege outright, and so does a fed job carrying
	// its own fork_pr fact. A privilege-role finding "on path" only counts
	// when its Job is in THIS set, not merely in Jobs, or a finding on a
	// job the platform rules already stripped would wrongly ride the
	// path's tier. Never serialized, never read outside this package.
	survivingJobs []string

	// gateBranches is the branch each branch-protection gate on Modifiers
	// is about (gate code to Data["branchName"]), so explain.go's gate
	// sentence can name it. Never serialized, never read outside this
	// package.
	gateBranches map[string]string

	// cacheWriters is, on a poisoned_cache path, the jobs whose run can
	// write the cache (keepCachePathsSomeoneCanWrite), so explain.go can
	// name one. Never serialized, never read outside this package.
	cacheWriters []string

	// ownRepo is the analysed repository's "owner/repo", lower case, empty
	// when unknown: an action of its owner is never read out as a third
	// party's. Never serialized.
	ownRepo string

	// insider is set on an untrusted_expression path whose expression only
	// someone with write access sets (insiderController): its entry
	// sentence names who, and it holds at High like a push entry. Never
	// serialized.
	insider bool

	// alternatives is every subject the entry stands for when one finding
	// identity covers several (the values of a matrix), sorted; nil for
	// one. Never serialized.
	alternatives []string

	// situation is the situation the path was assembled from, for what the
	// block reads off the entry job's facts (its environment). Never
	// serialized; nil on a path built by hand.
	situation *Situation

	// ceiling is the highest tier the path's entry lets it hold (the push
	// entry and dependency ceilings), Critical when none holds it, and
	// ceilingModifiers the modifiers that ceiling sets when it lowers a
	// path: what a cache its entry job writes inherits (cacheWriters).
	// Never serialized.
	ceiling          PathTier
	ceilingModifiers []string
}

// MarshalJSON writes modifiers, gateHashes, findingIds, anchorHashes and
// anchorCodes as arrays, empty
// when the path has none, never null: the JSON report is a public contract,
// and a consumer iterating a path's modifiers must not have to null-check
// them.
func (p AttackPath) MarshalJSON() ([]byte, error) {
	type wire AttackPath // no methods: marshals with the field tags above
	w := wire(p)
	if w.Modifiers == nil {
		w.Modifiers = []string{}
	}
	if w.GateHashes == nil {
		w.GateHashes = []string{}
	}
	if w.FindingIDs == nil {
		w.FindingIDs = []string{}
	}
	if w.AnchorHashes == nil {
		w.AnchorHashes = []string{}
	}
	if w.AnchorCodes == nil {
		w.AnchorCodes = []ErrorCode{}
	}
	if w.ReachKinds == nil {
		w.ReachKinds = []string{}
	}
	if w.Branches == nil {
		w.Branches = []PathBranch{}
	}
	return json.Marshal(w)
}

// PathBranch is one entry job of a path: the jobs walked from it (the
// entry job, then the jobs it feeds), what an attacker there reaches, and
// the tier, state and modifiers that reach gives once the tier rules
// applied. A job's attacker code never gets what another entry job holds,
// so each branch is priced on its own reach.
type PathBranch struct {
	Job       string    `json:"job"`
	Jobs      []string  `json:"jobs"`
	Reach     Reach     `json:"reach"`
	Tier      PathTier  `json:"tier"`
	State     PathState `json:"state"`
	Modifiers []string  `json:"modifiers"`
	// FeedsVia is, per job of Jobs the entry job feeds, the kinds of edge
	// that link them (JobSituation.FeedsVia); absent when it feeds none.
	FeedsVia map[string][]string `json:"feedsVia,omitempty"`

	// cause is the branch's own unresolvableCause, for the report lines
	// that say what could not be checked; survivingJobs is the branch's
	// own surviving-privilege job set (AttackPath.survivingJobs). Never
	// serialized.
	cause         unresolvableCause
	survivingJobs []string
	// ceiling and ceilingModifiers are the branch's own
	// (AttackPath.ceiling). Never serialized.
	ceiling          PathTier
	ceilingModifiers []string
	// triggers is the entry job's privileged triggers, then schedule when
	// it runs on one: the events the report names on the branch line.
	// Never serialized.
	triggers []string
}

// shownTriggers is the events a branch line names for its entry job: the
// privileged triggers, then schedule.
func shownTriggers(js JobSituation) []string {
	out := append([]string(nil), js.PrivilegedTriggers...)
	if slices.Contains(js.RefTriggers, "schedule") {
		out = append(out, "schedule")
	}
	return out
}

// MarshalJSON writes jobs and modifiers as arrays, never null.
func (b PathBranch) MarshalJSON() ([]byte, error) {
	type wire PathBranch
	w := wire(b)
	if w.Jobs == nil {
		w.Jobs = []string{}
	}
	if w.Modifiers == nil {
		w.Modifiers = []string{}
	}
	return json.Marshal(w)
}

var tierOrder = []PathTier{TierLow, TierMedium, TierHigh, TierCritical}

// TierRank orders tiers: low 1 .. critical 4. An unknown tier ranks 0, below
// every declared tier, so a caller comparing against a real tier never
// mistakes an unrecognized value for a match.
func TierRank(t PathTier) int {
	for i, x := range tierOrder {
		if x == t {
			return i + 1
		}
	}
	return 0
}

// tierShift moves a tier by delta steps (negative lowers it), clamped to
// [Low, Critical].
func tierShift(t PathTier, delta int) PathTier {
	i := TierRank(t) - 1 + delta
	if i < 0 {
		i = 0
	}
	if i > len(tierOrder)-1 {
		i = len(tierOrder) - 1
	}
	return tierOrder[i]
}

// contributorEntry reports whether an entry of kind into js is one anyone
// opening a pull request controls: a fork pull request run, a privileged
// checkout of the pull request head or of another workflow's run, or an
// untrusted expression on a pull request trigger (a fork pull request, a
// pull_request_target or review event). An expression only an insider
// sets is none (no such trigger reaches its job).
func contributorEntry(kind EntryKind, js JobSituation) bool {
	switch kind {
	case EntryForkPR, EntryPRTarget:
		return true
	case EntryUntrustedExpression:
		return len(js.ForkPR) > 0 || slices.ContainsFunc(js.PrivilegedTriggers, func(t string) bool { return strings.HasPrefix(t, "pull_request") })
	}
	return false
}

// contributorEntries are the entry kinds a repository's visibility actually
// changes the attacker population for: a fork PR, a pull_request_target run
// on fork content, or an untrusted expression fed by either. A tag hijack
// (mutable_dependency) or a push to an unprotected branch does not care who
// can see the repository.
var contributorEntries = map[EntryKind]bool{EntryForkPR: true, EntryPRTarget: true, EntryUntrustedExpression: true}

// pushEntryCeiling is the highest tier an unprotected_push path can hold
// once every other modifier has applied. Pushing to the branch needs an
// account with write access: an insider, who amplifies a path but never
// starts a Critical one, so an unprotected branch alone can never set the
// Critical-path cap. The path carries the "push_entry_cap" modifier when
// the ceiling actually lowered it.
const pushEntryCeiling = TierHigh

// dependencyCeiling is the highest tier a mutable_dependency path can hold
// once every other modifier has applied, unless one of its anchors says
// the dependency is already bad (knownBadDependencyCodes): changing what
// runs takes a compromise of the dependency first, so a dependency that
// can change never starts a Critical path on its own. A path whose anchors
// only say a reference is not pinned (pinningDependencyCodes) holds at
// pinningCeiling instead, unless the same subject comes from a source
// outside the authorized list (sourceDependencyCodes): a compromise of a
// source nobody vetted is more likely, so it holds at dependencyCeiling
// and also carries the "source_cap" modifier. The path carries the
// "dependency_cap" modifier when a ceiling actually lowered it.
const (
	dependencyCeiling = TierHigh
	pinningCeiling    = TierMedium
)

// pinningDependencyCodes are the codes saying a dependency reference is not
// pinned to what runs: an action off a full commit SHA (ISSUE-701), an
// image on a forbidden tag (ISSUE-102) or off a digest (ISSUE-103), an
// action, include or component reference naming both a tag and a branch
// (ISSUE-402), an include or component on a forbidden, mutable version
// (ISSUE-404).
var pinningDependencyCodes = map[ErrorCode]bool{
	CodeActionUnpinned:          true,
	CodeImageForbiddenTag:       true,
	CodeImageNotPinnedByDigest:  true,
	CodeRefConfusion:            true,
	CodeIncludeForbiddenVersion: true,
}

// sourceDependencyCodes are the codes saying a dependency comes from a
// source outside the authorized list: an action or reusable workflow owner
// (ISSUE-713), an image registry (ISSUE-101). They join the path their
// subject's pinning code anchors (subjectFindingCodes).
var sourceDependencyCodes = map[ErrorCode]bool{
	CodeActionUnauthorizedSource: true,
	CodeImageUnauthorizedSource:  true,
}

// outsiderExpressions are the event payloads someone outside the team
// writes whatever the trigger: an issue, a comment, a review, a
// discussion, the wiki.
var outsiderExpressions = []string{
	"github.event.issue.", "github.event.comment.", "github.event.review.", "github.event.review_comment.",
	"github.event.discussion.", "github.event.pages",
}

// insiderExpressions are the expressions only someone with write access
// sets once no fork pull request and no privileged trigger reaches the
// job, by the trigger that sets them: a branch of this repository, a
// release, a manual run's inputs, a pushed commit. First match wins.
var insiderExpressions = []struct {
	field   string
	trigger insiderTrigger
}{
	{"github.event.release.", insiderRelease},
	{"github.head_ref", insiderBranchPush},
	{"github.event.pull_request.", insiderBranchPush},
	{"github.event.inputs.", insiderManualRun},
	{"inputs.", insiderManualRun},
	{"github.event.head_commit.", insiderPush},
	{"github.event.commits", insiderPush},
	{"CI_COMMIT_", insiderPush},
	{"CI_MERGE_REQUEST_", insiderMergeRequest},
}

// insiderTrigger is what an insider does to set an insider expression.
type insiderTrigger int

const (
	_ insiderTrigger = iota
	insiderRelease
	insiderBranchPush
	insiderManualRun
	insiderPush
	insiderMergeRequest
)

// insiderTriggers names who sets an expression of each trigger: who, the
// subject of the entry sentence, and actor, as the So line names them.
var insiderTriggers = map[insiderTrigger]struct{ who, actor string }{
	insiderRelease:      {"Someone who can publish a release", "anyone who can publish a release"},
	insiderBranchPush:   {"Someone who can push a branch to this repository", "anyone who can push a branch"},
	insiderManualRun:    {"Someone who can run this workflow by hand", "anyone who can run the workflow"},
	insiderPush:         {"Someone who can push to this repository", "anyone who can push"},
	insiderMergeRequest: {"Someone who can open a merge request in this project", "anyone who can open a merge request"},
}

// insiderController names who sets an untrusted expression when only an
// insider can: the entry job carries no fork pull request fact (no
// pull_request trigger, or a same-repository guard) and no privileged
// trigger, and the expression is one an insider sets (insiderExpressions),
// never an outsider's payload (outsiderExpressions). "" otherwise, the
// expression then being an outsider's entry.
func insiderController(kind EntryKind, subject string, js JobSituation) string {
	if kind != EntryUntrustedExpression || len(js.ForkPR) > 0 || len(js.PrivilegedTriggers) > 0 {
		return ""
	}
	for _, field := range outsiderExpressions {
		if strings.Contains(subject, field) {
			return ""
		}
	}
	return insiderWho(subject)
}

// insiderWho is who sets an insider expression (insiderExpressions), ""
// for any other.
func insiderWho(subject string) string {
	if t, ok := insiderTriggerOf(subject); ok {
		return insiderTriggers[t].who
	}
	return ""
}

// insiderTriggerOf is the trigger that sets an insider expression
// (insiderExpressions), false for any other.
func insiderTriggerOf(subject string) (insiderTrigger, bool) {
	for _, e := range insiderExpressions {
		if strings.Contains(subject, e.field) {
			return e.trigger, true
		}
	}
	return 0, false
}

// knownBadDependencyCodes are the codes saying the dependency is already
// bad, not merely able to change: a published advisory on the pinned
// version (ISSUE-703), a pinned commit its repository does not have
// (ISSUE-707), an obfuscated remote fetch and execution (ISSUE-715). A
// path one of them anchors is not held by dependencyCeiling.
var knownBadDependencyCodes = map[ErrorCode]bool{
	CodeKnownVulnerableAction:      true,
	CodeImpostorCommit:             true,
	CodeActionObfuscatedRemoteExec: true,
}

// AssemblePaths joins entry-role (and branch-gate) findings with the
// situation facts of their job into attack paths (spec section 2). A path is
// one (entry kind, entry subject): one thing to fix, however many jobs the
// entry runs in. Every finding anchoring that entry is one attack, so they
// anchor one path together (AnchorHashes) rather than one path each. Each
// entry job is a branch of the path, walked and priced on its own (an
// attacker in one job never gets what another entry job holds), and the
// path holds the strongest branch's tier, modifiers and reach
// (strongerBranch); it is priced once. It is a
// pure function of its inputs: the output order never depends on the input
// order (TestOutputOrderIsDeterministicUnderShuffledInput).
//
// Two known gaps, by design rather than blocking this assembler. First,
// Feeds carries no GitLab stage-ordered edges yet (a job without
// needs/dependencies downloads every earlier stage, but the IR has no
// Stage field); the walk below under-reports reach on classic
// stage-ordered GitLab pipelines until that follow-up lands. Second, the
// walk below (walkedJobs) follows a direct edge only: a job fed by the
// entry job is reached, a job fed by THAT job is not, because the facts
// never say whether the intermediate job forwards what it received. A
// chain more than one hop from the entry is not walked, and is therefore
// not priced into the path.
//
// projectPath is the analysed repository's "owner/repo" (any case; empty
// when unknown): a dependency naming that repository itself is the
// repository's own and starts no path, and an action of its owner is never
// read out as a third party's.
func AssemblePaths(findings []opaengine.Finding, sit *Situation, projectPath string) []AttackPath {
	if sit == nil || len(sit.Jobs) == 0 {
		return nil
	}
	sit = liveSituation(sit)
	exposure := sit.Exposure
	if exposure == "" {
		exposure = ir.VisibilityUnknown
	}
	gates := gateFindings(findings)
	own := strings.ToLower(strings.Trim(projectPath, "/"))
	paths := map[string]*pathGroups{}
	var keys []string
	// seen keeps one finding identity to one entry subject per entry job:
	// findings sharing an identity hash are one issue for the
	// platform (ISSUE-207 is {"file", "job"}), so the first one in
	// sortedFindings order decides which subject that issue anchors.
	seen := map[string]bool{}
	// groupOf is the branch each finding identity anchors in each job.
	groupOf := map[string]*pathGroup{}
	var joining []opaengine.Finding
	for _, f := range sortedFindings(findings) {
		if f.Dismissed {
			continue
		}
		anchor, ok := findingAnchorHash(f)
		if !ok {
			// Codeless finding: nothing to key a path identity on.
			continue
		}
		if _, joins := subjectFindingCodes[ErrorCode(f.Code)]; joins {
			joining = append(joining, f)
			continue
		}
		for _, a := range anchorsFor(f, sit, own) {
			if seen[anchor+"|"+a.entryJob] {
				// One finding identity across the values of a matrix: the
				// entry stands for each of them.
				if g := groupOf[anchor+"|"+a.entryJob]; g != nil && a.fact.Subject != "" {
					g.alternatives[a.fact.Subject] = true
				}
				continue
			}
			seen[anchor+"|"+a.entryJob] = true
			key := string(a.kind) + "|" + a.fact.Subject
			pg := paths[key]
			if pg == nil {
				pg = &pathGroups{branches: map[string]*pathGroup{}}
				paths[key] = pg
				keys = append(keys, key)
			}
			g := pg.branches[a.entryJob]
			if g == nil {
				// The first finding in sortedFindings order decides the
				// entry; every later anchor on the key names the same
				// subject.
				jobs := walkedJobs(a.entryJob, a.kind, sit)
				reach, unresolvable, cause, surviving := reachOver(sit, jobs, a.kind)
				g = &pathGroup{anchor: a, jobs: jobs, reach: reach, unresolvable: unresolvable, cause: cause, surviving: surviving, hashes: map[string]bool{}, codes: map[ErrorCode]bool{},
					contributor: contributorEntry(a.kind, sit.Jobs[a.entryJob]), alternatives: map[string]bool{a.fact.Subject: true}}
				pg.branches[a.entryJob] = g
			}
			groupOf[anchor+"|"+a.entryJob] = g
			g.hashes[anchor] = true
			// A branch merging several anchors is proven as soon as one
			// of them proves its entry.
			if a.fact.State == "proven" {
				g.anchor.fact.State = "proven"
			}
			g.codes[ErrorCode(f.Code)] = true
		}
	}
	// A finding about the subject itself starts nothing: it joins the path
	// an entry finding already anchors on the same subject in the same
	// job, and is priced as an other finding when there is none. It never
	// proves the entry.
	for _, f := range joining {
		anchor, _ := findingAnchorHash(f)
		if seen[anchor+"|"+f.Job] {
			continue
		}
		seen[anchor+"|"+f.Job] = true
		key := string(subjectFindingCodes[ErrorCode(f.Code)]) + "|" + entrySubject(f)
		if pg := paths[key]; pg != nil {
			if g := pg.branches[f.Job]; g != nil {
				g.hashes[anchor] = true
				g.codes[ErrorCode(f.Code)] = true
			}
		}
	}
	out := make([]AttackPath, 0, len(keys))
	var cacheKeys []string
	for _, key := range keys {
		if strings.HasPrefix(key, string(EntryPoisonedCache)+"|") {
			cacheKeys = append(cacheKeys, key)
			continue
		}
		p := paths[key].path(key, exposure, gates, sit)
		p.ownRepo = own
		p.situation = sit
		out = append(out, p)
	}
	writers := cacheWriters(out, sit)
	for _, key := range cacheKeys {
		pg := paths[key]
		all := map[string]bool{}
		for job, g := range pg.branches {
			// The restoring job is never its own cache's writer: entered by
			// another path, it already holds what the cache would give.
			for _, w := range sortedKeys(writerJobs(writers)) {
				if w == job {
					continue
				}
				g.writers = append(g.writers, w)
				if TierRank(writers[w].ceiling) > TierRank(g.writer.ceiling) {
					g.writer = writers[w]
				}
				all[w] = true
			}
			if len(g.writers) == 0 {
				delete(pg.branches, job)
			}
		}
		if len(pg.branches) == 0 {
			// No run that can write this cache runs code from outside the
			// team: the cache findings anchor nothing and are priced as
			// individual findings.
			continue
		}
		p := pg.path(key, exposure, gates, sit)
		p.ownRepo = own
		p.situation = sit
		p.cacheWriters = sortedKeys(all)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return worseFirst(out[i], out[j]) })
	return out
}

// worseFirst is the order every report numbers paths in: the higher tier,
// then within a tier the stronger reach (reachStrength), then the id, so
// path 1 is always the worst.
func worseFirst(a, b AttackPath) bool {
	if TierRank(a.Tier) != TierRank(b.Tier) {
		return TierRank(a.Tier) > TierRank(b.Tier)
	}
	if sa, sb := reachStrength(a.Reach), reachStrength(b.Reach); sa != sb {
		return sa > sb
	}
	return a.ID < b.ID
}

// reachStrength ranks what a reach holds for worseFirst: every secret of
// the repository 3, listed secrets 2, a write token 1, code execution
// alone 0.
func reachStrength(r Reach) int {
	switch {
	case r.AllSecrets:
		return 3
	case len(r.Secrets) > 0:
		return 2
	case len(r.TokenWrite) > 0:
		return 1
	}
	return 0
}

// pathGroups is every entry job of one path key, one pathGroup each.
type pathGroups struct {
	branches map[string]*pathGroup
}

// path prices every branch on its own (pathGroup.path), then reads the
// path out of them: the strongest branch (strongerBranch) gives the tier,
// the modifiers, the reach and the entry; the path is proven as soon as
// one branch is; its anchors, gates and surviving jobs are every branch's;
// its jobs are the entry jobs, strongest first, then the jobs they feed.
func (pg *pathGroups) path(key, exposure string, gates []opaengine.Finding, sit *Situation) AttackPath {
	// The branches are one attack: an anchor of one never amplifies another.
	anchors := map[string]bool{}
	codes := map[ErrorCode]bool{}
	for _, g := range pg.branches {
		for h := range g.hashes {
			anchors[h] = true
		}
		for c := range g.codes {
			codes[c] = true
		}
	}
	subs := make([]AttackPath, 0, len(pg.branches))
	for _, g := range pg.branches {
		subs = append(subs, g.path(exposure, gates, sit, anchors))
	}
	sort.Slice(subs, func(i, j int) bool { return strongerBranch(subs[i], subs[j]) })
	p := subs[0]
	p.AnchorHashes = sortedKeys(anchors)
	p.AnchorCodes = nil
	for c := range codes {
		p.AnchorCodes = append(p.AnchorCodes, c)
	}
	p.AnchorHash, p.AnchorCode = anchorOf(p.AnchorHashes, p.AnchorCodes)
	p.Jobs, p.GateHashes = nil, nil
	inJobs, inGates, inSurviving := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range subs {
		if s.State == PathProven {
			p.State = PathProven
		}
		p.Jobs = append(p.Jobs, s.Jobs[0])
		inJobs[s.Jobs[0]] = true
		for _, h := range s.GateHashes {
			if !inGates[h] {
				inGates[h] = true
				p.GateHashes = append(p.GateHashes, h)
			}
		}
		for _, j := range s.survivingJobs {
			inSurviving[j] = true
		}
		p.Branches = append(p.Branches, PathBranch{
			Job: s.Jobs[0], Jobs: s.Jobs, Reach: s.Reach, Tier: s.Tier, State: s.State, Modifiers: s.Modifiers,
			FeedsVia: feedsViaOf(s.Jobs, sit),
			cause:    s.cause, survivingJobs: s.survivingJobs, triggers: shownTriggers(sit.Jobs[s.Jobs[0]]),
			ceiling: s.ceiling, ceilingModifiers: s.ceilingModifiers,
		})
	}
	for _, s := range subs {
		for _, j := range s.Jobs[1:] {
			if !inJobs[j] {
				inJobs[j] = true
				p.Jobs = append(p.Jobs, j)
			}
		}
	}
	p.survivingJobs = sortedKeys(inSurviving)
	alternatives := map[string]bool{}
	for _, g := range pg.branches {
		for s := range g.alternatives {
			alternatives[s] = true
		}
	}
	if len(alternatives) > 1 {
		p.alternatives = sortedKeys(alternatives)
	}
	sum := sha256.Sum256([]byte(key))
	p.ID = hex.EncodeToString(sum[:])[:16]
	return p
}

// anchorOf is the anchor a path reads as: its first hash, and the first
// of its codes that makes the entry one, or, when there is one, the code
// that keeps a dependency uncapped. It sorts codes in place.
func anchorOf(hashes []string, codes []ErrorCode) (string, ErrorCode) {
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	code := codes[0]
	for _, c := range codes {
		if RoleForCode(c) == RoleEntry {
			code = c // the entry reads as a code that makes it one
			break
		}
	}
	for _, c := range codes {
		if knownBadDependencyCodes[c] {
			code = c // and as the one that keeps it uncapped, when there is one
			break
		}
	}
	return hashes[0], code
}

// strongerBranch orders a path's branches strongest first: the higher
// tier, then a proven one, then the higher tier before the modifiers, then
// the wider reach (reachWeight), then the shorter walk, then the job name.
func strongerBranch(a, b AttackPath) bool {
	if TierRank(a.Tier) != TierRank(b.Tier) {
		return TierRank(a.Tier) > TierRank(b.Tier)
	}
	if (a.State == PathProven) != (b.State == PathProven) {
		return a.State == PathProven
	}
	if TierRank(a.BaseTier) != TierRank(b.BaseTier) {
		return TierRank(a.BaseTier) > TierRank(b.BaseTier)
	}
	if wa, wb := reachWeight(a.Reach), reachWeight(b.Reach); wa != wb {
		return wa > wb
	}
	if len(a.Jobs) != len(b.Jobs) {
		return len(a.Jobs) < len(b.Jobs) // the job holding the reach itself
	}
	return a.Jobs[0] < b.Jobs[0]
}

// reachWeight is how much a reach holds, for strongerBranch: every secret
// of the repository first (it holds whatever a list of them names), then
// its impact kinds, then how many secrets, then how many write scopes.
func reachWeight(r Reach) int {
	w := len(impactKinds(r.Impacts)) * 10000
	if r.AllSecrets {
		w += 100000
	}
	return w + min(len(r.Secrets), 99)*50 + min(len(r.TokenWrite), 49)
}

// pathGroup is every finding anchoring one entry job of a path key, with
// the walk and the reach computed once for that job and the entry kind.
type pathGroup struct {
	anchor       pathAnchor
	jobs         []string
	reach        Reach
	unresolvable bool
	cause        unresolvableCause
	surviving    []string
	hashes       map[string]bool
	codes        map[ErrorCode]bool
	// contributor is set when the entry is one anyone opening a pull
	// request controls (contributorEntry): a privilege alone makes it
	// Critical.
	contributor bool
	// writers is, on a poisoned_cache branch, the jobs whose run can write
	// the cache, never the restoring job itself; writer is the strongest
	// ceiling among the paths entering them (cacheWriter), which holds the
	// branch.
	writers []string
	writer  cacheWriter
	// alternatives is every subject the branch's findings name, the
	// values of a matrix one finding identity stands for.
	alternatives map[string]bool
}

// path applies the tier rules to one branch: base tier, then the private
// exposure and unresolvable modifiers, then one amplification per gate on
// the branch (never one of the path's anchors), then the push entry and
// dependency ceilings.
func (g *pathGroup) path(exposure string, gates []opaengine.Finding, sit *Situation, anchors map[string]bool) AttackPath {
	a := g.anchor
	p := AttackPath{
		EntryKind: a.kind, Entry: a.fact, AnchorHashes: sortedKeys(g.hashes),
		Jobs: g.jobs, Reach: g.reach, Exposure: exposure, State: PathProven,
		survivingJobs: g.surviving,
	}
	for c := range g.codes {
		p.AnchorCodes = append(p.AnchorCodes, c)
	}
	p.AnchorHash, p.AnchorCode = anchorOf(p.AnchorHashes, p.AnchorCodes)
	p.ReachKinds = reachKinds(g.reach)
	p.ReachKind = p.ReachKinds[0]
	p.BaseTier = baseTier(g.reach, g.cause, g.contributor)
	p.Tier = p.BaseTier
	p.insider = insiderController(a.kind, a.fact.Subject, sit.Jobs[g.jobs[0]]) != ""
	if exposure == ir.VisibilityPrivate && contributorEntries[a.kind] && !p.insider {
		p.Tier = tierShift(p.Tier, -1)
		p.Modifiers = append(p.Modifiers, "private_exposure")
	}
	p.cause = g.cause
	onPath := gatesOnPath(gates, g.jobs, sit, anchors, a.kind, g.reach, g.cause)
	// A gate raises a path only when it can do damage; when only secrets
	// Plumber could not list say it can, the raise rests on them too.
	raiseUnlisted := len(onPath) > 0 && !reachCanDamage(g.reach, "")
	if a.fact.State == "unresolvable" || g.unresolvable || raiseUnlisted {
		p.Tier = tierShift(p.Tier, -1)
		p.State = PathUnverified
		p.Modifiers = append(p.Modifiers, "unresolvable")
	}
	for _, gate := range onPath {
		p.Tier = tierShift(p.Tier, 1)
		p.Modifiers = append(p.Modifiers, "gate:"+gate.Code)
		if branch, ok := gate.Data["branchName"].(string); ok && branch != "" {
			if p.gateBranches == nil {
				p.gateBranches = map[string]string{}
			}
			p.gateBranches[gate.Code] = branch
		}
		if gateHash, ok := findingAnchorHash(gate); ok {
			p.GateHashes = append(p.GateHashes, gateHash)
		}
	}
	p.ceiling = TierCritical
	if a.kind == EntryUnprotectedPush || p.insider {
		p.ceiling, p.ceilingModifiers = pushEntryCeiling, []string{"push_entry_cap"}
	}
	if a.kind == EntryMutableDependency && !g.knownBad() {
		ceiling, source := g.ceiling()
		if TierRank(ceiling) < TierRank(p.ceiling) {
			p.ceiling, p.ceilingModifiers = ceiling, []string{"dependency_cap"}
			if source {
				p.ceilingModifiers = append(p.ceilingModifiers, "source_cap")
			}
		}
	}
	if TierRank(p.Tier) > TierRank(p.ceiling) {
		p.Tier = p.ceiling
		p.Modifiers = append(p.Modifiers, p.ceilingModifiers...)
	}
	// A poisoned cache holds at the strongest ceiling of the paths
	// entering its writers: poisoning it takes what entering them takes.
	if a.kind == EntryPoisonedCache && g.writer.ceiling != "" && TierRank(p.Tier) > TierRank(g.writer.ceiling) {
		p.Tier = g.writer.ceiling
		p.Modifiers = append(append(p.Modifiers, g.writer.modifiers...), "cache_writer_cap")
	}
	return p
}

// ceiling is the ceiling of a mutable_dependency branch that no
// anchor says is already bad: pinningCeiling when every entry anchor only
// says the reference is not pinned and no source finding joined it,
// dependencyCeiling otherwise. source is true when a source finding is
// what keeps the branch at dependencyCeiling.
func (g *pathGroup) ceiling() (ceiling PathTier, source bool) {
	pinningOnly := true
	for c := range g.codes {
		switch {
		case sourceDependencyCodes[c]:
			source = true
		case !pinningDependencyCodes[c]:
			pinningOnly = false
		}
	}
	if pinningOnly && !source {
		return pinningCeiling, false
	}
	return dependencyCeiling, pinningOnly && source
}

// knownBad reports whether one of the group's anchors says the dependency
// is already bad.
func (g *pathGroup) knownBad() bool {
	for c := range g.codes {
		if knownBadDependencyCodes[c] {
			return true
		}
	}
	return false
}

// cacheWriter is what entering a cache writer takes: the strongest
// ceiling among the branches entering the job (AttackPath.ceiling), and
// the modifiers that ceiling sets when it holds a cache path.
type cacheWriter struct {
	ceiling   PathTier
	modifiers []string
}

// cacheWriters is the jobs that can write a poisoned cache: the entry jobs,
// of every branch of the paths given (none a poisoned_cache path), that run
// code from outside the team in a run whose cache a release run reads.
// Their privilege was not pruned as a fork pull request run's, they run,
// and their runs save in the default branch's scope (savesForDefaultBranch).
// Whatever caches such a job
// declares, code running in it holds the run's cache token and can save any
// key, the one a release job restores included. Each writer keeps the
// strongest ceiling of the branches entering it, the first in the paths'
// order on a tie; it reads the assembled paths, so the order of the
// findings does not matter.
func cacheWriters(paths []AttackPath, sit *Situation) map[string]cacheWriter {
	out := map[string]cacheWriter{}
	ordered := append([]AttackPath(nil), paths...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, p := range ordered {
		for _, b := range p.Branches {
			if !slices.Contains(b.survivingJobs, b.Job) {
				continue // a fork pull request run saves only its merge ref's cache
			}
			if !savesForDefaultBranch(sit.Jobs[b.Job]) {
				continue
			}
			ceiling := b.ceiling
			if ceiling == "" {
				ceiling = TierCritical
			}
			if cur, ok := out[b.Job]; !ok || TierRank(ceiling) > TierRank(cur.ceiling) {
				out[b.Job] = cacheWriter{ceiling: ceiling, modifiers: b.ceilingModifiers}
			}
		}
	}
	return out
}

// savesForDefaultBranch reports whether a run of js saves what a run of
// another ref restores: a job that runs (not Dead) whose cache scopes hold
// the default branch, or any ref for a job carrying no trigger. A save in a
// pull request's, a tag's or another branch's scope reaches runs of that
// same ref only.
func savesForDefaultBranch(js JobSituation) bool {
	return !js.Dead && (slices.Contains(js.CacheScopes, "default") || slices.Contains(js.CacheScopes, "any"))
}

// writerJobs is the set of jobs of writers.
func writerJobs(writers map[string]cacheWriter) map[string]bool {
	out := make(map[string]bool, len(writers))
	for w := range writers {
		out[w] = true
	}
	return out
}

// stepCaches is the caches of js declared by the step a cache finding is
// about: the action it names, at its line when both carry one.
func stepCaches(js JobSituation, f opaengine.Finding) []CacheFact {
	uses, _ := f.Data["uses"].(string)
	var out []CacheFact
	for _, c := range js.Caches {
		if c.Uses == uses && (c.Line == 0 || f.Line == 0 || c.Line == f.Line) {
			out = append(out, c)
		}
	}
	return out
}

// rustCacheSubject opens the entry subject of a rust-cache key family.
const rustCacheSubject = "Rust build cache, key prefix "

// cacheEntrySubject names the cache a poisoned_cache entry is about, the
// identity of its path: the literal key of actions/cache (the finding's
// own subject), else the cache the step's action keys itself
// (builtinCacheRefs in the GitHub collector), by its family
// (CacheFact.Family, the key without the discriminators the edges match
// on; the key when the facts give none): a rust-cache key family, a
// setup action's cache of a manager, the Gradle cache. The finding's
// subject stands when the step declares no cache Plumber knows.
func cacheEntrySubject(f opaengine.Finding, caches []CacheFact) string {
	if len(caches) == 0 {
		return entrySubject(f)
	}
	c := caches[0]
	family := c.Family
	if family == "" {
		family = c.Key
	}
	name, _, _ := strings.Cut(strings.ToLower(c.Uses), "@")
	short := name[strings.LastIndex(name, "/")+1:]
	switch name {
	case "actions/cache", "actions/cache/restore", "actions/cache/save":
		return entrySubject(f)
	case "swatinem/rust-cache":
		return rustCacheSubject + family
	case "actions/setup-node", "actions/setup-python", "actions/setup-java", "actions/setup-dotnet", "actions/setup-go":
		if manager, ok := strings.CutPrefix(family, short+"-"); ok {
			return manager + " cache of " + short
		}
		return "cache of " + short
	case "gradle/actions/setup-gradle", "gradle/gradle-build-action":
		return "Gradle cache of " + short
	}
	return "cache of " + name
}

// AllAnchorHashes is every finding anchoring p: AnchorHashes, or AnchorHash
// alone for a path built without the list (a hand-built path, or one read
// back from an older report).
func (p AttackPath) AllAnchorHashes() []string {
	if len(p.AnchorHashes) > 0 {
		return p.AnchorHashes
	}
	if p.AnchorHash != "" {
		return []string{p.AnchorHash}
	}
	return nil
}

// EntryJobs is the entry job of every branch of p, strongest first; the
// first of Jobs alone for a path built without branches.
func (p AttackPath) EntryJobs() []string {
	if len(p.Branches) == 0 {
		return p.Jobs[:min(len(p.Jobs), 1)]
	}
	out := make([]string, len(p.Branches))
	for i, b := range p.Branches {
		out[i] = b.Job
	}
	return out
}

// anchoredBy reports whether the finding with this hash anchors p.
func (p AttackPath) anchoredBy(hash string) bool {
	return slices.Contains(p.AllAnchorHashes(), hash)
}

// sortedFindings orders findings into a fixed total order before anything
// else reads them. A few codes (ISSUE-207 is {"file", "job"}, the "one
// issue per rule" ruling) collapse several findings sharing one identity
// hash into the same path key. Deciding between them by raw input order
// would make Entry (and anything else read off the winning finding) depend
// on that order, which TestOutputOrderIsDeterministicUnderShuffledInput is
// meant to rule out. Processing findings in a fixed total order first makes
// the choice deterministic instead: same-hash findings are one issue for
// the platform, and the first one in (code, job, file, line, message, data)
// order wins, whatever order the caller handed them in. The canonical Data
// encoding is the final tie-break: every comparator above it can still tie
// (two findings on the same line of the same job differing only in their
// structured data), so without it the order would not be total. Returns a
// copy; the caller's slice is never reordered.
func sortedFindings(findings []opaengine.Finding) []opaengine.Finding {
	out := append([]opaengine.Finding(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Job != b.Job {
			return a.Job < b.Job
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Message != b.Message {
			return a.Message < b.Message
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return canonicalData(a) < canonicalData(b)
	})
	return out
}

// canonicalData is a finding's Data field marshalled to JSON (Go's
// encoding/json sorts map keys), the sortedFindings tie-break that makes
// its order total even when every other comparator ties. A finding whose
// Data cannot marshal (should not happen: Data is always built from
// strings and basic values) falls back to the empty string rather than
// panicking; it still ties deterministically with any other failure.
func canonicalData(f opaengine.Finding) string {
	b, err := json.Marshal(f.Data)
	if err != nil {
		return ""
	}
	return string(b)
}

// findingAnchorHash is identity.PlatformHash(f.IdentityInput()) with the ok
// flag folded in: false only for a codeless finding, which cannot happen
// for a finding that reaches here (anchorsFor already required a registered
// entry or gate code), but is handled rather than assumed away.
func findingAnchorHash(f opaengine.Finding) (string, bool) {
	hash, _, ok := identity.PlatformHash(f.IdentityInput())
	return hash, ok
}

// subjectFindingCodes are the codes that say something about a dependency
// without making it an entry: an owner (ISSUE-713) or a registry
// (ISSUE-101) outside the authorized list is a trust policy finding. When
// the reference can change, the pinning codes on the same subject and job
// anchor the path, and the finding joins it, with the entry kind it joins.
var subjectFindingCodes = map[ErrorCode]EntryKind{
	CodeActionUnauthorizedSource: EntryMutableDependency,
	CodeImageUnauthorizedSource:  EntryMutableDependency,
}

// pathAnchor is one entry a finding starts, together with the job that
// becomes the entry job of the path walked from it.
type pathAnchor struct {
	kind     EntryKind
	fact     EntryFact
	entryJob string
}

// anchorsFor returns the entries a finding starts (spec section 2,
// Assembly).
//
// An entry-role finding is its own entry: its kind is the registry's, its
// subject, state and evidence are read off the finding (entryFromFinding),
// and its job is the entry job. A finding whose job is absent from the
// situation has nothing to walk and starts no path, and neither does a
// dependency inside the repository itself (localReference).
//
// A job-less entry-role finding is ISSUE-404 or the GitLab branch of
// ISSUE-402, both mutable_dependency: it enters every job the include it
// names shapes (Situation.Includes, matched on the include's exact
// subject, "source@ref"), at the include's own location.
//
// A branch-protection finding (ISSUE-501, ISSUE-505) enters every job
// whose push fact names the finding's branch, as an unprotected_push
// entry; the push fact's state and evidence are the entry's. Such a
// finding anchoring a path never amplifies it (gatesOnPath skips a path's
// own anchors).
func anchorsFor(f opaengine.Finding, sit *Situation, own string) []pathAnchor {
	code := ErrorCode(f.Code)
	if kind, isEntry := EntryKindForCode(code); isEntry {
		if f.Job != "" {
			if _, ok := sit.Jobs[f.Job]; !ok {
				return nil
			}
			fact := entryFromFinding(f, kind)
			if kind == EntryMutableDependency && localReference(fact.Subject, own) {
				return nil
			}
			a := pathAnchor{kind: kind, fact: fact, entryJob: f.Job}
			if kind == EntryPoisonedCache {
				a.fact.Subject = cacheEntrySubject(f, stepCaches(sit.Jobs[f.Job], f))
			}
			return []pathAnchor{a}
		}
		if kind != EntryMutableDependency {
			return nil
		}
		subject := entrySubject(f)
		var anchors []pathAnchor
		for _, inc := range sit.Includes {
			if inc.Subject != subject {
				continue
			}
			for _, job := range inc.Jobs {
				if _, ok := sit.Jobs[job]; !ok {
					continue
				}
				fact := entryFromFinding(f, kind)
				if inc.File != "" {
					fact.File, fact.Line = inc.File, inc.Line
				}
				anchors = append(anchors, pathAnchor{kind: kind, fact: fact, entryJob: job})
			}
		}
		sortAnchorsByJob(anchors)
		return anchors
	}
	if RoleForCode(code) != RoleGate || (code != CodeBranchUnprotected && code != CodeBranchNonCompliant) {
		return nil
	}
	branch, _ := f.Data["branchName"].(string)
	if branch == "" {
		return nil
	}
	var anchors []pathAnchor
	for name, js := range sit.Jobs {
		for _, push := range js.Push {
			if push.Subject == branch {
				anchors = append(anchors, pathAnchor{kind: EntryUnprotectedPush, fact: push, entryJob: name})
			}
		}
	}
	sortAnchorsByJob(anchors)
	return anchors
}

// localReference reports whether a dependency names a workflow or an action
// inside the repository itself ("./.github/workflows/build.yml", the "$/"
// form some workflows write the same path in, or the repository's own
// "owner/repo" path, any case, own being that path in lower case): it
// changes only with a commit here, so it is no third-party dependency and
// anchors no path.
func localReference(subject, own string) bool {
	if strings.HasPrefix(subject, "./") || strings.HasPrefix(subject, "$/") {
		return true
	}
	if own == "" {
		return false
	}
	ref, _, _ := strings.Cut(strings.ToLower(subject), "@")
	return ref == own || strings.HasPrefix(ref, own+"/")
}

// sameOwner reports whether a dependency subject ("owner/repo/...@ref")
// belongs to the owner of own (the analysed repository's "owner/repo" in
// lower case).
func sameOwner(subject, own string) bool {
	ownOwner, _, ok := strings.Cut(own, "/")
	if !ok || ownOwner == "" {
		return false
	}
	owner, _, ok := strings.Cut(strings.ToLower(subject), "/")
	return ok && owner == ownOwner
}

// entryFromFinding is the entry an entry-role finding reports: its subject
// (entrySubject), its state (entryState), its message as the evidence, cut
// the way a rendered sentence is, and its own file and line.
func entryFromFinding(f opaengine.Finding, kind EntryKind) EntryFact {
	fact := EntryFact{
		Kind:     kind,
		State:    entryState(ErrorCode(f.Code)),
		Evidence: truncateWords(f.Message, 200),
		Subject:  entrySubject(f),
		File:     f.File,
		Line:     f.Line,
	}
	if kind == EntryMutableDependency && computedAtRunTime(ErrorCode(f.Code), fact.Subject) {
		fact.State = "unresolvable"
	}
	return fact
}

// unexpandedVariable is a variable an image reference still names: $NAME
// or ${NAME}.
var unexpandedVariable = regexp.MustCompile(`\$\{?[A-Za-z_]`)

// computedAtRunTime reports whether a dependency reference is only known
// when the job runs: it holds an expression (${{ ... }}), or, for an
// image, a variable left unexpanded. Plumber cannot know what runs, so
// the entry is unresolvable. A fetched script's subject is its URL or its
// line, not a reference, and never counts.
func computedAtRunTime(code ErrorCode, subject string) bool {
	if code == CodeUnverifiedScriptExecution {
		return false
	}
	if strings.Contains(subject, "${{") {
		return true
	}
	switch code {
	case CodeImageUnauthorizedSource, CodeImageForbiddenTag, CodeImageNotPinnedByDigest:
		return unexpandedVariable.MatchString(subject)
	}
	return false
}

// unresolvableEntryCodes are the entry codes whose finding says the entry
// itself could not be checked: the action's source could not be fetched
// (ISSUE-716), or its pinned commit is absent upstream (ISSUE-707), so who
// controls what runs is unknown; or the cache is on or off per trigger
// through an expression (ISSUE-717), so whether the job restores it when it
// publishes is unknown.
var unresolvableEntryCodes = map[ErrorCode]bool{
	CodeActionRemoteExecUnverified: true,
	CodeImpostorCommit:             true,
	CodeCachePoisoningUnresolved:   true,
}

// entryState is the state an entry code reports its entry with.
func entryState(code ErrorCode) FactState {
	if unresolvableEntryCodes[code] {
		return "unresolvable"
	}
	return "proven"
}

// entrySubject is what the finding names as its entry: the subject the
// rule emitted when it has one, else the field of its data that names it
// (the image reference, the fetched URL, the variable, the checkout ref,
// the action or reusable workflow), else its message.
func entrySubject(f opaengine.Finding) string {
	if f.Subject != "" {
		return f.Subject
	}
	data := func(key string) string {
		v, _ := f.Data[key].(string)
		return v
	}
	var s string
	switch ErrorCode(f.Code) {
	case CodeImageUnauthorizedSource, CodeImageForbiddenTag, CodeImageNotPinnedByDigest:
		// The GitLab collector writes "unknown" for a registry it could
		// not read: a placeholder, never part of the reference.
		s = strings.TrimPrefix(data("link"), "unknown/")
	case CodeUnverifiedScriptExecution:
		s = firstURLOrLine(data("scriptLine"))
	case CodeUnsafeVariableExpansion:
		s = data("variableName")
	case CodePullRequestTargetWithHeadCheckout:
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(data("ref"), "${{"), "}}"))
	default:
		s = data("uses")
	}
	if s == "" {
		s = f.Message
	}
	return s
}

// scriptURLPattern is a script's fetch target: the first URL, cut where a
// pipe, a semicolon, a closing parenthesis or a quote ends it.
var scriptURLPattern = regexp.MustCompile(`https?://[^\s|;)'"]+`)

// firstURLOrLine is the first URL a script fetches, else its first line,
// trimmed and cut at 200 characters.
func firstURLOrLine(script string) string {
	if u := scriptURLPattern.FindString(script); u != "" {
		return u
	}
	line, _, _ := strings.Cut(strings.TrimSpace(script), "\n")
	return truncateWords(line, 200)
}

func sortAnchorsByJob(anchors []pathAnchor) {
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].entryJob < anchors[j].entryJob })
}

// walkedJobs is the entry job followed by its directly fed jobs (one hop,
// not the transitive closure of Feeds), deduped, and filtered to jobs the
// situation actually knows about, so a Feeds entry naming a missing job
// never creates a phantom walk step, and a job that feeds itself never
// gets its reach (secrets, impacts) counted twice. A job fed by a job this
// walks, rather than by the entry job itself, is not reached: the facts
// say an edge exists, not that the intermediate job forwards what it
// received, so a deeper chain is deliberately left unwalked and unpriced.
// An entry that holds only in a GitHub fork pull request run (forkRunOnly)
// reaches no job through a cache alone: such a run saves only in its merge
// ref's scope, which no other ref's run restores.
func walkedJobs(entryJob string, kind EntryKind, sit *Situation) []string {
	seen := map[string]bool{entryJob: true}
	jobs := []string{entryJob}
	forkOnly := forkRunOnly(sit, entryJob, kind)
	for _, fed := range sit.Jobs[entryJob].Feeds {
		if seen[fed] {
			continue
		}
		if _, ok := sit.Jobs[fed]; !ok {
			continue
		}
		if via := sit.Jobs[entryJob].FeedsVia[fed]; forkOnly && len(via) == 1 && via[0] == FeedCache {
			continue
		}
		seen[fed] = true
		jobs = append(jobs, fed)
	}
	return jobs
}

// feedsViaOf is, for a walk (walkedJobs: the entry job, then the jobs it
// feeds), the kinds of edge from the entry job to each fed job, nil when
// none is known.
func feedsViaOf(walk []string, sit *Situation) map[string][]string {
	var out map[string][]string
	via := sit.Jobs[walk[0]].FeedsVia
	for _, fed := range walk[1:] {
		if kinds := via[fed]; len(kinds) > 0 {
			if out == nil {
				out = map[string][]string{}
			}
			out[fed] = kinds
		}
	}
	return out
}

// reachOver unions privilege and impact across the walked jobs, then applies
// the platform rules: an impact the job token gives (Source "token") counts
// only from a job whose privilege survived them, the token being gone from
// the others. unresolvable reports whether the path's tier rests on a fact
// that could not be decided: the tier the proven reach gives (listed
// secrets, a token that is not only assumed, proven impacts, code
// execution) differs from the tier the reach gives with those facts read
// as true (baseTier: an unresolvable impact, an unresolvable SecretsState,
// a default token write, since a default token is a guess about what the
// runner falls back to, not a read fact). The path is then priced one step
// below the second, which is never under the first. cause names which of
// the last two it was (set for unlisted secrets even when a proven
// privilege kept the path resolvable), for the
// paths explain.go renders a custom sentence for (empty when the entry or
// an impact fact is the unresolvable one instead, which explain.go reads
// off the path directly). surviving is the surviving-privilege job set
// (survivingPrivilegeJobs) computed along the way: AssemblePaths records
// it on the path so a privilege-role finding's "on path" check can
// read the one set both this function and that check agree on, rather
// than recomputing it a second time and risking the two drifting apart.
func reachOver(sit *Situation, jobs []string, kind EntryKind) (r Reach, unresolvable bool, cause unresolvableCause, surviving []string) {
	secrets := map[string]bool{}
	scopes := map[string]bool{}
	for _, name := range jobs {
		js, ok := sit.Jobs[name]
		if !ok {
			continue
		}
		for _, s := range js.Privilege.Secrets {
			secrets[s] = true
		}
		r.AllSecrets = r.AllSecrets || js.Privilege.AllSecrets
		for _, s := range js.Privilege.TokenWrite {
			scopes[s] = true
		}
		for _, imp := range js.Impact {
			if imp.Source == impactFromToken || !countedImpact(imp) {
				continue
			}
			r.Impacts = append(r.Impacts, imp)
		}
	}
	r.Secrets = sortedKeys(secrets)
	r.TokenWrite = sortedKeys(scopes)
	// Reach.Executes is true for every path: jobs always has at least the
	// entry job, so this is unconditional; the field stays for the outputs
	// and for a future entry kind that might not execute.
	r.Executes = true
	r = applyPlatformReachRules(sit, jobs, kind, r)

	// The per-job unresolvable check (SecretsState, declared vs default
	// token) reads only the jobs whose privilege survived the platform
	// rules above, not every walked job: a job the platform rules dropped
	// entirely (a GitHub fork run's own entry job, say) contributes
	// nothing to the path any more, so its own token source or secrets
	// state must not make the (now pruned) path unresolvable.
	surviving = survivingPrivilegeJobs(sit, jobs, kind)
	for _, name := range surviving {
		for _, imp := range sit.Jobs[name].Impact {
			if imp.Source == impactFromToken && countedImpact(imp) {
				r.Impacts = append(r.Impacts, imp)
			}
		}
	}
	r.parts = reachParts(sit, jobs, surviving, r)
	hasDeclaredToken := false
	hasDefaultToken := false
	for _, name := range surviving {
		js, ok := sit.Jobs[name]
		if !ok {
			continue
		}
		if js.Privilege.SecretsState == "unresolvable" {
			cause = unresolvableSecrets
		}
		if len(js.Privilege.TokenWrite) > 0 {
			switch js.Privilege.TokenWriteSource {
			case "declared":
				hasDeclaredToken = true
			case "default":
				hasDefaultToken = true
			}
		}
	}
	// The token check runs over the PRUNED reach, not the pre-prune one. A
	// GitHub fork pull_request run drops its default token entirely (there
	// never was a write token to begin with), so a dropped default token
	// must not mark the path unresolvable; gate on the pruned TokenWrite
	// so an emptied-out token is simply absent, not an open question.
	tokenAssumed := len(r.TokenWrite) > 0 && !hasDeclaredToken && hasDefaultToken
	r.tokenAssumed = tokenAssumed
	if tokenAssumed && len(r.Secrets) == 0 && !r.AllSecrets && cause == "" {
		cause = unresolvableDefaultToken
	}
	// A fact that could not be decided lowers the path only when its tier
	// rests on it: a listed secret or a declared write token holds the
	// tier unlisted secrets would give, one proven impact the tier an
	// unconfirmed one would give. cause stays set either way, so the path
	// still says the secrets could not be listed.
	contributor := contributorEntry(kind, sit.Jobs[jobs[0]])
	proven := tierFor(
		slices.ContainsFunc(r.Impacts, func(imp ImpactFact) bool { return imp.State != "unresolvable" }),
		len(r.Secrets) > 0 || r.AllSecrets || (len(r.TokenWrite) > 0 && !tokenAssumed),
		r.Executes, contributor,
	)
	unresolvable = baseTier(r, cause, contributor) != proven
	return r, unresolvable, cause, surviving
}

// reachParts splits a pruned reach r over the walked jobs, in walk order:
// what each job holds of it (reachPart). surviving is the jobs whose
// privilege the platform rules kept.
func reachParts(sit *Situation, jobs, surviving []string, r Reach) []reachPart {
	kept := map[string]bool{}
	for _, j := range surviving {
		kept[j] = true
	}
	parts := make([]reachPart, 0, len(jobs))
	for _, name := range jobs {
		js := sit.Jobs[name]
		part := reachPart{job: name}
		for _, imp := range js.Impact {
			if countedImpact(imp) && (imp.Source != impactFromToken || kept[name]) {
				part.impacts = append(part.impacts, imp)
			}
		}
		if kept[name] {
			for _, s := range js.Privilege.Secrets {
				if slices.Contains(r.Secrets, s) {
					part.secrets = append(part.secrets, s)
				}
			}
			part.allSecrets = js.Privilege.AllSecrets && r.AllSecrets
			for _, s := range js.Privilege.TokenWrite {
				if slices.Contains(r.TokenWrite, s) {
					part.scopes = append(part.scopes, s)
				}
			}
			sort.Strings(part.secrets)
			sort.Strings(part.scopes)
			part.assumed = len(part.scopes) > 0 && js.Privilege.TokenWriteSource == "default"
		}
		parts = append(parts, part)
	}
	return parts
}

// countedImpact reports whether an impact fact counts in a reach: a job's
// environment is a protection, never an impact by itself, whether the
// fact names it as its own kind or as a deploy read off the environment.
func countedImpact(imp ImpactFact) bool {
	if imp.Kind == "environment" {
		return false
	}
	return imp.Kind != "deploys" || !strings.HasPrefix(imp.Evidence, environmentEvidence)
}

// environmentEvidence opens the evidence of a deploy an older facts layer
// read off a job's environment.
const environmentEvidence = "environment: "

// environmentOf is the environment js runs in and whether it requires a
// review before the job runs ("required", "none" or "unknown"): the job's
// privilege's environment (its approval fact when the facts know it, else
// its protection), else a deploy an older facts layer read off it; ok is
// false when the job runs in none.
func environmentOf(js JobSituation) (name, reviewers string, ok bool) {
	if env := js.Privilege.Environment; env.Name != "" {
		switch {
		case env.Reviewers == "required" || env.Reviewers == "none":
			return env.Name, env.Reviewers, true
		case env.Protected == "true":
			return env.Name, "required", true
		case env.Protected == "false":
			return env.Name, "none", true
		}
		return env.Name, "unknown", true
	}
	for _, imp := range js.Impact {
		if name, found := strings.CutPrefix(imp.Evidence, environmentEvidence); imp.Kind == "deploys" && found && name != "" {
			return name, "unknown", true
		}
	}
	return "", "", false
}

// survivingPrivilegeJobs is jobs filtered to the ones whose privilege
// applyPlatformReachRules did not drop entirely: the entry job of a GitHub
// fork pull_request run (no privileged trigger on the same job) loses its
// own privilege outright, and so does any fed job carrying its own fork
// pull request fact. GitLab's fork rule drops protected secrets by name,
// never a whole job's privilege.
func survivingPrivilegeJobs(sit *Situation, jobs []string, kind EntryKind) []string {
	if !forkRunOnly(sit, jobs[0], kind) {
		return jobs
	}
	var out []string
	for _, j := range jobs[1:] {
		if len(sit.Jobs[j].ForkPR) > 0 {
			continue
		}
		out = append(out, j)
	}
	return out
}

// forkRunOnly reports whether an entry of kind into job holds only in a
// GitHub fork pull request run: the job runs on a fork pull request, with
// no privileged trigger, and the entry is that run (fork_pr) or what its
// author controls (untrusted_expression).
func forkRunOnly(sit *Situation, job string, kind EntryKind) bool {
	js := sit.Jobs[job]
	if len(js.ForkPR) == 0 || (kind != EntryForkPR && kind != EntryUntrustedExpression) {
		return false
	}
	return len(js.PrivilegedTriggers) == 0 && sit.Provider != string(ir.ProviderGitLab)
}

// applyPlatformReachRules encodes what the CI platform itself guarantees
// about a fork run, regardless of what the workflow text declares: a
// GitHub fork pull_request run has no secrets and a read-only token; a
// GitLab fork merge-request pipeline exposes every variable except the
// protected ones. A privileged trigger on the same job
// (PrivilegedTriggers) keeps the secrets in play.
func applyPlatformReachRules(sit *Situation, jobs []string, kind EntryKind, r Reach) Reach {
	entryJob := sit.Jobs[jobs[0]]
	if len(entryJob.ForkPR) == 0 || (kind != EntryForkPR && kind != EntryUntrustedExpression) {
		return r
	}
	if len(entryJob.PrivilegedTriggers) > 0 {
		return r // a privileged trigger on the same job: secrets are in play
	}
	if sit.Provider == string(ir.ProviderGitLab) {
		// GitLab: a fork MR pipeline never sees a protected variable. Drop
		// every secret the walked jobs listed as protected, keep the rest.
		protected := map[string]bool{}
		for _, j := range jobs {
			for _, s := range sit.Jobs[j].Privilege.ProtectedSecrets {
				protected[s] = true
			}
		}
		var kept []string
		for _, s := range r.Secrets {
			if !protected[s] {
				kept = append(kept, s)
			}
		}
		r.Secrets = kept
		return r
	}
	// GitHub: a fork pull_request run holds nothing of the entry job's own
	// secrets or write token. A fed job keeps its privilege only if it
	// carries no fork_pr fact of its own (a fed job running on the fork
	// event too is a fork run too, not a privileged escape from one).
	// Collected as a set, not an appended list: two fed jobs can legally
	// share a secret name or a scope, and Reach.Secrets/TokenWrite are
	// documented as the sorted set of what is reachable, not a multiset.
	secrets := map[string]bool{}
	scopes := map[string]bool{}
	r.AllSecrets = false
	for _, j := range jobs[1:] {
		js := sit.Jobs[j]
		if len(js.ForkPR) > 0 {
			continue
		}
		for _, s := range js.Privilege.Secrets {
			secrets[s] = true
		}
		r.AllSecrets = r.AllSecrets || js.Privilege.AllSecrets
		for _, s := range js.Privilege.TokenWrite {
			scopes[s] = true
		}
	}
	r.Secrets = sortedKeys(secrets)
	r.TokenWrite = sortedKeys(scopes)
	return r
}

// liveSituation is sit without the jobs that never run (JobSituation.Dead,
// a job under a constant false condition): they are no branch, no walked
// job and no cache writer. sit itself is never changed.
func liveSituation(sit *Situation) *Situation {
	jobs := make(map[string]JobSituation, len(sit.Jobs))
	for name, js := range sit.Jobs {
		if !js.Dead {
			jobs[name] = js
		}
	}
	if len(jobs) == len(sit.Jobs) {
		return sit
	}
	live := *sit
	live.Jobs = jobs
	return &live
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// impactFromToken is ImpactFact.Source for an impact the job token's write
// scope gives.
const impactFromToken = "token"

// reachKinds lists every reach kind of r, strongest first: one per impact
// kind, in impactOrder (publishes, deploys, writes_repo,
// signs_or_releases), then "secrets" (listed or every secret), "token" (a
// write token), "execution", else "none". A path's ReachKind is the first.
func reachKinds(r Reach) []string {
	var out []string
	for _, k := range impactKinds(r.Impacts) {
		out = append(out, "impact:"+k)
	}
	if len(r.Secrets) > 0 || r.AllSecrets {
		out = append(out, "secrets")
	}
	if len(r.TokenWrite) > 0 {
		out = append(out, "token")
	}
	if r.Executes {
		out = append(out, "execution")
	}
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

// baseTier is rule 6 over the reach with every fact Plumber could not
// decide read as true (an unconfirmed impact, a default token's assumed
// write, and secrets that could not be listed, which cause carries since
// they have no name in r): the tier the unresolvable modifier lowers.
// contributor is set for an entry anyone opening a pull request controls
// (contributorEntry).
func baseTier(r Reach, cause unresolvableCause, contributor bool) PathTier {
	privileged := len(r.Secrets) > 0 || r.AllSecrets || len(r.TokenWrite) > 0 || cause == unresolvableSecrets
	return tierFor(len(r.Impacts) > 0, privileged, r.Executes, contributor)
}

// tierFor is rule 6: impact present and privilege (secrets or tokenWrite)
// -> Critical; a contributor entry with a privilege alone -> Critical
// (anyone opening a pull request holds it); privilege without impact ->
// High; impact without privilege also -> High (the
// deploy/publish/write/sign itself is the damage); Executes without
// privilege also -> High (code running in the job holds the runner); else
// Low. Medium only comes from a modifier lowering a High path.
func tierFor(impact, privileged, executes, contributor bool) PathTier {
	switch {
	case (impact || contributor) && privileged:
		return TierCritical
	case impact, privileged, executes:
		return TierHigh
	}
	return TierLow
}

// gateFindings is every non-dismissed finding whose code role is gate, in a
// deterministic order so gatesOnPath's amplification is order-independent.
func gateFindings(findings []opaengine.Finding) []opaengine.Finding {
	var out []opaengine.Finding
	for _, f := range findings {
		if !f.Dismissed && RoleForCode(ErrorCode(f.Code)) == RoleGate {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ci, cj := out[i].Code+out[i].Job, out[j].Code+out[j].Job
		if ci != cj {
			return ci < cj
		}
		// Code+Job is not total when two gates share both but differ in
		// identity (ISSUE-305's identity includes file). Tie-break on the
		// hash so GateHashes/Modifiers order never depends on input order.
		hi, _ := findingAnchorHash(out[i])
		hj, _ := findingAnchorHash(out[j])
		return hi < hj
	})
	return out
}

// reachWritesRepo is gatesOnPath's own test for whether a branch gate
// should amplify a path at all: a path's reach writes the repository when
// it holds a real repository write, a "contents" write token a walked job
// declares (surviving the platform pruning), or a proven push, publish or
// deploy impact, never the repository's default token alone, which is
// assumed. An unprotected default branch protects nothing on a path that
// only reads, executes or exfiltrates secrets elsewhere, so such a path is
// left alone by gatesOnPath's branch rule, whatever its tier.
func reachWritesRepo(r Reach) bool {
	for _, imp := range r.Impacts {
		switch imp.Kind {
		case "writes_repo", "publishes", "deploys":
			if imp.State == "proven" {
				return true
			}
		}
	}
	return slices.ContainsFunc(partsOf(r), func(part reachPart) bool {
		return !part.assumed && slices.Contains(part.scopes, "contents")
	})
}

// gateCanRaise is reachCanDamage without a write token that is only
// assumed: no gate raises a path whose only privilege is the repository's
// default token.
func gateCanRaise(r Reach, cause unresolvableCause) bool {
	declared := slices.ContainsFunc(partsOf(r), func(part reachPart) bool { return !part.assumed && len(part.scopes) > 0 })
	return len(r.Secrets) > 0 || r.AllSecrets || declared || len(r.Impacts) > 0 || cause == unresolvableSecrets
}

// reachCanDamage reports whether a path's reach holds something a
// protection guards: a secret, listed, every secret of the repository, or
// one Plumber could not list, a write token, or an impact. A reach of code execution alone holds none.
func reachCanDamage(r Reach, cause unresolvableCause) bool {
	return len(r.Secrets) > 0 || r.AllSecrets || len(r.TokenWrite) > 0 || len(r.Impacts) > 0 || cause == unresolvableSecrets
}

// neverAmplifyingGateCodes are gate-role codes whose risk does not depend
// on any pipeline path, so they never amplify one, however they match: a
// hard-coded registry password (ISSUE-704) and Dependabot's insecure code
// execution (ISSUE-901) are both priced as other findings at their own
// severity, on or off any walked job, never through a path's tier.
var neverAmplifyingGateCodes = map[ErrorCode]bool{
	CodeContainerHardcodedCredentials: true,
	CodeDependabotInsecureExec:        true,
}

// branchGateTouchesPath is the one predicate behind both branch-gate
// clauses: the gate's branch is the pipeline's default branch, or the
// subject of an unprotected_push fact on a walked job, AND the path's reach
// writes the repository. An unprotected branch protects nothing on a path
// that only executes or reads, whichever way the path touches the branch.
func branchGateTouchesPath(branch string, jobs []string, sit *Situation, reach Reach) bool {
	if !reachWritesRepo(reach) {
		return false
	}
	if sit.DefaultBranch != "" && branch == sit.DefaultBranch {
		return true
	}
	for _, j := range jobs {
		for _, push := range sit.Jobs[j].Push {
			if push.Subject == branch {
				return true
			}
		}
	}
	return false
}

// gatesOnPath is rule 7's gate amplification: a gate finding on a walked job
// (f.Job in jobs, which also covers ISSUE-305), or a branch gate whose
// Data["branchName"] names an unprotected_push subject of a walked job or
// the pipeline's default branch (sit.DefaultBranch, decoded from the Rego
// result's "defaultBranch"), in both cases only when the path's own reach
// writes the repository (branchGateTouchesPath): such a gate never
// amplifies a path that only executes or reads. Exclusions hold regardless of how many ways a
// gate matches: none of the path's own anchoring findings amplifies the
// path it anchors (ISSUE-501 and ISSUE-505 are both RoleGate AND
// entry-anchoring codes); a gate amplifies a path at most once even when it matches
// through more than one walked job; a branch-protection gate
// (ISSUE-501/ISSUE-505) never amplifies an unprotected_push path,
// entryKind's own kind, since such a path already prices the unprotected
// branch itself and two branch gates on the same branch must not raise
// each other's paths; and neverAmplifyingGateCodes never amplifies any
// path, job-matched or branch-matched alike. A branch gate still
// amplifies every OTHER entry kind that writes the repository, including
// through the default-branch rule, and a job-matched gate outside
// neverAmplifyingGateCodes (ISSUE-305 and the other job-scoped gate
// codes) amplifies every path that walks its job and can do damage
// (reachCanDamage). No gate amplifies a path that cannot: a missing
// protection raises a path only when the protection would have stopped
// something, a privilege or an impact the path reaches.
func gatesOnPath(gates []opaengine.Finding, jobs []string, sit *Situation, anchors map[string]bool, entryKind EntryKind, reach Reach, cause unresolvableCause) []opaengine.Finding {
	if !gateCanRaise(reach, cause) {
		return nil
	}
	onPath := map[string]bool{}
	for _, j := range jobs {
		onPath[j] = true
	}
	seen := map[string]bool{}
	var out []opaengine.Finding
	for _, g := range gates {
		hash, ok := findingAnchorHash(g)
		if ok && anchors[hash] {
			continue // an anchor of this path never amplifies it
		}
		if ok && seen[hash] {
			continue // already counted once for this path
		}
		gateCode := ErrorCode(g.Code)
		if neverAmplifyingGateCodes[gateCode] {
			continue // this gate's risk needs no path, so it never amplifies one
		}
		if entryKind == EntryUnprotectedPush && (gateCode == CodeBranchUnprotected || gateCode == CodeBranchNonCompliant) {
			continue // a branch gate never amplifies an unprotected_push path
		}
		matched := onPath[g.Job]
		if !matched {
			branch, bok := g.Data["branchName"].(string)
			matched = bok && branch != "" && branchGateTouchesPath(branch, jobs, sit, reach)
		}
		if !matched {
			continue
		}
		out = append(out, g)
		if ok {
			seen[hash] = true
		}
	}
	return out
}
