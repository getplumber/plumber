package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	Secrets    []string     `json:"secrets"`    // names reachable by the attacker, after platform rules
	TokenWrite []string     `json:"tokenWrite"` // write scopes reachable by the attacker, after platform rules
	Impacts    []ImpactFact `json:"impacts"`    // impact facts of the walked jobs, concatenated
	// Executes is true for every path: a push runs the job's own steps, and
	// a job with no script of its own (a bare `uses:` push trigger, for
	// instance) still runs whatever that uses target executes. The field
	// stays (the outputs read it, and a future entry kind may need to turn
	// it off) but under the current entry kinds it is always true.
	Executes bool `json:"executes"`
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
	AnchorHash string    `json:"anchorHash"` // identity.PlatformHash of the anchoring finding
	AnchorCode ErrorCode `json:"anchorCode"`
	Jobs       []string  `json:"jobs"` // entry job first, then walked jobs
	Reach      Reach     `json:"reach"`
	ReachKind  string    `json:"reachKind"`  // "impact:<kind>" | "secrets" | "token" | "execution" | "none"
	Modifiers  []string  `json:"modifiers"`  // "private_exposure", "unresolvable", "gate:<code>"
	GateHashes []string  `json:"gateHashes"` // findings that amplified this path
	Exposure   string    `json:"exposure"`

	// Sentence, FindingIDs and Loss are the report fields spec section 4
	// lists, filled by ScoreV4WithExplanations once the path is priced
	// (AssemblePaths leaves them empty): the path's plain-language
	// sentence; the anchor's hash, then the gates', then the consumed
	// privilege findings'; and the path's share of its group's capped
	// loss, rounded to one decimal.
	Sentence   string   `json:"sentence"`
	FindingIDs []string `json:"findingIds"`
	Loss       float64  `json:"loss"`

	// cause is set alongside the "unresolvable" modifier when neither the
	// entry fact nor an impact fact is itself the unresolvable one, so
	// explain.go's modifierSentences can name the real cause. Never
	// serialized, never read outside this package.
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
}

// MarshalJSON writes modifiers, gateHashes and findingIds as arrays, empty
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

// contributorEntries are the entry kinds a repository's visibility actually
// changes the attacker population for: a fork PR, a pull_request_target run
// on fork content, or an untrusted expression fed by either. A tag hijack
// (mutable_dependency) or a push to an unprotected branch does not care who
// can see the repository.
var contributorEntries = map[EntryKind]bool{EntryForkPR: true, EntryPRTarget: true, EntryUntrustedExpression: true}

// AssemblePaths joins entry-role (and branch-gate) findings with the
// situation facts of their job into attack paths (spec section 2). It is a
// pure function of its inputs: the output order never depends on the input
// order (TestOutputOrderIsDeterministicUnderShuffledInput).
//
// One known gap, tracked separately rather than blocking this assembler:
// Feeds carries no GitLab stage-ordered edges yet (a job without
// needs/dependencies downloads every earlier stage, but the IR has no
// Stage field). The walk below is complete on GitHub and on GitLab
// pipelines using needs/dependencies, and under-reports reach on classic
// stage-ordered GitLab pipelines until that follow-up lands.
func AssemblePaths(findings []opaengine.Finding, sit *Situation) []AttackPath {
	if sit == nil || len(sit.Jobs) == 0 {
		return nil
	}
	exposure := sit.Exposure
	if exposure == "" {
		exposure = ir.VisibilityUnknown
	}
	gates := gateFindings(findings)
	seen := map[string]bool{}
	var out []AttackPath
	for _, f := range sortedFindings(findings) {
		if f.Dismissed {
			continue
		}
		anchor, ok := findingAnchorHash(f)
		if !ok {
			// Codeless finding: nothing to key a path identity on.
			continue
		}
		for _, a := range anchorsFor(f, sit) {
			jobs := walkedJobs(a.entryJob, sit)
			reach, unresolvable, cause, surviving := reachOver(sit, jobs, a.kind)
			for _, reachKind := range reachKinds(reach) {
				key := anchor + "|" + a.entryJob + "|" + reachKind
				if seen[key] {
					continue
				}
				seen[key] = true
				p := AttackPath{
					EntryKind: a.kind, Entry: a.fact, AnchorHash: anchor, AnchorCode: ErrorCode(f.Code),
					Jobs: jobs, Reach: reach, ReachKind: reachKind, Exposure: exposure, State: PathProven,
					survivingJobs: surviving,
				}
				p.BaseTier = baseTier(reach, reachKind)
				p.Tier = p.BaseTier
				if exposure == ir.VisibilityPrivate && contributorEntries[a.kind] {
					p.Tier = tierShift(p.Tier, -1)
					p.Modifiers = append(p.Modifiers, "private_exposure")
				}
				if a.fact.State == "unresolvable" || unresolvable {
					p.Tier = tierShift(p.Tier, -1)
					p.State = PathUnverified
					p.Modifiers = append(p.Modifiers, "unresolvable")
					p.cause = cause
				}
				for _, g := range gatesOnPath(gates, jobs, sit, anchor, a.kind, reach) {
					p.Tier = tierShift(p.Tier, 1)
					p.Modifiers = append(p.Modifiers, "gate:"+g.Code)
					if branch, ok := g.Data["branchName"].(string); ok && branch != "" {
						if p.gateBranches == nil {
							p.gateBranches = map[string]string{}
						}
						p.gateBranches[g.Code] = branch
					}
					if gateHash, ok := findingAnchorHash(g); ok {
						p.GateHashes = append(p.GateHashes, gateHash)
					}
				}
				sum := sha256.Sum256([]byte(key))
				p.ID = hex.EncodeToString(sum[:])[:16]
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if TierRank(out[i].Tier) != TierRank(out[j].Tier) {
			return TierRank(out[i].Tier) > TierRank(out[j].Tier)
		}
		return out[i].ID < out[j].ID
	})
	return out
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

// pathAnchor is one entry fact a finding anchors to, together with the job
// that becomes the entry job of the path walked from it.
type pathAnchor struct {
	kind     EntryKind
	fact     EntryFact
	entryJob string
}

// anchorsFor returns every entry fact a finding anchors to (spec section 2,
// rules 1 and 2).
//
// An entry-role finding with a job anchors inside that job's facts: the
// fact of the finding's kind whose subject matches the finding's structured
// data, falling back to the first fact of that kind when none matches. An
// entry-role finding always anchors a path (spec section 2, "findings on no
// path"): when the job carries no fact of the finding's own kind at all,
// the anchor is synthesized from the finding itself (syntheticEntryFact)
// rather than dropped to hygiene, so it still assembles into a path through
// the normal rules below (reach from the job, unresolvable, Low when
// nothing is reachable). Only when the finding's own job is absent from
// the situation entirely is there nothing to walk, and the finding stays
// hygiene; this package has no logger wired yet to also report that at
// Debug.
//
// An entry-role finding with no job is ISSUE-404 (always) or the GitLab
// branch of ISSUE-402 (includes are pipeline-level, not job-level). Both are
// always EntryMutableDependency. The include facts they anchor to
// (include_mutable_dependencies in situation.rego) attach to every job that
// carries the include's file, or to every job when none does, so this scans
// every JobSituation for a mutable_dependency fact whose subject matches the
// finding (includePathMatches: an exact match, or a "source@ref" prefix
// match, never a substring match) and anchors one path per job that has
// one; no fallback-to-first here, since falling back across unrelated jobs
// would anchor the finding everywhere.
//
// A gate-role finding anchors the unprotected_push fact it is itself about
// (ISSUE-501/ISSUE-505): every job whose unprotected_push fact names the
// finding's branch becomes an entry job of its own path. Spec:
// "findings on no path"; such a finding anchoring a path is not counted as
// a gate loss, and does not itself amplify the path it anchors: gatesOnPath
// excludes a gate whose own hash equals the path's AnchorHash, since
// ISSUE-501/505 would otherwise also match their own path through the
// branch clause (their Data["branchName"] is exactly the subject they
// anchor).
func anchorsFor(f opaengine.Finding, sit *Situation) []pathAnchor {
	code := ErrorCode(f.Code)
	if kind, isEntry := EntryKindForCode(code); isEntry {
		if f.Job != "" {
			js, ok := sit.Jobs[f.Job]
			if !ok {
				// The finding's own job is absent from the situation: nothing
				// to walk, so this finding stays hygiene.
				return nil
			}
			if fact, ok := matchEntryFact(f, js.Entries, kind); ok {
				return []pathAnchor{{kind: kind, fact: fact, entryJob: f.Job}}
			}
			// Spec section 2, "findings on no path": an entry-role finding
			// always anchors a path, even when the job carries no fact of its
			// own kind. Synthesize one from the finding so it still assembles
			// normally rather than dropping silently to hygiene.
			return []pathAnchor{{kind: kind, fact: syntheticEntryFact(f, kind), entryJob: f.Job}}
		}
		if kind != EntryMutableDependency {
			return nil
		}
		var anchors []pathAnchor
		for name, js := range sit.Jobs {
			for _, e := range js.Entries {
				if e.Kind == kind && includePathMatches(f, e.Subject) {
					anchors = append(anchors, pathAnchor{kind: kind, fact: e, entryJob: name})
				}
			}
		}
		// No job across the whole pipeline carries a matching include fact:
		// anchors stays nil and the finding falls to hygiene, the accepted
		// limit for a job-less finding. Unlike the job-bearing branch above,
		// nothing is synthesized here: a job-bearing finding synthesizes
		// against its own one job, but a job-less finding has no single job
		// to synthesize against, and guessing one from the whole pipeline
		// would risk anchoring an unrelated include.
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
		for _, e := range js.Entries {
			if e.Kind == EntryUnprotectedPush && e.Subject == branch {
				anchors = append(anchors, pathAnchor{kind: EntryUnprotectedPush, fact: e, entryJob: name})
			}
		}
	}
	sortAnchorsByJob(anchors)
	return anchors
}

func sortAnchorsByJob(anchors []pathAnchor) {
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].entryJob < anchors[j].entryJob })
}

// walkedJobs is the entry job followed by its fed jobs, deduped, and
// filtered to jobs the situation actually knows about, so a Feeds entry
// naming a missing job never creates a phantom walk step, and a job that
// feeds itself never gets its reach (secrets, impacts) counted twice.
func walkedJobs(entryJob string, sit *Situation) []string {
	seen := map[string]bool{entryJob: true}
	jobs := []string{entryJob}
	for _, fed := range sit.Jobs[entryJob].Feeds {
		if seen[fed] {
			continue
		}
		if _, ok := sit.Jobs[fed]; !ok {
			continue
		}
		seen[fed] = true
		jobs = append(jobs, fed)
	}
	return jobs
}

// matchEntryFact finds the entry fact of the given kind whose subject
// matches the finding, falling back to the first fact of that kind when
// none matches (rule 1).
func matchEntryFact(f opaengine.Finding, entries []EntryFact, kind EntryKind) (EntryFact, bool) {
	var first *EntryFact
	for i := range entries {
		e := &entries[i]
		if e.Kind != kind {
			continue
		}
		if first == nil {
			first = e
		}
		if subjectMatches(f, e.Subject) {
			return *e, true
		}
	}
	if first != nil {
		return *first, true
	}
	return EntryFact{}, false
}

// syntheticEntryFact builds the entry fact an entry-role finding anchors to
// when its job carries no fact of the finding's own kind at all (spec
// section 2, "findings on no path": an entry-role finding always anchors a
// path). The subject is read from whichever structured-data field
// subjectMatches already reads for this code, falling back to the
// finding's message; the evidence is the finding's own message, capped the
// same way a rendered sentence is. State "unresolvable" marks the path
// unverified and lowers its tier, since nothing on the job actually
// confirms this kind of entry, only the finding's own say-so.
func syntheticEntryFact(f opaengine.Finding, kind EntryKind) EntryFact {
	subject := ""
	for _, key := range []string{"uses", "image", "expression", "variableName", "branchName", "url", "includePath"} {
		if v, ok := f.Data[key].(string); ok && v != "" {
			subject = v
			break
		}
	}
	if subject == "" {
		subject = f.Message
	}
	return EntryFact{Kind: kind, State: "unresolvable", Evidence: truncateWords(f.Message, 200), Subject: subject}
}

// subjectMatches reports whether one of the finding's structured data
// fields, or its message, names the fact's subject. Include facts carry a
// "source@ref" subject while ISSUE-404/ISSUE-402 only ever report the bare
// source as includePath, so the comparison is substring-symmetric rather
// than exact. Used only for findings that carry a Job: the job-less
// include scan uses includePathMatches instead, since a loose match there
// would anchor an unrelated include in every job across the pipeline.
func subjectMatches(f opaengine.Finding, subject string) bool {
	if subject == "" {
		return false
	}
	for _, key := range []string{"uses", "image", "expression", "variableName", "branchName", "url", "includePath"} {
		if v, ok := f.Data[key].(string); ok && v != "" && (v == subject || strings.Contains(v, subject) || strings.Contains(subject, v)) {
			return true
		}
	}
	return f.Message != "" && strings.Contains(f.Message, subject)
}

// includePathMatches is the exact matching rule for a job-less include
// finding (ISSUE-404, or the GitLab branch of ISSUE-402): the fact's
// subject either
// equals the finding's includePath, or starts with includePath+"@" (the
// "source@ref" shape include facts carry). Never a substring match in
// either direction, and never splitting the subject on "@", so a bare
// filename fragment or a sibling path sharing a suffix never anchors an
// unrelated include.
func includePathMatches(f opaengine.Finding, subject string) bool {
	v, ok := f.Data["includePath"].(string)
	if !ok || v == "" || subject == "" {
		return false
	}
	return subject == v || strings.HasPrefix(subject, v+"@")
}

// reachOver unions privilege and impact across the walked jobs, then applies
// the platform rules. unresolvable reports whether any fact on the path
// could not be decided: an unresolvable SecretsState or impact, or a default
// (assumed) token write with no secret and no declared token anywhere on
// the path, since a default token is a guess about what the runner falls
// back to, not a read fact. cause names which of those it was, for the
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
		for _, s := range js.Privilege.TokenWrite {
			scopes[s] = true
		}
		for _, imp := range js.Impact {
			r.Impacts = append(r.Impacts, imp)
			if imp.State == "unresolvable" {
				unresolvable = true
			}
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
	hasDeclaredToken := false
	hasDefaultToken := false
	for _, name := range surviving {
		js, ok := sit.Jobs[name]
		if !ok {
			continue
		}
		if js.Privilege.SecretsState == "unresolvable" {
			unresolvable = true
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
	// This check runs over the PRUNED reach, not the pre-prune one. A
	// GitHub fork pull_request run drops its default token entirely (there
	// never was a write token to begin with), so a dropped default token
	// must not mark the path unresolvable; gate on the pruned TokenWrite
	// so an emptied-out token is simply absent, not an open question.
	if len(r.TokenWrite) > 0 && len(r.Secrets) == 0 && !hasDeclaredToken && hasDefaultToken {
		unresolvable = true
		if cause == "" {
			cause = unresolvableDefaultToken
		}
	}
	return r, unresolvable, cause, surviving
}

// survivingPrivilegeJobs is jobs filtered to the ones whose privilege
// applyPlatformReachRules did not drop entirely: the entry job of a GitHub
// fork pull_request run (no pull_request_target override) loses its own
// privilege outright, and so does any fed job carrying its own fork_pr
// fact. Every other case, including GitLab's fork rule (which drops
// protected secrets by name, never a whole job's privilege), survives
// unchanged. Used by the unresolvable check above so a dropped job's token
// source or secrets state cannot make a pruned path unresolvable.
func survivingPrivilegeJobs(sit *Situation, jobs []string, kind EntryKind) []string {
	entryJob := sit.Jobs[jobs[0]]
	forkFact, isFork := entryFactOfKind(entryJob, EntryForkPR)
	if !isFork || (kind != EntryForkPR && kind != EntryUntrustedExpression) {
		return jobs
	}
	if entryFactPresent(entryJob, EntryPRTarget) {
		return jobs
	}
	if strings.HasPrefix(forkFact.Evidence, "rules:") {
		return jobs // GitLab: secrets filtered by name, no job dropped outright.
	}
	var out []string
	for _, j := range jobs[1:] {
		if entryFactPresent(sit.Jobs[j], EntryForkPR) {
			continue
		}
		out = append(out, j)
	}
	return out
}

// applyPlatformReachRules encodes what the CI platform itself guarantees
// about a fork run, regardless of what the workflow text declares: a
// GitHub fork pull_request run has no secrets and a read-only token; a
// GitLab fork merge-request pipeline exposes every variable except the
// protected ones. Situation carries no provider field yet; the
// provider is derived from the fork entry fact's own evidence (GitLab's
// facts read "rules: ...", GitHub's read "on: ..."), the agreed seam until
// a real provider field lands on Situation.
func applyPlatformReachRules(sit *Situation, jobs []string, kind EntryKind, r Reach) Reach {
	entryJob := sit.Jobs[jobs[0]]
	forkFact, isFork := entryFactOfKind(entryJob, EntryForkPR)
	if !isFork || (kind != EntryForkPR && kind != EntryUntrustedExpression) {
		return r
	}
	if entryFactPresent(entryJob, EntryPRTarget) {
		return r // a privileged trigger on the same job: secrets are in play
	}
	if strings.HasPrefix(forkFact.Evidence, "rules:") {
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
	for _, j := range jobs[1:] {
		js := sit.Jobs[j]
		if entryFactPresent(js, EntryForkPR) {
			continue
		}
		for _, s := range js.Privilege.Secrets {
			secrets[s] = true
		}
		for _, s := range js.Privilege.TokenWrite {
			scopes[s] = true
		}
	}
	r.Secrets = sortedKeys(secrets)
	r.TokenWrite = sortedKeys(scopes)
	return r
}

// entryFactOfKind returns the job's entry fact of the given kind, if any.
func entryFactOfKind(js JobSituation, kind EntryKind) (EntryFact, bool) {
	for _, e := range js.Entries {
		if e.Kind == kind {
			return e, true
		}
	}
	return EntryFact{}, false
}

// entryFactPresent reports whether the job carries an entry fact of the
// given kind, without needing the fact itself.
func entryFactPresent(js JobSituation, kind EntryKind) bool {
	_, ok := entryFactOfKind(js, kind)
	return ok
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// reachKinds lists the reach kinds a path splits into: one per impact kind
// present, else the strongest privilege, else execution, else none (rule 5:
// a reach with two impact kinds yields two paths sharing the anchor).
func reachKinds(r Reach) []string {
	kinds := map[string]bool{}
	for _, imp := range r.Impacts {
		kinds["impact:"+imp.Kind] = true
	}
	if len(kinds) > 0 {
		return sortedKeys(kinds)
	}
	switch {
	case len(r.Secrets) > 0:
		return []string{"secrets"}
	case len(r.TokenWrite) > 0:
		return []string{"token"}
	case r.Executes:
		return []string{"execution"}
	}
	return []string{"none"}
}

// baseTier is rule 6: impact present and (secrets or tokenWrite) ->
// Critical; secrets or tokenWrite without impact -> High; impact without
// privilege also -> High (the deploy/publish/write/sign itself is the
// damage, a deliberate scope decision to flag in the PR body); Executes
// without privilege -> Medium; else Low.
func baseTier(r Reach, reachKind string) PathTier {
	privileged := len(r.Secrets) > 0 || len(r.TokenWrite) > 0
	switch {
	case strings.HasPrefix(reachKind, "impact:") && privileged:
		return TierCritical
	case strings.HasPrefix(reachKind, "impact:"), privileged:
		return TierHigh
	case r.Executes:
		return TierMedium
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

// reachWritesRepo is gatesOnPath's own test for whether a default-branch
// gate should amplify a path at all: a path's reach writes the repository
// when it carries a writes_repo impact fact, or a "contents" write token
// that survived the platform pruning. An unprotected default branch
// protects nothing on a path that only reads, executes or exfiltrates
// secrets elsewhere, so such a path is left alone by gatesOnPath's
// default-branch rule, whatever its tier.
func reachWritesRepo(r Reach) bool {
	for _, imp := range r.Impacts {
		if imp.Kind == "writes_repo" {
			return true
		}
	}
	for _, scope := range r.TokenWrite {
		if scope == "contents" {
			return true
		}
	}
	return false
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
		for _, e := range sit.Jobs[j].Entries {
			if e.Kind == EntryUnprotectedPush && e.Subject == branch {
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
// gate matches: the path's own anchoring finding never amplifies the path
// it anchors (ISSUE-501 and ISSUE-505 are both RoleGate AND entry-anchoring
// codes); a gate amplifies a path at most once even when it matches
// through more than one walked job; and a branch-protection gate
// (ISSUE-501/ISSUE-505) never amplifies an unprotected_push path,
// entryKind's own kind, since such a path already prices the unprotected
// branch itself and two branch gates on the same branch must not raise
// each other's paths. A branch gate still amplifies every OTHER entry
// kind that writes the repository, including through the default-branch
// rule.
func gatesOnPath(gates []opaengine.Finding, jobs []string, sit *Situation, anchor string, entryKind EntryKind, reach Reach) []opaengine.Finding {
	onPath := map[string]bool{}
	for _, j := range jobs {
		onPath[j] = true
	}
	seen := map[string]bool{}
	var out []opaengine.Finding
	for _, g := range gates {
		hash, ok := findingAnchorHash(g)
		if ok && hash == anchor {
			continue // the anchor of this path never amplifies it
		}
		if ok && seen[hash] {
			continue // already counted once for this path
		}
		gateCode := ErrorCode(g.Code)
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
