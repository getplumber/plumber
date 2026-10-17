package ir

import (
	"strings"

	"github.com/getplumber/plumber/internal/expr"
)

// GateClass says who can make a privileged job run.
type GateClass string

// Gate classes.
const (
	// GateOutsider means an outsider, acting alone, can make the job run
	// with its event action of choice: the condition is true for at
	// least one type an outsider can produce.
	GateOutsider GateClass = "outsider"
	// GateMaintainerApproved means the job only runs after some
	// maintainer action: a label, the author's identity, a merge, or a
	// protected environment's required reviewers.
	GateMaintainerApproved GateClass = "maintainer_approved"
	// GateSameRepo means the job only runs for code already in the
	// repository itself (no fork head), never for an outsider's pull
	// request.
	GateSameRepo GateClass = "same_repo"
	// GateNoOutsider means the privileged run never executes the job at
	// all: its condition names other events (github.event_name, or an
	// event action the trigger never produces), so it only runs on the
	// repository's own events, never on one an outsider starts.
	GateNoOutsider GateClass = "no_outsider"
	// GateUnknown means the facts available do not determine whether an
	// outsider can make the job run.
	GateUnknown GateClass = "unknown"
	// GateInsider means the party who can change what runs is a first
	// party (the scanned repository's own owner or domain) or a sibling
	// organisation's redirected repository: not an outsider, and not
	// gated behind a maintainer action either, but close enough to home
	// that a path through it holds at the Medium ceiling rather than
	// Critical (control/trust.go's actorFor).
	GateInsider GateClass = "insider"
)

// Gate is the result of classifying who can trigger a job, given the
// facts an outsider alone controls.
type Gate struct {
	Class     GateClass `json:"class"`
	Reason    string    `json:"reason,omitempty"`
	PinnedSha bool      `json:"pinnedSha,omitempty"`
	// Unknown lists the references ClassifyGate could not resolve when
	// Class is GateUnknown.
	Unknown []string `json:"unknown,omitempty"`
}

// labelRefs, authorRefs, actorRefs, mergedRefs and sameRepoRefs are the
// fact families causalReason hides one at a time to find which one a
// False result depends on. authorRefs is the pull request's author alone,
// the identity an outsider can never take ("author <login>"); actorRefs
// is whoever triggered the event or wrote the comment or issue, which an
// outsider can make a bot be (a synchronize event on their own pull
// request that the bot updates), read "actor <login>".
var (
	labelRefs = []string{
		"github.event.label.name",
		"github.event.pull_request.labels.*.name",
	}
	authorRefs = []string{
		"github.event.pull_request.user.login",
	}
	actorRefs = []string{
		"github.actor",
		"github.triggering_actor",
		"github.event.comment.user.login",
		"github.event.issue.user.login",
		"github.event.sender.login",
	}
	mergedRefs = []string{
		"github.event.pull_request.merged",
	}
	sameRepoRefs = []string{
		"github.event.pull_request.head.repo.full_name",
		"github.event.pull_request.head.repo.fork",
		"github.event.workflow_run.head_repository.full_name",
		"github.event.workflow_run.head_repository.fork",
	}
)

// ClassifyGate decides who can make job run: an outsider on their own,
// a maintainer who approved it (a label, the author's identity, a
// merge, or a protected environment), only code already in the
// repository, or unknown.
//
// trigger is the job's GitHub Actions event name and types is that
// event's `types:` filter (empty means every type fires). env and known
// carry the job's deployment environment protection rules, known being
// whether the provider could actually read them; when known is false
// the environment contributes nothing to the classification, it is
// neither evidence of a gate nor of its absence. base is the branch a
// pull request targets in the model, the repository's default branch
// ("" reads main): what github.ref, github.ref_name and github.base_ref
// name on a pull_request_target run.
func ClassifyGate(job Job, byName map[string]Job, trigger string, types []string, env Environment, known bool, base string) Gate {
	pinned := checkoutPinnedSha(job)

	if known && env.RequiredReviewers {
		return Gate{
			Class:     GateMaintainerApproved,
			Reason:    "environment " + env.Name + " requires reviewers",
			PinnedSha: pinned,
		}
	}

	producible, unknownTypes := splitTypes(trigger, types)

	if len(unknownTypes) > 0 {
		return classifyUnknownTypes(job, byName, trigger, base, producible, unknownTypes, pinned)
	}

	if len(types) > 0 && len(producible) == 0 {
		// Every declared type is maintainer-produced (e.g. `types:
		// [labeled]`): an outsider can never even make the event fire.
		// The condition itself may still explain a more specific cause
		// (it often checks the very label that gates the type filter),
		// so it is still worth evaluating; only fall back to the bare
		// type gate when the condition would otherwise read as reachable.
		class, reason, unknown := evaluateTypes(job, byName, trigger, base, types)
		if class == GateOutsider || class == GateUnknown {
			return Gate{
				Class:     GateMaintainerApproved,
				Reason:    "types " + strings.Join(types, " "),
				PinnedSha: pinned,
			}
		}
		return Gate{Class: class, Reason: reason, PinnedSha: pinned, Unknown: unknown}
	}

	class, reason, unknown := evaluateTypes(job, byName, trigger, base, producible)
	return Gate{Class: class, Reason: reason, PinnedSha: pinned, Unknown: unknown}
}

// classifyUnknownTypes classifies a job whose `types:` filter names a
// type neither list knows (unknownTypes, splitTypes): an outsider may be
// able to produce it, so the condition is evaluated for it as for an
// outsider's type, and a condition it does not close reads unknown
// (github.event.action unresolved), never a maintainer's gate. The
// outsider-producible types of the filter are evaluated as usual, and
// the weaker of the two results is the gate.
func classifyUnknownTypes(job Job, byName map[string]Job, trigger, base string, producible, unknownTypes []string, pinned bool) Gate {
	var known *Gate
	if len(producible) > 0 {
		class, reason, unknown := evaluateTypes(job, byName, trigger, base, producible)
		if class == GateOutsider {
			return Gate{Class: class, PinnedSha: pinned}
		}
		known = &Gate{Class: class, Reason: reason, PinnedSha: pinned, Unknown: unknown}
	}
	class, reason, unknown := evaluateTypes(job, byName, trigger, base, unknownTypes)
	if class == GateOutsider || class == GateUnknown {
		if known != nil {
			unknown = appendUnique(append([]string(nil), known.Unknown...), unknown)
		}
		return Gate{Class: GateUnknown, PinnedSha: pinned, Unknown: appendUnique(unknown, []string{"github.event.action"})}
	}
	g := Gate{Class: class, Reason: reason, PinnedSha: pinned}
	if known != nil {
		return weakerGate(*known, g)
	}
	return g
}

// evaluateTypes classifies job against each of testTypes in turn: True
// for at least one makes it GateOutsider; False for every one classifies
// the cause of the first False; anything else is GateUnknown with the
// union of unresolved references.
func evaluateTypes(job Job, byName map[string]Job, trigger, base string, testTypes []string) (GateClass, string, []string) {
	allFalse := true
	var falseType, falseJobName string
	var unknown []string

	for _, t := range testTypes {
		facts := newOutsiderFacts(trigger, t, job, byName, base)
		val, jobName := evalJobCondition(job, byName, facts, map[string]bool{})
		switch val {
		case expr.True:
			return GateOutsider, "", nil
		case expr.False:
			if falseType == "" {
				falseType = t
				falseJobName = jobName
			}
		default:
			allFalse = false
			unknown = appendUnique(unknown, unresolvedRefs(job, facts))
		}
	}

	if allFalse && falseType != "" {
		target := job
		if falseJobName != "" && falseJobName != job.Name {
			if j, ok := byName[falseJobName]; ok {
				target = j
			}
		}
		facts := newOutsiderFacts(trigger, falseType, job, byName, base)
		class, reason := causalReason(target.If, facts)
		return class, reason, nil
	}
	return GateUnknown, "", unknown
}

// evalJobCondition evaluates job's own `If` against facts, first
// walking job.Needs transitively: a predecessor whose own `If` is False
// for the outsider makes job False too, since job can never run without
// it. visited guards against a cyclic Needs graph; it is shared across
// the whole walk so no job is evaluated twice. It returns the value and,
// when the value is False, which job's own `If` decided it (job itself
// or a predecessor).
//
// A job whose own `If` calls a status function (always(), failure(),
// cancelled(), a negated success(): expr.HasStatusCall) runs even when a
// predecessor was skipped, so no predecessor's False reaches it: its own
// condition decides, and what a predecessor would add stays unknown.
func evalJobCondition(job Job, byName map[string]Job, facts outsiderFacts, visited map[string]bool) (expr.Value, string) {
	if visited[job.Name] {
		return expr.Unknown, ""
	}
	visited[job.Name] = true

	needs := job.Needs
	if expr.HasStatusCall(job.If) {
		needs = nil
	}
	for _, dep := range needs {
		pred, ok := byName[dep]
		if !ok {
			continue
		}
		val, falseJob := evalJobCondition(pred, byName, facts, visited)
		if val == expr.False {
			return expr.False, falseJob
		}
	}

	val := expr.Eval(job.If, facts)
	if val == expr.False {
		return expr.False, job.Name
	}
	return val, ""
}

// gateFamily is one family of facts causalReason hides to find what a
// False result depends on.
type gateFamily struct {
	refs  []string
	class GateClass
	name  string
}

// Fact families, in the order causalReason tries them when no strong
// gate holds alone: weakest first, so a disjunction that one weak
// branch opens is named by that branch.
var (
	actorFamily    = gateFamily{actorRefs, GateMaintainerApproved, "actor"}
	labelFamily    = gateFamily{labelRefs, GateMaintainerApproved, "label"}
	mergedFamily   = gateFamily{mergedRefs, GateMaintainerApproved, "merged"}
	authorFamily   = gateFamily{authorRefs, GateMaintainerApproved, "author"}
	sameRepoFamily = gateFamily{sameRepoRefs, GateSameRepo, "same repository"}
	gateFamilies   = []gateFamily{actorFamily, labelFamily, mergedFamily, authorFamily, sameRepoFamily}
)

// causalReason explains why ifText evaluated False for the outsider.
//
// The event family is read first (eventReason): a condition False because
// it names other events than the privileged run's proves the run never
// executes the job (GateNoOutsider), when that holds alone.
//
// The two gates that let no outsider in at all (a bot as the pull
// request's author, the same repository: control/actor.go's
// noOutsiderGate) are read first, and only when they hold alone: the
// condition stays False with every other family hidden, and stops being
// False once that family is hidden too. A bot author check next to an
// actor check (`author == 'dependabot[bot]' || github.actor ==
// 'dependabot[bot]'`) does not hold alone: whoever makes the bot the
// actor opens the job.
//
// Otherwise it hides each family in turn, weakest first (actor, label,
// merged, author, same repository), and names the first whose hiding
// turns the result from False to Unknown. A strong family reached there
// failed to hold alone, so it never reads as strong: a bot author reads
// the bare "author" and the same repository the bare "condition", both a
// maintainer's gate that keeps the path. No family explaining it falls
// back to the bare "condition" reason.
func causalReason(ifText string, facts outsiderFacts) (GateClass, string) {
	if reason, ok := eventReason(ifText, facts); ok {
		return GateNoOutsider, reason
	}
	allHidden := facts
	for _, fam := range gateFamilies {
		allHidden = allHidden.withHidden(fam.refs)
	}
	if expr.Eval(ifText, allHidden) != expr.False {
		for _, strong := range []gateFamily{authorFamily, sameRepoFamily} {
			others := facts
			for _, fam := range gateFamilies {
				if fam.name != strong.name {
					others = others.withHidden(fam.refs)
				}
			}
			if expr.Eval(ifText, others) != expr.False {
				continue
			}
			if strong.class == GateSameRepo {
				// Same-repo has no literal form: "same repository" is
				// already the full reason.
				return strong.class, strong.name
			}
			if literal, ok := expr.ComparedLiteral(ifText, strong.refs); ok && strings.HasSuffix(literal, "[bot]") {
				return strong.class, strong.name + " " + literal
			}
		}
	}
	for _, fam := range gateFamilies {
		hidden := facts.withHidden(fam.refs)
		if expr.Eval(ifText, hidden) != expr.Unknown {
			continue
		}
		literal, hasLiteral := expr.ComparedLiteral(ifText, fam.refs)
		switch {
		case fam.class == GateSameRepo:
			return GateMaintainerApproved, "condition"
		case fam.name == authorFamily.name && hasLiteral && strings.HasSuffix(literal, "[bot]"):
			return fam.class, fam.name
		case hasLiteral:
			return fam.class, fam.name + " " + literal
		}
		return fam.class, fam.name
	}
	return GateMaintainerApproved, "condition"
}

// eventNameRef and eventActionRef are the event family: which event and
// which of its actions the run is. Neither is an outsider's choice: the
// trigger and its type decide them.
const (
	eventNameRef   = "github.event_name"
	eventActionRef = "github.event.action"
)

// eventFamilyRefs is the event family of ifText on trigger: the event
// name, and the event action too when every value the condition compares
// it to is one the trigger never delivers (triggerActivityTypes), so the
// comparison names another event's run. An action compared to a value the
// trigger can deliver (a maintainer's `labeled`) is no proof the
// privileged run skips the job: actionJoins is false.
func eventFamilyRefs(ifText, trigger string) (refs []string, actionJoins bool) {
	refs = []string{eventNameRef}
	delivered, modeled := triggerActivityTypes[trigger]
	literals := expr.ComparedLiterals(ifText, []string{eventActionRef})
	if !modeled || len(literals) == 0 {
		return refs, false
	}
	for _, l := range literals {
		for _, d := range delivered {
			if strings.EqualFold(l, d) {
				return refs, false
			}
		}
	}
	return append(refs, eventActionRef), true
}

// eventReason reports whether ifText, False for the outsider, is False
// because the privileged run is not one the job runs on: hiding the event
// family opens it, and it stays False with every other family hidden (the
// event holds alone; an event action the family does not take in is
// hidden too, since a maintainer's type could open it). The reason is
// "event <literal>", the event or action the condition names, or the bare
// "event" when it names none (a fromJSON list).
func eventReason(ifText string, facts outsiderFacts) (string, bool) {
	refs, actionJoins := eventFamilyRefs(ifText, facts.trigger)
	if expr.Eval(ifText, facts.withHidden(refs)) == expr.False {
		return "", false
	}
	others := facts
	for _, fam := range gateFamilies {
		others = others.withHidden(fam.refs)
	}
	if !actionJoins {
		others = others.withHidden([]string{eventActionRef})
	}
	if expr.Eval(ifText, others) != expr.False {
		return "", false
	}
	if literal, ok := expr.ComparedLiteral(ifText, refs); ok {
		return "event " + literal, true
	}
	return "event", true
}

// unresolvedRefs lists the references job.If reads that facts cannot
// resolve, for a GateUnknown result.
func unresolvedRefs(job Job, facts outsiderFacts) []string {
	var out []string
	for _, ref := range expr.Refs(job.If) {
		if _, ok := facts.Resolve(ref); !ok {
			out = append(out, ref)
		}
	}
	return out
}

// appendUnique appends the elements of add to base that base does not
// already contain, preserving base's existing order.
func appendUnique(base, add []string) []string {
	for _, a := range add {
		found := false
		for _, b := range base {
			if a == b {
				found = true
				break
			}
		}
		if !found {
			base = append(base, a)
		}
	}
	return base
}

// checkoutPinnedSha reports whether every actions/checkout step of job
// that checks out the pull request or workflow_run head pins it to the
// head commit SHA, and there is at least one: what runs is then the
// commit the event named, never one pushed after it. One checkout of the
// head by branch name makes the job not pinned.
func checkoutPinnedSha(job Job) bool {
	pinned := false
	for _, a := range job.Uses {
		if !strings.HasPrefix(a.Uses, "actions/checkout") {
			continue
		}
		ref, ok := a.With["ref"].(string)
		if !ok || !IsPRHeadRef(ref) {
			continue
		}
		if !IsPRHeadShaRef(ref) {
			return false
		}
		pinned = true
	}
	return pinned
}

// prHeadRefMarkers are the fragments of a checkout ref that name the code
// of a pull request or of another workflow's run: its head commit, its
// head branch, its number (refs/pull/N/...).
var prHeadRefMarkers = []string{
	"github.event.pull_request.head.",
	"github.head_ref",
	"github.event.workflow_run.head_",
	"github.event.number",
	"refs/pull/",
}

// IsPRHeadRef reports whether a checkout ref (wrapped in ${{ }} or not)
// checks out the code of a pull request or of another workflow's run.
func IsPRHeadRef(ref string) bool {
	for _, m := range prHeadRefMarkers {
		if strings.Contains(ref, m) {
			return true
		}
	}
	return false
}

// IsPRHeadShaRef reports whether a checkout ref is the head commit SHA of
// the pull request or of the workflow run: what runs is the commit the
// event names, nothing pushed after it.
func IsPRHeadShaRef(ref string) bool {
	ref = stripRefWrapper(ref)
	return ref == "github.event.pull_request.head.sha" || ref == "github.event.workflow_run.head_sha"
}

// stripRefWrapper trims whitespace and, when present, the "${{ ... }}"
// wrapper around a `with: { ref: ... }` value.
func stripRefWrapper(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "${{")
	s = strings.TrimSuffix(s, "}}")
	return strings.TrimSpace(s)
}
