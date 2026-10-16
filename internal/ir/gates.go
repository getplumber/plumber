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
	// GateUnknown means the facts available do not determine whether an
	// outsider can make the job run.
	GateUnknown GateClass = "unknown"
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

// labelRefs, authorRefs, mergedRefs and sameRepoRefs are the fact
// families causalReason hides one at a time to find which one a False
// result depends on.
var (
	labelRefs = []string{
		"github.event.label.name",
		"github.event.pull_request.labels.*.name",
	}
	authorRefs = []string{
		"github.event.pull_request.user.login",
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
// neither evidence of a gate nor of its absence.
func ClassifyGate(job Job, byName map[string]Job, trigger string, types []string, env Environment, known bool) Gate {
	pinned := checkoutPinnedSha(job)

	if known && env.RequiredReviewers {
		return Gate{
			Class:     GateMaintainerApproved,
			Reason:    "environment " + env.Name + " requires reviewers",
			PinnedSha: pinned,
		}
	}

	producible := outsiderProducibleTypes(trigger, types)

	if len(types) > 0 && len(producible) == 0 {
		// Every declared type is maintainer-produced (e.g. `types:
		// [labeled]`): an outsider can never even make the event fire.
		// The condition itself may still explain a more specific cause
		// (it often checks the very label that gates the type filter),
		// so it is still worth evaluating; only fall back to the bare
		// type gate when the condition would otherwise read as reachable.
		class, reason, unknown := evaluateTypes(job, byName, trigger, types)
		if class == GateOutsider || class == GateUnknown {
			return Gate{
				Class:     GateMaintainerApproved,
				Reason:    "types " + strings.Join(types, " "),
				PinnedSha: pinned,
			}
		}
		return Gate{Class: class, Reason: reason, PinnedSha: pinned, Unknown: unknown}
	}

	class, reason, unknown := evaluateTypes(job, byName, trigger, producible)
	return Gate{Class: class, Reason: reason, PinnedSha: pinned, Unknown: unknown}
}

// evaluateTypes classifies job against each of testTypes in turn: True
// for at least one makes it GateOutsider; False for every one classifies
// the cause of the first False; anything else is GateUnknown with the
// union of unresolved references.
func evaluateTypes(job Job, byName map[string]Job, trigger string, testTypes []string) (GateClass, string, []string) {
	allFalse := true
	var falseType, falseJobName string
	var unknown []string

	for _, t := range testTypes {
		facts := newOutsiderFacts(trigger, t, job, byName)
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
		facts := newOutsiderFacts(trigger, falseType, job, byName)
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
func evalJobCondition(job Job, byName map[string]Job, facts outsiderFacts, visited map[string]bool) (expr.Value, string) {
	if visited[job.Name] {
		return expr.Unknown, ""
	}
	visited[job.Name] = true

	for _, dep := range job.Needs {
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

// causalReason explains why ifText evaluated False for the outsider: it
// re-evaluates ifText with each fact family hidden in turn, in this
// order (labels, author, merged, same-repo), and names the first one
// whose hiding turns the result from False to Unknown. No family
// explaining it falls back to the bare "condition" reason.
func causalReason(ifText string, facts outsiderFacts) (GateClass, string) {
	families := []struct {
		refs  []string
		class GateClass
		name  string
	}{
		{labelRefs, GateMaintainerApproved, "label"},
		{authorRefs, GateMaintainerApproved, "author"},
		{mergedRefs, GateMaintainerApproved, "merged"},
		{sameRepoRefs, GateSameRepo, "same repository"},
	}
	for _, fam := range families {
		hidden := facts.withHidden(fam.refs)
		if expr.Eval(ifText, hidden) != expr.Unknown {
			continue
		}
		if fam.class == GateSameRepo {
			// Same-repo has no literal form: "same repository" is
			// already the full reason.
			return fam.class, fam.name
		}
		if literal, ok := nearestLiteral(ifText, fam.refs); ok {
			return fam.class, fam.name + " " + literal
		}
		return fam.class, fam.name
	}
	return GateMaintainerApproved, "condition"
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

// nearestLiteral scans text for one of refs and, when found, the single
// quoted string literal written nearest to it: the quoted literal a
// condition compares that reference against is almost always right next
// to it (`== 'literal'`, `contains(ref, 'literal')`), so this is a plain
// text scan rather than a re-parse of the expression.
func nearestLiteral(text string, refs []string) (string, bool) {
	refPos := -1
	refLen := 0
	for _, ref := range refs {
		if idx := strings.Index(text, ref); idx >= 0 {
			if refPos < 0 {
				refPos = idx
				refLen = len(ref)
			}
		}
	}
	if refPos < 0 {
		return "", false
	}

	literals := quotedLiterals(text)
	if len(literals) == 0 {
		return "", false
	}

	best := -1
	bestDist := -1
	for i, lit := range literals {
		dist := distanceToRange(lit.start, lit.end, refPos, refPos+refLen)
		if bestDist < 0 || dist < bestDist {
			bestDist = dist
			best = i
		}
	}
	return literals[best].val, true
}

type quotedLiteral struct {
	start, end int
	val        string
}

// quotedLiterals finds every single-quoted substring in text, mirroring
// how internal/expr's lexer reads a string literal (no escape handling:
// a condition's string literals never need one).
func quotedLiterals(text string) []quotedLiteral {
	var out []quotedLiteral
	i, n := 0, len(text)
	for i < n {
		if text[i] != '\'' {
			i++
			continue
		}
		j := i + 1
		for j < n && text[j] != '\'' {
			j++
		}
		if j < n {
			out = append(out, quotedLiteral{start: i, end: j + 1, val: text[i+1 : j]})
			i = j + 1
		} else {
			break
		}
	}
	return out
}

// distanceToRange is how far [bStart, bEnd) is from [aStart, aEnd), 0
// when they overlap or touch.
func distanceToRange(aStart, aEnd, bStart, bEnd int) int {
	if aEnd <= bStart {
		return bStart - aEnd
	}
	if bEnd <= aStart {
		return aStart - bEnd
	}
	return 0
}

// checkoutPinnedSha reports whether job's actions/checkout step pins the
// ref to the pull request or workflow_run head, the one way a checkout
// can run code an outsider controls regardless of how the job itself is
// gated.
func checkoutPinnedSha(job Job) bool {
	for _, a := range job.Uses {
		if !strings.HasPrefix(a.Uses, "actions/checkout") {
			continue
		}
		ref, ok := a.With["ref"].(string)
		if !ok {
			continue
		}
		ref = stripRefWrapper(ref)
		if ref == "github.event.pull_request.head.sha" || ref == "github.event.workflow_run.head_sha" {
			return true
		}
	}
	return false
}

// stripRefWrapper trims whitespace and, when present, the "${{ ... }}"
// wrapper around a `with: { ref: ... }` value.
func stripRefWrapper(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "${{")
	s = strings.TrimSuffix(s, "}}")
	return strings.TrimSpace(s)
}
