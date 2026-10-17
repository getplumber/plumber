package ir

import (
	"strings"

	"github.com/getplumber/plumber/internal/expr"
)

// scannedRepository is the facts model's stand-in for `github.repository`:
// the repository being analyzed. It only has to differ from the fork
// facts below (headRepoFullName), never match a real repository.
const scannedRepository = "acme/repo"

// headRepoFullName and headRepoFork are what an outsider's own pull
// request or workflow_run head repository looks like: a fork, never the
// scanned repository.
const (
	headRepoFullName = "fork/repo"
	headRepoFork     = "true"
)

// outsiderIdentity is the login the model gives every actor/author
// reference when the person behind the event is an outsider: it can
// never equal a maintainer's or a bot's literal login.
const outsiderIdentity = "outsider"

// canonicalOutsiderTypes is, per trigger, every `github.event.action`
// value an outsider can produce on their own (opening, editing or closing
// their own pull request, issue, comment or discussion, requesting a run
// from a fork). It is also the set a trigger without a `types:` filter
// (every type fires) is evaluated over.
var canonicalOutsiderTypes = map[string][]string{
	"pull_request_target":         {"opened", "synchronize", "reopened", "edited", "closed", "ready_for_review", "converted_to_draft"},
	"pull_request":                {"opened", "synchronize", "reopened", "edited", "closed", "ready_for_review", "converted_to_draft"},
	"issue_comment":               {"created", "edited", "deleted"},
	"pull_request_review_comment": {"created", "edited", "deleted"},
	"discussion_comment":          {"created", "edited", "deleted"},
	"pull_request_review":         {"submitted", "edited", "dismissed"},
	"workflow_run":                {"requested", "completed", "in_progress"},
	"issues":                      {"opened", "edited", "closed", "reopened"},
	"discussion":                  {"created", "edited", "answered", "unanswered", "category_changed"},
}

// maintainerOnlyTypes is every `github.event.action` value only a
// maintainer (someone with triage or write access) produces, whatever the
// trigger: a label, an assignment, a milestone, a lock, a transfer, a
// pin, requesting a reviewer, auto-merge, the merge queue. A type in neither
// this list nor the trigger's canonicalOutsiderTypes is unknown: the gate
// it gives is unknown, never a maintainer's.
var maintainerOnlyTypes = map[string]bool{
	"labeled": true, "unlabeled": true,
	"assigned": true, "unassigned": true,
	"milestoned": true, "demilestoned": true,
	"locked": true, "unlocked": true,
	"transferred": true,
	"pinned":      true, "unpinned": true,
	"review_requested": true, "review_request_removed": true,
	"auto_merge_enabled": true, "auto_merge_disabled": true,
	"enqueued": true, "dequeued": true,
}

// triggerActivityTypes is, per trigger the condition model knows, every
// `github.event.action` value GitHub can deliver for it, whoever acts. A
// condition comparing the action to a value outside its trigger's list
// names a run that trigger never makes (eventFamilyRefs).
var triggerActivityTypes = map[string][]string{
	"pull_request_target":         pullRequestActivityTypes,
	"pull_request":                pullRequestActivityTypes,
	"issue_comment":               {"created", "edited", "deleted"},
	"pull_request_review_comment": {"created", "edited", "deleted"},
	"discussion_comment":          {"created", "edited", "deleted"},
	"pull_request_review":         {"submitted", "edited", "dismissed"},
	"workflow_run":                {"requested", "completed", "in_progress"},
	"issues": {"opened", "edited", "deleted", "transferred", "pinned", "unpinned", "closed", "reopened",
		"assigned", "unassigned", "labeled", "unlabeled", "locked", "unlocked", "milestoned", "demilestoned", "typed", "untyped"},
	"discussion": {"created", "edited", "deleted", "transferred", "pinned", "unpinned", "labeled", "unlabeled",
		"locked", "unlocked", "category_changed", "answered", "unanswered"},
}

var pullRequestActivityTypes = []string{
	"assigned", "unassigned", "labeled", "unlabeled", "opened", "edited", "closed", "reopened", "synchronize",
	"converted_to_draft", "locked", "unlocked", "enqueued", "dequeued", "milestoned", "demilestoned",
	"ready_for_review", "review_requested", "review_request_removed", "auto_merge_enabled", "auto_merge_disabled",
}

// isOutsiderProducibleType reports whether an outsider can make trigger
// fire with event.action equal to t.
func isOutsiderProducibleType(trigger, t string) bool {
	for _, v := range canonicalOutsiderTypes[trigger] {
		if v == t {
			return true
		}
	}
	return false
}

// splitTypes sorts a trigger's `types:` filter into the types an outsider
// can produce and the types neither list knows (unknownTypes); the rest
// are maintainer-only. An empty types means "every type", so it resolves
// to the canonical outsider set.
func splitTypes(trigger string, types []string) (producible, unknownTypes []string) {
	if len(types) == 0 {
		return canonicalOutsiderTypes[trigger], nil
	}
	for _, t := range types {
		switch {
		case isOutsiderProducibleType(trigger, t):
			producible = append(producible, t)
		case !maintainerOnlyTypes[t]:
			unknownTypes = append(unknownTypes, t)
		}
	}
	return producible, unknownTypes
}

// pullRequestRefTriggers are the triggers whose `github.ref` an outsider
// pull request sets to the merge ref rather than a branch ref
// (pull_request_target runs on the base branch instead: ref).
var pullRequestRefTriggers = map[string]bool{
	"pull_request":                true,
	"pull_request_review":         true,
	"pull_request_review_comment": true,
}

// outsiderFacts is the evaluator's expr.Facts answer for what an
// outsider, acting alone, can make true about a job's conditions on a
// given trigger and event action. Every reference the model does not
// explicitly define resolves unknown rather than guessing.
type outsiderFacts struct {
	trigger   string
	eventType string
	pushRef   string
	// base is the branch a pull request targets: the repository's
	// default branch, the one an outsider's pull request is opened
	// against in the model.
	base string
	// baseKnown is whether the base may be read as the default branch:
	// every literal the conditions compare the base references to
	// (baseRefs) is the default branch. An outsider opens a pull request
	// against any existing branch, so a condition naming another branch
	// leaves the base unresolved rather than settling it either way.
	baseKnown bool
	byName    map[string]Job
	// hide forces the named references unknown regardless of what the
	// model would otherwise answer, used to find which fact family a
	// False result depends on (see causalReason in gates.go).
	hide []string
	// resolving is the chain of job names whose needs.*.outputs.*
	// resolution is in progress, so a step condition that reads back
	// into a job already being resolved (two jobs whose output-gating
	// conditions reference each other) stops instead of recursing
	// forever: untrusted workflows get to define this chain, so it must
	// never crash the process.
	resolving []string
}

// newOutsiderFacts is the model for job on trigger with event action
// eventType; base is the branch a pull request targets ("" reads main).
func newOutsiderFacts(trigger, eventType string, job Job, byName map[string]Job, base string) outsiderFacts {
	if base == "" {
		base = "main"
	}
	return outsiderFacts{
		trigger:   trigger,
		eventType: eventType,
		pushRef:   defaultPushRef(job),
		base:      base,
		baseKnown: baseLiteralsAreDefault(job, byName, base),
		byName:    byName,
	}
}

// baseRefs are the references that name the branch a pull request
// targets on pull_request_target (github.ref, github.ref_name,
// github.base_ref; on pull_request only github.base_ref does).
var baseRefs = []string{"github.ref", "github.ref_name", "github.base_ref"}

// baseLiteralsAreDefault reports whether every literal the conditions
// the evaluation can read (job's own if:, and the if: and step
// conditions of every job it needs, transitively: the predecessors and
// outputs evalJobCondition and resolveNeedsOutput walk) compare a base
// reference to is the default branch (refs/heads/<base> for github.ref,
// <base> for the two names), each wanting them equal (expr.Comparisons:
// no `!=`, no negation). The outsider picks the base, so a condition
// that only ever asks for the default branch is the one their best
// choice settles; `!= 'main'` or another branch they could satisfy by
// targeting another branch, which the model cannot name, so it stays
// unresolved. A step condition the walk never reads only ever leaves the
// base unresolved more often, the safe side.
func baseLiteralsAreDefault(job Job, byName map[string]Job, base string) bool {
	conds := []string{job.If}
	seen := map[string]bool{job.Name: true}
	queue := append([]string(nil), job.Needs...)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		pred, ok := byName[name]
		if !ok {
			continue
		}
		conds = append(conds, pred.If)
		conds = append(conds, pred.ScriptIfs...)
		queue = append(queue, pred.Needs...)
	}
	for _, c := range conds {
		for _, cmp := range expr.Comparisons(c, baseRefs[:1]) {
			if cmp.Negated || !strings.EqualFold(cmp.Literal, "refs/heads/"+base) {
				return false
			}
		}
		for _, cmp := range expr.Comparisons(c, baseRefs[1:]) {
			if cmp.Negated || !strings.EqualFold(cmp.Literal, base) {
				return false
			}
		}
	}
	return true
}

// withHidden returns a copy of f that answers unknown for every
// reference in refs, on top of those f already hides, otherwise
// unchanged. The copy still resolves needs.*.outputs.* through the same
// hiding, since that resolution evaluates a predecessor's step condition
// against f itself.
func (f outsiderFacts) withHidden(refs []string) outsiderFacts {
	g := f
	g.hide = append(append([]string(nil), f.hide...), refs...)
	return g
}

func (f outsiderFacts) hidden(ref string) bool {
	for _, h := range f.hide {
		if h == ref {
			return true
		}
	}
	return false
}

// resolvingJob reports whether jobName's needs.*.outputs.* resolution is
// already in progress somewhere up the current call chain.
func (f outsiderFacts) resolvingJob(jobName string) bool {
	for _, j := range f.resolving {
		if j == jobName {
			return true
		}
	}
	return false
}

// withResolving returns a copy of f with jobName appended to the
// in-progress resolution chain.
func (f outsiderFacts) withResolving(jobName string) outsiderFacts {
	g := f
	g.resolving = append(append([]string{}, f.resolving...), jobName)
	return g
}

// Resolve implements expr.Facts.
func (f outsiderFacts) Resolve(ref string) (string, bool) {
	if f.hidden(ref) {
		return "", false
	}
	if strings.HasPrefix(ref, "needs.") {
		return f.resolveNeedsOutput(ref)
	}
	switch ref {
	case "github.event_name":
		return f.trigger, true
	case "github.event.action":
		if f.eventType == "" {
			return "", false
		}
		return f.eventType, true
	case "github.event.label.name":
		// An outsider's own pull request or issue carries no label: an
		// outsider cannot label anything.
		return "", true
	case "github.event.pull_request.labels.*.name":
		// No labels: an empty collection, not an unresolved one.
		return "", true
	case "github.event.pull_request.user.login",
		"github.actor",
		"github.triggering_actor",
		"github.event.comment.user.login",
		"github.event.issue.user.login",
		"github.event.sender.login":
		return outsiderIdentity, true
	case "github.event.pull_request.head.repo.full_name",
		"github.event.workflow_run.head_repository.full_name":
		return headRepoFullName, true
	case "github.event.pull_request.head.repo.fork",
		"github.event.workflow_run.head_repository.fork":
		return headRepoFork, true
	case "github.event.pull_request.merged":
		return "false", true
	case "github.repository":
		return scannedRepository, true
	case "github.ref":
		return f.ref()
	case "github.ref_name":
		ref, ok := f.ref()
		if !ok {
			return "", false
		}
		if name, isBranch := strings.CutPrefix(ref, "refs/heads/"); isBranch {
			return name, true
		}
		return strings.TrimPrefix(ref, "refs/pull/"), true
	case "github.base_ref":
		// The branch the pull request targets, on the two pull request
		// events only. Its head (github.head_ref) is the outsider's own
		// branch, named as they like: it stays unresolved, no literal
		// comparison of it settled either way.
		// Read as the default branch only when that is the one branch the
		// conditions name (baseKnown).
		if (f.trigger == "pull_request_target" || f.trigger == "pull_request") && f.baseKnown {
			return f.base, true
		}
	}
	return "", false
}

// ref is github.ref: a pull_request_target run is on the base branch the
// pull request targets (refs/heads/<base>, when the conditions name no
// other branch: baseKnown; unresolved otherwise), the other pull request
// events on the pull request's merge ref, a push on its branch.
func (f outsiderFacts) ref() (string, bool) {
	if f.trigger == "pull_request_target" {
		if !f.baseKnown {
			return "", false
		}
		return "refs/heads/" + f.base, true
	}
	if pullRequestRefTriggers[f.trigger] {
		return "refs/pull/1/merge", true
	}
	if f.trigger == "push" {
		return f.pushRef, true
	}
	return "", false
}

// defaultPushRef is the push trigger's github.ref: the job's single push
// branch filter when it names exactly one, refs/heads/main otherwise.
// Kept simple deliberately; a job with several push branch filters does
// not get a more precise answer here.
func defaultPushRef(job Job) string {
	if len(job.PushBranches) == 1 {
		return "refs/heads/" + job.PushBranches[0]
	}
	return "refs/heads/main"
}

// resolveNeedsOutput resolves a "needs.<job>.outputs.<output>" reference
// by finding, in the named predecessor job, the run step that writes
// <output>= to $GITHUB_OUTPUT and evaluating that step's own `if:`
// against f: True yields the literal value written, False yields the
// empty string (the step never ran, so the output was never set, which
// is a known fact, not an unresolved one), and Unknown stays unresolved.
//
// That step's `if:` can itself read another job's output, so this
// recurses; jobName joins f.resolving before the recursive Eval so a
// cycle (two jobs whose output-gating conditions read each other's
// output) is caught as unknown instead of recursing without end.
func (f outsiderFacts) resolveNeedsOutput(ref string) (string, bool) {
	jobName, output, ok := parseNeedsOutputRef(ref)
	if !ok {
		return "", false
	}
	if f.resolvingJob(jobName) {
		return "", false
	}
	job, ok := f.byName[jobName]
	if !ok {
		return "", false
	}
	value, cond, found := findOutputStep(job, output)
	if !found {
		return "", false
	}
	switch expr.Eval(cond, f.withResolving(jobName)) {
	case expr.True:
		return value, true
	case expr.False:
		return "", true
	default:
		return "", false
	}
}

// parseNeedsOutputRef splits "needs.<job>.outputs.<output>" into its job
// and output parts. Job names may contain dots themselves (reusable
// workflow job names are workflow-qualified), so the split anchors on
// the literal ".outputs." marker rather than naively splitting on every
// dot.
func parseNeedsOutputRef(ref string) (job, output string, ok bool) {
	const prefix = "needs."
	const marker = ".outputs."
	if !strings.HasPrefix(ref, prefix) {
		return "", "", false
	}
	rest := ref[len(prefix):]
	idx := strings.Index(rest, marker)
	if idx < 0 {
		return "", "", false
	}
	job = rest[:idx]
	output = rest[idx+len(marker):]
	if job == "" || output == "" {
		return "", "", false
	}
	return job, output, true
}

// findOutputStep finds the Scripts entry of job that writes output= to
// $GITHUB_OUTPUT and returns its literal value and the step-level `if:`
// (from ScriptIfs at the same index, "" when the step is unconditional).
func findOutputStep(job Job, output string) (value, cond string, found bool) {
	for i, script := range job.Scripts {
		v, ok := scriptOutputValue(script, output)
		if !ok {
			continue
		}
		if i < len(job.ScriptIfs) {
			cond = job.ScriptIfs[i]
		}
		return v, cond, true
	}
	return "", "", false
}

// scriptOutputValue reads the literal value a shell script entry writes
// to $GITHUB_OUTPUT for the given output name, e.g. `echo
// "run_privileged=true" >> $GITHUB_OUTPUT` yields ("true", true) for
// output "run_privileged". It is a plain text scan, not a shell parser:
// good enough for the common `echo "name=value" >> $GITHUB_OUTPUT`
// shape this model needs to read. The name must start a word: another
// output whose name ends in the wanted name (dry_run for run) is a
// different output and is skipped.
func scriptOutputValue(script, output string) (string, bool) {
	if !strings.Contains(script, "GITHUB_OUTPUT") {
		return "", false
	}
	marker := output + "="
	idx := -1
	for from := 0; from <= len(script)-len(marker); {
		i := strings.Index(script[from:], marker)
		if i < 0 {
			break
		}
		at := from + i
		if at == 0 || isOutputNameBoundary(script[at-1]) {
			idx = at
			break
		}
		from = at + 1
	}
	if idx < 0 {
		return "", false
	}
	rest := script[idx+len(marker):]
	end := len(rest)
	for i, r := range rest {
		if strings.ContainsRune("\"'\n \t>;&|)<", r) {
			end = i
			break
		}
	}
	val := strings.TrimSpace(rest[:end])
	// A value computed at run time (an expression `${{ ... }}`, a shell
	// variable, a command substitution) is no settled literal: reading
	// its first token as the value would close a gate on text an
	// outsider may control. Unknown keeps the path, unverified.
	if strings.HasPrefix(val, "$") {
		return "", false
	}
	return val, true
}

// isOutputNameBoundary reports whether the byte before an output name
// lets the name start a word in a shell script: whitespace, a quote, or
// the characters a shell puts right before a word (`(`, `{`, `;`, `&`,
// `|`). A letter, digit or underscore means the match sits inside a
// longer name.
func isOutputNameBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '"', '\'', '(', '{', ';', '&', '|', '`':
		return true
	}
	return false
}
