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

// canonicalOutsiderTypes is the default `github.event.action` values an
// outsider can produce for a trigger, used when the workflow's
// `on.<trigger>.types` filter is absent (every type fires).
var canonicalOutsiderTypes = map[string][]string{
	"pull_request_target":         {"opened", "synchronize", "reopened", "edited", "ready_for_review"},
	"pull_request":                {"opened", "synchronize", "reopened", "edited", "ready_for_review"},
	"issue_comment":               {"created"},
	"pull_request_review_comment": {"created"},
	"discussion_comment":          {"created"},
	"pull_request_review":         {"submitted"},
	"workflow_run":                {"completed"},
	"issues":                      {"opened"},
	"discussion":                  {"opened"},
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

// outsiderProducibleTypes is the subset of types an outsider can
// actually produce for trigger. An empty types means "every type", so
// it resolves to the canonical default set.
func outsiderProducibleTypes(trigger string, types []string) []string {
	if len(types) == 0 {
		return canonicalOutsiderTypes[trigger]
	}
	var out []string
	for _, t := range types {
		if isOutsiderProducibleType(trigger, t) {
			out = append(out, t)
		}
	}
	return out
}

// pullRequestRefTriggers are the triggers whose `github.ref` an outsider
// pull request sets to the merge ref rather than a branch ref.
var pullRequestRefTriggers = map[string]bool{
	"pull_request_target":         true,
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

func newOutsiderFacts(trigger, eventType string, job Job, byName map[string]Job) outsiderFacts {
	return outsiderFacts{
		trigger:   trigger,
		eventType: eventType,
		pushRef:   defaultPushRef(job),
		byName:    byName,
	}
}

// withHidden returns a copy of f that answers unknown for every
// reference in refs, otherwise unchanged. The copy still resolves
// needs.*.outputs.* through the same hiding, since that resolution
// evaluates a predecessor's step condition against f itself.
func (f outsiderFacts) withHidden(refs []string) outsiderFacts {
	g := f
	g.hide = refs
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
	}
	return "", false
}

func (f outsiderFacts) ref() (string, bool) {
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
// shape this model needs to read.
func scriptOutputValue(script, output string) (string, bool) {
	if !strings.Contains(script, "GITHUB_OUTPUT") {
		return "", false
	}
	marker := output + "="
	idx := strings.Index(script, marker)
	if idx < 0 {
		return "", false
	}
	rest := script[idx+len(marker):]
	end := len(rest)
	for i, r := range rest {
		if r == '"' || r == '\'' || r == '\n' || r == ' ' || r == '\t' {
			end = i
			break
		}
	}
	return strings.TrimSpace(rest[:end]), true
}
