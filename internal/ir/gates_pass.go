package ir

import (
	"slices"
	"sort"
	"strings"
)

// PrivilegedTriggers are the events whose run holds the base repository's
// secrets and token while someone outside the team can start it: the
// triggers that, alone, make a run privileged. It is the one list:
// policies/situation/situation.rego's privileged_triggers is the same set
// (TestPrivilegedTriggersMatchTheSituation keeps the two equal).
var PrivilegedTriggers = []string{
	"pull_request_target",
	"workflow_run",
	"issue_comment",
	"pull_request_review",
	"pull_request_review_comment",
	"discussion_comment",
	"discussion",
	"gollum",
	"fork",
}

// unprivilegedRuns are the modelled triggers whose run is never a
// privileged one: a pull_request run from a fork has no secret and a
// read-only token (it is the separate fork_pr entry, an outsider's
// already), so it has no privilege for a gate to hold.
var unprivilegedRuns = map[string]bool{"pull_request": true}

// classifiedTriggers are the triggers ClassifyGates decides a gate for:
// every privileged trigger, and every trigger the condition model knows
// whose run holds the base repository's privileges (canonicalOutsiderTypes
// without unprivilegedRuns: issues and the like). A job carrying one of
// the latter is still reached by an outsider through it (anyone opens an
// issue), so the weakest gate across them all is the job's: the gate says
// who can make the privileged run happen. Sorted.
var classifiedTriggers = func() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range PrivilegedTriggers {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for t := range canonicalOutsiderTypes {
		if !seen[t] && !unprivilegedRuns[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}()

// gateStrength orders the gate classes from the outsider's side: the
// lower, the easier for an outsider to get in.
// The two strong classes (same_repo, no_outsider) share one rank: either
// admits no path.
var gateStrength = map[GateClass]int{
	GateOutsider:           0,
	GateUnknown:            1,
	GateMaintainerApproved: 2,
	GateSameRepo:           3,
	GateNoOutsider:         3,
}

// ClassifyGates fills Job.Gate on every GitHub job carrying a privileged
// trigger: ClassifyGate per trigger it carries (classifiedTriggers, the
// privileged ones and every one an outsider fires), with its types: filter
// and the job's deployment environment looked up among p.Environments,
// keeping the weakest result (weakerGate). A job of a reusable workflow
// (workflow_call) runs under its callers' events instead, so it also
// takes the weakest gate among its calls (callGate). A no-op on GitLab,
// whose jobs carry no trigger.
func ClassifyGates(p *NormalizedPipeline) {
	if p == nil || p.Provider != ProviderGitHub {
		return
	}
	byName := make(map[string]Job, len(p.Jobs))
	for _, j := range p.Jobs {
		byName[j.Name] = j
	}
	for i := range p.Jobs {
		job := p.Jobs[i]
		var gate *Gate
		// A job appended from another repository's workflow (Nested) runs
		// only for its calling job, under that job's events and behind its
		// `if:`: its calls decide its gate (callGate), never its own
		// condition read alone.
		throughCalls := job.Nested && len(job.Callers) > 0
		if hasAnyTrigger(job, PrivilegedTriggers) && !throughCalls {
			gate = triggersGate(p, byName, job, job.Triggers)
		}
		if hasTrigger(job, "workflow_call") || throughCalls {
			for _, c := range job.Callers {
				gate = weakerOf(gate, callGate(p, byName, job, c))
			}
		}
		// A job with no privileged run to gate keeps no gate (nil).
		p.Jobs[i].Gate = gate
	}
}

// triggersGate is the weakest gate of job across the classified triggers
// among triggers, with its types: filter and its deployment environment;
// nil when none of them is classified.
func triggersGate(p *NormalizedPipeline, byName map[string]Job, job Job, triggers []string) *Gate {
	var gate *Gate
	for _, trigger := range classifiedTriggers {
		if !slices.Contains(triggers, trigger) {
			continue
		}
		g := triggerGate(p, byName, job, trigger, job.TriggerTypes[trigger])
		gate = weakerOf(gate, &g)
	}
	return gate
}

// triggerGate is ClassifyGate of job on trigger, an outsider's for a
// trigger the condition model does not know (fork, gollum): nothing about
// who fires it is read.
func triggerGate(p *NormalizedPipeline, byName map[string]Job, job Job, trigger string, types []string) Gate {
	if _, modeled := canonicalOutsiderTypes[trigger]; !modeled {
		return Gate{Class: GateOutsider}
	}
	return ClassifyGate(job, byName, trigger, types, jobEnvironment(p, job.Environment), p.EnvironmentsKnown, p.DefaultBranch)
}

// callGate is who can make job, a job of a reusable workflow, run through
// the call c: per privileged event of the call (c.Triggers, those of the
// top of the chain), the calling job's own gate (its if:, its types:
// filter, its environment) and the called job's own gate under that same
// event, the stronger of the two since the run needs both; then the
// weakest across the events. A calling job the scan does not have
// (another repository's, or one not among the jobs) is unknown, never an
// outsider's by default and never a strong gate. nil when the call
// carries no privileged event: it gives the job no privileged run.
func callGate(p *NormalizedPipeline, byName map[string]Job, job Job, c ReusableCaller) *Gate {
	if !slices.ContainsFunc(c.Triggers, func(t string) bool { return slices.Contains(PrivilegedTriggers, t) }) {
		return nil
	}
	caller, known := byName[c.Job]
	var gate *Gate
	for _, trigger := range classifiedTriggers {
		if !slices.Contains(c.Triggers, trigger) {
			continue
		}
		callerSide := Gate{Class: GateUnknown, Unknown: []string{"caller " + c.Job}}
		if known {
			callerSide = triggerGate(p, byName, caller, trigger, caller.TriggerTypes[trigger])
		}
		g := strongerGate(callerSide, triggerGate(p, byName, job, trigger, nil))
		// What runs is the called job's checkout, never the caller's.
		g.PinnedSha = checkoutPinnedSha(job)
		gate = weakerOf(gate, &g)
	}
	return gate
}

// weakerGate is the gate of a and b an outsider gets through more easily
// (gateStrength), a on a tie.
func weakerGate(a, b Gate) Gate {
	if gateStrength[b.Class] < gateStrength[a.Class] {
		return b
	}
	return a
}

// strongerGate is the gate of a and b an outsider gets through less
// easily (gateStrength), a on a tie: what holds when a run has to pass
// both.
func strongerGate(a, b Gate) Gate {
	if gateStrength[b.Class] > gateStrength[a.Class] {
		return b
	}
	return a
}

// weakerOf is weakerGate over optional gates: a nil one has no say.
func weakerOf(a, b *Gate) *Gate {
	switch {
	case b == nil:
		return a
	case a == nil:
		return b
	}
	w := weakerGate(*a, *b)
	return &w
}

// jobEnvironment is the environment of p named name, with its Name set
// even when the repository's environments do not list it (an environment
// the job names but the repository does not define protects nothing).
func jobEnvironment(p *NormalizedPipeline, name string) Environment {
	if name == "" {
		return Environment{}
	}
	for _, e := range p.Environments {
		if strings.EqualFold(e.Name, name) {
			return e
		}
	}
	return Environment{Name: name}
}

func hasAnyTrigger(job Job, triggers []string) bool {
	for _, t := range triggers {
		if hasTrigger(job, t) {
			return true
		}
	}
	return false
}

func hasTrigger(job Job, trigger string) bool {
	for _, t := range job.Triggers {
		if t == trigger {
			return true
		}
	}
	return false
}
