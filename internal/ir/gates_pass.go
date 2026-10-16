package ir

import "sort"

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
var gateStrength = map[GateClass]int{
	GateOutsider:           0,
	GateUnknown:            1,
	GateMaintainerApproved: 2,
	GateSameRepo:           3,
}

// ClassifyGates fills Job.Gate on every GitHub job carrying a privileged
// trigger: ClassifyGate per trigger it carries (classifiedTriggers, the
// privileged ones and every one an outsider fires), with its types: filter
// and the job's deployment environment looked up among p.Environments,
// keeping the weakest result (weakerGate). A no-op on GitLab, whose
// jobs carry no trigger.
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
		env := jobEnvironment(p, job.Environment)
		var gate *Gate
		if !hasAnyTrigger(job, PrivilegedTriggers) {
			// No privileged run to gate: the job keeps no gate.
			continue
		}
		for _, trigger := range classifiedTriggers {
			if !hasTrigger(job, trigger) {
				continue
			}
			// A trigger the condition model does not know (fork, gollum)
			// lets an outsider in: nothing about who fires it is read.
			g := Gate{Class: GateOutsider}
			if _, modeled := canonicalOutsiderTypes[trigger]; modeled {
				g = ClassifyGate(job, byName, trigger, job.TriggerTypes[trigger], env, p.EnvironmentsKnown)
			}
			if gate == nil {
				gate = &g
				continue
			}
			w := weakerGate(*gate, g)
			gate = &w
		}
		p.Jobs[i].Gate = gate
	}
}

// weakerGate is the gate of a and b an outsider gets through more easily
// (gateStrength), a on a tie.
func weakerGate(a, b Gate) Gate {
	if gateStrength[b.Class] < gateStrength[a.Class] {
		return b
	}
	return a
}

// jobEnvironment is the environment of p named name, with its Name set
// even when the repository's environments do not list it (an environment
// the job names but the repository does not define protects nothing).
func jobEnvironment(p *NormalizedPipeline, name string) Environment {
	if name == "" {
		return Environment{}
	}
	for _, e := range p.Environments {
		if e.Name == name {
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
