package ir

import (
	"strings"

	"github.com/getplumber/plumber/internal/expr"
	"github.com/getplumber/plumber/internal/runners"
)

// githubWorkflowsPathMarker is the repo-relative directory every GitHub
// Actions workflow file lives under, the anchor WorkflowStateKey looks
// for to strip off a local scan's absolute filesystem prefix.
const githubWorkflowsPathMarker = ".github/workflows/"

// WorkflowStateKey normalizes originFile to the repo-relative form
// WorkflowStates is keyed by: the remote scan already sets Job.OriginFile
// to that form, so it passes through unchanged, but the local scan sets
// it to the absolute filesystem path (the workflows directory joined
// with the file name), which never matches the map directly. Slashes are
// normalized to "/" first, since filepath.Join on the local scan uses
// the OS separator. originFile is returned unchanged when the marker is
// not found at all (an unexpected shape, safer than guessing).
func WorkflowStateKey(originFile string) string {
	normalized := strings.ReplaceAll(originFile, "\\", "/")
	idx := strings.Index(normalized, githubWorkflowsPathMarker)
	if idx < 0 {
		return originFile
	}
	return normalized[idx:]
}

// MarkInert fills Job.Inert on every job of p that cannot run at all:
// its workflow is disabled, its runner label is retired, it has no
// trigger, it is a reusable workflow nobody calls, or it is pinned to
// another repository. An inert job starts no attack path and is walked
// by none (see every_dead in policies/situation/situation.rego, which
// also reads this field, and liveSituation in control/paths.go, which
// reads it the same way it already reads Job.Dead).
//
// A no-op on GitLab: every reason below reads a GitHub-only signal
// (workflow state, runs-on, workflow_call, the triggers a workflow
// declares). Gating the whole function on the pipeline's provider,
// rather than on WorkflowHasTriggers alone, keeps a GitLab job's always-
// empty Triggers from misreading as "no trigger" — a GitLab job simply
// never carries this field at all, by design (see Job.Triggers).
func MarkInert(p *NormalizedPipeline) {
	if p == nil || p.Provider != ProviderGitHub {
		return
	}
	for i := range p.Jobs {
		p.Jobs[i].Inert = inertReason(p, p.Jobs[i])
	}
}

// inertReason decides job's reason, in the one precedence order a job
// can carry at most one of: actions disabled (repository-wide), the
// job's own workflow disabled, no trigger, a workflow_call job nobody
// calls, a retired runner label, then a condition that only ever runs
// in another repository.
func inertReason(p *NormalizedPipeline, job Job) string {
	if p.ActionsDisabled {
		return "actions disabled"
	}
	if reason := workflowDisabledReason(p, job); reason != "" {
		return reason
	}
	if !job.WorkflowHasTriggers && len(job.Triggers) == 0 {
		return "no trigger"
	}
	if len(job.Triggers) == 1 && job.Triggers[0] == "workflow_call" && len(job.Callers) == 0 {
		return "workflow_call without a caller"
	}
	if reason := retiredRunnerReason(job); reason != "" {
		return reason
	}
	return repositoryLiteralReason(p, job)
}

// workflowDisabledReason reads the job's own workflow state off
// p.WorkflowStates, keyed by WorkflowStateKey(job.OriginFile): the
// workflows-listing fetch always keys its map by the repo-relative path
// (".github/workflows/<file>"), the same shape the remote scan's
// OriginFile already carries, but the local scan's OriginFile is the
// absolute filesystem path (dir joined with the file name), so the two
// need normalizing onto one another before they can be compared. Empty
// when the states lane never resolved (WorkflowStatesKnown false), when
// the job's workflow is not in the map (a lookup gap, never treated as
// disabled) or when its state is the healthy "active".
func workflowDisabledReason(p *NormalizedPipeline, job Job) string {
	if !p.WorkflowStatesKnown {
		return ""
	}
	state, ok := p.WorkflowStates[WorkflowStateKey(job.OriginFile)]
	if !ok || state == "" || state == "active" {
		return ""
	}
	return "workflow disabled (" + state + ")"
}

// retiredRunnerReason reads job.RunsOn against runners.Retired: a single
// label is enough on its own, a list of several is inert only when every
// one of them is retired (the brief's conservative reading), named by
// the first retired label in the list. RunsOnExpression or an empty
// RunsOn (no literal label the collector could read) sets nothing.
func retiredRunnerReason(job Job) string {
	if job.RunsOnExpression || len(job.RunsOn) == 0 {
		return ""
	}
	first := ""
	for _, label := range job.RunsOn {
		if !runners.Retired(label) {
			return ""
		}
		if first == "" {
			first = label
		}
	}
	return "runner label retired (" + first + ")"
}

// repositoryFacts resolves only github.repository, to the repository
// actually being scanned; every other reference stays unresolved, so
// Eval only ever decides the part of a condition that compares
// github.repository against a literal.
type repositoryFacts struct {
	repository string
}

func (f repositoryFacts) Resolve(ref string) (string, bool) {
	if ref == "github.repository" {
		return f.repository, true
	}
	return "", false
}

// githubRepositoryRef is the single reference repositoryLiteralReason
// resolves, read by expr.Eval and reused to find the literal the
// condition compares it against (nearestLiteral, from gates.go).
var githubRepositoryRef = []string{"github.repository"}

// repositoryLiteralReason reports a job whose own `if:` is provably
// False for the repository actually being scanned and names a different
// literal for github.repository (`if: github.repository ==
// 'other/repo'`): such a job can only ever run in that other
// repository's fork or template use, never here.
func repositoryLiteralReason(p *NormalizedPipeline, job Job) string {
	if job.If == "" || p.ProjectPath == "" {
		return ""
	}
	if expr.Eval(job.If, repositoryFacts{repository: p.ProjectPath}) != expr.False {
		return ""
	}
	literal, ok := nearestLiteral(job.If, githubRepositoryRef)
	if !ok {
		return ""
	}
	return "runs only in " + literal
}
