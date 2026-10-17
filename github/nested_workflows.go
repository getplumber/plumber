package github

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/getplumber/plumber/internal/ir"
)

// splitWorkflowRef splits a call of a workflow of another repository,
// owner/repo/.github/workflows/x.yml@ref.
func splitWorkflowRef(uses string) (owner, repo, file, ref string, ok bool) {
	if strings.HasPrefix(uses, "./") {
		return "", "", "", "", false
	}
	head, ref, found := strings.Cut(uses, "@")
	if !found || ref == "" {
		return "", "", "", "", false
	}
	parts := strings.SplitN(head, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", "", "", false
	}
	if !strings.HasSuffix(parts[2], ".yml") && !strings.HasSuffix(parts[2], ".yaml") {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], ref, true
}

// canonicalWorkflowRef is the workflow a job calls, absolute, owner and
// repo lower-cased (the visited-set key, spec 4.3): a nested job's
// `./.github/workflows/y.yml` names its own repository at its own ref
// (spec 3.3). "" for no call, or a relative call of the scanned repository.
func canonicalWorkflowRef(job ir.Job) string {
	uses := job.ReusableWorkflowUses
	if rel, ok := strings.CutPrefix(uses, "./"); ok {
		if !job.Nested {
			return ""
		}
		owner, repo, _, ref, ok := splitWorkflowRef(job.OriginFile)
		if !ok {
			return ""
		}
		uses = owner + "/" + repo + "/" + path.Clean(rel) + "@" + ref
	}
	owner, repo, file, ref, ok := splitWorkflowRef(uses)
	if !ok {
		return ""
	}
	return strings.ToLower(owner) + "/" + strings.ToLower(repo) + "/" + file + "@" + ref
}

// jobIDGrammar is the job id GitHub accepts. A callee's YAML is untrusted
// input: an id outside it (a `/` would break callerOfNested) is never
// appended (the ingestion hardening rule).
var jobIDGrammar = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// maxWarnedJobID bounds the untrusted id a warning quotes.
const maxWarnedJobID = 100

// readWorkflow reads a called workflow (spec 4.3, R8). A workflow is one
// container: its key counts against the budget once, at its first sight
// from a nested job, and never when the scanned repository calls it
// directly. A later call of a key already read is the fetcher's cache and
// costs nothing. A path that climbs out of its repository is refused
// before any read, so it never decides the R6 cause. The second value is
// the unexpanded reason, "" when the text was read.
func (w *nestedWalk) readWorkflow(owner, repo, file, ref string, direct bool) (string, string) {
	if escapesRoot(file) {
		return "", ir.UnexpandedFetch
	}
	if w.cause != "" {
		return "", ir.UnexpandedAPIDisabled
	}
	key := containerKey(owner, repo, file, ref)
	if !w.workflows[key] {
		if !direct && w.fetched >= MaxNestedContainers {
			w.overflow = true
			w.defs.seal()
			return "", ir.UnexpandedBudget
		}
		w.workflows[key] = true
		d := w.defs.file(owner, repo, ref, file)
		w.noteStatus(d.Status)
		if w.cause != "" {
			return "", ir.UnexpandedAPIDisabled
		}
		if !direct {
			w.fetched++
		}
	}
	if d := w.defs.file(owner, repo, ref, file); d.Status == fetchOK {
		return d.Text, ""
	}
	return "", ir.UnexpandedFetch
}

// takeCallerEvents gives a nested job the events of its calling job (spec
// 3.2, R9): it runs for that job, so the callee's own `on:` never says
// when it runs. Its triggers and the facts read off `on:` (whether it
// declares any event, the types: filters, push branches and tags,
// workflow_run upstreams) are the caller's, already the effective ones
// when the caller is itself nested, since it was expanded first.
func takeCallerEvents(cj *ir.Job, caller ir.Job) {
	cj.Triggers = slices.Clone(caller.Triggers)
	cj.WorkflowHasTriggers = caller.WorkflowHasTriggers
	cj.TriggerTypes = maps.Clone(caller.TriggerTypes)
	cj.PushBranches = slices.Clone(caller.PushBranches)
	cj.PushBranchesIgnore = slices.Clone(caller.PushBranchesIgnore)
	cj.PushTags = slices.Clone(caller.PushTags)
	cj.PushTagsIgnore = slices.Clone(caller.PushTagsIgnore)
	cj.WorkflowRunWorkflows = slices.Clone(caller.WorkflowRunWorkflows)
}

// resolveWorkflows appends the jobs of every workflow called in another
// repository (spec 3.2), breadth-first: an appended job calling another
// repository's workflow is visited in turn, and a call already on its
// chain is the cycle guard. Every entry of an appended job, at any depth
// of the chain, sits at the line of the outermost call, the scanned
// workflow's step (R9). Every call appends its own copy of the callee's
// jobs, at most MaxNestedJobs in the run: past the cap the calls left are
// listed with reason budget and the run degrades (R3). A call outside
// GitHub's grammar is never fetched (reason fetch, its Invalid mark).
func (w *nestedWalk) resolveWorkflows(pipeline *ir.NormalizedPipeline) {
	if w.workflows == nil {
		w.workflows = map[string]bool{}
	}
	chains := map[string][]string{}
	anchor := map[string]int{}
	for i := 0; i < len(pipeline.Jobs); i++ {
		caller := pipeline.Jobs[i]
		// A call of the scanned repository's own workflow, by any name the
		// scan knows for it and from any depth (review of PR 549), is never
		// fetched and never appended: its jobs already are the scan's, the
		// file read from the checkout, so a second copy would duplicate
		// every finding, and a failed read of it is never the run's first
		// remote read that decides the R6 cause. linkReusableCallers links
		// the direct ones.
		if w.scope.ownsCall(caller) {
			continue
		}
		ref := canonicalWorkflowRef(caller)
		if slices.Contains(chains[caller.Name], ref) {
			continue
		}
		owner, repo, file, at, _ := splitWorkflowRef(ref)
		text, reason, invalid := "", "", false
		switch {
		case !escapesRoot(file) && !validActionReference(owner, repo, file, at):
			// Outside GitHub's grammar: never fetched (SECURITY item 1), the
			// capped fetch warning names the reason from the Invalid mark.
			reason, invalid = ir.UnexpandedFetch, true
		case w.jobsCapped:
			reason = ir.UnexpandedBudget
		default:
			text, reason = w.readWorkflow(owner, repo, file, at, !caller.Nested)
		}
		capped := w.jobsCapped
		if reason == "" {
			callees, err := parseGitHubWorkflowJobs([]byte(text), caller.Name, ref)
			if err != nil {
				reason = ir.UnexpandedFetch
			}
			via := append(slices.Clone(caller.Via), caller.ReusableWorkflowUses)
			line := caller.OriginLine
			if caller.Nested {
				line = anchor[caller.Name]
			}
			sort.SliceStable(callees, func(a, b int) bool { return callees[a].Name < callees[b].Name })
			callees = slices.DeleteFunc(callees, func(cj ir.Job) bool {
				id := strings.TrimPrefix(cj.Name, caller.Name+"/")
				if jobIDGrammar.MatchString(id) {
					return false
				}
				if r := []rune(id); len(r) > maxWarnedJobID {
					id = string(r[:maxWarnedJobID])
				}
				pipeline.AdvisoryWarnings = append(pipeline.AdvisoryWarnings,
					fmt.Sprintf("the job %q of %s was not resolved, its id is not a valid GitHub job id", id, ref))
				return true
			})
			if w.nestedJobs+len(callees) > MaxNestedJobs {
				// The run-wide cap (MaxNestedJobs): this call and every later
				// one are listed with reason budget, nothing more is appended.
				w.jobsCapped, capped = true, true
				reason, callees = ir.UnexpandedBudget, nil
			}
			w.nestedJobs += len(callees)
			for _, cj := range callees {
				cj.Nested, cj.Via = true, slices.Clone(via)
				takeCallerEvents(&cj, caller)
				if cj.CacheMode != nil {
					// The declaration sits in the callee, outside the scan:
					// ISSUE-705 lands at the outermost call (R9).
					decl := *cj.CacheMode
					decl.Line = line
					cj.CacheMode = &decl
				}
				for k := range cj.Uses {
					u := &cj.Uses[k]
					u.DefinedIn = ir.WorkflowDefinedIn(ref, u.Line)
					u.Line = line
					u.Nested, u.Via = true, slices.Clone(via)
				}
				anchor[cj.Name] = line
				chains[cj.Name] = append(slices.Clone(chains[caller.Name]), ref)
				pipeline.Jobs = append(pipeline.Jobs, cj)
			}
		}
		if reason != "" {
			u := ir.UnexpandedAction{Uses: caller.ReusableWorkflowUses, Via: slices.Clone(caller.Via), Reason: reason, Invalid: invalid}
			w.unexpanded = append(w.unexpanded, u)
			if capped && reason == ir.UnexpandedBudget {
				w.overflow = true
				if w.jobsOverflow == nil {
					w.jobsOverflow = map[string]bool{}
				}
				w.jobsOverflow[unexpandedKey(u)] = true
			}
		}
	}
	sort.SliceStable(pipeline.Jobs, func(a, b int) bool { return pipeline.Jobs[a].Name < pipeline.Jobs[b].Name })
}
