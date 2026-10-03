package situation_test

import (
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

func entriesOfKind(entries []entry, kind string) []entry {
	var out []entry
	for _, e := range entries {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// TestPRTargetCoversWorkflowRunHead pins that pr_target covers every
// privileged trigger and attacker-controlled checkout ref that
// ISSUE-802 (dangerous_triggers.rego) and ISSUE-804
// (pull_request_target_head_checkout.rego) detect: a workflow_run job
// that checks out github.event.workflow_run.head_sha is a pr_target
// entry, so an ISSUE-802 finding on it always has a matching fact.
func TestPRTargetCoversWorkflowRunHead(t *testing.T) {
	r := evaluate(t, githubFixture(t, "pr_target_workflow_run.workflow.yml", "public"), nil)
	got := entriesOfKind(r.Jobs["build"].Entries, "pr_target")
	if len(got) != 1 || got[0].State != "proven" || got[0].Subject != "github.event.workflow_run.head_sha" {
		t.Errorf("pr_target: %+v", got)
	}
}

// TestPRTargetCoversEveryControlTriggerAndRef pins the full trigger set
// (ISSUE-804's pull_request_target plus ISSUE-802's eight events) and the
// full ref set (both controls' patterns).
func TestPRTargetCoversEveryControlTriggerAndRef(t *testing.T) {
	triggers := []string{
		"pull_request_target", "workflow_run", "issue_comment", "pull_request_review",
		"pull_request_review_comment", "discussion_comment", "discussion", "gollum", "fork",
	}
	refs := []string{
		"${{ github.event.pull_request.head.sha }}",
		"${{ github.event.pull_request.head.ref }}",
		"${{ github.head_ref }}",
		"${{ github.event.workflow_run.head_sha }}",
		"${{ github.event.workflow_run.head_branch }}",
		"refs/pull/${{ github.event.number }}/merge",
	}
	for _, trig := range triggers {
		for _, ref := range refs {
			p := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitHub,
				Jobs: []ir.Job{{
					Name:     "build",
					Triggers: []string{trig},
					Uses:     []ir.Action{{Uses: "actions/checkout@v4", With: map[string]any{"ref": ref}}},
				}},
			}
			got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "pr_target")
			if len(got) != 1 || got[0].State != "proven" {
				t.Errorf("on %s, ref %s: pr_target = %+v", trig, ref, got)
			}
		}
	}
}

// TestPRTargetInputsRefIsUnresolvable pins that a checkout whose ref comes
// from a workflow input (and names no attacker-controlled field) cannot be
// judged statically: it is an unresolvable pr_target entry, not a proven
// one and not an absent one.
func TestPRTargetInputsRefIsUnresolvable(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:     "build",
			Triggers: []string{"pull_request_target"},
			Uses:     []ir.Action{{Uses: "actions/checkout@v4", With: map[string]any{"ref": "${{ inputs.ref }}"}}},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "pr_target")
	if len(got) != 1 || got[0].State != "unresolvable" || got[0].Subject != "inputs.ref" {
		t.Errorf("pr_target: %+v", got)
	}
}

// TestPRTargetSameRepoGuardExempts pins the reviewer's example: a
// pull_request_target job guarded by a same-repo (family-1) if: condition
// must yield no pr_target entry at all, exactly as ISSUE-804
// (pull_request_target_head_checkout.rego) abstains on the same job.
func TestPRTargetSameRepoGuardExempts(t *testing.T) {
	r := evaluate(t, githubFixture(t, "pr_target_same_repo_guard.workflow.yml", "public"), nil)
	got := entriesOfKind(r.Jobs["build"].Entries, "pr_target")
	if len(got) != 0 {
		t.Errorf("pr_target: %+v, want none (same-repo guard neutralizes the pull_request_target job)", got)
	}
}

// TestPRTargetWorkflowRunPushGuardExempts pins ISSUE-802's family-2 guard:
// a workflow_run job (no pull_request_target trigger) restricted to a
// trusted upstream push must yield no pr_target entry, exactly as
// ISSUE-802 abstains on the same job.
func TestPRTargetWorkflowRunPushGuardExempts(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:     "build",
			Triggers: []string{"workflow_run"},
			If:       "${{ github.event.workflow_run.event == 'push' }}",
			Uses:     []ir.Action{{Uses: "actions/checkout@v4", With: map[string]any{"ref": "${{ github.event.workflow_run.head_sha }}"}}},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "pr_target")
	if len(got) != 0 {
		t.Errorf("pr_target: %+v, want none (workflow_run gated to a trusted push)", got)
	}
}

// TestPRTargetAuthorAssociationGuardExempts pins ISSUE-802's family-3
// guard on an issue_comment job (no pull_request_target trigger): a
// trusted author_association ALLOWLIST (equality) exempts the job, but
// the denylist spelling (!= 'OWNER') does not, exactly mirroring
// ISSUE-802's own _has_guard.
func TestPRTargetAuthorAssociationGuardExempts(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:     "build",
			Triggers: []string{"issue_comment"},
			If:       "${{ github.event.comment.author_association == 'MEMBER' }}",
			Uses:     []ir.Action{{Uses: "actions/checkout@v4", With: map[string]any{"ref": "${{ github.event.pull_request.head.ref }}"}}},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "pr_target")
	if len(got) != 0 {
		t.Errorf("pr_target: %+v, want none (trusted author_association allowlist)", got)
	}

	p.Jobs[0].If = "${{ github.event.comment.author_association != 'OWNER' }}"
	got = entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "pr_target")
	if len(got) != 1 || got[0].State != "proven" {
		t.Errorf("pr_target: %+v, want one proven entry (!= is a denylist, not a guard)", got)
	}
}

// TestPRTargetAuthorAssociationGuardDoesNotExemptPullRequestTarget pins
// ISSUE-804 parity: a pull_request_target job guarded ONLY by an
// author_association check (a family-3 guard, not family-1) must still
// yield the proven entry, because ISSUE-804 honours only the family-1
// same-repo guard and would still flag this job.
func TestPRTargetAuthorAssociationGuardDoesNotExemptPullRequestTarget(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:     "build",
			Triggers: []string{"pull_request_target"},
			If:       "${{ github.event.comment.author_association == 'OWNER' }}",
			Uses:     []ir.Action{{Uses: "actions/checkout@v4", With: map[string]any{"ref": "${{ github.event.pull_request.head.sha }}"}}},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "pr_target")
	if len(got) != 1 || got[0].State != "proven" {
		t.Errorf("pr_target: %+v, want one proven entry (author_association does not satisfy ISSUE-804)", got)
	}
}

// TestPRTargetGuardFamiliesTableExemptAn802Job pins every pattern of every
// ISSUE-802 guard family (family 1, the same-repo forms already proven for
// fork_pr; family 2, workflow_run-from-push; family 3, the
// author_association allowlist, both spellings), applied through the
// job's conditions list rather than its own if:, on a workflow_run job
// (no pull_request_target trigger, so all three families apply).
func TestPRTargetGuardFamiliesTableExemptAn802Job(t *testing.T) {
	cases := []struct {
		name      string
		condition string
	}{
		{"family 1: full_name == github.repository", "github.event.pull_request.head.repo.full_name == github.repository"},
		{"family 1: reversed operands", "github.repository == github.event.pull_request.head.repo.full_name"},
		{"family 1: fork == false", "github.event.pull_request.head.repo.fork == false"},
		{"family 1: fork != true", "github.event.pull_request.head.repo.fork != true"},
		{"family 1: negated shorthand", "!github.event.pull_request.head.repo.fork"},
		{"family 2: workflow_run.event == push", "github.event.workflow_run.event == 'push'"},
		{"family 3: author_association equality", "github.event.comment.author_association == 'MEMBER'"},
		{"family 3: contains() allowlist", "contains(fromJSON('[\"OWNER\", \"MEMBER\", \"COLLABORATOR\"]'), github.event.comment.author_association)"},
	}
	for _, c := range cases {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs: []ir.Job{{
				Name:       "build",
				Triggers:   []string{"workflow_run"},
				Conditions: []string{c.condition},
				Uses:       []ir.Action{{Uses: "actions/checkout@v4", With: map[string]any{"ref": "${{ github.event.workflow_run.head_sha }}"}}},
			}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "pr_target")
		if len(got) != 0 {
			t.Errorf("%s: pr_target = %+v, want none", c.name, got)
		}
	}
}

// sameNamedJobs is two workflow files whose names reduce to the same
// namespace ("ci.yml" and "ci.yaml" both give "ci"), so the collector
// emits two jobs both named "ci/build".
func sameNamedJobs() *ir.NormalizedPipeline {
	return &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{
				Name:       "ci/build",
				OriginFile: ".github/workflows/ci.yml",
				Triggers:   []string{"pull_request"},
				Scripts:    []string{`echo "${{ github.event.pull_request.title }}"`},
			},
			{
				Name:        "ci/build",
				OriginFile:  ".github/workflows/ci.yaml",
				Triggers:    []string{"push"},
				Permissions: map[string]any{"contents": "write"},
			},
		},
	}
}

// TestSameNamedJobsAreMerged pins that two jobs sharing a name do not fail
// the evaluation (an object-key conflict on jobs) and that the one fact
// set under that name carries the entries of both.
func TestSameNamedJobsAreMerged(t *testing.T) {
	r := evaluate(t, sameNamedJobs(), nil)
	j, ok := r.Jobs["ci/build"]
	if !ok || len(r.Jobs) != 1 {
		t.Fatalf("jobs = %+v", r.Jobs)
	}
	k := kinds(j.Entries)
	if _, ok := k["fork_pr"]; !ok {
		t.Errorf("fork_pr from ci.yml missing: %+v", j.Entries)
	}
	if e, ok := k["untrusted_expression"]; !ok || e.File != ".github/workflows/ci.yml" {
		t.Errorf("untrusted_expression from ci.yml missing: %+v", j.Entries)
	}
	if !containsAll(j.Privilege.TokenWrite, "contents") || j.Privilege.TokenWriteSource != "declared" {
		t.Errorf("the contents: write of ci.yaml must survive the merge: %+v", j.Privilege)
	}
}

// TestGitLabWhenNeverRuleIsAnExclusion pins that a rule with when: never
// excludes the pipelines it matches: a job whose merge-request (or push)
// rule says when: never does not run on that source, so it is not an
// entry of that kind.
func TestGitLabWhenNeverRuleIsAnExclusion(t *testing.T) {
	for _, source := range []string{"merge_request_event", "push"} {
		p := &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitLab,
			DefaultBranch: "main",
			Branches:      []ir.Branch{{Name: "main", Protected: false}},
			Jobs: []ir.Job{{
				Name: "test",
				Rules: []map[string]any{
					{"if": `$CI_PIPELINE_SOURCE == "` + source + `"`, "when": "never"},
					{"when": "on_success"},
				},
			}},
		}
		k := kinds(evaluate(t, p, nil).Jobs["test"].Entries)
		if _, ok := k["fork_pr"]; ok {
			t.Errorf("%s when: never: not an MR job: %+v", source, k)
		}
		if _, ok := k["unprotected_push"]; ok {
			t.Errorf("%s when: never: not a push job: %+v", source, k)
		}
		p.Jobs[0].Rules[0]["when"] = "on_success"
		k = kinds(evaluate(t, p, nil).Jobs["test"].Entries)
		want := map[string]string{"merge_request_event": "fork_pr", "push": "unprotected_push"}[source]
		if _, ok := k[want]; !ok {
			t.Errorf("%s when: on_success: want %s, got %+v", source, want, k)
		}
	}
}

// TestGitLabNotEqualOperatorIsNotAnInclusion pins the reviewer's false
// positive: a rule whose if: reads "$CI_PIPELINE_SOURCE != ..." is an
// EXCLUSION of the named source (the job runs on every OTHER source), never
// an inclusion of it, so a substring match on the bare operand must not
// treat it as one.
func TestGitLabNotEqualOperatorIsNotAnInclusion(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name: "test",
			Rules: []map[string]any{
				{"if": `$CI_COMMIT_BRANCH && $CI_PIPELINE_SOURCE != "merge_request_event"`},
			},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "fork_pr")
	if len(got) != 0 {
		t.Errorf("fork_pr: %+v, want none (the rule excludes merge_request_event, it does not include it)", got)
	}
}

// TestGitLabExcludeOtherSourcesThenRunIdiomIncludesIt pins the "exclude
// every other source, then run" idiom: a rule with
// if: '$CI_PIPELINE_SOURCE != "merge_request_event"', when: never excludes
// every source EXCEPT merge_request_event, so a later rule whose when is
// not never still lets a merge_request_event pipeline run the job: that is
// a fork_pr entry. Dropping the second rule removes the only path that lets
// the job run at all, so no fork_pr survives.
func TestGitLabExcludeOtherSourcesThenRunIdiomIncludesIt(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name: "test",
			Rules: []map[string]any{
				{"if": `$CI_PIPELINE_SOURCE != "merge_request_event"`, "when": "never"},
				{"when": "always"},
			},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "fork_pr")
	if len(got) != 1 {
		t.Errorf("fork_pr: %+v, want one (every other source is excluded, so this one runs)", got)
	}

	p.Jobs[0].Rules = p.Jobs[0].Rules[:1]
	got = entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "fork_pr")
	if len(got) != 0 {
		t.Errorf("fork_pr: %+v, want none (no rule left ever runs the job)", got)
	}
}

// TestGitLabPushOperatorSpellings pins that push_job recognizes
// $CI_PIPELINE_SOURCE == "push" whatever its quoting and spacing, not just
// the one literal double-quoted, single-spaced spelling the old substring
// check required.
func TestGitLabPushOperatorSpellings(t *testing.T) {
	spellings := []string{
		`$CI_PIPELINE_SOURCE == 'push'`,
		`$CI_PIPELINE_SOURCE=="push"`,
		`$CI_PIPELINE_SOURCE   ==   "push"`,
		`$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`,
	}
	for _, spelling := range spellings {
		t.Run(spelling, func(t *testing.T) {
			p := &ir.NormalizedPipeline{
				Provider:      ir.ProviderGitLab,
				DefaultBranch: "main",
				Branches:      []ir.Branch{{Name: "main", Protected: false}},
				Jobs: []ir.Job{{
					Name:  "deploy",
					Rules: []map[string]any{{"if": spelling}},
				}},
			}
			got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
			if len(got) != 1 || got[0].State != "proven" {
				t.Errorf("unprotected_push: %+v", got)
			}
		})
	}
}

// TestGitLabCommitBranchEqualsDefaultBranchIdiom pins finding A of the
// round-9 review: the $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH idiom (and its
// reversed spelling, its bare-presence spelling and its quoted-literal
// spelling) is the dominant way a GitLab job restricts itself to a push to
// the default branch, so it must prove unprotected_push on an unprotected
// default branch exactly like an explicit $CI_PIPELINE_SOURCE == "push"
// rule already does.
func TestGitLabCommitBranchEqualsDefaultBranchIdiom(t *testing.T) {
	t.Run("fixture: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", func(t *testing.T) {
		p := gitlabFixture(t, "default_branch_deploy.gitlab-ci.yml", "public")
		p.DefaultBranch = "main"
		p.Branches = []ir.Branch{{Name: "main", Protected: false}}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	newPipeline := func(ifText string) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitLab,
			DefaultBranch: "main",
			Branches:      []ir.Branch{{Name: "main", Protected: false}},
			Jobs: []ir.Job{{
				Name:  "deploy",
				Rules: []map[string]any{{"if": ifText}},
			}},
		}
	}

	t.Run("in-memory: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`)
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("reversed: $CI_DEFAULT_BRANCH == $CI_COMMIT_BRANCH", func(t *testing.T) {
		p := newPipeline(`$CI_DEFAULT_BRANCH == $CI_COMMIT_BRANCH`)
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("bare $CI_COMMIT_BRANCH", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH`)
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("bare $CI_COMMIT_BRANCH with a trailing condition", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH && $CI_PIPELINE_SOURCE != "merge_request_event"`)
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("literal equal to the default branch name is proven", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == "main"`)
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("literal equal to some other branch is not an entry", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == "develop"`)
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("literal equal with no configured default branch is unresolvable", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == "main"`)
		p.DefaultBranch = ""
		p.Branches = nil
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "unresolvable" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("regex is unresolvable", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH =~ /^release-/`)
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "unresolvable" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("not-equal is not an inclusion", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH`)
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("when: never is an exclusion", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`)
		p.Jobs[0].Rules[0]["when"] = "never"
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})
}

// TestGitLabPushNotEqualOperatorIsNotAnInclusion pins the push counterpart
// of TestGitLabNotEqualOperatorIsNotAnInclusion: a rule reading
// "$CI_PIPELINE_SOURCE != "push"" (when not never) excludes push, it does
// not include it, so no unprotected_push entry follows.
func TestGitLabPushNotEqualOperatorIsNotAnInclusion(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}},
		Jobs: []ir.Job{{
			Name:  "deploy",
			Rules: []map[string]any{{"if": `$CI_PIPELINE_SOURCE != "push"`}},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
	if len(got) != 0 {
		t.Errorf("unprotected_push: %+v, want none", got)
	}
}

// TestGitLabNoRulesIsAPushJob pins that a GitLab job with no rules: block
// at all is a push job (push_job's no-rules branch): on an unprotected
// default branch it gets a proven unprotected_push entry naming that branch.
func TestGitLabNoRulesIsAPushJob(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}},
		Jobs:          []ir.Job{{Name: "test"}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "unprotected_push")
	if len(got) != 1 || got[0].State != "proven" || got[0].Subject != "main" {
		t.Errorf("unprotected_push: %+v", got)
	}
}

// TestGitLabPushOnProtectedDefaultBranchHasNoEntry pins the GitLab wiring
// of the default branch's protection, the GitHub twin of which is
// TestPushToUnprotectedDefaultBranch: a push job (no rules, or a rule on
// $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH) on a protected default branch
// yields no unprotected_push entry at all, and with the protection unknown
// (no branches collected) the entry is unresolvable, never proven. Dropping
// the push_entry_state != "protected" guard, or the GitLab fall-through to
// default_branch_state, turns the first case into a proven false positive.
func TestGitLabPushOnProtectedDefaultBranchHasNoEntry(t *testing.T) {
	jobs := map[string]ir.Job{
		"no rules":    {Name: "deploy"},
		"branch rule": {Name: "deploy", Rules: []map[string]any{{"if": `$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`}}},
	}
	for name, job := range jobs {
		t.Run(name, func(t *testing.T) {
			p := &ir.NormalizedPipeline{
				Provider:      ir.ProviderGitLab,
				DefaultBranch: "main",
				Branches:      []ir.Branch{{Name: "main", Protected: true}},
				Jobs:          []ir.Job{job},
			}
			if got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push"); len(got) != 0 {
				t.Errorf("protected default branch: unprotected_push = %+v, want none", got)
			}
			p.Branches = nil
			got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
			if len(got) != 1 || got[0].State != "unresolvable" || got[0].Subject != "main" {
				t.Errorf("unknown protection: unprotected_push = %+v, want one unresolvable entry on main", got)
			}
		})
	}
}

// TestGitLabOnlyTagsIsNotAPushJob pins that a job whose legacy only: names
// only non-branch sources (here tags) never runs on a push to the default
// branch, so it gets no unprotected_push entry at all, even on an
// unprotected default branch.
func TestGitLabOnlyTagsIsNotAPushJob(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}},
		Jobs:          []ir.Job{{Name: "deploy", Only: []string{"tags"}}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
	if len(got) != 0 {
		t.Errorf("unprotected_push: %+v, want none", got)
	}
}

// TestGitLabOnlyMainIsAProvenPushJob pins that only: [main] (a literal
// branch name) admits a push to the default branch exactly like the
// no-rules default, so it is a proven unprotected_push entry on an
// unprotected default branch.
func TestGitLabOnlyMainIsAProvenPushJob(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}},
		Jobs:          []ir.Job{{Name: "deploy", Only: []string{"main"}}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
	if len(got) != 1 || got[0].State != "proven" || got[0].Subject != "main" {
		t.Errorf("unprotected_push: %+v", got)
	}
}

// TestGitLabOnlyUnknownRefIsUnresolvable pins that an only: entry that is
// neither a recognized branch-push ref nor a recognized non-branch source
// (a regex, or an unknown named ref) cannot be decided statically: the
// unprotected_push entry still exists, but unresolvable, not proven.
func TestGitLabOnlyUnknownRefIsUnresolvable(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}},
		Jobs:          []ir.Job{{Name: "deploy", Only: []string{`/^release-.*$/`}}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
	if len(got) != 1 || got[0].State != "unresolvable" {
		t.Errorf("unprotected_push: %+v", got)
	}
}

// TestGitLabOnlyMergeRequestsIsLiveNotDead pins that the merge_request_job
// only: branch (previously dead while Job.Only was never populated) now
// fires once the collector carries only:, with both the fork_pr entry and
// the independent untrusted_expression entry from a dangerous GitLab
// variable used in the script.
func TestGitLabOnlyMergeRequestsIsLiveNotDead(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:    "build",
			Only:    []string{"merge_requests"},
			Scripts: []string{`echo "$CI_MERGE_REQUEST_TITLE"`},
		}},
	}
	k := kinds(evaluate(t, p, nil).Jobs["build"].Entries)
	if e, ok := k["fork_pr"]; !ok || e.State != "proven" {
		t.Errorf("fork_pr: %+v", k)
	}
	if _, ok := k["untrusted_expression"]; !ok {
		t.Errorf("untrusted_expression: %+v", k)
	}
}

// TestGitLabMergeRequestIIDIdiom pins finding B of the round-9 review: a
// rule gated on the bare $CI_MERGE_REQUEST_IID (or its _ID spelling) is a
// merge-request pipeline idiom, read the way an operator would, since that
// variable is only ever set on a merge-request pipeline. A rule that
// instead tests the variable for null or "" is testing its ABSENCE (not a
// merge-request pipeline), so that spelling must not be read as inclusion,
// unless it is itself excluded with when: never and a genuine catch-all
// rule follows it, the same "exclude then run" shape
// gitlab_rules_run_on's second body already recognizes.
func TestGitLabMergeRequestIIDIdiom(t *testing.T) {
	newPipeline := func(rules []map[string]any) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{
			Provider: ir.ProviderGitLab,
			Jobs:     []ir.Job{{Name: "test", Rules: rules}},
		}
	}

	t.Run("bare $CI_MERGE_REQUEST_IID", func(t *testing.T) {
		p := newPipeline([]map[string]any{{"if": `$CI_MERGE_REQUEST_IID`}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "fork_pr")
		if len(got) != 1 {
			t.Errorf("fork_pr: %+v, want one", got)
		}
	})

	t.Run("bare $CI_MERGE_REQUEST_ID", func(t *testing.T) {
		p := newPipeline([]map[string]any{{"if": `$CI_MERGE_REQUEST_ID`}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "fork_pr")
		if len(got) != 1 {
			t.Errorf("fork_pr: %+v, want one", got)
		}
	})

	t.Run("== null with when not never yields none", func(t *testing.T) {
		p := newPipeline([]map[string]any{{"if": `$CI_MERGE_REQUEST_IID == null`}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "fork_pr")
		if len(got) != 0 {
			t.Errorf("fork_pr: %+v, want none (null-tests its absence, not its presence)", got)
		}
	})

	t.Run("== null with when: never then a genuine catch-all yields fork_pr", func(t *testing.T) {
		p := newPipeline([]map[string]any{
			{"if": `$CI_MERGE_REQUEST_IID == null`, "when": "never"},
			{"when": "always"},
		})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "fork_pr")
		if len(got) != 1 {
			t.Errorf("fork_pr: %+v, want one (every non-MR pipeline is excluded, so this one runs)", got)
		}
	})

	t.Run("== null with when: never alone yields none", func(t *testing.T) {
		p := newPipeline([]map[string]any{
			{"if": `$CI_MERGE_REQUEST_IID == null`, "when": "never"},
		})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "fork_pr")
		if len(got) != 0 {
			t.Errorf("fork_pr: %+v, want none (no rule left ever runs the job)", got)
		}
	})
}

// TestGitLabExceptBranchesIsNotAPushJob pins that except: [branches]
// vetoes the push-to-default-branch path outright, even with no rules:
// and no only: at all, so there is no unprotected_push entry.
func TestGitLabExceptBranchesIsNotAPushJob(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}},
		Jobs:          []ir.Job{{Name: "deploy", Except: []string{"branches"}}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
	if len(got) != 0 {
		t.Errorf("unprotected_push: %+v, want none", got)
	}
}

// TestGitLabOnlyExceptBranchRefIsTheConfiguredDefaultBranchNotAHardcodedName
// pins that only:/except: branch names are judged against the project's
// actual configured default branch, never a hard-coded "main" or
// "master": a project whose default branch is "main" gated to
// only: [master] must not look like a push to the default branch
// (master is some other, specific branch, not main), and
// except: [master] on that same project must not look like it drops
// the default-branch entry either. When the default branch itself is
// not known, a named branch cannot be ruled in or out, so the state is
// unresolvable rather than guessed either way.
func TestGitLabOnlyExceptBranchRefIsTheConfiguredDefaultBranchNotAHardcodedName(t *testing.T) {
	t.Run("only master on a main-default project is not the default branch", func(t *testing.T) {
		p := &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitLab,
			DefaultBranch: "main",
			Branches:      []ir.Branch{{Name: "main", Protected: false}},
			Jobs:          []ir.Job{{Name: "deploy", Only: []string{"master"}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("only main on a main-default project is proven", func(t *testing.T) {
		p := &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitLab,
			DefaultBranch: "main",
			Branches:      []ir.Branch{{Name: "main", Protected: false}},
			Jobs:          []ir.Job{{Name: "deploy", Only: []string{"main"}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" || got[0].Subject != "main" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("except master on a main-default project still proves the main push", func(t *testing.T) {
		p := &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitLab,
			DefaultBranch: "main",
			Branches:      []ir.Branch{{Name: "main", Protected: false}},
			Jobs:          []ir.Job{{Name: "deploy", Except: []string{"master"}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" || got[0].Subject != "main" {
			t.Errorf("unprotected_push: %+v, want one proven entry for main", got)
		}
	})

	t.Run("only main with no configured default branch is unresolvable", func(t *testing.T) {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitLab,
			Jobs:     []ir.Job{{Name: "deploy", Only: []string{"main"}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "unresolvable" {
			t.Errorf("unprotected_push: %+v, want one unresolvable entry", got)
		}
	})
}

// TestMutableReusableWorkflowMirrorsActionUnpinned pins the job-level
// half of ISSUE-701 (action_unpinned.rego reads reusableWorkflowUses): a
// reusable workflow called by a branch or tag ref is a mutable dependency
// whose subject is the call as written; a SHA pin and a local call are not.
func TestMutableReusableWorkflowMirrorsActionUnpinned(t *testing.T) {
	cases := []struct {
		uses      string
		wantEntry bool
	}{
		{"org/repo/.github/workflows/x.yml@main", true},
		{"org/repo/.github/workflows/x.yml@08c6903cd8c0fde910a37f88322edcfb5dd907a8", false},
		{"./.github/workflows/x.yml", false},
	}
	for _, tc := range cases {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "call", ReusableWorkflowUses: tc.uses}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["call"].Entries, "mutable_dependency")
		if tc.wantEntry && (len(got) != 1 || got[0].Subject != tc.uses || got[0].State != "proven") {
			t.Errorf("%s: mutable_dependency = %+v", tc.uses, got)
		}
		if !tc.wantEntry && len(got) != 0 {
			t.Errorf("%s: want no entry, got %+v", tc.uses, got)
		}
	}
}

// TestMutableReusableWorkflowUntrustedSourceIsProven pins a finding from
// the PR #513 review: ISSUE-713 (action_authorized_sources.rego) also flags a
// SHA-pinned reusable workflow from an owner outside the trust conditions,
// the same way it flags a step action; mutable_reusable_workflow must carry
// that fact too, not just the unpinned-ref case.
func TestMutableReusableWorkflowUntrustedSourceIsProven(t *testing.T) {
	const sha = "08c6903cd8c0fde910a37f88322edcfb5dd907a8"
	cfg := map[string]any{"githubActionMustComeFromAuthorizedSources": map[string]any{
		"trustGithubOfficialActions": true,
		"trustedGithubActions":       []string{"trusted-org/*"},
	}}
	untrusted := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "call", ReusableWorkflowUses: "random-org/repo/.github/workflows/x.yml@" + sha}},
	}
	got := entriesOfKind(evaluate(t, untrusted, cfg).Jobs["call"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].State != "proven" {
		t.Errorf("untrusted owner: mutable_dependency = %+v", got)
	}

	trusted := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "call", ReusableWorkflowUses: "trusted-org/repo/.github/workflows/x.yml@" + sha}},
	}
	if got := entriesOfKind(evaluate(t, trusted, cfg).Jobs["call"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("allowlisted owner: mutable_dependency = %+v, want none", got)
	}

	if got := entriesOfKind(evaluate(t, untrusted, nil).Jobs["call"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("policy not configured: mutable_dependency = %+v, want none", got)
	}
}

// TestFetchedScriptsMirrorUnverifiedScripts pins the fetched-script forms
// of ISSUE-411 (unverified_scripts.rego) beyond curl | sh: interpreters
// other than a shell, the inline base64 payload, and download-then-execute.
// npx is not one of ISSUE-411's forms and is not detected here either (the
// fact layer must mirror 411, not exceed it): an unversioned npx resolves
// lockfile-pinned local binaries in the common case, so neither an
// unversioned nor a versioned invocation is an entry.
func TestFetchedScriptsMirrorUnverifiedScripts(t *testing.T) {
	cases := []struct {
		script    string
		wantEntry bool
	}{
		{`curl -sSL https://example.com/get.py | python3`, true},
		{`wget -qO- https://example.com/x.pl | perl`, true},
		{`echo "aGVsbG8K" | base64 -d | bash`, true},
		{`curl -sSLo /tmp/i.sh https://example.com/i.sh && bash /tmp/i.sh`, true},
		{`npx -y cowsay`, false},
		{`npx -y cowsay@1.2.3`, false},
	}
	for _, tc := range cases {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitLab,
			Jobs:     []ir.Job{{Name: "test", Scripts: []string{tc.script}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "mutable_dependency")
		if (len(got) > 0) != tc.wantEntry {
			t.Errorf("%s: mutable_dependency = %+v, want entry %v", tc.script, got, tc.wantEntry)
		}
	}
}

// TestFetchedScriptPipeMustBeOnSameLineAndHonorsCommentsAndQuotes pins the
// fetched-script first branch's own line discipline: the curl/wget pipe
// only counts, for that branch, when the pipe sits on the same line as
// the fetch, and the quoted-substring and comment stripping
// unverified_script_line already applies before its own matching also
// applies here.
//
// A fetch split so the pipe lands on its own later line ("curl ...\n|
// bash") still produces an entry, just not through this branch: a bare
// "| bash" is, on its own, exactly the generic pipe-to-shell form
// unverified_script_line's catch-all exists to catch (it never required
// a curl/wget on the same line, mirroring ISSUE-411 verbatim), so the
// fact layer's own invariant, that every form ISSUE-411 detects also
// produces a fact here, still holds for that split case.
func TestFetchedScriptPipeMustBeOnSameLineAndHonorsCommentsAndQuotes(t *testing.T) {
	cases := []struct {
		name      string
		script    string
		wantEntry bool
	}{
		{"commented-out fetch is not an entry", "  # curl -sSL https://example.com/i.sh | bash", false},
		{"fetch and pipe on one line is still an entry", "curl -sSL https://example.com/i.sh | bash", true},
		{"fetch on one line, pipe alone on the next is still an entry, via the generic catch-all, not this branch", "curl -sSL https://example.com/i.sh\n| bash", true},
		{"a quoted fetch-and-pipe is not an entry", `echo "curl https://example.com/i.sh | bash"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitLab,
				Jobs:     []ir.Job{{Name: "test", Scripts: []string{tc.script}}},
			}
			got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "mutable_dependency")
			if (len(got) > 0) != tc.wantEntry {
				t.Errorf("%s: mutable_dependency = %+v, want entry %v", tc.script, got, tc.wantEntry)
			}
		})
	}
}

// TestUnverifiedScriptLineHeredocAndLocalEchoExemptions pins finding C of
// the round-9 review: unverified_script_line's generic (bare "| shell")
// body is a copy of ISSUE-411's own code, heredoc and local-echo exemptions
// included, but no test here exercised those two guards yet. A heredoc
// block is never a fetch-and-execute pipe, whatever shell name happens to
// sit after a "<<" marker inside it; an echo/printf of local data (no
// curl/wget/base64 anywhere on the line) piped to a shell is not fetching
// anything remote either. The positive mirror (an actual fetch-and-execute
// pipe) is already pinned by TestScriptEvidenceIsTheMatchingLine, so it is
// referenced here rather than duplicated.
func TestUnverifiedScriptLineHeredocAndLocalEchoExemptions(t *testing.T) {
	t.Run("heredoc is not a mutable_dependency", func(t *testing.T) {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitLab,
			Jobs:     []ir.Job{{Name: "test", Scripts: []string{"cat <<EOF | bash\n echo hello\nEOF"}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "mutable_dependency")
		if len(got) != 0 {
			t.Errorf("heredoc: mutable_dependency = %+v, want none", got)
		}
	})

	t.Run("echo of local data is not a mutable_dependency", func(t *testing.T) {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitLab,
			Jobs:     []ir.Job{{Name: "test", Scripts: []string{`echo "$FOO" | bash`}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "mutable_dependency")
		if len(got) != 0 {
			t.Errorf("echo of local data: mutable_dependency = %+v, want none (no curl/wget/base64)", got)
		}
	})
}

// TestGitLabServicesAreMutableDependencies pins that the GitLab services:
// block (ir.Job.Services, extractGitLabServices in gitlab/gitlab_ir.go)
// feeds the same mutable-image check as the job's own image: one entry
// per service image, its subject the full reference, covering both
// accepted services: forms (a bare string and a {name: ...} map entry).
func TestGitLabServicesAreMutableDependencies(t *testing.T) {
	r := evaluate(t, gitlabFixture(t, "services.gitlab-ci.yml", "private"), nil)
	subjects := map[string]bool{}
	for _, e := range r.Jobs["test"].Entries {
		if e.Kind == "mutable_dependency" {
			subjects[e.Subject] = true
		}
	}
	for _, want := range []string{"alpine:3.19", "postgres:latest", "redis:7"} {
		if !subjects[want] {
			t.Errorf("missing mutable_dependency subject %q, got %v", want, subjects)
		}
	}
	if len(subjects) != 3 {
		t.Errorf("want exactly 3 mutable_dependency entries (image + two services), got %v", subjects)
	}
}

// TestPipInstallFromURLIsMutableDependency pins the pip-install half of
// fetched_script_line's first branch: pip install https://... fetches
// and installs code outside the package index at execution time, a
// mutable dependency whose subject is the URL; pip install of an
// ordinary package name resolves through the index and is not one.
func TestPipInstallFromURLIsMutableDependency(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs:     []ir.Job{{Name: "test", Scripts: []string{"pip install https://example.com/pkg.tar.gz"}}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].State != "proven" || got[0].Subject != "https://example.com/pkg.tar.gz" {
		t.Errorf("pip install https URL: %+v", got)
	}

	p.Jobs[0].Scripts = []string{"pip install requests"}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["test"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("pip install requests: want no entry, got %+v", got)
	}
}

// TestMutableImageSubjectIsTheFullReference pins the image subject to the
// whole reference, registry and tag included, the value ISSUE-102 and
// ISSUE-103 carry for the same image.
func TestMutableImageSubjectIsTheFullReference(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:  "build",
			Image: &ir.Image{Registry: "registry.example.com", Name: "team/app", Tag: "latest"},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].Subject != "registry.example.com/team/app:latest" {
		t.Errorf("mutable_dependency = %+v", got)
	}
}

// TestMutableImageUnknownRegistryIsDroppedLikeEmpty pins finding D of the
// round-9 review: image_registry_prefix drops a registry of "unknown"
// exactly like an empty one, since the GitLab collector writes "unknown"
// as its own placeholder for an unresolved registry, never something the
// author wrote, so it must never be read as a literal registry hostname in
// the subject.
func TestMutableImageUnknownRegistryIsDroppedLikeEmpty(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:  "build",
			Image: &ir.Image{Registry: "unknown", Name: "team/app", Tag: "latest"},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].Subject != "team/app:latest" {
		t.Errorf("mutable_dependency = %+v, want subject team/app:latest", got)
	}
}

// TestUntrustedExpressionGitHubMirrorsTemplateInjection pins the GitHub
// untrusted_expression list against ISSUE-207 (template_injection.rego):
// each attacker-controlled field that control flags inside a run script is
// an entry whose subject is the bare expression, and an expression that
// only sits in a step if: is never one (an if: is not a shell sink).
func TestUntrustedExpressionGitHubMirrorsTemplateInjection(t *testing.T) {
	fields := []string{
		"github.event.issue.title",
		"github.event.pull_request.body",
		"github.head_ref",
		"github.event.pull_request.head.label",
		"github.event.workflow_run.head_branch",
		"github.event.pull_request.head.repo.default_branch",
		"github.event.workflow_run.head_repository.default_branch",
		"github.event.workflow_run.head_commit.message",
		"github.event.repository.description",
		"github.event.head_commit.author.name",
		"github.event.head_commit.committer.email",
		"github.event.pages.page_name",
	}
	for _, f := range fields {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "build", Scripts: []string{"echo \"${{ " + f + " }}\""}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression")
		if len(got) != 1 || got[0].Subject != f || got[0].State != "proven" {
			t.Errorf("%s: untrusted_expression = %+v", f, got)
		}
	}

	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:      "build",
			Scripts:   []string{"make"},
			ScriptIfs: []string{"${{ github.event.workflow_run.head_branch == 'main' || github.event.issue.title == 'x' }}"},
		}},
	}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 0 {
		t.Errorf("an if: is not a shell sink, got %+v", got)
	}

	p.Jobs[0].ScriptIfs = nil
	p.Jobs[0].Scripts = []string{"echo github.event.issue.title"}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 0 {
		t.Errorf("a field name outside ${{ }} is plain text, got %+v", got)
	}
}

// TestUntrustedExpressionGitLabMirrorsUnsafeVariableExpansion pins the
// GitLab list against ISSUE-204 (unsafe_variable_expansion.rego): the
// variable names come from input.config.unsafeVariableExpansion
// .dangerousVariables (the default list when absent), both $VAR and
// ${VAR} match, the unbraced form needs a word boundary, and the subject
// is the bare variable name, the same value as ISSUE-204's variableName.
func TestUntrustedExpressionGitLabMirrorsUnsafeVariableExpansion(t *testing.T) {
	cases := []struct {
		name, script string
		cfg          map[string]any
		want         []string
	}{
		{"unbraced default variable", `sh -c "echo $CI_COMMIT_REF_SLUG"`, nil, []string{"CI_COMMIT_REF_SLUG"}},
		{"braced default variable", `echo ${CI_COMMIT_TITLE}`, nil, []string{"CI_COMMIT_TITLE"}},
		{"tag message is in the default list", `eval "$CI_COMMIT_TAG_MESSAGE"`, nil, []string{"CI_COMMIT_TAG_MESSAGE"}},
		{"word boundary on the unbraced form", `echo $CI_COMMIT_TITLEX`, nil, nil},
		{
			"configured list replaces the default", `echo $MY_VAR $CI_COMMIT_TITLE`,
			map[string]any{"unsafeVariableExpansion": map[string]any{"dangerousVariables": []string{"MY_VAR"}}},
			[]string{"MY_VAR"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &ir.NormalizedPipeline{
				Provider: ir.ProviderGitLab,
				Jobs:     []ir.Job{{Name: "test", Scripts: []string{tc.script}}},
			}
			var subjects []string
			for _, e := range entriesOfKind(evaluate(t, p, tc.cfg).Jobs["test"].Entries, "untrusted_expression") {
				subjects = append(subjects, e.Subject)
			}
			if len(subjects) != len(tc.want) {
				t.Fatalf("subjects = %v, want %v", subjects, tc.want)
			}
			for i := range subjects {
				if subjects[i] != tc.want[i] {
					t.Errorf("subjects = %v, want %v", subjects, tc.want)
				}
			}
		})
	}
}

// TestUntrustedExpressionGitLabSkipsWholeLineComments pins that a GitLab
// script line whose trimmed form starts with "#" is never scanned for a
// dangerous variable, mirroring ISSUE-204
// (unsafe_variable_expansion.rego) at the line level. A trailing comment
// after real code on the same line still counts: only a whole-line comment
// is skipped.
func TestUntrustedExpressionGitLabSkipsWholeLineComments(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:    "build",
			Scripts: []string{"echo building\n# - eval \"$CI_COMMIT_MESSAGE\"   # disabled"},
		}},
	}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 0 {
		t.Errorf("commented-out eval line: untrusted_expression = %+v, want none", got)
	}

	p.Jobs[0].Scripts = []string{"echo building\neval \"$CI_COMMIT_MESSAGE\""}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression")
	if len(got) != 1 || got[0].Evidence != `eval "$CI_COMMIT_MESSAGE"` {
		t.Errorf("uncommented eval line: untrusted_expression = %+v", got)
	}

	// A trailing comment after real code on the same line still counts:
	// only a whole-line comment is skipped.
	p.Jobs[0].Scripts = []string{`echo $CI_COMMIT_MESSAGE # legit`}
	got = entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression")
	if len(got) != 1 {
		t.Errorf("trailing comment: untrusted_expression = %+v, want one", got)
	}
}

// TestUntrustedExpressionGitHubCommentsAreStillSubstituted pins a ruling
// of the PR #513 review, specific to GitHub: GitHub substitutes "${{ }}"
// before the shell ever reads the script (the runner expands it as a
// templating step over the raw file text), so an expression sitting
// inside a shell comment line is still injected and must still yield an
// entry, whole-line comment or not.
// GitLab's shell reads "$VAR" verbatim and a shell comment really is inert
// there, so TestUntrustedExpressionGitLabSkipsWholeLineComments above is
// unaffected: the comment skip stays GitLab-only.
func TestUntrustedExpressionGitHubCommentsAreStillSubstituted(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:    "build",
			Scripts: []string{"# echo ${{ github.event.issue.title }}"},
		}},
	}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("commented script line: untrusted_expression = %+v, want one (GitHub expands ${{ }} before the shell reads the comment)", got)
	}

	p.Jobs[0].Scripts = []string{"echo ${{ github.event.issue.title }}"}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("uncommented script line: untrusted_expression = %+v, want one", got)
	}

	// An indented comment line is substituted just the same (trim_space
	// has no bearing on whether GitHub expands it).
	p.Jobs[0].Scripts = []string{"echo ok\n    # echo ${{ github.event.issue.title }}"}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("indented commented line: untrusted_expression = %+v, want one", got)
	}

	// A with: value is not a shell line: comment handling never applied to
	// it in the first place, nothing changes here.
	p.Jobs[0].Scripts = nil
	p.Jobs[0].Uses = []ir.Action{{Uses: "some/action@v1", With: map[string]any{"body": "# ${{ github.event.issue.title }}"}}}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("with value: untrusted_expression = %+v, want one (no comment skipping for with values)", got)
	}
}

// TestGitLabExcludeThenRunRequiresGenuineCatchAll pins that the "exclude
// every other source, then run" idiom (a rule excluding every OTHER
// source with when: never) only proves an inclusion of
// <source> when the later rule is a genuine catch-all, with no if: of its
// own. A later rule that carries its own if: is not statically decidable
// (it might or might not match a <source> pipeline), so it must not be read
// as an inclusion, even though it is not when: never either.
func TestGitLabExcludeThenRunRequiresGenuineCatchAll(t *testing.T) {
	cases := []struct {
		source, entryKind string
	}{
		{"push", "unprotected_push"},
		{"merge_request_event", "fork_pr"},
	}
	for _, c := range cases {
		t.Run(c.source, func(t *testing.T) {
			// Genuine catch-all (no if:) still includes the source.
			p := &ir.NormalizedPipeline{
				Provider:      ir.ProviderGitLab,
				DefaultBranch: "main",
				Branches:      []ir.Branch{{Name: "main", Protected: false}},
				Jobs: []ir.Job{{
					Name: "deploy",
					Rules: []map[string]any{
						{"if": `$CI_PIPELINE_SOURCE != "` + c.source + `"`, "when": "never"},
						{"when": "always"},
					},
				}},
			}
			got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, c.entryKind)
			if len(got) != 1 {
				t.Errorf("catch-all: %s = %+v, want one entry", c.entryKind, got)
			}

			// A later rule with its own if: is not a genuine catch-all: it
			// might or might not match a <source> pipeline, so the
			// exclude-then-run idiom alone proves nothing.
			p.Jobs[0].Rules[1] = map[string]any{"if": `$CI_COMMIT_REF_PROTECTED == "true"`}
			got = entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, c.entryKind)
			if len(got) != 0 {
				t.Errorf("later rule with its own if:: %s = %+v, want none", c.entryKind, got)
			}

			// A later rule the $CI_COMMIT_BRANCH idiom CAN read is decided by
			// that idiom on its own, whatever came before it: on a push to
			// main the exclusion does not match and the branch rule does, so
			// the job is a default-branch push job (unprotected_push, proven);
			// $CI_COMMIT_BRANCH is unset on a merge-request pipeline, so the
			// same shape is still not a merge-request job (no fork_pr).
			p.Jobs[0].Rules[1] = map[string]any{"if": `$CI_COMMIT_BRANCH == "main"`}
			got = entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, c.entryKind)
			want := map[string]int{"push": 1, "merge_request_event": 0}[c.source]
			if len(got) != want {
				t.Errorf("later $CI_COMMIT_BRANCH rule: %s = %+v, want %d", c.entryKind, got, want)
			}
			if want == 1 && len(got) == 1 && got[0].State != "proven" {
				t.Errorf("later $CI_COMMIT_BRANCH rule: state = %q, want proven", got[0].State)
			}
		})
	}
}

// TestGitLabExcludeThenRunReviewerProtectedBranchExample pins the reviewer's
// exact finding: a deploy job excluded from every source but push, then
// gated by a protected-branch check, is a push job that runs only on
// protected-branch pushes. It must not be read as an unconditional push job
// (unprotected_push), because the later rule carries its own if: and is
// therefore not a genuine catch-all.
func TestGitLabExcludeThenRunReviewerProtectedBranchExample(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Branches:      []ir.Branch{{Name: "main", Protected: false}},
		Jobs: []ir.Job{{
			Name: "deploy",
			Rules: []map[string]any{
				{"if": `$CI_PIPELINE_SOURCE != "push"`, "when": "never"},
				{"if": `$CI_COMMIT_REF_PROTECTED == "true"`},
			},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
	if len(got) != 0 {
		t.Errorf("unprotected_push: %+v, want none (the later rule is gated on protected branch, not a catch-all)", got)
	}
}

// ---------------------------------------------------------- PR #513 review

// TestUntrustedExpressionGitHubContextDump pins the 213
// (unsafe_github_context_dump.rego) context-dump pattern, toJson(github) and
// toJson(github.event), matched directly against the raw text the same way
// 213 itself does (PR #513 review): a script line, a job
// variable value, or a step with: value that serialises the whole github
// context is just as attacker-controlled as any single field it would
// otherwise have to name, whatever else surrounds the call in the text.
func TestUntrustedExpressionGitHubContextDump(t *testing.T) {
	for _, expr := range []string{"toJson(github)", "toJson(github.event)", "toJSON( github )"} {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitHub,
			Jobs:     []ir.Job{{Name: "build", Scripts: []string{"echo '${{ " + expr + " }}'"}}},
		}
		got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("%s: untrusted_expression = %+v", expr, got)
		}
	}

	// A field that is not a context dump and not otherwise on the unsafe
	// list (github.run_id) is not an entry.
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "build", Scripts: []string{"echo '${{ github.run_id }}'"}}},
	}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 0 {
		t.Errorf("github.run_id: untrusted_expression = %+v, want none", got)
	}

	// format('{0}', toJson(github)): the inner "}" of "{0}" ends a naive
	// "${{[^}]*" isolation span before it ever reaches toJson(github), so
	// this form needs the direct, unisolated match 213 itself uses, not
	// the two-pass "${{ ... }}" span the other GitHub patterns go through.
	obfuscated := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "build", Scripts: []string{"echo '${{ format('{0}', toJson(github)) }}'"}}},
	}
	if got := entriesOfKind(evaluate(t, obfuscated, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("format('{0}', toJson(github)): untrusted_expression = %+v, want one", got)
	}

	// The same obfuscated form in a step with: value and in a job
	// variable, 213's other two sources.
	withValue := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{Uses: "some/action@v1", With: map[string]any{"body": "${{ format('{0}', toJson(github)) }}"}}},
		}},
	}
	if got := entriesOfKind(evaluate(t, withValue, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("with value, format('{0}', toJson(github)): untrusted_expression = %+v, want one", got)
	}

	envValue := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "build", Variables: map[string]string{"DUMP": "${{ format('{0}', toJson(github)) }}"}}},
	}
	if got := entriesOfKind(evaluate(t, envValue, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("variable, format('{0}', toJson(github)): untrusted_expression = %+v, want one", got)
	}
}

// TestUntrustedExpressionGitHubContextDumpSplitAcrossLines pins that a
// toJson(github) call broken onto two lines by a run: | block (213's own
// pattern uses \s* between "toJson(" and "github)", which crosses
// newlines) is caught the same as the single-line form. Matching only
// against split script lines, as the dump branch below used to, would
// never see the call: neither half contains the whole pattern on its own.
func TestUntrustedExpressionGitHubContextDumpSplitAcrossLines(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "build", Scripts: []string{"echo 'toJson(\n  github)'"}}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression")
	if len(got) != 1 || got[0].State != "proven" {
		t.Errorf("toJson(\\n  github): untrusted_expression = %+v, want one proven entry", got)
	}
}

// TestUntrustedExpressionScansJobVariables pins that untrusted_expression
// also scans job variables/localVariables values (PR #513 review):
// ISSUE-209 (github_env_injection.rego) binds an attacker-controlled
// expression through env: before writing it to $GITHUB_ENV, and ISSUE-213's
// env-binding branch does the same for toJson(github); either way the value
// sits in the job's variables before any script runs, so this fact must see
// it there, independent of whether a script later writes it to a sink.
func TestUntrustedExpressionScansJobVariables(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:      "build",
			Variables: map[string]string{"BODY": "${{ github.event.issue.body }}"},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression")
	if len(got) != 1 || got[0].Subject != "github.event.issue.body" || got[0].State != "proven" {
		t.Errorf("variables: untrusted_expression = %+v", got)
	}

	p.Jobs[0].Variables = nil
	p.Jobs[0].LocalVariables = map[string]string{"DUMP": "${{ toJson(github) }}"}
	got = entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression")
	if len(got) != 1 || got[0].Subject != "toJson(github)" {
		t.Errorf("localVariables: untrusted_expression = %+v", got)
	}

	p.Jobs[0].LocalVariables = map[string]string{"SAFE": "${{ github.run_id }}"}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 0 {
		t.Errorf("safe variable: untrusted_expression = %+v, want none", got)
	}
}

// TestMutableActionRefKnownAbsentIsUnresolvable pins the 707
// (impostor_commit.rego) signal on a SHA-pinned action: a commit the
// collector confirmed absent upstream cannot be judged as controlled by
// anyone in particular (a typo, or a removed commit; the runner falls back
// to the default branch), so the entry is unresolvable, never proven.
func TestMutableActionRefKnownAbsentIsUnresolvable(t *testing.T) {
	const sha = "08c6903cd8c0fde910a37f88322edcfb5dd907a8"
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{Uses: "some/action@" + sha, Metadata: &ir.ActionMetadata{RefKnownAbsent: true}}},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].State != "unresolvable" || got[0].Subject != "some/action@"+sha {
		t.Errorf("mutable_dependency: %+v", got)
	}

	p.Jobs[0].Uses[0].Metadata = &ir.ActionMetadata{RefKnownAbsent: false}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("refKnownAbsent false: mutable_dependency = %+v, want none", got)
	}
}

// TestMutableActionAdvisoryIsProven pins the 703
// (known_vulnerable_action.rego) signal: a SHA-pinned action carrying a
// published advisory is a proven mutable dependency even though its ref
// cannot move; the advisory itself is the positive signal.
func TestMutableActionAdvisoryIsProven(t *testing.T) {
	const sha = "08c6903cd8c0fde910a37f88322edcfb5dd907a8"
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{Uses: "some/action@" + sha, Metadata: &ir.ActionMetadata{Advisories: []string{"GHSA-aaaa-bbbb-cccc"}}}},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].State != "proven" {
		t.Errorf("mutable_dependency: %+v", got)
	}

	p.Jobs[0].Uses[0].Metadata = &ir.ActionMetadata{}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("no advisories: mutable_dependency = %+v, want none", got)
	}
}

// TestMutableActionUntrustedSourceIsProven pins the 713
// (action_authorized_sources.rego) signal on a SHA-pinned action: an owner
// outside every trust condition 713 reads from
// input.config.githubActionMustComeFromAuthorizedSources is a proven mutable
// dependency even though its ref is pinned, because 713 flags the source
// alone; the check only runs when that policy is configured.
func TestMutableActionUntrustedSourceIsProven(t *testing.T) {
	const sha = "08c6903cd8c0fde910a37f88322edcfb5dd907a8"
	cfg := map[string]any{"githubActionMustComeFromAuthorizedSources": map[string]any{
		"trustGithubOfficialActions": true,
		"trustedGithubActions":       []string{"trusted-org/*"},
	}}
	untrusted := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "build", Uses: []ir.Action{{Uses: "random-org/action@" + sha}}}},
	}
	got := entriesOfKind(evaluate(t, untrusted, cfg).Jobs["build"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].State != "proven" {
		t.Errorf("untrusted owner: mutable_dependency = %+v", got)
	}

	trusted := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs:     []ir.Job{{Name: "build", Uses: []ir.Action{{Uses: "trusted-org/action@" + sha}}}},
	}
	if got := entriesOfKind(evaluate(t, trusted, cfg).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("allowlisted owner: mutable_dependency = %+v, want none", got)
	}

	if got := entriesOfKind(evaluate(t, untrusted, nil).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("policy not configured: mutable_dependency = %+v, want none", got)
	}
}

// TestMutableActionMultipleReasonsCollapseToOneProvenEntry pins a finding
// from the PR #513 review: a pinned action with two independent reasons
// (refKnownAbsent, unresolvable on its own, plus an advisory, proven on its
// own) must not get two conflicting mutable_dependency entries on the same
// subject. One entry comes out, proven (any proven reason wins), and its
// evidence names both reasons.
func TestMutableActionMultipleReasonsCollapseToOneProvenEntry(t *testing.T) {
	const sha = "08c6903cd8c0fde910a37f88322edcfb5dd907a8"
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name: "build",
			Uses: []ir.Action{{Uses: "some/action@" + sha, Metadata: &ir.ActionMetadata{
				RefKnownAbsent: true,
				Advisories:     []string{"GHSA-aaaa-bbbb-cccc"},
			}}},
		}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency")
	if len(got) != 1 {
		t.Fatalf("mutable_dependency = %+v, want exactly one entry", got)
	}
	if got[0].State != "proven" {
		t.Errorf("state = %q, want proven (an advisory is a proven reason)", got[0].State)
	}
	if !strings.Contains(got[0].Evidence, "advisory") && !strings.Contains(got[0].Evidence, "703") {
		t.Errorf("evidence = %q, want it to name the advisory reason", got[0].Evidence)
	}
	if !strings.Contains(got[0].Evidence, "absent") && !strings.Contains(got[0].Evidence, "707") {
		t.Errorf("evidence = %q, want it to name the refKnownAbsent reason", got[0].Evidence)
	}
}

// TestMutableImageUntrustedRegistryIsProvenEvenDigestPinned pins the 101
// (image_authorized_sources.rego) signal: an image from a registry outside
// imageAuthorizedSources.trustedUrls is a proven mutable dependency even
// when it carries a digest, because 101 flags the source, not the pin; the
// check only runs when that policy is configured.
func TestMutableImageUntrustedRegistryIsProvenEvenDigestPinned(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	cfg := map[string]any{"imageAuthorizedSources": map[string]any{
		"trustedUrls": []string{"registry.trusted.example.com/*"},
	}}
	untrusted := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:  "build",
			Image: &ir.Image{Registry: "registry.evil.example.com", Name: "team/app", Tag: "v1", Digest: digest},
		}},
	}
	got := entriesOfKind(evaluate(t, untrusted, cfg).Jobs["build"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].State != "proven" {
		t.Errorf("untrusted registry: mutable_dependency = %+v", got)
	}

	trusted := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:  "build",
			Image: &ir.Image{Registry: "registry.trusted.example.com", Name: "team/app", Tag: "v1", Digest: digest},
		}},
	}
	if got := entriesOfKind(evaluate(t, trusted, cfg).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("trusted registry, digest-pinned, no forbidden tag: mutable_dependency = %+v, want none", got)
	}

	if got := entriesOfKind(evaluate(t, untrusted, nil).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("policy not configured: mutable_dependency = %+v, want none", got)
	}
}

// TestGitHubPushTriggerFiltersDecideTheEntry pins unprotected_push's new
// GitHub trigger-filter reading (PR #513 review): Job.PushBranches/
// PushBranchesIgnore/PushTags/PushTagsIgnore decide whether a push trigger
// actually reaches the default branch, replacing the old blanket
// "unresolvable" the IR's missing filters used to force.
func TestGitHubPushTriggerFiltersDecideTheEntry(t *testing.T) {
	newPipeline := func(job ir.Job) *ir.NormalizedPipeline {
		return &ir.NormalizedPipeline{
			Provider:      ir.ProviderGitHub,
			DefaultBranch: "main",
			Branches:      []ir.Branch{{Name: "main", Protected: false}},
			Jobs:          []ir.Job{job},
		}
	}

	t.Run("no filter at all is proven", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("branches filter including the default branch is proven", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"main", "release/*"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("branches filter excluding the default branch is absent", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"release/*"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("branches-ignore naming the default branch is absent", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"main"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("tags only is absent", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushTags: []string{"v*"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("an expression filter is unresolvable", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"${{ env.TARGET_BRANCH }}"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "unresolvable" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	// PR #513 review: branches-ignore that does not name the
	// default branch must not drop the entry. GitHub still runs the
	// workflow on every push that the ignore list does not exclude.
	t.Run("branches-ignore naming another branch is proven", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"experimental"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry", got)
		}
	})

	t.Run("branches-ignore plus tags, other branch, is proven", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"experimental"}, PushTags: []string{"v*"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry", got)
		}
	})

	// PR #513 review: GitHub evaluates branches:/branches-ignore:
	// patterns in the order written, and the LAST pattern that matches
	// decides; a leading "!" negates. The two orderings of the same two
	// patterns must give opposite results.
	t.Run("negation: a later plain pattern re-excludes main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"**", "!main"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none (['**', '!main'] excludes main)", got)
		}
	})

	t.Run("negation: a later catch-all re-includes main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"!main", "**"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry (['!main', '**'] includes main)", got)
		}
	})

	t.Run("negation: branches-ignore's own '!' re-includes main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"main", "!main"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry (['main', '!main'] re-includes main)", got)
		}
	})

	t.Run("negation: branches-ignore order matters, plain pattern wins last", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"!main", "main"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none (['!main', 'main'] excludes main)", got)
		}
	})

	// PR #513 review: tags-ignore alone (no branches, no
	// branches-ignore) reads exactly like tags alone: a tag-only filter
	// never runs on a branch push.
	t.Run("tags-ignore only is absent", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushTagsIgnore: []string{"v*-rc"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	// PR #513 review: glob.match with ["/"] delimiters mirrors
	// GitHub's branches:/tags: semantics closely but not exactly.
	t.Run("** alone includes main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"**"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry", got)
		}
	})

	t.Run("releases/** does not include main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"releases/**"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	// mai?n matches main on GitHub (? means "zero or one of the preceding
	// character" there), but not through OPA's glob.match, which reads ?
	// as "exactly one arbitrary character" instead: documented divergence
	// (PR #513 review), not translated.
	t.Run("mai?n does not match main (OPA glob semantics, documented divergence)", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"mai?n"}})
		got := entriesOfKind(evaluate(t, p, nil).Jobs["deploy"].Entries, "unprotected_push")
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none (OPA's ? is not GitHub's optional-preceding-character ?)", got)
		}
	})
}

// TestIncludeForbiddenVersionIsMutableDependency pins the 404
// (includes_forbidden_version.rego) signal on a pipeline include: a ref
// matching includesForbiddenVersions.forbiddenVersions is a proven
// mutable_dependency, attached to every job whose originFile is the
// include's source (the jobs the include contributes).
func TestIncludeForbiddenVersionIsMutableDependency(t *testing.T) {
	cfg := map[string]any{"includesForbiddenVersions": map[string]any{"forbiddenVersions": []string{"main", "master"}}}
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{{Kind: "project", Source: "group/ci-templates", Ref: "main"}},
		Jobs: []ir.Job{
			{Name: "build", OriginFile: "group/ci-templates"},
			{Name: "lint", OriginFile: ".gitlab-ci.yml"},
		},
	}
	r := evaluate(t, p, cfg)
	build := entriesOfKind(r.Jobs["build"].Entries, "mutable_dependency")
	if len(build) != 1 || build[0].State != "proven" || build[0].Subject != "group/ci-templates@main" {
		t.Errorf("build: mutable_dependency = %+v", build)
	}
	if got := entriesOfKind(r.Jobs["lint"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("lint: mutable_dependency = %+v, want none (does not carry the include's file)", got)
	}

	// When no job carries the include's file, it is attached to every job.
	p.Jobs[0].OriginFile = "something/else"
	p.Jobs[1].OriginFile = "something/else/too"
	r = evaluate(t, p, cfg)
	for _, name := range []string{"build", "lint"} {
		if got := entriesOfKind(r.Jobs[name].Entries, "mutable_dependency"); len(got) != 1 {
			t.Errorf("%s: no job carries the include's file, want it on every job, got %+v", name, got)
		}
	}
}

// TestIncludeHardcodedIsNeverAMutableDependency pins 404's own exclusion: a
// hardcoded include (no pinnable version) never counts, whatever its ref.
func TestIncludeHardcodedIsNeverAMutableDependency(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{{Kind: "hardcoded", Source: "group/ci-templates", Ref: "main"}},
		Jobs:     []ir.Job{{Name: "build"}},
	}
	cfg := map[string]any{"includesForbiddenVersions": map[string]any{"forbiddenVersions": []string{"main"}}}
	if got := entriesOfKind(evaluate(t, p, cfg).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("hardcoded include: mutable_dependency = %+v, want none", got)
	}
}

// TestIncludeDefaultBranchIsForbiddenByDefault pins 404's ruling R6: with no
// explicit forbiddenVersions configured, an include pinned to the project's
// own default branch is still forbidden by default, and
// defaultBranchIsForbiddenVersion: false opts out of that default. The
// nil-config case is a superset of 404 itself, not a mirror of its exact
// finding: 404's own _default_branch_is_forbidden dereferences
// input.config.includesForbiddenVersions directly (object.get's own
// default never applies when that outer key is undefined), so 404 stays
// silent, with no finding at all, on a nil config (PR #513 review);
// this fact still fires, by design.
func TestIncludeDefaultBranchIsForbiddenByDefault(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider:      ir.ProviderGitLab,
		DefaultBranch: "main",
		Includes:      []ir.Include{{Kind: "project", Source: "group/ci-templates", Ref: "main"}},
		Jobs:          []ir.Job{{Name: "build"}},
	}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency"); len(got) != 1 {
		t.Errorf("mutable_dependency = %+v, want one (default branch forbidden by default)", got)
	}

	cfg := map[string]any{"includesForbiddenVersions": map[string]any{"defaultBranchIsForbiddenVersion": false}}
	if got := entriesOfKind(evaluate(t, p, cfg).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("defaultBranchIsForbiddenVersion: false: mutable_dependency = %+v, want none", got)
	}
}

// TestIncludeRefConfusionIsMutableDependency pins the 402 (ref_confusion.rego)
// signal: an include whose ref resolves as both a tag and a branch upstream
// is a proven mutable_dependency, independent of the forbidden-version list.
func TestIncludeRefConfusionIsMutableDependency(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Includes: []ir.Include{{Kind: "project", Source: "group/ci-templates", Ref: "v1.2.3", RefIsAmbiguous: true}},
		Jobs:     []ir.Job{{Name: "build"}},
	}
	got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency")
	if len(got) != 1 || got[0].State != "proven" || got[0].Subject != "group/ci-templates@v1.2.3" {
		t.Errorf("mutable_dependency = %+v", got)
	}

	p.Includes[0].RefIsAmbiguous = false
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "mutable_dependency"); len(got) != 0 {
		t.Errorf("ref not ambiguous, not forbidden: mutable_dependency = %+v, want none", got)
	}
}
