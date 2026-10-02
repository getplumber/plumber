package situation_test

import (
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

// TestUntrustedExpressionGitLabSkipsWholeLineComments pins finding A of the
// round-8 review: a GitLab script line whose trimmed form starts with "#" is
// never scanned for a dangerous variable, mirroring ISSUE-204
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

// TestUntrustedExpressionGitHubSkipsWholeLineComments pins the GitHub half
// of finding A: a commented-out script line (whole-line, trim_space applied
// so indentation does not matter) never yields an untrusted_expression
// entry, but a step with: value holding the same unsafe expression still
// does: with: values are not shell lines and get no comment handling.
func TestUntrustedExpressionGitHubSkipsWholeLineComments(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{{
			Name:    "build",
			Scripts: []string{"# echo ${{ github.event.issue.title }}"},
		}},
	}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 0 {
		t.Errorf("commented script line: untrusted_expression = %+v, want none", got)
	}

	p.Jobs[0].Scripts = []string{"echo ${{ github.event.issue.title }}"}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("uncommented script line: untrusted_expression = %+v, want one", got)
	}

	// An indented comment line is skipped too (trim_space).
	p.Jobs[0].Scripts = []string{"echo ok\n    # echo ${{ github.event.issue.title }}"}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 0 {
		t.Errorf("indented commented line: untrusted_expression = %+v, want none", got)
	}

	// A with: value is not a shell line: comment logic never applies to it.
	p.Jobs[0].Scripts = nil
	p.Jobs[0].Uses = []ir.Action{{Uses: "some/action@v1", With: map[string]any{"body": "# ${{ github.event.issue.title }}"}}}
	if got := entriesOfKind(evaluate(t, p, nil).Jobs["build"].Entries, "untrusted_expression"); len(got) != 1 {
		t.Errorf("with value: untrusted_expression = %+v, want one (no comment skipping for with values)", got)
	}
}

// TestGitLabExcludeThenRunRequiresGenuineCatchAll pins finding B of the
// round-8 review: the "exclude every other source, then run" idiom (a rule
// excluding every OTHER source with when: never) only proves an inclusion of
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
