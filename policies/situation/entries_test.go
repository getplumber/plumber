package situation_test

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// triggerFacts is the job's trigger facts of the given kind: its fork pull
// request fact for "fork_pr", its push facts for "unprotected_push".
func triggerFacts(j jobFacts, kind string) []entry {
	switch kind {
	case "fork_pr":
		return j.ForkPR
	case "unprotected_push":
		return j.Push
	}
	return nil
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
// set under that name carries the facts of both.
func TestSameNamedJobsAreMerged(t *testing.T) {
	r := evaluate(t, sameNamedJobs(), nil)
	j, ok := r.Jobs["ci/build"]
	if !ok || len(r.Jobs) != 1 {
		t.Fatalf("jobs = %+v", r.Jobs)
	}
	if e, ok := firstEntry(j.ForkPR); !ok || e.File != ".github/workflows/ci.yml" {
		t.Errorf("fork_pr from ci.yml missing: %+v", j.ForkPR)
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
		j := evaluate(t, p, nil).Jobs["test"]
		if len(j.ForkPR) != 0 {
			t.Errorf("%s when: never: not an MR job: %+v", source, j.ForkPR)
		}
		if len(j.Push) != 0 {
			t.Errorf("%s when: never: not a push job: %+v", source, j.Push)
		}
		p.Jobs[0].Rules[0]["when"] = "on_success"
		want := map[string]string{"merge_request_event": "fork_pr", "push": "unprotected_push"}[source]
		if got := triggerFacts(evaluate(t, p, nil).Jobs["test"], want); len(got) == 0 {
			t.Errorf("%s when: on_success: want %s, got none", source, want)
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
	got := evaluate(t, p, nil).Jobs["test"].ForkPR
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
	got := evaluate(t, p, nil).Jobs["test"].ForkPR
	if len(got) != 1 {
		t.Errorf("fork_pr: %+v, want one (every other source is excluded, so this one runs)", got)
	}

	p.Jobs[0].Rules = p.Jobs[0].Rules[:1]
	got = evaluate(t, p, nil).Jobs["test"].ForkPR
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
			got := evaluate(t, p, nil).Jobs["deploy"].Push
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
		got := evaluate(t, p, nil).Jobs["deploy"].Push
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
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("reversed: $CI_DEFAULT_BRANCH == $CI_COMMIT_BRANCH", func(t *testing.T) {
		p := newPipeline(`$CI_DEFAULT_BRANCH == $CI_COMMIT_BRANCH`)
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("bare $CI_COMMIT_BRANCH", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH`)
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("bare $CI_COMMIT_BRANCH with a trailing condition", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH && $CI_PIPELINE_SOURCE != "merge_request_event"`)
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("literal equal to the default branch name is proven", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == "main"`)
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("literal equal to some other branch is not an entry", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == "develop"`)
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("literal equal with no configured default branch is unresolvable", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == "main"`)
		p.DefaultBranch = ""
		p.Branches = nil
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "unresolvable" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("regex is unresolvable", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH =~ /^release-/`)
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "unresolvable" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("not-equal is not an inclusion", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH`)
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("when: never is an exclusion", func(t *testing.T) {
		p := newPipeline(`$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`)
		p.Jobs[0].Rules[0]["when"] = "never"
		got := evaluate(t, p, nil).Jobs["deploy"].Push
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
	got := evaluate(t, p, nil).Jobs["deploy"].Push
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
	got := evaluate(t, p, nil).Jobs["test"].Push
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
			if got := evaluate(t, p, nil).Jobs["deploy"].Push; len(got) != 0 {
				t.Errorf("protected default branch: unprotected_push = %+v, want none", got)
			}
			p.Branches = nil
			got := evaluate(t, p, nil).Jobs["deploy"].Push
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
	got := evaluate(t, p, nil).Jobs["deploy"].Push
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
	got := evaluate(t, p, nil).Jobs["deploy"].Push
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
	got := evaluate(t, p, nil).Jobs["deploy"].Push
	if len(got) != 1 || got[0].State != "unresolvable" {
		t.Errorf("unprotected_push: %+v", got)
	}
}

// TestGitLabOnlyMergeRequestsIsLiveNotDead pins that the merge_request_job
// only: branch (previously dead while Job.Only was never populated) now
// fires once the collector carries only:, with the fork_pr fact.
func TestGitLabOnlyMergeRequestsIsLiveNotDead(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitLab,
		Jobs: []ir.Job{{
			Name:    "build",
			Only:    []string{"merge_requests"},
			Scripts: []string{`echo "$CI_MERGE_REQUEST_TITLE"`},
		}},
	}
	if e, ok := firstEntry(evaluate(t, p, nil).Jobs["build"].ForkPR); !ok || e.State != "proven" {
		t.Errorf("fork_pr: %+v", e)
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
		got := evaluate(t, p, nil).Jobs["test"].ForkPR
		if len(got) != 1 {
			t.Errorf("fork_pr: %+v, want one", got)
		}
	})

	t.Run("bare $CI_MERGE_REQUEST_ID", func(t *testing.T) {
		p := newPipeline([]map[string]any{{"if": `$CI_MERGE_REQUEST_ID`}})
		got := evaluate(t, p, nil).Jobs["test"].ForkPR
		if len(got) != 1 {
			t.Errorf("fork_pr: %+v, want one", got)
		}
	})

	t.Run("== null with when not never yields none", func(t *testing.T) {
		p := newPipeline([]map[string]any{{"if": `$CI_MERGE_REQUEST_IID == null`}})
		got := evaluate(t, p, nil).Jobs["test"].ForkPR
		if len(got) != 0 {
			t.Errorf("fork_pr: %+v, want none (null-tests its absence, not its presence)", got)
		}
	})

	t.Run("== null with when: never then a genuine catch-all yields fork_pr", func(t *testing.T) {
		p := newPipeline([]map[string]any{
			{"if": `$CI_MERGE_REQUEST_IID == null`, "when": "never"},
			{"when": "always"},
		})
		got := evaluate(t, p, nil).Jobs["test"].ForkPR
		if len(got) != 1 {
			t.Errorf("fork_pr: %+v, want one (every non-MR pipeline is excluded, so this one runs)", got)
		}
	})

	t.Run("== null with when: never alone yields none", func(t *testing.T) {
		p := newPipeline([]map[string]any{
			{"if": `$CI_MERGE_REQUEST_IID == null`, "when": "never"},
		})
		got := evaluate(t, p, nil).Jobs["test"].ForkPR
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
	got := evaluate(t, p, nil).Jobs["deploy"].Push
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
		got := evaluate(t, p, nil).Jobs["deploy"].Push
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
		got := evaluate(t, p, nil).Jobs["deploy"].Push
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
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" || got[0].Subject != "main" {
			t.Errorf("unprotected_push: %+v, want one proven entry for main", got)
		}
	})

	t.Run("only main with no configured default branch is unresolvable", func(t *testing.T) {
		p := &ir.NormalizedPipeline{
			Provider: ir.ProviderGitLab,
			Jobs:     []ir.Job{{Name: "deploy", Only: []string{"main"}}},
		}
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "unresolvable" {
			t.Errorf("unprotected_push: %+v, want one unresolvable entry", got)
		}
	})
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
			got := triggerFacts(evaluate(t, p, nil).Jobs["deploy"], c.entryKind)
			if len(got) != 1 {
				t.Errorf("catch-all: %s = %+v, want one entry", c.entryKind, got)
			}

			// A later rule with its own if: is not a genuine catch-all: it
			// might or might not match a <source> pipeline, so the
			// exclude-then-run idiom alone proves nothing.
			p.Jobs[0].Rules[1] = map[string]any{"if": `$CI_COMMIT_REF_PROTECTED == "true"`}
			got = triggerFacts(evaluate(t, p, nil).Jobs["deploy"], c.entryKind)
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
			got = triggerFacts(evaluate(t, p, nil).Jobs["deploy"], c.entryKind)
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
	got := evaluate(t, p, nil).Jobs["deploy"].Push
	if len(got) != 0 {
		t.Errorf("unprotected_push: %+v, want none (the later rule is gated on protected branch, not a catch-all)", got)
	}
}

// ---------------------------------------------------------- PR #513 review

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
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("branches filter including the default branch is proven", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"main", "release/*"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	t.Run("branches filter excluding the default branch is absent", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"release/*"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("branches-ignore naming the default branch is absent", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"main"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("tags only is absent", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushTags: []string{"v*"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	t.Run("an expression filter is unresolvable", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"${{ env.TARGET_BRANCH }}"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "unresolvable" {
			t.Errorf("unprotected_push: %+v", got)
		}
	})

	// PR #513 review: branches-ignore that does not name the
	// default branch must not drop the entry. GitHub still runs the
	// workflow on every push that the ignore list does not exclude.
	t.Run("branches-ignore naming another branch is proven", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"experimental"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry", got)
		}
	})

	t.Run("branches-ignore plus tags, other branch, is proven", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"experimental"}, PushTags: []string{"v*"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
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
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none (['**', '!main'] excludes main)", got)
		}
	})

	t.Run("negation: a later catch-all re-includes main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"!main", "**"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry (['!main', '**'] includes main)", got)
		}
	})

	t.Run("negation: branches-ignore's own '!' re-includes main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"main", "!main"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry (['main', '!main'] re-includes main)", got)
		}
	})

	t.Run("negation: branches-ignore order matters, plain pattern wins last", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranchesIgnore: []string{"!main", "main"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none (['!main', 'main'] excludes main)", got)
		}
	})

	// PR #513 review: tags-ignore alone (no branches, no
	// branches-ignore) reads exactly like tags alone: a tag-only filter
	// never runs on a branch push.
	t.Run("tags-ignore only is absent", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushTagsIgnore: []string{"v*-rc"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none", got)
		}
	})

	// PR #513 review: glob.match with ["/"] delimiters mirrors
	// GitHub's branches:/tags: semantics closely but not exactly.
	t.Run("** alone includes main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"**"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 1 || got[0].State != "proven" {
			t.Errorf("unprotected_push: %+v, want one proven entry", got)
		}
	})

	t.Run("releases/** does not include main", func(t *testing.T) {
		p := newPipeline(ir.Job{Name: "deploy", Triggers: []string{"push"}, PushBranches: []string{"releases/**"}})
		got := evaluate(t, p, nil).Jobs["deploy"].Push
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
		got := evaluate(t, p, nil).Jobs["deploy"].Push
		if len(got) != 0 {
			t.Errorf("unprotected_push: %+v, want none (OPA's ? is not GitHub's optional-preceding-character ?)", got)
		}
	})
}
