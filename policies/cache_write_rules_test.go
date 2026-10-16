package policies_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	githubpkg "github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
)

// issue705Fixtures is where the ISSUE-705 workflows live. A fixture is one
// workflow file, or a directory whose files are all one repository's
// workflows (a reusable workflow and its caller).
var issue705Fixtures = filepath.Join("testdata", "ISSUE-705", "github")

// issue705Hit is one ISSUE-705 finding as the cases read it.
type issue705Hit struct {
	Job  string
	Line int
}

// scanIssue705Fixture copies a fixture into a repository's workflow
// directory and parses it with the real scanner.
func scanIssue705Fixture(t *testing.T, fixture string) *ir.NormalizedPipeline {
	t.Helper()
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(issue705Fixtures, fixture)
	files := []string{src}
	if info, err := os.Stat(src); err == nil && info.IsDir() {
		entries, err := os.ReadDir(src)
		if err != nil {
			t.Fatal(err)
		}
		files = files[:0]
		for _, e := range entries {
			files = append(files, filepath.Join(src, e.Name()))
		}
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(wfDir, filepath.Base(f)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pipeline, _, err := githubpkg.ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return pipeline
}

func issue705Hits(t *testing.T, engine *opaengine.Engine, pipeline *ir.NormalizedPipeline, cfg map[string]any) []issue705Hit {
	t.Helper()
	findings, err := evaluateStrict(engine, context.Background(), pipeline, cfg)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	hits := []issue705Hit{}
	for _, f := range findings {
		switch f.Code {
		case "ISSUE-705":
			hits = append(hits, issue705Hit{Job: f.Job, Line: f.Line})
		case "ISSUE-717":
			t.Errorf("ISSUE-717 is retired, got %+v", f)
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Job < hits[j].Job })
	return hits
}

func loadedEngine(t *testing.T) *opaengine.Engine {
	t.Helper()
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load embedded policies: %v", err)
	}
	return engine
}

// TestIssue705_CacheWriteOnUntrustedTrigger pins ISSUE-705: a job whose
// triggers include an event outside the safe set (GitHub's trusted
// triggers plus pull_request, release and merge_group, which write only
// their own ref's scope) and whose effective cache-mode (its own, else its
// workflow's) grants write lifts GitHub's read-only cache access for
// low-trust events. The finding points at the cache-mode line.
func TestIssue705_CacheWriteOnUntrustedTrigger(t *testing.T) {
	cases := []struct {
		fixture string
		cfg     map[string]any
		want    []issue705Hit
	}{
		{fixture: "violation_issue_comment_job_write.yml", want: []issue705Hit{{"violation_issue_comment_job_write/label", 7}}},
		{fixture: "violation_pull_request_target_write.yml", want: []issue705Hit{{"violation_pull_request_target_write/preview", 5}}},
		{fixture: "violation_workflow_run_write.yml", want: []issue705Hit{{"violation_workflow_run_write/report", 8}}},
		{fixture: "violation_discussion_and_review_write.yml", want: []issue705Hit{{"violation_discussion_and_review_write/reply", 5}}},
		{fixture: "violation_mixed_push_issue_comment.yml", want: []issue705Hit{{"violation_mixed_push_issue_comment/build", 8}}},
		{fixture: "violation_workflow_write_inherited.yml", want: []issue705Hit{
			{"violation_workflow_write_inherited/lint", 2},
			{"violation_workflow_write_inherited/test", 2},
		}},
		{fixture: "violation_write_only.yml", want: []issue705Hit{{"violation_write_only/warm", 5}}},
		{fixture: "violation_job_write_overrides_workflow_read.yml", want: []issue705Hit{{"violation_job_write_overrides_workflow_read/build", 6}}},
		{fixture: "violation_constant_expression_write.yml", want: []issue705Hit{{"violation_constant_expression_write/build", 5}}},
		{fixture: "clean_job_read_overrides_workflow_write.yml"},
		{fixture: "clean_job_none_overrides_workflow_write.yml"},
		{fixture: "clean_pull_request_write.yml"},
		{fixture: "clean_release_merge_group_write.yml"},
		{fixture: "clean_trusted_only_write.yml"},
		{fixture: "clean_no_cache_mode_low_trust.yml"},
		{fixture: "clean_read_explicit_low_trust.yml"},
		{fixture: "clean_constant_expression_read.yml"},
		{fixture: "clean_context_expression.yml"},
		{fixture: "reusable_low_trust_caller", want: []issue705Hit{{"warm/warm", 5}}},
		{fixture: "reusable_trusted_caller"},
		{
			fixture: "clean_exempt_workflow.yml",
			cfg:     exempt705([]string{"clean_exempt_*.yml"}, nil),
		},
		{
			fixture: "violation_exempt_job_sibling.yml",
			cfg:     exempt705(nil, []string{"violation_exempt_job_sibling/label"}),
			want:    []issue705Hit{{"violation_exempt_job_sibling/greet", 13}},
		},
		{
			fixture: "violation_exempt_job_sibling.yml",
			want: []issue705Hit{
				{"violation_exempt_job_sibling/greet", 13},
				{"violation_exempt_job_sibling/label", 5},
			},
		},
	}
	engine := loadedEngine(t)
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			got := issue705Hits(t, engine, scanIssue705Fixture(t, tc.fixture), tc.cfg)
			want := tc.want
			if want == nil {
				want = []issue705Hit{}
			}
			if len(got) != len(want) {
				t.Fatalf("hits = %+v, want %+v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("hit %d = %+v, want %+v", i, got[i], want[i])
				}
			}
		})
	}
}

func exempt705(workflows, jobs []string) map[string]any {
	block := map[string]any{}
	if len(workflows) > 0 {
		block["exemptWorkflows"] = workflows
	}
	if len(jobs) > 0 {
		block["exemptJobs"] = jobs
	}
	return map[string]any{"untrustedTriggersMustNotWriteCache": block}
}

// TestIssue705_EveryEvent pins the safe set event by event: a job granted
// cache-mode: write fires exactly when one of its events is outside it.
func TestIssue705_EveryEvent(t *testing.T) {
	safe := map[string]bool{
		"push": true, "workflow_dispatch": true, "repository_dispatch": true, "delete": true,
		"registry_package": true, "page_build": true, "schedule": true,
		"pull_request": true, "release": true, "merge_group": true,
		"pull_request_review": true, "pull_request_review_comment": true,
	}
	events := []string{
		"push", "workflow_dispatch", "repository_dispatch", "delete", "registry_package", "page_build",
		"schedule", "pull_request", "release", "merge_group", "pull_request_target", "issue_comment",
		"issues", "workflow_run", "discussion", "discussion_comment", "pull_request_review",
		"pull_request_review_comment", "create", "fork", "gollum", "label", "milestone", "project",
		"project_card", "project_column", "public", "status", "watch", "check_run", "check_suite",
		"deployment", "deployment_status", "branch_protection_rule",
	}
	engine := loadedEngine(t)
	for _, ev := range events {
		for _, mode := range []string{"write", "write-only", "read", "none"} {
			p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{
				Name: "wf/j", Triggers: []string{ev},
				CacheMode: &ir.CacheModeDecl{Value: mode, Effective: mode, Line: 4, Level: "job"},
			}}}
			fires := len(issue705Hits(t, engine, p, nil)) > 0
			want := !safe[ev] && (mode == "write" || mode == "write-only")
			if fires != want {
				t.Errorf("%s with cache-mode %s: fires = %v, want %v", ev, mode, fires, want)
			}
		}
	}
}
