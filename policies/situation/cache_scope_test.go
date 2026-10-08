package situation_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// scopeFacts is the part of a job's facts the cache scope tests read.
type scopeFacts struct {
	CacheScopes []string `json:"cacheScopes"`
	Feeds       []string `json:"feeds"`
}

func scopesOf(t *testing.T, p *ir.NormalizedPipeline) map[string]scopeFacts {
	t.Helper()
	var r struct {
		Jobs map[string]scopeFacts `json:"jobs"`
	}
	evaluateInto(t, p, nil, &r)
	return r.Jobs
}

// TestCacheScopeFollowsTheRunsRef pins the cache scope of a job's runs, the
// ref GitHub files what they save under: the default branch for a push to
// it, a schedule, a manual dispatch, a workflow_run or a pull_request_target
// run (they run on the default branch); a tag for a tag push or a release;
// the pull request's merge ref for a pull_request run. A job-level if: that
// names one event narrows the job to it. A job with no trigger at all (a
// GitLab job) has an unknown scope, "any".
func TestCacheScopeFollowsTheRunsRef(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main", Jobs: []ir.Job{
		{Name: "main-push", Triggers: []string{"push"}, PushBranches: []string{"main"}},
		{Name: "tags", Triggers: []string{"push"}, PushTags: []string{"v*"}},
		{Name: "release", Triggers: []string{"release"}},
		{Name: "pr", Triggers: []string{"pull_request"}},
		{Name: "nightly", Triggers: []string{"schedule", "workflow_dispatch"}},
		{Name: "privileged", Triggers: []string{"pull_request_target", "workflow_run"}},
		{Name: "pr-only-step", Triggers: []string{"pull_request", "push"}, PushBranches: []string{"main"}, If: "github.event_name == 'pull_request'"},
		{Name: "unknown"},
	}}
	want := map[string][]string{
		"main-push":    {"default"},
		"tags":         {"tag"},
		"release":      {"tag"},
		"pr":           {"pull_request"},
		"nightly":      {"default"},
		"privileged":   {"default"},
		"pr-only-step": {"pull_request"},
		"unknown":      {"any"},
	}
	got := scopesOf(t, p)
	for name, w := range want {
		if !reflect.DeepEqual(got[name].CacheScopes, w) {
			t.Errorf("%s: cacheScopes = %v, want %v", name, got[name].CacheScopes, w)
		}
	}
}

// TestCacheEdgesFollowTheScope pins that a cache edge exists only where
// GitHub lets the restorer read what the saver saved: a default-branch
// save reaches every run (a tag release and a pull request read the
// default branch's caches); a tag run's or a pull request run's save
// reaches runs of that same kind of ref only, never the default branch.
func TestCacheEdgesFollowTheScope(t *testing.T) {
	both := []ir.CacheRef{{Key: "deps", Mode: "both"}}
	restore := []ir.CacheRef{{Key: "deps", Mode: "restore"}}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main", Jobs: []ir.Job{
		{Name: "main-save", Triggers: []string{"push"}, PushBranches: []string{"main"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "tag-save", Triggers: []string{"push"}, PushTags: []string{"v*"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "pr-save", Triggers: []string{"pull_request"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "tag-release", Triggers: []string{"push"}, PushTags: []string{"v*"}, Caches: restore},
		{Name: "nightly", Triggers: []string{"schedule"}, Caches: restore},
		{Name: "pr-test", Triggers: []string{"pull_request"}, Caches: restore},
		{Name: "gitlab-like", Caches: both},
	}}
	got := scopesOf(t, p)
	want := map[string][]string{
		"main-save": {"gitlab-like", "nightly", "pr-test", "tag-release"},
		"tag-save":  {"gitlab-like", "tag-release"},
		"pr-save":   {"gitlab-like", "pr-test"},
	}
	for name, w := range want {
		f := append([]string{}, got[name].Feeds...)
		sort.Strings(f)
		if !reflect.DeepEqual(f, w) {
			t.Errorf("%s.feeds = %v, want %v", name, f, w)
		}
	}
}
