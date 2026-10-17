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
		{Name: "privileged", Triggers: []string{"pull_request_target", "workflow_run"}, CacheMode: &ir.CacheModeDecl{Value: "write", Effective: "write", Line: 3, Level: "job"}},
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

// TestCacheScopeHonoursCacheMode pins that cacheScopes names only the
// scopes a job's runs can save under. A low-trust event on the default
// branch (pull_request_target, issue_comment, workflow_run...) gets
// read-only cache access unless the job, or its workflow, declares
// cache-mode: write or write-only; read and none save nothing on any
// trigger. A trusted trigger saves by default.
func TestCacheScopeHonoursCacheMode(t *testing.T) {
	mode := func(effective string) *ir.CacheModeDecl {
		return &ir.CacheModeDecl{Value: effective, Effective: effective, Line: 3, Level: "job"}
	}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main", Jobs: []ir.Job{
		{Name: "pr-target-default", Triggers: []string{"pull_request_target"}},
		{Name: "pr-target-write", Triggers: []string{"pull_request_target"}, CacheMode: mode("write")},
		{Name: "comment-write-only", Triggers: []string{"issue_comment"}, CacheMode: mode("write-only")},
		{Name: "push-read", Triggers: []string{"push"}, PushBranches: []string{"main"}, CacheMode: mode("read")},
		{Name: "schedule-none", Triggers: []string{"schedule"}, CacheMode: mode("none")},
		{Name: "schedule-default", Triggers: []string{"schedule"}},
		{Name: "mixed-default", Triggers: []string{"push", "issue_comment"}, PushBranches: []string{"main"}},
		{Name: "unresolved", Triggers: []string{"issue_comment"}, CacheMode: mode("")},
		// A pull request review runs on the pull request's merge ref, as
		// pull_request does: its own scope, saved by default.
		{Name: "review-default", Triggers: []string{"pull_request_review", "pull_request_review_comment"}},
		{Name: "review-write", Triggers: []string{"pull_request_review"}, CacheMode: mode("write")},
	}}
	want := map[string][]string{
		"pr-target-default":  nil,
		"pr-target-write":    {"default"},
		"comment-write-only": {"default"},
		"push-read":          nil,
		"schedule-none":      nil,
		"schedule-default":   {"default"},
		"mixed-default":      {"default"},
		"unresolved":         nil,
		"review-default":     {"pull_request"},
		"review-write":       {"pull_request"},
	}
	got := scopesOf(t, p)
	for name, w := range want {
		g := got[name].CacheScopes
		if len(g) == 0 {
			g = nil
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s: cacheScopes = %v, want %v", name, g, w)
		}
	}
}

// TestCacheEdgesHonourCacheMode pins that a cache edge needs a saver whose
// cache-mode lets it save and a restorer whose cache-mode lets it restore:
// a pull_request_target job saving a key feeds nothing by default, and
// feeds a push job once it declares write; a restorer on write-only or
// none restores nothing.
func TestCacheEdgesHonourCacheMode(t *testing.T) {
	save := []ir.CacheRef{{Key: "deps", Mode: "save"}}
	restore := []ir.CacheRef{{Key: "deps", Mode: "restore"}}
	mode := func(effective string) *ir.CacheModeDecl {
		return &ir.CacheModeDecl{Value: effective, Effective: effective, Line: 3, Level: "job"}
	}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main", Jobs: []ir.Job{
		{Name: "pr-target-default", Triggers: []string{"pull_request_target"}, Caches: save},
		{Name: "pr-target-write", Triggers: []string{"pull_request_target"}, Caches: save, CacheMode: mode("write")},
		{Name: "build", Triggers: []string{"push"}, PushBranches: []string{"main"}, Caches: restore},
		{Name: "build-write-only", Triggers: []string{"push"}, PushBranches: []string{"main"}, Caches: restore, CacheMode: mode("write-only")},
		{Name: "build-none", Triggers: []string{"push"}, PushBranches: []string{"main"}, Caches: restore, CacheMode: mode("none")},
	}}
	got := scopesOf(t, p)
	want := map[string][]string{
		"pr-target-default": nil,
		"pr-target-write":   {"build"},
	}
	for name, w := range want {
		f := append([]string(nil), got[name].Feeds...)
		sort.Strings(f)
		if len(f) == 0 {
			f = nil
		}
		if !reflect.DeepEqual(f, w) {
			t.Errorf("%s.feeds = %v, want %v", name, f, w)
		}
	}
}

// TestRestoresCacheFollowsCacheMode pins the restoresCache fact: the job
// declares a cache it restores (restore or both) and its cache-mode does
// not take restoring away (write-only, none).
func TestRestoresCacheFollowsCacheMode(t *testing.T) {
	mode := func(effective string) *ir.CacheModeDecl {
		return &ir.CacheModeDecl{Value: effective, Effective: effective, Line: 3, Level: "job"}
	}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main", Jobs: []ir.Job{
		{Name: "restores", Triggers: []string{"push"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "restore"}}},
		{Name: "both-read", Triggers: []string{"push"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "both"}}, CacheMode: mode("read")},
		{Name: "saves-only", Triggers: []string{"push"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "write-only", Triggers: []string{"push"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "both"}}, CacheMode: mode("write-only")},
		{Name: "none", Triggers: []string{"push"}, Caches: []ir.CacheRef{{Key: "deps", Mode: "restore"}}, CacheMode: mode("none")},
		{Name: "no-cache", Triggers: []string{"push"}},
	}}
	var r struct {
		Jobs map[string]struct {
			RestoresCache bool `json:"restoresCache"`
		} `json:"jobs"`
	}
	evaluateInto(t, p, nil, &r)
	want := map[string]bool{"restores": true, "both-read": true, "saves-only": false, "write-only": false, "none": false, "no-cache": false}
	for name, w := range want {
		if r.Jobs[name].RestoresCache != w {
			t.Errorf("%s: restoresCache = %v, want %v", name, r.Jobs[name].RestoresCache, w)
		}
	}
}

// TestSaveScopesSplitByEvent pins saveScopesByEvent: per event the job
// runs on, the scopes a run of that event saves under, empty for a
// low-trust event GitHub keeps read-only, so an entry holding only in
// some events' runs saves only where they do. A job with no trigger
// carries none.
func TestSaveScopesSplitByEvent(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, DefaultBranch: "main", Jobs: []ir.Job{
		{Name: "mixed", Triggers: []string{"push", "pull_request", "pull_request_target"}, PushBranches: []string{"main"}},
		{Name: "unknown"},
	}}
	var r struct {
		Jobs map[string]struct {
			SaveScopesByEvent map[string][]string `json:"saveScopesByEvent"`
		} `json:"jobs"`
	}
	evaluateInto(t, p, nil, &r)
	want := map[string][]string{"push": {"default"}, "pull_request": {"pull_request"}, "pull_request_target": {}}
	if got := r.Jobs["mixed"].SaveScopesByEvent; !reflect.DeepEqual(got, want) {
		t.Errorf("mixed: saveScopesByEvent = %v, want %v", got, want)
	}
	if got := r.Jobs["unknown"].SaveScopesByEvent; len(got) != 0 {
		t.Errorf("unknown: want no event, got %v", got)
	}
}
