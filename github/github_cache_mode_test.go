package github

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// cacheModesOf parses one workflow and returns each job's cache-mode by job
// name.
func cacheModesOf(t *testing.T, workflow string) map[string]*ir.CacheModeDecl {
	t.Helper()
	jobs, err := parseGitHubWorkflowJobs([]byte(workflow), "ci", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*ir.CacheModeDecl{}
	for _, j := range jobs {
		out[j.Name] = j.CacheMode
	}
	return out
}

// A workflow-level cache-mode reaches every job that sets none of its own,
// and a job-level one overrides it on that job only.
func TestCacheModeJobOverridesWorkflow(t *testing.T) {
	got := cacheModesOf(t, `name: ci
on: issue_comment
cache-mode: write
jobs:
  inherit:
    runs-on: ubuntu-latest
    steps:
      - run: true
  own:
    runs-on: ubuntu-latest
    cache-mode: read
    steps:
      - run: true
`)
	want := map[string]*ir.CacheModeDecl{
		"ci/inherit": {Value: "write", Effective: "write", Line: 3, Level: "workflow"},
		"ci/own":     {Value: "read", Effective: "read", Line: 11, Level: "job"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cache modes:\n got %+v\nwant %+v", deref(got), deref(want))
	}
}

// No cache-mode anywhere leaves the job on GitHub's trigger-based default.
func TestCacheModeAbsentIsNil(t *testing.T) {
	got := cacheModesOf(t, `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: true
`)
	if got["ci/build"] != nil {
		t.Errorf("cache mode = %+v, want nil", *got["ci/build"])
	}
}

// GitHub accepts a cache-mode expression only when it reads no context, so
// its value is the same on every run. Without evaluating it, the parser
// takes the widest grant it quotes: write or write-only when one is quoted,
// else read when quoted, else none. An expression reading a context makes
// the workflow file invalid (no effective mode).
func TestCacheModeExpressionResolves(t *testing.T) {
	cases := []struct {
		value, effective string
	}{
		{`write-only`, "write-only"},
		{`none`, "none"},
		{`bogus`, ""},
		{`${{ 'write' }}`, "write"},
		{`${{ 'write-only' }}`, "write-only"},
		{`${{ 'read' }}`, "read"},
		{`${{ true && 'none' || 'read' }}`, "read"},
		{`${{ 'none' }}`, "none"},
		{`${{ false && 'read' || 'write' }}`, "write"},
		{`${{ github.event_name == 'issue_comment' && 'write' || 'read' }}`, ""},
		{`${{ vars.CACHE_MODE || 'write' }}`, ""},
		{`${{ inputs.mode || 'write' }}`, ""},
		{`${{ format('wr{0}', 'ite') }}`, ""},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			got := cacheModesOf(t, "on: issue_comment\njobs:\n  j:\n    runs-on: ubuntu-latest\n    cache-mode: \""+c.value+"\"\n    steps:\n      - run: true\n")
			d := got["ci/j"]
			if d == nil {
				t.Fatal("no cache mode recorded")
			}
			if d.Value != c.value || d.Effective != c.effective || d.Line != 5 || d.Level != "job" {
				t.Errorf("got %+v, want value %q effective %q line 5 level job", *d, c.value, c.effective)
			}
		})
	}
}

// A non-string cache-mode is not a value GitHub accepts: nothing recorded.
func TestCacheModeNonStringIgnored(t *testing.T) {
	got := cacheModesOf(t, `on: issue_comment
jobs:
  j:
    runs-on: ubuntu-latest
    cache-mode: [write]
    steps:
      - run: true
`)
	if got["ci/j"] != nil {
		t.Errorf("cache mode = %+v, want nil", *got["ci/j"])
	}
}

func deref(m map[string]*ir.CacheModeDecl) map[string]ir.CacheModeDecl {
	out := map[string]ir.CacheModeDecl{}
	for k, v := range m {
		if v != nil {
			out[k] = *v
		}
	}
	return out
}
