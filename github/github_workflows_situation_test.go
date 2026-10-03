package github

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

const situationWorkflow = `
name: ci
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  build:
    runs-on: [self-hosted, linux]
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-${{ hashFiles('**/package-lock.json') }}
      - uses: actions/cache/restore@v4
        with:
          path: dist
          key: dist-cache
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
      - uses: actions/upload-artifact@v4
        with:
          path: logs/
  deploy:
    runs-on: ubuntu-latest
    needs: [lint, build]
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
      - uses: actions/download-artifact@v4
      - uses: actions/cache/save@v4
        with:
          path: dist
          key: dist-cache
  cache_multi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: |
            ~/.npm
              ~/.cache
          key: multi
`

func TestBuildJobSituationFields(t *testing.T) {
	jobs, err := parseGitHubWorkflowJobs([]byte(situationWorkflow), "", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ir.Job{}
	for _, j := range jobs {
		byName[j.Name] = j
	}
	if got := byName["/lint"].RunsOn; !reflect.DeepEqual(got, []string{"ubuntu-latest"}) {
		t.Errorf("lint.RunsOn = %v", got)
	}
	if got := byName["/build"].RunsOn; !reflect.DeepEqual(got, []string{"self-hosted", "linux"}) {
		t.Errorf("build.RunsOn = %v", got)
	}
	if got := byName["/build"].Needs; !reflect.DeepEqual(got, []string{"/lint"}) {
		t.Errorf("build.Needs = %v", got)
	}
	if got := byName["/deploy"].Needs; !reflect.DeepEqual(got, []string{"/lint", "/build"}) {
		t.Errorf("deploy.Needs = %v", got)
	}
	wantCaches := []ir.CacheRef{
		{Key: "npm-${{ hashFiles('**/package-lock.json') }}", Paths: []string{"~/.npm"}, Mode: "both"},
		{Key: "dist-cache", Paths: []string{"dist"}, Mode: "restore"},
	}
	if got := byName["/build"].Caches; !reflect.DeepEqual(got, wantCaches) {
		t.Errorf("build.Caches = %+v, want %+v", got, wantCaches)
	}
	// actions/upload-artifact with no with.name falls back to the action's
	// documented default artifact name "artifact".
	wantBuildArtifacts := []ir.ArtifactRef{
		{Name: "dist", Paths: []string{"dist/"}, Mode: "produce"},
		{Name: "artifact", Paths: []string{"logs/"}, Mode: "produce"},
	}
	if got := byName["/build"].Artifacts; !reflect.DeepEqual(got, wantBuildArtifacts) {
		t.Errorf("build.Artifacts = %+v, want %+v", got, wantBuildArtifacts)
	}
	wantConsume := []ir.ArtifactRef{{Name: "dist", Mode: "consume"}, {Mode: "consume"}}
	if got := byName["/deploy"].Artifacts; !reflect.DeepEqual(got, wantConsume) {
		t.Errorf("deploy.Artifacts = %+v, want %+v", got, wantConsume)
	}
	if got := byName["/deploy"].Caches; !reflect.DeepEqual(got, []ir.CacheRef{{Key: "dist-cache", Paths: []string{"dist"}, Mode: "save"}}) {
		t.Errorf("deploy.Caches = %+v", got)
	}
	// with.path as a multi-line YAML block scalar is split per line and each
	// line trimmed, independent of how much indentation a given line carries.
	wantMultiCaches := []ir.CacheRef{{Key: "multi", Paths: []string{"~/.npm", "~/.cache"}, Mode: "both"}}
	if got := byName["/cache_multi"].Caches; !reflect.DeepEqual(got, wantMultiCaches) {
		t.Errorf("cache_multi.Caches = %+v, want %+v", got, wantMultiCaches)
	}
}

const restoreKeysWorkflow = `
name: release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-
            ${{ runner.os }}-
      - uses: actions/cache/restore@v4
        with:
          path: dist
          key: dist-${{ github.sha }}
          restore-keys: dist-
      - uses: actions/cache/save@v4
        with:
          path: out
          key: out-${{ github.sha }}
          restore-keys: out-
`

// TestCacheRestoreKeysAreOneRestoreEntryPerPrefix: actions/cache and
// actions/cache/restore fall back to the most recent cache whose key starts
// with one of restore-keys, in order, when the exact key misses. Each
// prefix is a way in for whoever saved a matching key, so each becomes its
// own restore entry marked as a prefix, carrying the step's paths.
// actions/cache/save takes no restore-keys and gets none.
func TestCacheRestoreKeysAreOneRestoreEntryPerPrefix(t *testing.T) {
	jobs, err := parseGitHubWorkflowJobs([]byte(restoreKeysWorkflow), "release", ".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	want := []ir.CacheRef{
		{Key: "${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}", Paths: []string{"~/.cache/pip"}, Mode: "both"},
		{Key: "${{ runner.os }}-pip-", Paths: []string{"~/.cache/pip"}, Mode: "restore", Prefix: true},
		{Key: "${{ runner.os }}-", Paths: []string{"~/.cache/pip"}, Mode: "restore", Prefix: true},
		{Key: "dist-${{ github.sha }}", Paths: []string{"dist"}, Mode: "restore"},
		{Key: "dist-", Paths: []string{"dist"}, Mode: "restore", Prefix: true},
		{Key: "out-${{ github.sha }}", Paths: []string{"out"}, Mode: "save"},
	}
	if got := jobs[0].Caches; !reflect.DeepEqual(got, want) {
		t.Errorf("publish.Caches =\n%+v\nwant\n%+v", got, want)
	}
}

// TestBuildJobNeedsNamespace pins that Job.Needs is qualified with the same
// workflow namespace prefix as Job.Name, so a path assembler matching Needs
// entries against Name values finds the right job instead of silently
// failing to connect "lint" to "ci/lint".
func TestBuildJobNeedsNamespace(t *testing.T) {
	jobs, err := parseGitHubWorkflowJobs([]byte(situationWorkflow), "ci", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ir.Job{}
	for _, j := range jobs {
		byName[j.Name] = j
	}
	if got := byName["ci/deploy"].Needs; !reflect.DeepEqual(got, []string{"ci/lint", "ci/build"}) {
		t.Errorf("deploy.Needs = %v", got)
	}
}

func TestStringOrList(t *testing.T) {
	if got := stringOrList("a"); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("string: %v", got)
	}
	if got := stringOrList([]any{"a", "b", 3}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("list drops non-strings: %v", got)
	}
	if got := stringOrList(nil); got != nil {
		t.Errorf("nil: %v", got)
	}
}

// TestGitHubPushTriggerFilters pins that on.push.branches/branches-ignore/
// tags/tags-ignore land on every job of the workflow as Job.PushBranches/
// PushBranchesIgnore/PushTags/PushTagsIgnore (PR #513 review): branches: and
// tags: as written, branches-ignore: and tags-ignore: each under their own
// field, and a push with no filter (the bare string or list-element form)
// leaves all four empty rather than inventing one.
func TestGitHubPushTriggerFilters(t *testing.T) {
	withFilters := `
name: ci
on:
  push:
    branches: [main, 'release/*']
    tags: ['v*']
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	jobs, err := parseGitHubWorkflowJobs([]byte(withFilters), "", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := jobs[0].PushBranches; !reflect.DeepEqual(got, []string{"main", "release/*"}) {
		t.Errorf("PushBranches = %v", got)
	}
	if got := jobs[0].PushTags; !reflect.DeepEqual(got, []string{"v*"}) {
		t.Errorf("PushTags = %v", got)
	}
	if len(jobs[0].PushBranchesIgnore) != 0 {
		t.Errorf("PushBranchesIgnore = %v, want none", jobs[0].PushBranchesIgnore)
	}

	ignore := `
name: ci
on:
  push:
    branches-ignore: [experimental]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	jobs, err = parseGitHubWorkflowJobs([]byte(ignore), "", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := jobs[0].PushBranchesIgnore; !reflect.DeepEqual(got, []string{"experimental"}) {
		t.Errorf("PushBranchesIgnore = %v", got)
	}
	if len(jobs[0].PushBranches) != 0 || len(jobs[0].PushTags) != 0 {
		t.Errorf("branches-ignore only: PushBranches = %v, PushTags = %v, want both empty", jobs[0].PushBranches, jobs[0].PushTags)
	}

	// tags-ignore: alone is a tag filter, exactly like tags: alone (PR #513
	// review): it must land on its own field, not get silently dropped.
	tagsIgnore := `
name: ci
on:
  push:
    tags-ignore: ['v*-rc']
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	jobs, err = parseGitHubWorkflowJobs([]byte(tagsIgnore), "", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := jobs[0].PushTagsIgnore; !reflect.DeepEqual(got, []string{"v*-rc"}) {
		t.Errorf("PushTagsIgnore = %v", got)
	}
	if len(jobs[0].PushBranches) != 0 || len(jobs[0].PushBranchesIgnore) != 0 || len(jobs[0].PushTags) != 0 {
		t.Errorf("tags-ignore only: PushBranches = %v, PushBranchesIgnore = %v, PushTags = %v, want all empty", jobs[0].PushBranches, jobs[0].PushBranchesIgnore, jobs[0].PushTags)
	}

	for _, noFilter := range []string{"push", "[push, pull_request]"} {
		src := "name: ci\non: " + noFilter + "\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
		jobs, err = parseGitHubWorkflowJobs([]byte(src), "", ".github/workflows/ci.yml")
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs[0].PushBranches) != 0 || len(jobs[0].PushBranchesIgnore) != 0 || len(jobs[0].PushTags) != 0 || len(jobs[0].PushTagsIgnore) != 0 {
			t.Errorf("on: %s: filters = %+v, want all empty", noFilter, jobs[0])
		}
	}
}
