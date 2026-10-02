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
