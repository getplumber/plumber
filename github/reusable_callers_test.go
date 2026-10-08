package github

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// scanWorkflows writes each workflow under a temporary checkout and scans
// it the way a local run does, jobs keyed by name.
func scanWorkflows(t *testing.T, files map[string]string) map[string]ir.Job {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p, _, err := ScanGitHubWorkflowsWithProgress("acme/app", "main", root, "", false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ir.Job{}
	for _, j := range p.Jobs {
		out[j.Name] = j
	}
	return out
}

const reusableCaller = `
name: nightly
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: x
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: wheel-cpu
          path: dist
  upload:
    needs: build
    permissions:
      id-token: write
      contents: read
    uses: ./.github/workflows/_upload.yml
    with:
      build_name: wheel-cpu
      container: '{"image":"ghcr.io/acme/build:${{ needs.build.outputs.sha }}","options":"--user root"}'
    secrets:
      github-token: ${{ secrets.GITHUB_TOKEN }}
      R2_KEY: ${{ secrets.R2_KEY }}
`

const reusableOtherCaller = `
name: other
on: pull_request
jobs:
  lint:
    uses: ./.github/workflows/_upload.yml
    with:
      build_name: lint-out
    secrets: inherit
`

const reusableCallee = `
name: upload
on:
  workflow_call:
    inputs:
      build_name: {type: string}
      container: {type: string}
jobs:
  upload:
    runs-on: x
    container: ${{ fromJSON(inputs.container) }}
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: ${{ inputs.build_name }}
      - run: bash .ci/binary_upload.sh
        env:
          R2: ${{ secrets.R2_KEY }}
          GITHUB_TOKEN: ${{ secrets.github-token }}
`

// TestReusableWorkflowCallersAreRecordedOnTheCallee pins the caller map of
// a local reusable workflow: each job of the called workflow lists every
// job calling it, with the permissions, the events, the secrets (the
// explicit map or inherit) and the inputs that call gives it, since a
// called workflow runs with its caller's token and secrets. The calling
// job lists the jobs it runs and takes in the artifacts they download,
// their inputs replaced by the literals it passes, so the upload its
// called workflow downloads hands an artifact over to it. A container
// built from an input resolves to the image each caller passes.
func TestReusableWorkflowCallersAreRecordedOnTheCallee(t *testing.T) {
	jobs := scanWorkflows(t, map[string]string{
		"nightly.yml": reusableCaller,
		"other.yml":   reusableOtherCaller,
		"_upload.yml": reusableCallee,
	})
	callee, ok := jobs["_upload/upload"]
	if !ok {
		t.Fatalf("no callee job in %v", jobs)
	}
	want := []ir.ReusableCaller{
		{
			Job:         "nightly/upload",
			Permissions: map[string]string{"contents": "read", "id-token": "write"},
			Triggers:    []string{"push"},
			Secrets:     map[string]string{"github-token": "${{ secrets.GITHUB_TOKEN }}", "R2_KEY": "${{ secrets.R2_KEY }}"},
			With: map[string]any{
				"build_name": "wheel-cpu",
				"container":  `{"image":"ghcr.io/acme/build:${{ needs.build.outputs.sha }}","options":"--user root"}`,
			},
		},
		{
			Job:            "other/lint",
			Triggers:       []string{"pull_request"},
			SecretsInherit: true,
			With:           map[string]any{"build_name": "lint-out"},
		},
	}
	if !reflect.DeepEqual(callee.Callers, want) {
		t.Errorf("callers = %+v\nwant %+v", callee.Callers, want)
	}
	caller := jobs["nightly/upload"]
	if !reflect.DeepEqual(caller.ReusableCallees, []string{"_upload/upload"}) {
		t.Errorf("callees = %v", caller.ReusableCallees)
	}
	if !reflect.DeepEqual(caller.Artifacts, []ir.ArtifactRef{{Name: "wheel-cpu", Mode: "consume"}}) {
		t.Errorf("caller artifacts = %+v, want the callee's download of wheel-cpu", caller.Artifacts)
	}
	if got := jobs["other/lint"].Artifacts; !reflect.DeepEqual(got, []ir.ArtifactRef{{Name: "lint-out", Mode: "consume"}}) {
		t.Errorf("other caller artifacts = %+v", got)
	}
	images := []string{}
	for _, img := range callee.MatrixImages {
		images = append(images, img.Name+":"+img.Tag)
	}
	if !reflect.DeepEqual(images, []string{"ghcr.io/acme/build:${{ needs.build.outputs.sha }}"}) {
		t.Errorf("callee images = %v, want the image the caller passes", images)
	}
}

// TestNestedReusableCallersTakeTheRootsTokenAndEvents pins that a called
// workflow called from another called workflow takes the token and the
// events of the run at the top of the chain, and an input passed through
// (`${{ inputs.x }}`) resolves to the root's literal.
func TestNestedReusableCallersTakeTheRootsTokenAndEvents(t *testing.T) {
	jobs := scanWorkflows(t, map[string]string{
		"build.yml": `
name: build
on: schedule
permissions: read-all
jobs:
  pipeline:
    uses: ./.github/workflows/pipeline.yml
    with:
      build-container: '{"image":"ghcr.io/acme/build:1"}'
`,
		"pipeline.yml": `
name: pipeline
on: workflow_call
jobs:
  segment:
    uses: ./.github/workflows/segment.yml
    with:
      build-container: ${{ inputs.build-container }}
`,
		"segment.yml": `
name: segment
on: workflow_call
jobs:
  build:
    runs-on: x
    container: ${{ fromJSON(inputs.build-container) }}
    steps:
      - run: make
`,
	})
	callee := jobs["segment/build"]
	if len(callee.Callers) != 1 {
		t.Fatalf("callers = %+v", callee.Callers)
	}
	c := callee.Callers[0]
	if c.Job != "pipeline/segment" || c.Permissions != "read-all" || !reflect.DeepEqual(c.Triggers, []string{"schedule"}) {
		t.Errorf("caller = %+v, want pipeline/segment with the root's read-all token and schedule", c)
	}
	if len(callee.MatrixImages) != 1 || callee.MatrixImages[0].Name != "ghcr.io/acme/build" || callee.MatrixImages[0].Tag != "1" {
		t.Errorf("images = %+v, want ghcr.io/acme/build:1", callee.MatrixImages)
	}
	if got := jobs["build/pipeline"].ReusableCallees; !reflect.DeepEqual(got, []string{"pipeline/segment", "segment/build"}) {
		t.Errorf("root callees = %v, want both levels", got)
	}
}

// TestCallerImageThatIsAnExpressionAloneStaysUnresolved pins that a
// container input a caller fills with an expression alone (another job's
// output) names no image: the reference stays as written rather than one
// expression replacing another, which would only split one image by the
// text of each caller.
func TestCallerImageThatIsAnExpressionAloneStaysUnresolved(t *testing.T) {
	jobs := scanWorkflows(t, map[string]string{
		"ci.yml": `
name: ci
on: push
jobs:
  test:
    uses: ./.github/workflows/_test.yml
    with:
      docker-image: ${{ needs.build.outputs.docker-image }}
`,
		"_test.yml": `
name: test
on: workflow_call
jobs:
  test:
    runs-on: x
    container: ${{ inputs.docker-image }}
    steps:
      - run: make
`,
	})
	if got := jobs["_test/test"].MatrixImages; len(got) != 0 {
		t.Errorf("images = %+v, want none", got)
	}
}

// TestCallerMatrixInputNamesEachArtifact pins that an input the caller
// builds from its matrix (`build_name: ${{ matrix.build_name }}`) names
// one artifact per literal the matrix lists, so the upload of one build
// is matched to the call that downloads it.
func TestCallerMatrixInputNamesEachArtifact(t *testing.T) {
	jobs := scanWorkflows(t, map[string]string{
		"nightly.yml": `
name: nightly
on: push
jobs:
  upload:
    uses: ./.github/workflows/_upload.yml
    strategy:
      matrix:
        include:
          - build_name: wheel-py3_11-cpu
          - build_name: wheel-py3_12-cpu
    with:
      build_name: ${{ matrix.build_name }}
`,
		"_upload.yml": reusableCallee,
	})
	want := []ir.ArtifactRef{{Name: "wheel-py3_11-cpu", Mode: "consume"}, {Name: "wheel-py3_12-cpu", Mode: "consume"}}
	if got := jobs["nightly/upload"].Artifacts; !reflect.DeepEqual(got, want) {
		t.Errorf("artifacts = %+v, want %+v", got, want)
	}
}
