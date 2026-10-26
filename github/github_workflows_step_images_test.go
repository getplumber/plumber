package github

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

const dockerStepWorkflow = `name: CI
on: push
jobs:
  docker:
    runs-on: ubuntu-latest
    container: node:20
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:3.20
        with:
          args: echo tag
      - run: echo between
      - uses: docker://alpine
      - uses: docker://ghcr.io/owner/image@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
  actions-only:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`

// TestDockerStepsAreJobImages pins that a job's own `uses: docker://` steps
// become its StepImages (#571), in step order, a tagless one on `latest`,
// next to the container image rather than in place of it.
func TestDockerStepsAreJobImages(t *testing.T) {
	jobs, err := parseGitHubWorkflowJobs([]byte(dockerStepWorkflow), "ci", ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ir.Job{}
	for _, j := range jobs {
		byName[j.Name] = j
	}
	want := []ir.Image{
		{Name: "alpine", Tag: "3.20"},
		{Name: "alpine", Tag: "latest"},
		{Name: "ghcr.io/owner/image", Digest: "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"},
	}
	docker := byName["ci/docker"]
	if !reflect.DeepEqual(docker.StepImages, want) {
		t.Errorf("ci/docker: StepImages = %+v, want %+v", docker.StepImages, want)
	}
	if docker.Image == nil || docker.Image.Name != "node" || docker.Image.Tag != "20" {
		t.Errorf("ci/docker: Image = %+v, want node:20", docker.Image)
	}
	if imgs := byName["ci/actions-only"].StepImages; imgs != nil {
		t.Errorf("ci/actions-only: StepImages = %+v, want none", imgs)
	}
}

// TestDockerStepImagesSkipNestedSteps: a docker:// step a composite action
// pulls in is not one of the job's own images.
func TestDockerStepImagesSkipNestedSteps(t *testing.T) {
	got := dockerStepImages([]ir.Action{
		{Uses: "owner/composite@v1"},
		{Uses: "docker://busybox:1", Nested: true, Via: []string{"owner/composite@v1"}},
		{Uses: "docker://alpine:3.20"},
		{Uses: "docker://"},
	})
	want := []ir.Image{{Name: "alpine", Tag: "3.20"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dockerStepImages = %+v, want %+v", got, want)
	}
}
