package github

import (
	"reflect"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

const matrixImageWorkflow = `name: Release
on: push
jobs:
  zsh:
    runs-on: ubuntu-latest
    container:
      image: ${{ matrix.image }}
    strategy:
      matrix:
        include:
          - target: x86_64
            image: ubuntu:24.04
          - target: aarch64
            image: arm64v8/ubuntu:24.04
    steps:
      - run: make
  cuda:
    runs-on: ubuntu-latest
    container: nvidia/cuda:${{ matrix.cuda }}-devel-ubuntu24.04
    strategy:
      matrix:
        cuda: ["12.4.0", "12.8.1"]
    steps:
      - run: make
  computed:
    runs-on: ubuntu-latest
    container: ${{ matrix.image }}
    strategy:
      matrix: ${{ fromJSON(needs.setup.outputs.matrix) }}
    steps:
      - run: make
  mixed:
    runs-on: ubuntu-latest
    container: ${{ matrix.image }}:${{ inputs.tag }}
    strategy:
      matrix:
        image: [alpine]
    steps:
      - run: make
  plain:
    runs-on: ubuntu-latest
    container: alpine:3.20
    steps:
      - run: make
`

// TestContainerImageResolvesMatrixLiterals pins that a container image
// built from `${{ matrix.X }}` resolves to the images the matrix lists as
// literals (the key's own list and every include entry), one per value,
// while the image as written stays the job's image. A matrix computed at
// run time, an expression other than a matrix value, or a plain image
// resolves to nothing.
func TestContainerImageResolvesMatrixLiterals(t *testing.T) {
	jobs, err := parseGitHubWorkflowJobs([]byte(matrixImageWorkflow), "release", ".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ir.Job{}
	for _, j := range jobs {
		byName[j.Name] = j
	}
	want := map[string][]ir.Image{
		"release/zsh": {
			{Name: "arm64v8/ubuntu", Tag: "24.04"},
			{Name: "ubuntu", Tag: "24.04"},
		},
		"release/cuda": {
			{Name: "nvidia/cuda", Tag: "12.4.0-devel-ubuntu24.04"},
			{Name: "nvidia/cuda", Tag: "12.8.1-devel-ubuntu24.04"},
		},
		"release/computed": nil,
		"release/mixed":    nil,
		"release/plain":    nil,
	}
	for name, images := range want {
		job, ok := byName[name]
		if !ok {
			t.Fatalf("no job %s", name)
		}
		if !reflect.DeepEqual(job.MatrixImages, images) {
			t.Errorf("%s: MatrixImages = %+v, want %+v", name, job.MatrixImages, images)
		}
	}
	if img := byName["release/zsh"].Image; img == nil || img.Name != "${{ matrix.image }}" {
		t.Errorf("release/zsh: Image = %+v, want the reference as written", img)
	}
}
