package github

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v2"
)

// jobSection parses a job's YAML the way the collector reads it.
func jobSection(t *testing.T, src string) map[string]any {
	t.Helper()
	var section map[string]any
	if err := yaml.Unmarshal([]byte(src), &section); err != nil {
		t.Fatal(err)
	}
	return section
}

// The combinations a matrix runs, as GitHub documents them: the cartesian
// product of its lists, less what exclude removes, then each include entry
// added to every original combination none of whose original values it
// would change (overwriting a value an earlier entry added), or run as a
// combination of its own when it fits none. This is the documentation's
// own example.
func TestMatrixCombinationsFollowTheDocumentedIncludeSemantics(t *testing.T) {
	section := jobSection(t, `
strategy:
  matrix:
    fruit: [apple, pear]
    animal: [cat, dog]
    include:
      - color: green
      - color: pink
        animal: cat
      - fruit: apple
        shape: circle
      - fruit: banana
      - fruit: banana
        animal: cat
`)
	want := []map[string]string{
		{"fruit": "apple", "animal": "cat", "color": "pink", "shape": "circle"},
		{"fruit": "apple", "animal": "dog", "color": "green", "shape": "circle"},
		{"fruit": "pear", "animal": "cat", "color": "pink"},
		{"fruit": "pear", "animal": "dog", "color": "green"},
		{"fruit": "banana"},
		{"fruit": "banana", "animal": "cat"},
	}
	if got := matrixCombinations(section); !reflect.DeepEqual(comboSet(got), comboSet(want)) {
		t.Errorf("combos = %v, want %v", got, want)
	}
}

// comboSet is combos in a canonical order (fmt prints a map by sorted key).
func comboSet(combos []map[string]string) []string {
	out := make([]string, 0, len(combos))
	for _, r := range combos {
		out = append(out, fmt.Sprint(r))
	}
	sort.Strings(out)
	return out
}

// An image built from matrix values resolves to the image of each
// combination the matrix runs: an include entry pairing keys adds exactly
// that pair, never a cross of its values with the others'.
func TestMatrixImageRefsResolvePerCombination(t *testing.T) {
	cases := []struct {
		name, ref, matrix string
		want              []string
	}{
		{"one list", "${{ matrix.v }}", "v: [a, b]", []string{"a", "b"}},
		{"two lists cross", "${{ matrix.os }}:${{ matrix.v }}", "os: [p, q]\n    v: ['1', '2']", []string{"p:1", "p:2", "q:1", "q:2"}},
		{"include only pairs", "${{ matrix.base }}:${{ matrix.ver }}", `include:
      - {base: ubuntu, ver: "22.04"}
      - {base: alpine, ver: latest}`, []string{"alpine:latest", "ubuntu:22.04"}},
		{"include only, registry and repository", "${{ matrix.registry }}/${{ matrix.repo }}:v1", `include:
      - {registry: ghcr.io, repo: myorg/ci-base}
      - {registry: docker.io, repo: myorg/ci-extra}`, []string{"docker.io/myorg/ci-extra:v1", "ghcr.io/myorg/ci-base:v1"}},
		{"include adds a combination of its own", "${{ matrix.registry }}/app:${{ matrix.tag }}", `registry: [ghcr.io]
    tag: [v1]
    include:
      - {registry: docker.io, tag: latest}`, []string{"docker.io/app:latest", "ghcr.io/app:v1"}},
		{"include extends the combinations it matches", "${{ matrix.image }}", `os: [linux, windows]
    include:
      - {os: linux, image: alpine}
      - {os: windows, image: mcr.microsoft.com/windows/nanoserver}`, []string{"alpine", "mcr.microsoft.com/windows/nanoserver"}},
		{"include with no original key extends every combination", "${{ matrix.base }}:${{ matrix.v }}", `v: ['1', '2']
    include:
      - {base: alpine}`, []string{"alpine:1", "alpine:2"}},
		{"exclude removes its combinations", "${{ matrix.os }}:${{ matrix.v }}", `os: [p, q]
    v: ['1', '2']
    exclude:
      - {os: q, v: '2'}`, []string{"p:1", "p:2", "q:1"}},
		{"one key twice takes one value", "${{ matrix.tag }}-${{matrix.tag}}", "tag: [p, q]", []string{"p-p", "q-q"}},
		{"numbers and booleans read as GitHub reads them", "python:${{ matrix.v }}-${{ matrix.slim }}", "v: [3.10, 3, 3.9]\n    slim: [true]", []string{"python:3-true", "python:3.1-true", "python:3.9-true"}},
		{"a list the ref does not use", "${{ matrix.image }}", "image: [alpine]\n    os: ${{ fromJSON(inputs.os) }}", []string{"alpine"}},
		{"a combination without the key", "${{ matrix.image }}", `os: [linux, windows]
    include:
      - {os: linux, image: alpine}`, nil},
		{"a computed value", "${{ matrix.image }}", "image: ${{ fromJSON(inputs.images) }}", nil},
		{"a value that is not a scalar", "${{ matrix.image }}", "image: [{name: alpine}]", nil},
		{"another expression", "${{ matrix.image }}:${{ inputs.tag }}", "image: [alpine]", nil},
		{"past the job limit", "${{ matrix.a }}", "a: [1, 2, 3, 4, 5, 6, 7]\n    b: [1, 2, 3, 4, 5, 6, 7]\n    c: [1, 2, 3, 4, 5, 6, 7]", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			section := jobSection(t, "strategy:\n  matrix:\n    "+c.matrix+"\n")
			if got := expandMatrixRef(c.ref, matrixCombinations(section)); !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s over\n%s\n= %v, want %v", c.ref, c.matrix, got, c.want)
			}
		})
	}
	computed := jobSection(t, "strategy:\n  matrix: ${{ fromJSON(needs.setup.outputs.matrix) }}\n")
	if combos := matrixCombinations(computed); combos != nil {
		t.Errorf("a matrix computed at run time has combos %v", combos)
	}
}
