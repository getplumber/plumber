package situation_test

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestOwnImageIsAFact pins the ownImage fact: the job's container (every
// image it resolves to, through its matrix or its callers) is under the
// repository owner's own ghcr.io namespace, so a path can name it the
// image of the repository's organization rather than an outside one.
func TestOwnImageIsAFact(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, ProjectPath: "electron/electron", Jobs: []ir.Job{
		{Name: "own", Image: &ir.Image{Name: "ghcr.io/electron/build", Tag: "${{ needs.setup.outputs.sha }}"}},
		{Name: "resolved", Image: &ir.Image{Name: "${{ fromJSON(inputs.container) }}"},
			MatrixImages: []ir.Image{{Name: "ghcr.io/Electron/build", Tag: "1"}, {Name: "ghcr.io/electron/test", Tag: "2"}}},
		{Name: "mixed", Image: &ir.Image{Name: "x"}, MatrixImages: []ir.Image{{Name: "ghcr.io/electron/build", Tag: "1"}, {Name: "node", Tag: "20"}}},
		{Name: "outside", Image: &ir.Image{Name: "ghcr.io/other/build", Tag: "1"}},
		{Name: "none"},
	}}
	var r struct {
		Jobs map[string]struct {
			OwnImage bool `json:"ownImage"`
		} `json:"jobs"`
	}
	evaluateInto(t, p, nil, &r)
	for name, want := range map[string]bool{"own": true, "resolved": true, "mixed": false, "outside": false, "none": false} {
		if got := r.Jobs[name].OwnImage; got != want {
			t.Errorf("%s: ownImage = %v, want %v", name, got, want)
		}
	}
}
