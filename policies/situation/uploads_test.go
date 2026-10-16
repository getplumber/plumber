package situation_test

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestUploadsIsAFact pins the uploads fact: a job producing an artifact
// leaves something a later run downloads, so code on its runner can
// poison it; a job only downloading one, or touching none, leaves
// nothing.
func TestUploadsIsAFact(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "upload", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}},
		{Name: "download", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}}},
		{Name: "none"},
	}}
	var r struct {
		Jobs map[string]struct {
			Uploads bool `json:"uploads"`
		} `json:"jobs"`
	}
	evaluateInto(t, p, nil, &r)
	for name, want := range map[string]bool{"upload": true, "download": false, "none": false} {
		if got := r.Jobs[name].Uploads; got != want {
			t.Errorf("%s: uploads = %v, want %v", name, got, want)
		}
	}
}
