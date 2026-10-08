package situation_test

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// TestDeadJobIsAFactAndFeedsNothing pins that a job the collector records
// as dead (a constant false if:) carries the dead fact, so a path never
// enters it, and is no edge either way: it uploads, saves and outputs
// nothing, and restores nothing a live job saves.
func TestDeadJobIsAFactAndFeedsNothing(t *testing.T) {
	type deadFacts struct {
		Dead  bool     `json:"dead"`
		Feeds []string `json:"feeds"`
	}
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{
		{Name: "ci/build", OriginFile: "ci.yml", Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "produce"}}, Caches: []ir.CacheRef{{Key: "deps", Mode: "save"}}},
		{Name: "ci/off", OriginFile: "ci.yml", Dead: true, Artifacts: []ir.ArtifactRef{{Name: "dist", Mode: "consume"}, {Name: "out", Mode: "produce"}}, Caches: []ir.CacheRef{{Key: "deps", Mode: "both"}}},
		{Name: "ci/publish", OriginFile: "ci.yml", Artifacts: []ir.ArtifactRef{{Name: "out", Mode: "consume"}}},
	}}
	var r struct {
		Jobs map[string]deadFacts `json:"jobs"`
	}
	evaluateInto(t, p, nil, &r)
	if !r.Jobs["ci/off"].Dead || r.Jobs["ci/build"].Dead {
		t.Errorf("dead facts: %+v", r.Jobs)
	}
	if got := r.Jobs["ci/build"].Feeds; len(got) != 0 {
		t.Errorf("build feeds a dead job: %v", got)
	}
	if got := r.Jobs["ci/off"].Feeds; len(got) != 0 {
		t.Errorf("a dead job feeds %v", got)
	}
}
