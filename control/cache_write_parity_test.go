package control

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/getplumber/plumber/configuration"
	githubpkg "github.com/getplumber/plumber/github"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies"
	"github.com/getplumber/plumber/utils"
)

// TestCacheWriteRegoAndGoAgree pins the Go mirror of ISSUE-705 (the stats
// listing the exempted jobs) to the rule, over every rule fixture and with
// or without exemptions: the jobs the rule flags plus the jobs the stats
// list as exempted are exactly the jobs the Go predicate finds at risk.
// A trigger, a cache-mode or a glob the two read differently fails here.
func TestCacheWriteRegoAndGoAgree(t *testing.T) {
	dir := filepath.Join("..", "policies", "testdata", "ISSUE-705", "github")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	engine := opaengine.New()
	if err := engine.LoadFromFSFiltered(policies.FS, nil); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	exemptions := []*configuration.CacheWriteControlConfig{
		{},
		{ExemptWorkflows: []string{"violation_*.yml", "warm.yml"}},
		{ExemptJobs: []string{"*/label", "*/build"}},
	}
	for _, e := range entries {
		pipeline := scanFixture(t, filepath.Join(dir, e.Name()))
		var atRisk []string
		for i := range pipeline.Jobs {
			j := &pipeline.Jobs[i]
			if j.CacheMode != nil && len(utils.CacheWriteRiskyTriggers(j.CacheMode.Effective, effectiveTriggers(j))) > 0 {
				atRisk = append(atRisk, j.Name)
			}
		}
		slices.Sort(atRisk)
		for _, c := range exemptions {
			pc := &configuration.PlumberConfig{GitHub: &configuration.ProviderConfig{Controls: configuration.ControlsConfig{
				UntrustedTriggersMustNotWriteCache: c,
			}}}
			findings, err := evaluateStrict(engine, context.Background(), pipeline, buildEngineConfig(pc.ControlsFor("github"), ""))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			got := append([]string(nil), AggregateGitHubStats(pipeline, pc).CacheWriteExempted...)
			for _, f := range findings {
				if f.Code == string(CodeCachePoisoning) {
					got = append(got, f.Job)
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, atRisk) {
				t.Errorf("%s, exemptions %+v: flagged + exempted = %v, want the Go at-risk set %v", e.Name(), *c, got, atRisk)
			}
		}
	}
}

// scanFixture parses a workflow file, or a directory of them, with the
// real scanner.
func scanFixture(t *testing.T, src string) *ir.NormalizedPipeline {
	t.Helper()
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := []string{src}
	if info, err := os.Stat(src); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(src)
		files = files[:0]
		for _, e := range entries {
			files = append(files, filepath.Join(src, e.Name()))
		}
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wfDir, filepath.Base(f)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pipeline, _, err := githubpkg.ScanGitHubWorkflowsWithProgress("owner/repo", "main", tmp, "", false, true, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return pipeline
}
