package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/getplumber/plumber/configuration"
	"github.com/getplumber/plumber/provider"
)

// A degraded run withholds its score on the terminal, so no artifact may
// carry it either: the JSON report, the run cache `plumber explain -a`
// reads back and the PBOM all leave out plumberScore and pathBlocks, while
// the same run collected in full keeps them.
func TestDegradedRunArtifactsCarryNoScore(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		root := withCacheDir(t)
		dir := withArtifactFiles(t)
		outputFile = filepath.Join(dir, "out.json")
		pbomFile = filepath.Join(dir, "pbom.json")
		newGateFlagsCmd(t)
		gh := &provider.GitHubProvider{}
		conf := configuration.NewDefaultConfiguration()
		conf.PlumberConfig = defaultGitHubPlumberConfig(t)
		result := releaseMutableActionResult()
		result.ProjectPath = "grp/app"
		result.DataCollectionDegraded = degraded
		if degraded {
			result.DegradedReasons = []string{"branch protection: 403"}
		}
		s := buildComplianceSummary(gh, result, conf)
		if s.score == nil || len(s.score.Paths) == 0 {
			t.Fatalf("degraded=%v: the fixture priced no path: %+v", degraded, s.score)
		}
		_ = captureStderr(t, func() {
			if err := writeOutputsWithProvider(gh, result, conf, s, nil, nil); err != nil {
				t.Fatal(err)
			}
		})
		cached, err := os.ReadFile(filepath.Join(root, "github", "grp", "app.json"))
		if err != nil {
			t.Fatal(err)
		}
		written, _ := os.ReadFile(outputFile)
		bom, _ := os.ReadFile(pbomFile)
		for name, doc := range map[string][]byte{"--output": written, "run cache": cached, "pbom": bom} {
			var m map[string]any
			if err := json.Unmarshal(doc, &m); err != nil {
				t.Fatalf("degraded=%v: %s: %v", degraded, name, err)
			}
			if _, score := m["plumberScore"]; score == degraded {
				t.Errorf("degraded=%v: %s has plumberScore = %v", degraded, name, score)
			}
			if _, blocks := m["pathBlocks"]; blocks && degraded {
				t.Errorf("degraded run: %s carries pathBlocks", name)
			}
		}
	}
}
