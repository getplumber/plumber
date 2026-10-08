package cmd

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/getplumber/plumber/control"
	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// fiveJobPushResult is one unprotected branch five jobs run on, the
// shape of a repository whose every workflow runs on push: one path, five
// branches.
func fiveJobPushResult() *control.AnalysisResult {
	push := []control.EntryFact{{Kind: control.EntryUnprotectedPush, State: "proven", Evidence: "push: branches: [main]", Subject: "main"}}
	sit := &control.Situation{Exposure: ir.VisibilityPublic, Provider: "github", DefaultBranch: "main", Jobs: map[string]control.JobSituation{}}
	build := control.JobSituation{Push: push, Impact: []control.ImpactFact{{Kind: "publishes", State: "proven", Evidence: "npm publish"}}}
	build.Privilege.AllSecrets = true
	sit.Jobs["ci/build"] = build
	approve := control.JobSituation{Push: push}
	approve.Privilege.TokenWrite = []string{"contents"}
	approve.Privilege.TokenWriteSource = "declared"
	sit.Jobs["ci/auto-approve"] = approve
	for _, j := range []string{"build/release-notes", "build/security-scan", "plumber/scan"} {
		sit.Jobs[j] = control.JobSituation{Push: push}
	}
	branch := opaengine.Finding{Code: "ISSUE-501", Data: map[string]any{"branchName": "main"}}
	perms := opaengine.Finding{Code: "ISSUE-803", Job: "ci/auto-approve", File: ".github/workflows/ci.yml", Line: 9}
	return &control.AnalysisResult{Findings: []opaengine.Finding{branch, perms}, Situation: sit}
}

// The platform receives the same path shape as before paths had branches:
// the same keys, jobs as a list of names (every entry job), every finding
// of every branch in finding_hashes, and no branches.
func TestPlatformPushKeepsThePathShapeWithBranches(t *testing.T) {
	result := fiveJobPushResult()
	score := control.ScoreV4WithExplanations(result)
	if len(score.Paths) != 1 || len(score.Paths[0].Branches) != 5 {
		t.Fatalf("paths = %+v, want one path with five branches", score.Paths)
	}
	body, err := buildPlatformPush(testProvider(t), nil, result, &score, ".plumber.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	var pushed struct {
		Results []struct {
			ScoreContext struct {
				Paths []map[string]json.RawMessage `json:"paths"`
			} `json:"score_context"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &pushed); err != nil {
		t.Fatal(err)
	}
	if len(pushed.Results) == 0 || len(pushed.Results[0].ScoreContext.Paths) != 1 {
		t.Fatalf("pushed = %s", body)
	}
	path := pushed.Results[0].ScoreContext.Paths[0]
	var keys []string
	for k := range path {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if want := []string{"entry_kind", "finding_hashes", "id", "jobs", "modifiers", "reach_kind", "sentence", "state", "tier"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("pushed path keys = %v, want %v", keys, want)
	}
	var jobs, hashes []string
	if err := json.Unmarshal(path["jobs"], &jobs); err != nil {
		t.Fatalf("jobs = %s, want a list of names: %v", path["jobs"], err)
	}
	if !reflect.DeepEqual(jobs, score.Paths[0].Jobs) || len(jobs) != 5 {
		t.Errorf("jobs = %v, want every entry job %v", jobs, score.Paths[0].Jobs)
	}
	if err := json.Unmarshal(path["finding_hashes"], &hashes); err != nil {
		t.Fatal(err)
	}
	want := append(append([]string(nil), score.Paths[0].AllAnchorHashes()...), score.Paths[0].GateHashes...)
	if !reflect.DeepEqual(hashes, want) {
		t.Errorf("finding_hashes = %v, want %v", hashes, want)
	}
}
