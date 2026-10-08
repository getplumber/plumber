package control

import (
	"fmt"
	"reflect"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
	"github.com/getplumber/plumber/internal/ir"
)

// Within a tier the paths read by what they reach: every secret before
// listed secrets, listed secrets before a write token, a write token before
// code execution alone, then by id. Path 1 is the worst.
func TestPathsWorstFirstOrdersATierByReachStrength(t *testing.T) {
	in := []AttackPath{
		{ID: "a", Tier: TierHigh, Reach: Reach{Executes: true}},
		{ID: "b", Tier: TierHigh, Reach: Reach{TokenWrite: []string{"contents"}, Executes: true}},
		{ID: "c", Tier: TierHigh, Reach: Reach{Secrets: []string{"S"}, Executes: true}},
		{ID: "d", Tier: TierHigh, Reach: Reach{AllSecrets: true, Executes: true}},
		{ID: "e", Tier: TierCritical, Reach: Reach{Executes: true}},
		{ID: "f", Tier: TierHigh, Reach: Reach{Secrets: []string{"S", "T"}, Executes: true}},
	}
	var ids []string
	for _, p := range PathsWorstFirst(in) {
		ids = append(ids, p.ID)
	}
	if want := []string{"e", "d", "c", "f", "b", "a"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("order %v, want %v", ids, want)
	}
}

// strongAndWeakSituation is a job holding a secret and a job holding
// nothing, on GitHub.
func strongAndWeakSituation() *Situation {
	strong := JobSituation{}
	strong.Privilege.Secrets, strong.Privilege.SecretsState = []string{"S"}, "proven"
	return &Situation{Exposure: ir.VisibilityPublic, Provider: "github", Jobs: map[string]JobSituation{"ci/a": {}, "ci/b": strong}}
}

// AssemblePaths returns its paths in the order the reports number them.
func TestAssembledPathsFollowTheReportOrder(t *testing.T) {
	var findings []opaengine.Finding
	for i := range 6 {
		job := "ci/a"
		if i%2 == 1 {
			job = "ci/b"
		}
		findings = append(findings, finding("ISSUE-714", job, map[string]any{"uses": fmt.Sprintf("o/a%d@v1", i)}))
	}
	paths := assemblePaths(findings, strongAndWeakSituation())
	if got := PathsWorstFirst(paths); !reflect.DeepEqual(got, paths) {
		t.Errorf("assembly order differs from the report order")
	}
	if paths[0].Jobs[0] != "ci/b" || paths[len(paths)-1].Jobs[0] != "ci/a" {
		t.Errorf("the paths reaching a secret come first: %v first, %v last", paths[0].Jobs, paths[len(paths)-1].Jobs)
	}
}

// Two paths of one tier recovering the same points: the best fix is the
// one the report numbers first, the one reaching a secret.
func TestTheBestFixTieFollowsTheReportOrder(t *testing.T) {
	sit := strongAndWeakSituation()
	for _, subjects := range [][2]string{{"o/a@v1", "o/z@v1"}, {"o/z@v1", "o/a@v1"}} {
		findings := []opaengine.Finding{
			finding("ISSUE-714", "ci/a", map[string]any{"uses": subjects[0]}),
			finding("ISSUE-714", "ci/b", map[string]any{"uses": subjects[1]}),
		}
		in := ScoreInputV4{Findings: findings, Paths: assemblePaths(findings, sit)}
		fix := ComputeBestFix(in, sit, ComputePlumberScoreV4(in))
		if fix == nil || fix.Job != "ci/b" {
			t.Errorf("%v: the best fix is the path reaching the secret, got %+v", subjects, fix)
		}
	}
}
