package situation_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
	"github.com/getplumber/plumber/policies/situation"
)

type gateFacts struct {
	Jobs map[string]struct {
		ForkPR []struct {
			Kind  string `json:"kind"`
			Actor string `json:"actor"`
		} `json:"forkPR"`
		Gate *struct {
			Class     string   `json:"class"`
			Reason    string   `json:"reason"`
			PinnedSha bool     `json:"pinnedSha"`
			Unknown   []string `json:"unknown"`
		} `json:"gate"`
	} `json:"jobs"`
}

// TestJobFactsCarryTheGate pins that the facts of a job carry the gate
// ir.ClassifyGates stored on it (class, reason, pinned head commit), the
// weakest one when same-named jobs merge, and none on a job without one.
func TestJobFactsCarryTheGate(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "ci/cloud", Triggers: []string{"pull_request_target"}, Gate: &ir.Gate{Class: ir.GateMaintainerApproved, Reason: "label tests:run-cloud", PinnedSha: true}},
			{Name: "ci/merged", OriginFile: "a.yml", Triggers: []string{"pull_request_target"}, Gate: &ir.Gate{Class: ir.GateSameRepo, Reason: "same repository"}},
			{Name: "ci/merged", OriginFile: "b.yml", Triggers: []string{"workflow_run"}, Gate: &ir.Gate{Class: ir.GateUnknown, Unknown: []string{"inputs.mode"}}},
			{Name: "ci/build", Triggers: []string{"push"}},
		},
	}
	var r gateFacts
	evaluateInto(t, p, nil, &r)
	if g := r.Jobs["ci/cloud"].Gate; g == nil || g.Class != "maintainer_approved" || g.Reason != "label tests:run-cloud" || !g.PinnedSha {
		t.Errorf("ci/cloud gate = %+v", g)
	}
	if g := r.Jobs["ci/merged"].Gate; g == nil || g.Class != "unknown" || len(g.Unknown) != 1 || g.Unknown[0] != "inputs.mode" {
		t.Errorf("ci/merged gate = %+v, want the weakest (unknown)", g)
	}
	if g := r.Jobs["ci/build"].Gate; g != nil {
		t.Errorf("ci/build gate = %+v, want none", g)
	}
}

// TestPrivilegedTriggersMatchTheSituation pins that the privileged
// triggers this module reads (privileged_triggers) are exactly the ones
// ir.ClassifyGates decides a gate for (ir.PrivilegedTriggers): one list,
// so a privileged trigger is never left without a gate.
func TestPrivilegedTriggersMatchTheSituation(t *testing.T) {
	src, err := situation.SituationFS.ReadFile(situation.SituationModule)
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(src), "\nprivileged_triggers := {")
	block, _, ok2 := strings.Cut(block, "}")
	if !ok || !ok2 {
		t.Fatal("privileged_triggers not found")
	}
	var rego []string
	for _, line := range strings.Split(block, "\n") {
		if name := strings.Trim(strings.TrimSpace(line), `",`); name != "" {
			rego = append(rego, name)
		}
	}
	goList := slices.Clone(ir.PrivilegedTriggers)
	slices.Sort(rego)
	slices.Sort(goList)
	if !slices.Equal(rego, goList) {
		t.Errorf("rego %v, ir %v", rego, goList)
	}
}

// TestSiblingWithoutAGateIsAnOutsider pins that a same-named job carrying a
// privileged trigger but no gate (never classified) makes the merged gate
// an outsider's, whatever its sibling's gate says.
func TestSiblingWithoutAGateIsAnOutsider(t *testing.T) {
	p := &ir.NormalizedPipeline{
		Provider: ir.ProviderGitHub,
		Jobs: []ir.Job{
			{Name: "ci/merged", OriginFile: "a.yml", Triggers: []string{"pull_request_target"}, Gate: &ir.Gate{Class: ir.GateSameRepo, Reason: "same repository"}},
			{Name: "ci/merged", OriginFile: "b.yml", Triggers: []string{"workflow_run"}},
			{Name: "ci/other", OriginFile: "c.yml", Triggers: []string{"pull_request_target"}, Gate: &ir.Gate{Class: ir.GateSameRepo, Reason: "same repository"}},
			{Name: "ci/other", OriginFile: "d.yml", Triggers: []string{"push"}},
		},
	}
	var r gateFacts
	evaluateInto(t, p, nil, &r)
	if g := r.Jobs["ci/merged"].Gate; g == nil || g.Class != "outsider" {
		t.Errorf("ci/merged gate = %+v, want outsider", g)
	}
	if g := r.Jobs["ci/other"].Gate; g == nil || g.Class != "same_repo" {
		t.Errorf("ci/other gate = %+v, want same_repo (the sibling has no privileged trigger)", g)
	}
}

// TestForkPREntryIsAnOutsiders pins that a fork pull request entry names
// its actor: an outsider, always (no gate stands before a pull_request
// run from a fork).
func TestForkPREntryIsAnOutsiders(t *testing.T) {
	p := &ir.NormalizedPipeline{Provider: ir.ProviderGitHub, Jobs: []ir.Job{{Name: "ci/test", Triggers: []string{"pull_request"}}}}
	var r gateFacts
	evaluateInto(t, p, nil, &r)
	fork := r.Jobs["ci/test"].ForkPR
	if len(fork) != 1 || fork[0].Actor != "outsider" {
		t.Errorf("forkPR = %+v", fork)
	}
}
