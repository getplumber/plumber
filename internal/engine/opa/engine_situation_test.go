package opa

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

const situationStub = `
package situation

import rego.v1

result := {"exposure": input.pipeline.visibility, "jobs": {j.name: {"runsOn": j.runsOn} | some j in input.pipeline.jobs}}
`

func TestEvaluateSituationReturnsTheResultRule(t *testing.T) {
	e := New()
	p := &ir.NormalizedPipeline{Visibility: "private", Jobs: []ir.Job{{Name: "build", RunsOn: []string{"ubuntu-latest"}}}}
	raw, err := e.EvaluateSituation(context.Background(), situationStub, p, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Exposure string                         `json:"exposure"`
		Jobs     map[string]map[string][]string `json:"jobs"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, raw)
	}
	if got.Exposure != "private" || got.Jobs["build"]["runsOn"][0] != "ubuntu-latest" {
		t.Fatalf("unexpected result %s", raw)
	}
}

func TestEvaluateSituationWithoutResultRuleIsAnError(t *testing.T) {
	e := New()
	_, err := e.EvaluateSituation(context.Background(), "package situation\n\nimport rego.v1\n\nx := 1\n", &ir.NormalizedPipeline{}, nil)
	if err == nil {
		t.Fatal("want an error when data.situation.result is undefined")
	}
}
