package control

import (
	"encoding/json"
	"strings"
	"testing"

	opaengine "github.com/getplumber/plumber/internal/engine/opa"
)

// TestAnnotateFindingsV4 checks the full contract: a finding that anchors a
// critical mutable-dependency path gets its contextual severity, its
// registered severity preserved as baseSeverity, a role line, the path id,
// and the path's own sentence as its explanation, all inside the same Data
// map the finding already marshals through.
func TestAnnotateFindingsV4(t *testing.T) {
	anchor := opaengine.Finding{Code: "ISSUE-701", Job: "release", Severity: "high", Data: map[string]any{"uses": "some/action@v1"}}
	res := &AnalysisResult{Findings: []opaengine.Finding{anchor}}
	p := AttackPath{ID: "p1", Tier: TierCritical, EntryKind: EntryMutableDependency, Jobs: []string{"release"}, Entry: EntryFact{Subject: "some/action@v1"}, Reach: Reach{Executes: true, Secrets: []string{"NPM_TOKEN"}, Impacts: []ImpactFact{{Kind: "publishes"}}}}
	hash, ok := findingAnchorHash(anchor)
	if !ok {
		t.Fatalf("findingAnchorHash: expected ok for a codeful finding")
	}
	p.AnchorHash = hash
	res.Paths = []AttackPath{p}

	AnnotateFindingsV4(res)

	f := res.Findings[0]
	if f.Severity != "critical" || f.Data["baseSeverity"] != "high" || f.Data["role"] != "Entry of path p1" {
		t.Fatalf("%+v", f)
	}
	if ids, _ := f.Data["pathIds"].([]string); len(ids) != 1 || ids[0] != "p1" {
		t.Errorf("pathIds = %v", f.Data["pathIds"])
	}
	if expl, _ := f.Data["explanation"].(string); !strings.Contains(expl, "some/action@v1") {
		t.Errorf("explanation = %q", expl)
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	for _, key := range []string{`"severity":"critical"`, `"baseSeverity":"high"`, `"explanation"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("JSON lacks %s: %s", key, raw)
		}
	}
}

// TestAnnotateFindingsV4GateFindingOnNoPathGetsNoExplanation pins the "for
// anchors" half of the contract: a gate-role finding that amplifies no path
// (so FindingLine does not say "Entry of path ...") still gets its base
// severity, contextual severity and role, but no explanation sentence, since
// there is no anchored path to render one for.
func TestAnnotateFindingsV4GateFindingOnNoPathGetsNoExplanation(t *testing.T) {
	gate := opaengine.Finding{Code: "ISSUE-501", Job: "release"}
	res := &AnalysisResult{Findings: []opaengine.Finding{gate}}

	AnnotateFindingsV4(res)

	f := res.Findings[0]
	if _, ok := f.Data["explanation"]; ok {
		t.Errorf("explanation must be absent for a finding on no path, got %q", f.Data["explanation"])
	}
	if _, ok := f.Data["pathIds"]; ok {
		t.Errorf("pathIds must be absent for a finding on no path, got %v", f.Data["pathIds"])
	}
	if f.Data["role"] != "Gate: no path to amplify today" {
		t.Errorf("role = %q", f.Data["role"])
	}
}

// TestAnnotateFindingsV4NilDataMap pins the Data-initialization branch: a
// finding whose Data map is nil (never populated by the opa engine for this
// code) still gets annotated rather than panicking on a nil-map write.
func TestAnnotateFindingsV4NilDataMap(t *testing.T) {
	f := opaengine.Finding{Code: "ISSUE-102", Job: "build"}
	res := &AnalysisResult{Findings: []opaengine.Finding{f}}

	AnnotateFindingsV4(res)

	if res.Findings[0].Data == nil {
		t.Fatalf("Data must be initialized, not left nil")
	}
	if _, ok := res.Findings[0].Data["baseSeverity"]; !ok {
		t.Errorf("baseSeverity must be set even with no prior Data")
	}
}
