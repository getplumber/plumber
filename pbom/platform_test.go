package pbom

import (
	"encoding/json"
	"testing"
)

// platformPBOM is a PBOM as a platform-mode run writes it: no run-level
// score, one entry per policy, and the platform's own global score.
func platformPBOM(t *testing.T) *PBOM {
	t.Helper()
	pb := NewGenerator("acme/target", 42, "https://gitlab.com", "main").Generate(nil, nil)
	sixtySix := 66
	pb.Policies = []PolicyScore{
		{Name: "A", Enforcement: "report", Score: "C", FinalPoints: &sixtySix, Applied: true},
		{Name: "Prod", Enforcement: "block", Applied: false, Reason: "control tree could not be applied"},
	}
	pb.PlatformGlobalScore = &PlatformGlobalScore{Letter: "B", Points: 83}
	return pb
}

// Spec s5: the PBOM of a platform-mode run carries the per-policy scores and
// the platform's global score, and NO top-level plumberScore - there is no
// run-level grade in that mode, and emitting a locally computed one is the
// wrong-verdict failure the mode removes (QUESTIONS row 44).
func TestPBOM_PlatformMode_PoliciesAndNoRunLevelScore(t *testing.T) {
	pb := platformPBOM(t)
	// scoreMode is still true in platform mode; the score itself is nil, so
	// the summary builder withholds the block rather than inventing one.
	pb.PlumberScore = BuildPlumberScoreSummary(nil, true)

	raw, err := json.Marshal(pb)
	if err != nil {
		t.Fatalf("marshal pbom: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("pbom is not valid JSON: %v", err)
	}
	if _, present := doc["plumberScore"]; present {
		t.Errorf("plumberScore must be absent in platform mode, got %v", doc["plumberScore"])
	}
	policies, ok := doc["policies"].([]any)
	if !ok || len(policies) != 2 {
		t.Fatalf("policies: %#v", doc["policies"])
	}
	first, _ := policies[0].(map[string]any)
	if first["name"] != "A" || first["enforcement"] != "report" || first["score"] != "C" || first["finalPoints"] != 66.0 {
		t.Errorf("policy entry: %#v", first)
	}
	second, _ := policies[1].(map[string]any)
	if _, present := second["score"]; present {
		t.Errorf("a policy that evaluated nothing must carry no letter: %#v", second)
	}
	if _, present := second["finalPoints"]; present {
		t.Errorf("a policy that evaluated nothing must carry no points: %#v", second)
	}
	global, ok := doc["platformGlobalScore"].(map[string]any)
	if !ok || global["letter"] != "B" || global["points"] != 83.0 {
		t.Fatalf("platformGlobalScore: %#v", doc["platformGlobalScore"])
	}
}

// A standalone PBOM is unchanged: neither key appears.
func TestPBOM_StandaloneCarriesNoPolicyKeys(t *testing.T) {
	pb := NewGenerator("acme/target", 42, "https://gitlab.com", "main").Generate(nil, nil)
	raw, err := json.Marshal(pb)
	if err != nil {
		t.Fatalf("marshal pbom: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("pbom is not valid JSON: %v", err)
	}
	for _, k := range []string{"policies", "platformGlobalScore"} {
		if _, present := doc[k]; present {
			t.Errorf("key %q must be absent outside platform mode", k)
		}
	}
}

// Spec s5 for CycloneDX: the same facts as properties, and no plumber:score
// property, because there is no run-level score to name.
func TestToCycloneDX_PlatformMode_PolicyProperties(t *testing.T) {
	cdx := platformPBOM(t).ToCycloneDX("v0.0.0-test")

	props := map[string]string{}
	for _, p := range cdx.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if props["plumber:policy:A:score"] != "C" {
		t.Errorf("plumber:policy:A:score = %q, want C", props["plumber:policy:A:score"])
	}
	if props["plumber:policy:A:enforcement"] != "report" {
		t.Errorf("plumber:policy:A:enforcement = %q, want report", props["plumber:policy:A:enforcement"])
	}
	if props["plumber:policy:A:points-final"] != "66" {
		t.Errorf("plumber:policy:A:points-final = %q, want 66", props["plumber:policy:A:points-final"])
	}
	if props["plumber:policy:Prod:enforcement"] != "block" {
		t.Errorf("a policy that evaluated nothing is still listed: %#v", props)
	}
	if _, present := props["plumber:policy:Prod:score"]; present {
		t.Errorf("a policy that evaluated nothing must carry no letter: %q", props["plumber:policy:Prod:score"])
	}
	if props["plumber:platform-global-score"] != "B" || props["plumber:platform-global-points"] != "83" {
		t.Errorf("the platform's global score must be carried: %#v", props)
	}
	if _, present := props["plumber:score"]; present {
		t.Errorf("plumber:score is the run-level grade and there is none in platform mode: %q", props["plumber:score"])
	}
}
