package ir

import (
	"encoding/json"
	"testing"
)

func TestNormalizeVisibility(t *testing.T) {
	for raw, want := range map[string]string{
		"public": VisibilityPublic, "PUBLIC": VisibilityPublic,
		"private": VisibilityPrivate, "internal": VisibilityPrivate,
		"": VisibilityUnknown, "weird": VisibilityUnknown,
	} {
		if got := NormalizeVisibility(raw); got != want {
			t.Errorf("NormalizeVisibility(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The situation facts read these through the Rego input, so the JSON keys are
// part of the contract with situation.rego.
func TestSituationFieldsReachTheRegoInput(t *testing.T) {
	p := NormalizedPipeline{
		Visibility: VisibilityPrivate,
		Jobs: []Job{{
			Name:      "build",
			Needs:     []string{"lint"},
			Caches:    []CacheRef{{Key: "npm-${{ hashFiles('**/package-lock.json') }}", Paths: []string{"~/.npm"}, Mode: "both"}},
			Artifacts: []ArtifactRef{{Name: "dist", Paths: []string{"dist/"}, Mode: "produce"}},
		}},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["visibility"] != "private" {
		t.Errorf("visibility = %v", m["visibility"])
	}
	job := m["jobs"].([]any)[0].(map[string]any)
	for _, key := range []string{"needs", "caches", "artifacts"} {
		if _, ok := job[key]; !ok {
			t.Errorf("job JSON lacks %q: %v", key, job)
		}
	}
	cache := job["caches"].([]any)[0].(map[string]any)
	if cache["mode"] != "both" {
		t.Errorf("cache mode = %v", cache["mode"])
	}
	artifact := job["artifacts"].([]any)[0].(map[string]any)
	if artifact["mode"] != "produce" {
		t.Errorf("artifact mode = %v", artifact["mode"])
	}
}
