package ir

import (
	"encoding/json"
	"strings"
	"testing"
)

// Row 85 (platform QUESTIONS, 2026-09-16): the fingerprint names the CURRENT override
// content and nothing else, so a dismissal keyed on it lapses when the override changes.
// Values is the whole local job block, so every fixture below is a complete job map.
func TestOverrideFingerprint_Row85(t *testing.T) {
	a := []OverriddenJob{{Name: "build", Keys: []string{"script"}, Values: map[string]any{"script": []any{"make"}}}}
	b := []OverriddenJob{{Name: "build", Keys: []string{"script"}, Values: map[string]any{"script": []any{"make test"}}}}
	c := []OverriddenJob{{Name: "test", Keys: []string{"image"}, Values: map[string]any{"image": "alpine"}}}
	if OverrideFingerprint(nil) != "" {
		t.Fatal("no override: empty fingerprint")
	}
	fa := OverrideFingerprint(a)
	if len(fa) != 16 {
		t.Fatalf("want a 16-hex fingerprint, got %q", fa)
	}
	if fa != OverrideFingerprint(a) {
		t.Fatal("not deterministic")
	}
	if fa == OverrideFingerprint(b) {
		t.Fatal("a value change must move the fingerprint")
	}
	both := append(append([]OverriddenJob{}, c...), a...)
	bothReversed := append(append([]OverriddenJob{}, a...), c...)
	if OverrideFingerprint(both) != OverrideFingerprint(bothReversed) {
		t.Fatal("discovery order must not move the fingerprint")
	}
	if OverrideFingerprint(both) == fa {
		t.Fatal("an added overridden job must move the fingerprint")
	}
	// The override content is the local job block as a whole: a key the
	// regex never matches is still part of what the user redefined.
	withExtra := []OverriddenJob{{Name: "build", Keys: []string{"script"}, Values: map[string]any{
		"script":    []any{"make"},
		"variables": map[string]any{"LEVEL": "prod"},
	}}}
	if OverrideFingerprint(withExtra) == fa {
		t.Fatal("a non-forbidden key added to the overriding block must move the fingerprint")
	}
}

// Row 85 (platform QUESTIONS, 2026-09-16): the fingerprint hashes the whole local
// job block, so a forbidden keyword that only ever appears NESTED under another key
// still moves it. Here "image" is matched by the key regex inside "variables" and
// never exists at the job's top level: hashing only the matched keys' top-level
// values would hash the same null twice and let the content change unnoticed.
func TestOverrideFingerprint_NestedOnlyKeyMovesIt_Row85(t *testing.T) {
	block := func(image string) []OverriddenJob {
		return []OverriddenJob{{
			Name:   "build",
			Keys:   []string{"image"},
			Values: map[string]any{"variables": map[string]any{"image": image}},
		}}
	}
	three := OverrideFingerprint(block("alpine:3"))
	four := OverrideFingerprint(block("alpine:4"))
	if three == "" || four == "" {
		t.Fatalf("both blocks must have a fingerprint, got %q and %q", three, four)
	}
	if three == four {
		t.Fatal("a change to a nested-only forbidden keyword must move the fingerprint")
	}
}

// Row 85 (platform QUESTIONS, 2026-09-16): same guarantee one level down in a list.
// "when" lives inside the "rules" array, never at the job's top level.
func TestOverrideFingerprint_NestedRulesValueMovesIt_Row85(t *testing.T) {
	block := func(when string) []OverriddenJob {
		return []OverriddenJob{{
			Name:   "deploy",
			Keys:   []string{"rules", "when"},
			Values: map[string]any{"rules": []any{map[string]any{"when": when}}},
		}}
	}
	if OverrideFingerprint(block("always")) == OverrideFingerprint(block("manual")) {
		t.Fatal("a change inside the rules block must move the fingerprint")
	}
}

// Row 85 (platform QUESTIONS, 2026-09-16): the overridden values feed the
// fingerprint and nothing else. The IR is the policy engine's input and may be
// dumped, so an overridden job's content must never be serialised: only the
// fingerprint, the job name and the key names travel.
func TestOverriddenJobValuesNeverSerialised_Row85(t *testing.T) {
	job := OverriddenJob{
		Name:   "build",
		Keys:   []string{"script"},
		Values: map[string]any{"script": []any{"curl https://internal.example.com/deploy"}},
	}
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal overridden job: %v", err)
	}
	got := string(raw)
	if strings.Contains(got, "values") {
		t.Fatalf("an overridden job must not serialise a values key, got %s", got)
	}
	if strings.Contains(got, "internal.example.com") {
		t.Fatalf("an overridden job must not serialise the overridden content, got %s", got)
	}
	if !strings.Contains(got, `"name":"build"`) || !strings.Contains(got, `"keys":["script"]`) {
		t.Fatalf("an overridden job must still carry its name and its keys, got %s", got)
	}
}
