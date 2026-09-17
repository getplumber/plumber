package ir

import "testing"

// Row 85 (platform QUESTIONS, 2026-09-16): the fingerprint names the CURRENT override
// content and nothing else, so a dismissal keyed on it lapses when the override changes.
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
}
