package gitlab

import "testing"

// TestReplaceVariable_EmptyValueIsNotASubstitution pins the empty-value
// guard (re-raised #431 review thread): substituting an empty value renders
// `$PREFIX/semgrep:5` as `/semgrep:5` - a reference that looks resolved,
// carries no `$` for anyone to notice, and names an image that does not
// exist. The placeholder must stay so parseImageReference marks the ref
// unresolved and the image rules abstain.
func TestReplaceVariable_EmptyValueIsNotASubstitution(t *testing.T) {
	projectVars := map[string]string{"PREFIX": "", "REG": "registry.example.com"}

	got := ReplaceVariable("$PREFIX/semgrep:5", projectVars, nil, nil, nil, nil, nil)
	if got != "$PREFIX/semgrep:5" {
		t.Fatalf("an empty value substituted: got %q, want the placeholder kept", got)
	}

	got = ReplaceVariable("$REG/app:1", projectVars, nil, nil, nil, nil, nil)
	if got != "registry.example.com/app:1" {
		t.Fatalf("a non-empty value must substitute: got %q", got)
	}
}
