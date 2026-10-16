package expr

import "testing"

// TestComparedLiteralReadsTheReferencesOwnComparison pins that the literal
// a reference is compared against comes from that very comparison (either
// operand order, ==, != or a contains/startsWith call), never from a
// neighbouring clause, and that a reference compared to another reference,
// or to nothing, has none.
func TestComparedLiteralReadsTheReferencesOwnComparison(t *testing.T) {
	labels := []string{"github.event.label.name", "github.event.pull_request.labels.*.name"}
	for _, c := range []struct {
		expr, want string
		ok         bool
	}{
		{"github.event_name == 'issues' || github.event.label.name == 'ok'", "ok", true},
		{"'ok' == github.event.label.name && github.event_name == 'issues'", "ok", true},
		{"contains(github.event.pull_request.labels.*.name, 'safe to test')", "safe to test", true},
		{"${{ github.event.label.name != 'skip' }}", "skip", true},
		{"github.event.label.name == github.event.inputs.label || github.event_name == 'issues'", "", false},
		{"github.event_name == 'issues'", "", false},
	} {
		got, ok := ComparedLiteral(c.expr, labels)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: (%q, %v), want (%q, %v)", c.expr, got, ok, c.want, c.ok)
		}
	}
}
