package expr

import "testing"

// TestComparisonsReadThePolarity pins that each comparison of a reference
// to a literal says whether the condition wants them equal: != and an odd
// number of negations around it flip it.
func TestComparisonsReadThePolarity(t *testing.T) {
	refs := []string{"github.base_ref"}
	for _, c := range []struct {
		expr string
		want []Comparison
	}{
		{"github.base_ref == 'main'", []Comparison{{Literal: "main"}}},
		{"github.base_ref != 'main'", []Comparison{{Literal: "main", Negated: true}}},
		{"!(github.base_ref == 'main')", []Comparison{{Literal: "main", Negated: true}}},
		{"!(github.base_ref != 'main') || startsWith(github.base_ref, 'rel')", []Comparison{{Literal: "main"}, {Literal: "rel"}}},
		{"!contains(github.base_ref, 'x')", []Comparison{{Literal: "x", Negated: true}}},
		{"github.event_name == 'push'", nil},
	} {
		got := Comparisons(c.expr, refs)
		if len(got) != len(c.want) {
			t.Errorf("%s: %+v, want %+v", c.expr, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %+v, want %+v", c.expr, got, c.want)
			}
		}
	}
}

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
